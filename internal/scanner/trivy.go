package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	fanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// TrivyScanner implements Scanner by invoking the trivy library in-process.
// It is safe for concurrent use; each Scan call constructs its own runner.
type TrivyScanner struct {
	// CacheDir is where trivy stores its vulnerability DB and layer cache.
	// Defaults to /tmp/heimdall-trivy when empty.
	CacheDir string

	// DBRepository overrides the trivy vulnerability DB OCI reference.
	DBRepository string

	// JavaDBRepository overrides the trivy Java DB OCI reference.
	JavaDBRepository string

	// DefaultTimeout bounds a scan when Request.Timeout is zero.
	DefaultTimeout time.Duration

	// Offline instructs trivy to skip DB updates (requires a pre-populated cache).
	Offline bool

	// Insecure allows insecure (non-TLS) registries. Not recommended.
	Insecure bool
}

// NewTrivyScanner returns a scanner with reasonable defaults.
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		CacheDir:       "/tmp/heimdall-trivy",
		DefaultTimeout: 5 * time.Minute,
	}
}

// Name implements Scanner.
func (t *TrivyScanner) Name() string { return "trivy" }

// Version implements Scanner. The real version is embedded by the trivy
// library at build time; we read it from Go build info.
func (t *TrivyScanner) Version() string { return trivyVersion() }

// Scan performs an image vulnerability scan with trivy.
func (t *TrivyScanner) Scan(ctx context.Context, req Request) (*Report, error) {
	if req.ImageRef == "" {
		return nil, fmt.Errorf("scanner: image reference is required")
	}
	target := req.ImageRef
	if req.ImageDigest != "" {
		target = pinToDigest(req.ImageRef, req.ImageDigest)
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = t.DefaultTimeout
	}

	opts, err := t.buildOptions(target, req, timeout)
	if err != nil {
		return nil, err
	}

	runner, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("new trivy runner: %w", err)
	}
	defer runner.Close(ctx)

	raw, err := runner.ScanImage(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("trivy scan %s: %w", target, err)
	}

	report := &Report{
		ImageRef:       req.ImageRef,
		ImageDigest:    req.ImageDigest,
		Scanner:        t.Name(),
		ScannerVersion: t.Version(),
		GeneratedAt:    time.Now().UTC(),
		Findings:       normalize(raw),
	}
	if req.IgnoreUnfixed {
		report.Findings = dropUnfixed(report.Findings)
	}
	if req.MinSeverity != "" {
		report.Findings = filterBySeverity(report.Findings, req.MinSeverity)
	}
	return report, nil
}

// buildOptions constructs the trivy flag.Options for a container image scan.
func (t *TrivyScanner) buildOptions(target string, req Request, timeout time.Duration) (trivyflag.Options, error) {
	opts := trivyflag.Options{
		GlobalOptions: trivyflag.GlobalOptions{
			Timeout:  timeout,
			CacheDir: cacheDirOrDefault(t.CacheDir),
			Insecure: t.Insecure,
			Quiet:    true,
		},
		ScanOptions: trivyflag.ScanOptions{
			Target:   target,
			Scanners: trivytypes.Scanners{trivytypes.VulnerabilityScanner},
		},
		ImageOptions: trivyflag.ImageOptions{
			ImageSources: fanaltypes.ImageSources{fanaltypes.RemoteImageSource},
		},
		DBOptions: trivyflag.DBOptions{
			SkipDBUpdate:     t.Offline,
			SkipJavaDBUpdate: t.Offline,
			NoProgress:       true,
		},
		ReportOptions: trivyflag.ReportOptions{
			Format: trivytypes.FormatJSON,
			Severities: []trivydbtypes.Severity{
				trivydbtypes.SeverityUnknown,
				trivydbtypes.SeverityLow,
				trivydbtypes.SeverityMedium,
				trivydbtypes.SeverityHigh,
				trivydbtypes.SeverityCritical,
			},
		},
	}
	if t.DBRepository != "" {
		ref, err := name.ParseReference(t.DBRepository)
		if err != nil {
			return opts, fmt.Errorf("parse DB repository: %w", err)
		}
		opts.DBOptions.DBRepositories = []name.Reference{ref}
	}
	if t.JavaDBRepository != "" {
		ref, err := name.ParseReference(t.JavaDBRepository)
		if err != nil {
			return opts, fmt.Errorf("parse Java DB repository: %w", err)
		}
		opts.DBOptions.JavaDBRepositories = []name.Reference{ref}
	}
	if req.Auth != nil {
		creds, err := authToTrivy(req.Auth)
		if err != nil {
			return opts, err
		}
		opts.RegistryOptions.Credentials = creds
	}
	return opts, nil
}

// authToTrivy converts a go-containerregistry authenticator into trivy's
// RegistryOptions.Credentials slice.
func authToTrivy(a authn.Authenticator) ([]fanaltypes.Credential, error) {
	cfg, err := a.Authorization()
	if err != nil {
		return nil, fmt.Errorf("resolve authn: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}
	if cfg.Username == "" && cfg.Password == "" && cfg.RegistryToken == "" && cfg.IdentityToken == "" {
		return nil, nil
	}
	user, pass := cfg.Username, cfg.Password
	if cfg.RegistryToken != "" && user == "" {
		user = "oauth2accesstoken"
		pass = cfg.RegistryToken
	}
	return []fanaltypes.Credential{{Username: user, Password: pass}}, nil
}

// normalize converts a trivy Report into the local Finding slice.
func normalize(r trivytypes.Report) []Finding {
	var out []Finding
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, Finding{
				VulnID:      v.VulnerabilityID,
				Severity:    severityFromTrivy(v.Severity),
				PackageName: v.PkgName,
				Version:     v.InstalledVersion,
				FixedIn:     v.FixedVersion,
				Title:       v.Title,
				PrimaryURL:  v.PrimaryURL,
				Target:      res.Target,
			})
		}
	}
	return out
}

func severityFromTrivy(s string) Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

func dropUnfixed(in []Finding) []Finding {
	out := in[:0]
	for _, f := range in {
		if f.FixedIn != "" {
			out = append(out, f)
		}
	}
	return out
}

func filterBySeverity(in []Finding, min Severity) []Finding {
	threshold := severityOrder(min)
	out := in[:0]
	for _, f := range in {
		if severityOrder(f.Severity) >= threshold {
			out = append(out, f)
		}
	}
	return out
}

func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func pinToDigest(imageRef, digest string) string {
	if digest == "" {
		return imageRef
	}
	// Strip tag if present and append digest.
	last := strings.LastIndex(imageRef, "/")
	segment := imageRef
	prefix := ""
	if last >= 0 {
		prefix = imageRef[:last+1]
		segment = imageRef[last+1:]
	}
	if idx := strings.LastIndex(segment, ":"); idx >= 0 {
		segment = segment[:idx]
	}
	return prefix + segment + "@" + digest
}

func cacheDirOrDefault(d string) string {
	if d == "" {
		return "/tmp/heimdall-trivy"
	}
	return d
}
