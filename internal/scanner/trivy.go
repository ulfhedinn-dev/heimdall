package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	trivydbmeta "github.com/aquasecurity/trivy-db/pkg/metadata"
	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	trivydb "github.com/aquasecurity/trivy/pkg/db"
	fanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/javadb"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	_ "modernc.org/sqlite" // sqlite driver for the RPM DB and Java DB, as registered by the trivy CLI
)

// TrivyScanner implements Scanner by invoking the trivy library in-process.
//
// Trivy keeps process-global state (the vulnerability DB handle and the
// default HTTP transport), so scans are serialized: concurrent Scan calls
// queue behind each other. Cooldown adds a pause between consecutive scans to
// keep CPU and network use low on small nodes (e.g. Raspberry Pi).
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

	// Cooldown is the minimum pause between the end of one scan and the start
	// of the next. Zero disables the pause.
	Cooldown time.Duration

	// Platform selects which image of a multi-arch index is scanned. Defaults
	// to linux on the operator's own architecture, which matches its node.
	Platform *v1.Platform

	mu           sync.Mutex
	lastFinished time.Time
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
		pinned, err := pinToDigest(req.ImageRef, req.ImageDigest)
		if err != nil {
			return nil, err
		}
		target = pinned
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = t.DefaultTimeout
	}

	opts, err := t.buildOptions(target, req, timeout)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.waitCooldown(ctx); err != nil {
		return nil, err
	}
	defer func() { t.lastFinished = time.Now() }()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetContainerImage)
	if err != nil {
		return nil, fmt.Errorf("new trivy runner: %w", err)
	}
	defer func() { _ = runner.Close(ctx) }()

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

	// Populate the vulnerability DB version from the local cache metadata.
	mc := trivydbmeta.NewClient(trivydb.Dir(cacheDirOrDefault(t.CacheDir)))
	if dbMeta, err := mc.Get(); err == nil && dbMeta.Version != 0 {
		report.VulnDBVersion = strconv.Itoa(dbMeta.Version)
	}

	if req.IgnoreUnfixed {
		report.Findings = dropUnfixed(report.Findings)
	}
	if req.MinSeverity != "" {
		report.Findings = filterBySeverity(report.Findings, req.MinSeverity)
	}
	return report, nil
}

// waitCooldown blocks until Cooldown has elapsed since the previous scan
// finished. Must be called with t.mu held.
func (t *TrivyScanner) waitCooldown(ctx context.Context) error {
	if t.Cooldown <= 0 || t.lastFinished.IsZero() {
		return nil
	}
	wait := time.Until(t.lastFinished.Add(t.Cooldown))
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// buildOptions constructs the trivy flag.Options for a container image scan.
// Options are built directly rather than via trivy's CLI flag parser, so every
// default the CLI would normally fill in (package types, DB repositories, …)
// must be set explicitly here.
func (t *TrivyScanner) buildOptions(target string, req Request, timeout time.Duration) (trivyflag.Options, error) {
	cacheDir := cacheDirOrDefault(t.CacheDir)
	platform := t.Platform
	if platform == nil {
		platform = &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	}
	dbRepos, err := parseRefs(t.DBRepository, trivydb.DefaultGCRRepository, trivydb.DefaultGHCRRepository)
	if err != nil {
		return trivyflag.Options{}, fmt.Errorf("parse DB repository: %w", err)
	}
	javaDBRepos, err := parseRefs(t.JavaDBRepository, javadb.DefaultGCRRepository, javadb.DefaultGHCRRepository)
	if err != nil {
		return trivyflag.Options{}, fmt.Errorf("parse Java DB repository: %w", err)
	}

	opts := trivyflag.Options{
		AppVersion: t.Version(),
		GlobalOptions: trivyflag.GlobalOptions{
			Timeout:  timeout,
			CacheDir: cacheDir,
			Insecure: t.Insecure,
			Quiet:    true,
		},
		CacheOptions: trivyflag.CacheOptions{
			CacheBackend: "fs",
		},
		ScanOptions: trivyflag.ScanOptions{
			Target:            target,
			Scanners:          trivytypes.Scanners{trivytypes.VulnerabilityScanner},
			OfflineScan:       t.Offline,
			Parallel:          1,
			DetectionPriority: fanaltypes.PriorityPrecise,
			SkipVersionCheck:  true,
			DisableTelemetry:  true,
		},
		VulnerabilityOptions: trivyflag.VulnerabilityOptions{
			// Without a severity source every finding is UNKNOWN.
			VulnSeveritySources: []trivydbtypes.SourceID{"auto"},
		},
		ImageOptions: trivyflag.ImageOptions{
			ImageSources: fanaltypes.ImageSources{fanaltypes.RemoteImageSource},
			Platform:     fanaltypes.Platform{Platform: platform},
		},
		PackageOptions: trivyflag.PackageOptions{
			PkgTypes:         trivytypes.PkgTypes,
			PkgRelationships: fanaltypes.Relationships,
		},
		DBOptions: trivyflag.DBOptions{
			SkipDBUpdate:       t.Offline,
			SkipJavaDBUpdate:   t.Offline,
			NoProgress:         true,
			DBRepositories:     dbRepos,
			JavaDBRepositories: javaDBRepos,
		},
		ModuleOptions: trivyflag.ModuleOptions{
			ModuleDir: filepath.Join(cacheDir, "modules"),
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
	if req.Auth != nil {
		creds, err := authToTrivy(req.Auth)
		if err != nil {
			return opts, err
		}
		opts.Credentials = creds
	}
	return opts, nil
}

// parseRefs parses override when set, otherwise the given defaults.
func parseRefs(override string, defaults ...string) ([]name.Reference, error) {
	raw := defaults
	if override != "" {
		raw = []string{override}
	}
	refs := make([]name.Reference, 0, len(raw))
	for _, r := range raw {
		ref, err := name.ParseReference(r)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
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
	if cfg.IdentityToken != "" && user == "" {
		user = "oauth2accesstoken"
		pass = cfg.IdentityToken
	} else if cfg.RegistryToken != "" && user == "" {
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
				Severity:    severityFromTrivy(v.Severity), //nolint:staticcheck // overall severity, as shown by the trivy CLI
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
	threshold := SeverityRank(min)
	out := in[:0]
	for _, f := range in {
		if SeverityRank(f.Severity) >= threshold {
			out = append(out, f)
		}
	}
	return out
}

// pinToDigest rewrites imageRef to reference digest instead of its tag (or any
// digest already present), keeping the registry and repository.
func pinToDigest(imageRef, digest string) (string, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}
	pinned, err := name.NewDigest(ref.Context().Name()+"@"+digest, name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("pin %q to %q: %w", imageRef, digest, err)
	}
	return pinned.String(), nil
}

func cacheDirOrDefault(d string) string {
	if d == "" {
		return "/tmp/heimdall-trivy"
	}
	return d
}
