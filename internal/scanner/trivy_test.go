package scanner

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"testing"
	"time"

	trivydb "github.com/aquasecurity/trivy/pkg/db"
	fanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/authn"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPinToDigest(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"nginx", "index.docker.io/library/nginx@" + testDigest},
		{"nginx:1.27", "index.docker.io/library/nginx@" + testDigest},
		{"ghcr.io/org/app:v1", "ghcr.io/org/app@" + testDigest},
		{"registry.local:5000/team/app:v2", "registry.local:5000/team/app@" + testDigest},
		{"registry.local:5000/team/app", "registry.local:5000/team/app@" + testDigest},
		{"ghcr.io/org/app:v1@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ghcr.io/org/app@" + testDigest},
	}
	for _, tc := range cases {
		got, err := pinToDigest(tc.ref, testDigest)
		if err != nil {
			t.Errorf("pinToDigest(%q): %v", tc.ref, err)
			continue
		}
		if got != tc.want {
			t.Errorf("pinToDigest(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
	if _, err := pinToDigest("Not A Ref!", testDigest); err == nil {
		t.Error("expected error for invalid reference")
	}
}

func TestBuildOptionsDefaults(t *testing.T) {
	s := NewTrivyScanner()
	s.CacheDir = "/cache"
	opts, err := s.buildOptions("nginx@"+testDigest, Request{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Without explicit package types trivy detects nothing, so every image
	// would be reported clean.
	if !slices.Equal(opts.PkgTypes, trivytypes.PkgTypes) {
		t.Errorf("PkgTypes = %v, want %v", opts.PkgTypes, trivytypes.PkgTypes)
	}
	if len(opts.PkgRelationships) == 0 {
		t.Error("PkgRelationships must be set")
	}
	if len(opts.DBRepositories) != 2 || opts.DBRepositories[0].String() != trivydb.DefaultGCRRepository {
		t.Errorf("DBRepositories = %v", opts.DBRepositories)
	}
	if len(opts.JavaDBRepositories) != 2 {
		t.Errorf("JavaDBRepositories = %v", opts.JavaDBRepositories)
	}
	if !opts.SkipVersionCheck || !opts.DisableTelemetry {
		t.Error("version check and telemetry must be disabled")
	}
	if len(opts.VulnSeveritySources) != 1 || opts.VulnSeveritySources[0] != "auto" {
		t.Errorf("VulnSeveritySources = %v, want [auto]", opts.VulnSeveritySources)
	}
	if opts.Parallel != 1 {
		t.Errorf("Parallel = %d, want 1", opts.Parallel)
	}
	if opts.CacheDir != "/cache" || opts.ModuleDir != "/cache/modules" {
		t.Errorf("CacheDir=%q ModuleDir=%q", opts.CacheDir, opts.ModuleDir)
	}
	if opts.Platform.Platform == nil || opts.Platform.OS != "linux" || opts.Platform.Architecture != runtime.GOARCH {
		t.Errorf("Platform = %+v", opts.Platform.Platform)
	}
	if !slices.Equal(opts.ImageSources, fanaltypes.ImageSources{fanaltypes.RemoteImageSource}) {
		t.Errorf("ImageSources = %v", opts.ImageSources)
	}
	if opts.Timeout != time.Minute || opts.Target != "nginx@"+testDigest {
		t.Errorf("Timeout=%v Target=%q", opts.Timeout, opts.Target)
	}
}

func TestBuildOptionsOverridesAndAuth(t *testing.T) {
	s := NewTrivyScanner()
	s.Offline = true
	s.DBRepository = "registry.local/trivy-db:2"
	s.JavaDBRepository = "registry.local/trivy-java-db:1"
	opts, err := s.buildOptions("x", Request{Auth: &authn.Basic{Username: "u", Password: "p"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.SkipDBUpdate || !opts.SkipJavaDBUpdate || !opts.OfflineScan {
		t.Error("offline mode must skip DB updates")
	}
	if len(opts.DBRepositories) != 1 || opts.DBRepositories[0].String() != "registry.local/trivy-db:2" {
		t.Errorf("DBRepositories = %v", opts.DBRepositories)
	}
	if len(opts.Credentials) != 1 || opts.Credentials[0].Username != "u" || opts.Credentials[0].Password != "p" {
		t.Errorf("Credentials = %+v", opts.Credentials)
	}

	s.DBRepository = "Not A Ref!"
	if _, err := s.buildOptions("x", Request{}, time.Minute); err == nil {
		t.Error("expected error for invalid DB repository")
	}
}

type fakeAuth struct {
	cfg *authn.AuthConfig
	err error
}

func (f fakeAuth) Authorization() (*authn.AuthConfig, error) { return f.cfg, f.err }

func TestAuthToTrivy(t *testing.T) {
	cases := []struct {
		name     string
		auth     authn.Authenticator
		wantUser string
		wantPass string
		wantNone bool
		wantErr  bool
	}{
		{name: "anonymous", auth: authn.Anonymous, wantNone: true},
		{name: "basic", auth: &authn.Basic{Username: "u", Password: "p"}, wantUser: "u", wantPass: "p"},
		{name: "identity token", auth: fakeAuth{cfg: &authn.AuthConfig{IdentityToken: "idt"}}, wantUser: "oauth2accesstoken", wantPass: "idt"},
		{name: "registry token", auth: fakeAuth{cfg: &authn.AuthConfig{RegistryToken: "rt"}}, wantUser: "oauth2accesstoken", wantPass: "rt"},
		{name: "nil config", auth: fakeAuth{}, wantNone: true},
		{name: "error", auth: fakeAuth{err: errors.New("boom")}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := authToTrivy(tc.auth)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNone {
				if len(creds) != 0 {
					t.Fatalf("want no creds, got %+v", creds)
				}
				return
			}
			if len(creds) != 1 || creds[0].Username != tc.wantUser || creds[0].Password != tc.wantPass {
				t.Fatalf("got %+v", creds)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	r := trivytypes.Report{Results: trivytypes.Results{
		{Target: "debian 12", Vulnerabilities: []trivytypes.DetectedVulnerability{
			{VulnerabilityID: "CVE-1", PkgName: "openssl", InstalledVersion: "3.0.1", FixedVersion: "3.0.2"},
			{VulnerabilityID: "CVE-2", PkgName: "zlib", InstalledVersion: "1.2"},
		}},
		{Target: "app/go.mod"},
	}}
	r.Results[0].Vulnerabilities[0].Severity = "critical" //nolint:staticcheck // field heimdall reads
	r.Results[0].Vulnerabilities[1].Severity = "weird"    //nolint:staticcheck // field heimdall reads
	got := normalize(r)
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].VulnID != "CVE-1" || got[0].Severity != SeverityCritical || got[0].FixedIn != "3.0.2" || got[0].Target != "debian 12" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Severity != SeverityUnknown {
		t.Errorf("got[1].Severity = %q", got[1].Severity)
	}
}

func TestFilters(t *testing.T) {
	in := []Finding{
		{VulnID: "a", Severity: SeverityLow, FixedIn: "1"},
		{VulnID: "b", Severity: SeverityHigh},
		{VulnID: "c", Severity: SeverityCritical, FixedIn: "2"},
		{VulnID: "d", Severity: SeverityUnknown, FixedIn: "3"},
	}
	high := filterBySeverity(slices.Clone(in), SeverityHigh)
	if len(high) != 2 || high[0].VulnID != "b" || high[1].VulnID != "c" {
		t.Errorf("filterBySeverity = %+v", high)
	}
	fixed := dropUnfixed(slices.Clone(in))
	if len(fixed) != 3 || fixed[1].VulnID != "c" {
		t.Errorf("dropUnfixed = %+v", fixed)
	}
}

func TestSummarizeAndRank(t *testing.T) {
	c, h, m, l, u := Summarize([]Finding{
		{Severity: SeverityCritical}, {Severity: SeverityHigh}, {Severity: SeverityHigh},
		{Severity: SeverityMedium}, {Severity: SeverityLow}, {Severity: "?"},
	})
	if c != 1 || h != 2 || m != 1 || l != 1 || u != 1 {
		t.Errorf("Summarize = %d %d %d %d %d", c, h, m, l, u)
	}
	order := []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if SeverityRank(order[i]) <= SeverityRank(order[i-1]) {
			t.Errorf("rank(%s) <= rank(%s)", order[i], order[i-1])
		}
	}
}

func TestScanRequiresImageRef(t *testing.T) {
	if _, err := NewTrivyScanner().Scan(context.Background(), Request{}); err == nil {
		t.Error("expected error for empty image ref")
	}
}

func TestWaitCooldown(t *testing.T) {
	s := &TrivyScanner{Cooldown: 50 * time.Millisecond}
	if err := s.waitCooldown(context.Background()); err != nil {
		t.Fatal(err)
	}

	s.lastFinished = time.Now()
	start := time.Now()
	if err := s.waitCooldown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("waited only %v", time.Since(start))
	}

	s.lastFinished = time.Now()
	s.Cooldown = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.waitCooldown(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
