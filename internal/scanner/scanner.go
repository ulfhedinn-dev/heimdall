// Package scanner defines the pluggable image-vulnerability scanning interface
// used by the Heimdall operator.
package scanner

import (
	"context"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
)

// Severity mirrors the trivy severity classification but is kept local so the
// controller package does not need to import trivy types directly.
type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is a single scanner-reported vulnerability.
type Finding struct {
	VulnID      string
	Severity    Severity
	PackageName string
	Version     string
	FixedIn     string
	Title       string
	PrimaryURL  string
	Target      string
}

// Report is the normalized output of a scan.
type Report struct {
	ImageRef       string
	ImageDigest    string
	Scanner        string
	ScannerVersion string
	VulnDBVersion  string
	GeneratedAt    time.Time
	Findings       []Finding
}

// Request parameters for a scan.
type Request struct {
	// ImageRef is the human-readable image reference.
	ImageRef string

	// ImageDigest is the resolved digest (preferred over tag for reproducibility).
	// When set, scanners should pin to this digest.
	ImageDigest string

	// Auth is the authenticator to use when fetching the image.
	Auth authn.Authenticator

	// MinSeverity, when non-empty, instructs scanners to filter findings below
	// this threshold. Scanners may still return all findings; this is a hint.
	MinSeverity Severity

	// IgnoreUnfixed, when true, drops findings that have no known fix version.
	IgnoreUnfixed bool

	// Timeout bounds the scan. Zero means use the scanner's default.
	Timeout time.Duration
}

// Scanner is the pluggable interface implemented by Trivy (and any future
// scanner — Grype, Snyk, etc.) wired into Heimdall.
type Scanner interface {
	// Name returns the scanner identifier (e.g. "trivy").
	Name() string

	// Version returns the running scanner version.
	Version() string

	// Scan performs a single image scan and returns a normalized report.
	Scan(ctx context.Context, req Request) (*Report, error)
}

// Summarize counts findings per severity.
func Summarize(findings []Finding) (critical, high, medium, low, unknown int) {
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			critical++
		case SeverityHigh:
			high++
		case SeverityMedium:
			medium++
		case SeverityLow:
			low++
		default:
			unknown++
		}
	}
	return
}
