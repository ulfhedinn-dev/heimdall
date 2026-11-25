package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

type webhook struct {
	mu       sync.Mutex
	payloads []slackPayload
	status   int
}

func (w *webhook) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var p slackPayload
	_ = json.Unmarshal(body, &p)
	w.mu.Lock()
	w.payloads = append(w.payloads, p)
	w.mu.Unlock()
	if w.status != 0 {
		rw.WriteHeader(w.status)
	}
}

func testReport(findings ...scanner.Finding) *scanner.Report {
	return &scanner.Report{
		ImageRef:       "nginx:1.27",
		ImageDigest:    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Scanner:        "trivy",
		ScannerVersion: "v0.76.2",
		GeneratedAt:    time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC),
		Findings:       findings,
	}
}

func TestNewSlackAlerterNoopWithoutURL(t *testing.T) {
	if _, ok := NewSlackAlerter("", heimdallv1alpha1.SeverityHigh).(Noop); !ok {
		t.Fatal("expected Noop alerter for empty URL")
	}
	if err := (Noop{}).Notify(context.Background(), testReport()); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyFiltersAndDeduplicates(t *testing.T) {
	hook := &webhook{}
	srv := httptest.NewServer(hook)
	defer srv.Close()

	a := NewSlackAlerter(srv.URL, "")
	rep := testReport(
		scanner.Finding{VulnID: "CVE-LOW", Severity: scanner.SeverityLow},
		scanner.Finding{VulnID: "CVE-HIGH", Severity: scanner.SeverityHigh, PackageName: "zlib", Version: "1.2"},
		scanner.Finding{VulnID: "CVE-CRIT", Severity: scanner.SeverityCritical, PackageName: "openssl", Version: "3.0.1", FixedIn: "3.0.2"},
	)
	if err := a.Notify(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if len(hook.payloads) != 1 {
		t.Fatalf("payloads = %d, want 1", len(hook.payloads))
	}
	p := hook.payloads[0]
	if !strings.Contains(p.Text, "nginx:1.27") || !strings.Contains(p.Text, "2 new findings") {
		t.Errorf("text = %q", p.Text)
	}
	body := p.Attachments[0].Text
	if strings.Contains(body, "CVE-LOW") {
		t.Error("LOW finding must be filtered at default HIGH threshold")
	}
	if strings.Index(body, "CVE-CRIT") > strings.Index(body, "CVE-HIGH") {
		t.Error("critical findings must be listed first")
	}
	if !strings.Contains(body, "no fix") || !strings.Contains(body, "3.0.2") {
		t.Errorf("body = %q", body)
	}
	if p.Attachments[0].Color != "danger" {
		t.Errorf("color = %q, want danger", p.Attachments[0].Color)
	}

	// Same findings again: suppressed.
	if err := a.Notify(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if len(hook.payloads) != 1 {
		t.Fatalf("duplicate alert sent: %d payloads", len(hook.payloads))
	}

	// Only LOW findings: nothing sent.
	if err := a.Notify(context.Background(), testReport(scanner.Finding{VulnID: "CVE-L2", Severity: scanner.SeverityLow})); err != nil {
		t.Fatal(err)
	}
	if len(hook.payloads) != 1 {
		t.Fatalf("below-threshold alert sent")
	}
}

func TestNotifyReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(&webhook{status: http.StatusInternalServerError})
	defer srv.Close()
	a := NewSlackAlerter(srv.URL, heimdallv1alpha1.SeverityCritical)
	err := a.Notify(context.Background(), testReport(scanner.Finding{VulnID: "CVE-1", Severity: scanner.SeverityCritical}))
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want HTTP 500 error", err)
	}
	if err := a.Notify(context.Background(), nil); err != nil {
		t.Fatalf("nil report: %v", err)
	}
}

func TestBuildPayloadTruncatesPreview(t *testing.T) {
	var findings []scanner.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, scanner.Finding{VulnID: "CVE-" + string(rune('A'+i)), Severity: scanner.SeverityHigh})
	}
	p := buildPayload(testReport(), findings, "#sec", "heimdall", ":eye:")
	if !strings.Contains(p.Attachments[0].Text, "…and 5 more") {
		t.Errorf("text = %q", p.Attachments[0].Text)
	}
	if p.Attachments[0].Color != "warning" || p.Channel != "#sec" || p.Username != "heimdall" {
		t.Errorf("payload = %+v", p)
	}
	if got := shortDigest("sha256:0123456789abcdef0123"); got != "sha256:0123456789ab…" {
		t.Errorf("shortDigest = %q", got)
	}
}

func TestNotifyKeepsSameCVEInDifferentPackages(t *testing.T) {
	hook := &webhook{}
	srv := httptest.NewServer(hook)
	defer srv.Close()
	a := NewSlackAlerter(srv.URL, heimdallv1alpha1.SeverityHigh)
	err := a.Notify(context.Background(), testReport(
		scanner.Finding{VulnID: "CVE-1", Severity: scanner.SeverityHigh, PackageName: "libssl3"},
		scanner.Finding{VulnID: "CVE-1", Severity: scanner.SeverityHigh, PackageName: "openssl"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(hook.payloads) != 1 || !strings.Contains(hook.payloads[0].Text, "2 new findings") {
		t.Fatalf("payloads = %+v", hook.payloads)
	}
}
