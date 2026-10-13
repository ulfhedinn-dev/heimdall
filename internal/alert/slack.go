// Package alert publishes new vulnerability findings to outbound notification
// channels. The initial implementation targets Slack incoming webhooks.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

// Alerter publishes an alert for a newly scanned image.
type Alerter interface {
	// Notify sends a notification for the given report. Implementations should
	// de-duplicate findings they have already announced for the same digest.
	Notify(ctx context.Context, report *scanner.Report) error
}

// Noop is an Alerter that discards notifications. Used when no webhook is
// configured.
type Noop struct{}

// Notify implements Alerter.
func (Noop) Notify(context.Context, *scanner.Report) error { return nil }

// SlackAlerter posts to a Slack-compatible incoming webhook URL.
//
// It filters findings below MinSeverity and remembers the vuln-id set it has
// already announced per image digest, so repeated scans of the same digest do
// not re-page on-call every reconcile.
type SlackAlerter struct {
	WebhookURL  string
	MinSeverity heimdallv1alpha1.Severity
	HTTPClient  *http.Client

	// Channel overrides the default channel. Leave empty to use the webhook's
	// configured destination.
	Channel string

	// Username and IconEmoji override the Slack sender's identity.
	Username  string
	IconEmoji string

	mu       sync.Mutex
	notified map[string]map[string]struct{} // digest -> vuln ids already announced
}

// NewSlackAlerter constructs an alerter. When url is empty, Noop is returned.
func NewSlackAlerter(url string, min heimdallv1alpha1.Severity) Alerter {
	if url == "" {
		return Noop{}
	}
	if min == "" {
		min = heimdallv1alpha1.SeverityHigh
	}
	return &SlackAlerter{
		WebhookURL:  url,
		MinSeverity: min,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
		notified:    map[string]map[string]struct{}{},
	}
}

// Notify sends an alert for findings at or above MinSeverity that have not
// been announced for this digest before.
func (s *SlackAlerter) Notify(ctx context.Context, report *scanner.Report) error {
	if report == nil {
		return nil
	}
	threshold := severityOrder(scannerSeverityFromAPI(s.MinSeverity))
	// Collect new findings.
	var newOnes []scanner.Finding
	s.mu.Lock()
	seen := s.notified[report.ImageDigest]
	if seen == nil {
		seen = map[string]struct{}{}
	}
	for _, f := range report.Findings {
		if severityOrder(f.Severity) < threshold {
			continue
		}
		if _, ok := seen[f.VulnID]; ok {
			continue
		}
		seen[f.VulnID] = struct{}{}
		newOnes = append(newOnes, f)
	}
	s.notified[report.ImageDigest] = seen
	s.mu.Unlock()

	if len(newOnes) == 0 {
		return nil
	}

	payload := buildPayload(report, newOnes, s.Channel, s.Username, s.IconEmoji)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("post slack webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// slackPayload is the minimal subset of the Slack incoming webhook payload
// used by this alerter.
type slackPayload struct {
	Channel     string       `json:"channel,omitempty"`
	Username    string       `json:"username,omitempty"`
	IconEmoji   string       `json:"icon_emoji,omitempty"`
	Text        string       `json:"text"`
	Attachments []attachment `json:"attachments,omitempty"`
}

type attachment struct {
	Color  string  `json:"color,omitempty"`
	Title  string  `json:"title,omitempty"`
	Text   string  `json:"text,omitempty"`
	Fields []field `json:"fields,omitempty"`
}

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func buildPayload(r *scanner.Report, findings []scanner.Finding, channel, username, icon string) slackPayload {
	critical, high, medium, low, _ := scanner.Summarize(findings)
	// Sort findings by severity (desc) then vulnID.
	sort.SliceStable(findings, func(i, j int) bool {
		if severityOrder(findings[i].Severity) != severityOrder(findings[j].Severity) {
			return severityOrder(findings[i].Severity) > severityOrder(findings[j].Severity)
		}
		return findings[i].VulnID < findings[j].VulnID
	})

	preview := findings
	const maxPreview = 10
	if len(preview) > maxPreview {
		preview = preview[:maxPreview]
	}
	var lines []string
	for _, f := range preview {
		fix := f.FixedIn
		if fix == "" {
			fix = "no fix"
		}
		lines = append(lines, fmt.Sprintf("• `%s` *%s* %s@%s → %s", f.VulnID, f.Severity, f.PackageName, f.Version, fix))
	}
	if len(findings) > maxPreview {
		lines = append(lines, fmt.Sprintf("…and %d more", len(findings)-maxPreview))
	}

	color := "warning"
	if critical > 0 {
		color = "danger"
	}

	header := fmt.Sprintf(":warning: *%s* — %d new findings (%d critical, %d high, %d medium, %d low)",
		r.ImageRef, len(findings), critical, high, medium, low)

	return slackPayload{
		Channel:   channel,
		Username:  username,
		IconEmoji: icon,
		Text:      header,
		Attachments: []attachment{{
			Color: color,
			Title: fmt.Sprintf("Image digest %s", shortDigest(r.ImageDigest)),
			Text:  strings.Join(lines, "\n"),
			Fields: []field{
				{Title: "Scanner", Value: r.Scanner + " " + r.ScannerVersion, Short: true},
				{Title: "Scanned at", Value: r.GeneratedAt.Format(time.RFC3339), Short: true},
			},
		}},
	}
}

func shortDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") && len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

func scannerSeverityFromAPI(s heimdallv1alpha1.Severity) scanner.Severity {
	switch s {
	case heimdallv1alpha1.SeverityCritical:
		return scanner.SeverityCritical
	case heimdallv1alpha1.SeverityHigh:
		return scanner.SeverityHigh
	case heimdallv1alpha1.SeverityMedium:
		return scanner.SeverityMedium
	case heimdallv1alpha1.SeverityLow:
		return scanner.SeverityLow
	default:
		return scanner.SeverityUnknown
	}
}

func severityOrder(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 4
	case scanner.SeverityHigh:
		return 3
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityLow:
		return 1
	default:
		return 0
	}
}
