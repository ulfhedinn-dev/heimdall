package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

var (
	scansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "heimdall_scans_total",
		Help: "Image scans by result (success|error).",
	}, []string{"result"})

	scanDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "heimdall_scan_duration_seconds",
		Help:    "Duration of image scans, including vulnerability DB updates.",
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600, 1200},
	})

	alertsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "heimdall_alerts_total",
		Help: "Alert notifications by result (sent|error).",
	}, []string{"result"})

	imageVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "heimdall_image_vulnerabilities",
		Help: "Vulnerabilities found in the latest scan of each image, by severity.",
	}, []string{"inventory", "image", "severity"})
)

func init() {
	metrics.Registry.MustRegister(scansTotal, scanDuration, alertsTotal, imageVulnerabilities)
}

// recordFindings publishes per-severity counts for the inventory's latest scan.
func recordFindings(inv *heimdallv1alpha1.ImageInventory, rep *scanner.Report) {
	critical, high, medium, low, unknown := scanner.Summarize(rep.Findings)
	for sev, n := range map[scanner.Severity]int{
		scanner.SeverityCritical: critical,
		scanner.SeverityHigh:     high,
		scanner.SeverityMedium:   medium,
		scanner.SeverityLow:      low,
		scanner.SeverityUnknown:  unknown,
	} {
		imageVulnerabilities.WithLabelValues(inv.Name, inv.Spec.ImageRef, string(sev)).Set(float64(n))
	}
}

// forgetFindings removes an inventory's series, e.g. once no pod uses it.
func forgetFindings(inv *heimdallv1alpha1.ImageInventory) {
	imageVulnerabilities.DeletePartialMatch(prometheus.Labels{"inventory": inv.Name})
}
