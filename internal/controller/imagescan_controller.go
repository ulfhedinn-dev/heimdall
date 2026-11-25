package controller

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/google/go-containerregistry/pkg/authn"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
	"github.com/ulfhedinn-dev/heimdall/internal/alert"
	"github.com/ulfhedinn-dev/heimdall/internal/registry"
	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

// ImageScanReconciler reconciles ImageInventory objects by triggering a
// scanner run when the inventory record is stale, writing a VulnerabilityReport
// and updating the inventory's status.
type ImageScanReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Scanner  scanner.Scanner
	Creds    registry.CredentialProvider
	Alerter  alert.Alerter
	Interval time.Duration

	// ScanTimeout bounds a single scan. Zero means 10 minutes.
	ScanTimeout time.Duration

	// MaxConcurrent bounds how many scans run in parallel across the
	// controller workqueue; map to the controller MaxConcurrentReconciles.
	MaxConcurrent int

	// Clock is overridable for tests. Zero means time.Now.
	Clock func() time.Time

	inflight sync.Map // digest -> struct{}
}

// Reconcile implements reconcile.Reconciler.
func (r *ImageScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("inventory", req.Name)

	var inv heimdallv1alpha1.ImageInventory
	if err := r.Get(ctx, req.NamespacedName, &inv); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if inv.Spec.ImageDigest == "" {
		return ctrl.Result{}, nil
	}
	// Images no longer used by any pod are kept as history but not rescanned.
	// A new pod using the digest adds a ref, which triggers a reconcile.
	if len(inv.Spec.Pods) == 0 {
		forgetFindings(&inv)
		return ctrl.Result{}, nil
	}
	if !r.isDue(&inv) {
		return ctrl.Result{RequeueAfter: r.requeueAfter(&inv)}, nil
	}

	// Avoid duplicate concurrent scans for the same digest.
	if _, loaded := r.inflight.LoadOrStore(inv.Spec.ImageDigest, struct{}{}); loaded {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	defer r.inflight.Delete(inv.Spec.ImageDigest)

	logger.Info("starting scan", "image", inv.Spec.ImageRef, "digest", inv.Spec.ImageDigest)

	// Resolve credentials: when the image is only used by pods that reference
	// imagePullSecrets, build a per-pod secret-aware provider on top of the
	// base chain.
	creds := r.credentialProviderFor(ctx, &inv)
	auth, err := creds.GetCredentials(ctx, inv.Spec.ImageRef)
	if err != nil {
		return r.markError(ctx, &inv, fmt.Errorf("resolve credentials: %w", err))
	}

	timeout := r.ScanTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	start := time.Now()
	report, err := r.Scanner.Scan(ctx, scanner.Request{
		ImageRef:    inv.Spec.ImageRef,
		ImageDigest: inv.Spec.ImageDigest,
		Auth:        auth,
		Timeout:     timeout,
	})
	scanDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		scansTotal.WithLabelValues("error").Inc()
		return r.markError(ctx, &inv, err)
	}
	scansTotal.WithLabelValues("success").Inc()

	newFindings, err := r.upsertReport(ctx, &inv, report)
	if err != nil {
		return r.markError(ctx, &inv, fmt.Errorf("persist report: %w", err))
	}

	if err := r.updateInventoryStatus(ctx, &inv, report); err != nil {
		return r.markError(ctx, &inv, fmt.Errorf("update inventory status: %w", err))
	}

	recordFindings(&inv, report)

	// Only findings not present in the previously stored report are sent, so
	// operator restarts and periodic rescans don't repeat old alerts.
	if r.Alerter != nil && len(newFindings) > 0 {
		alertReport := *report
		alertReport.Findings = newFindings
		if alertErr := r.Alerter.Notify(ctx, &alertReport); alertErr != nil {
			// Alert failures are logged, not fatal.
			alertsTotal.WithLabelValues("error").Inc()
			logger.Error(alertErr, "alert dispatch")
		} else {
			alertsTotal.WithLabelValues("sent").Inc()
		}
	}

	logger.Info("scan complete", "image", inv.Spec.ImageRef, "findings", len(report.Findings), "new", len(newFindings))
	return ctrl.Result{RequeueAfter: r.Interval}, nil
}

// SetupWithManager wires the reconciler.
func (r *ImageScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = time.Hour
	}
	if r.MaxConcurrent <= 0 {
		r.MaxConcurrent = 3
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("image-scanner").
		For(&heimdallv1alpha1.ImageInventory{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: r.MaxConcurrent}).
		Complete(r)
}

func (r *ImageScanReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *ImageScanReconciler) isDue(inv *heimdallv1alpha1.ImageInventory) bool {
	if inv.Status.LastScannedAt == nil {
		return true
	}
	return r.now().Sub(inv.Status.LastScannedAt.Time) >= r.Interval
}

func (r *ImageScanReconciler) requeueAfter(inv *heimdallv1alpha1.ImageInventory) time.Duration {
	if inv.Status.LastScannedAt == nil {
		return 0
	}
	elapsed := r.now().Sub(inv.Status.LastScannedAt.Time)
	remaining := r.Interval - elapsed
	if remaining < time.Minute {
		return time.Minute
	}
	return remaining
}

// credentialProviderFor returns a provider that layers an imagePullSecrets
// resolver on top of the base chain. It iterates all pods using the image
// and returns a scoped chain for the first pod whose pull secrets yield
// non-anonymous credentials. Falls back to the base chain if none do.
func (r *ImageScanReconciler) credentialProviderFor(ctx context.Context, inv *heimdallv1alpha1.ImageInventory) registry.CredentialProvider {
	if r.Creds == nil {
		return registry.NewChain() // empty chain returns authn.Anonymous safely
	}
	if len(inv.Spec.Pods) == 0 {
		return r.Creds
	}
	chain, ok := r.Creds.(*registry.Chain)
	if !ok {
		return r.Creds
	}
	logger := log.FromContext(ctx)
	for _, pod := range inv.Spec.Pods {
		providers := make([]registry.CredentialProvider, 0, len(chain.Providers))
		for _, p := range chain.Providers {
			if ps, ok2 := p.(*registry.PullSecretProvider); ok2 {
				providers = append(providers, ps.WithPod(pod.Namespace, pod.Name))
				continue
			}
			providers = append(providers, p)
		}
		scopedChain := registry.NewChain(providers...)
		auth, err := scopedChain.GetCredentials(ctx, inv.Spec.ImageRef)
		if err != nil {
			logger.V(1).Info("pod credentials failed, trying next pod", "pod", pod.Name, "namespace", pod.Namespace)
			continue
		}
		if auth != nil && auth != authn.Anonymous {
			return scopedChain
		}
	}
	logger.V(1).Info("no pod pull secrets resolved, using base chain", "inventory", inv.Name)
	return r.Creds
}

// upsertReport writes the VulnerabilityReport for the inventory's digest and
// returns the findings that were not present in the previously stored report.
func (r *ImageScanReconciler) upsertReport(ctx context.Context, inv *heimdallv1alpha1.ImageInventory, rep *scanner.Report) ([]scanner.Finding, error) {
	report := &heimdallv1alpha1.VulnerabilityReport{}
	report.Name = reportNameForDigest(inv.Spec.ImageDigest)

	var newFindings []scanner.Finding
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, report, func() error {
		if err := controllerutil.SetControllerReference(inv, report, r.Scheme); err != nil {
			return err
		}
		if report.Labels == nil {
			report.Labels = map[string]string{}
		}
		report.Labels["heimdall.ulfhedinn.dev/image-inventory"] = inv.Name
		report.Spec.ImageDigest = inv.Spec.ImageDigest
		report.Spec.ImageRef = inv.Spec.ImageRef
		report.Spec.Scanner = rep.Scanner
		report.Spec.ScannerVersion = rep.ScannerVersion
		report.Spec.VulnDBVersion = rep.VulnDBVersion
		// Build a map of existing findings so we can preserve FirstSeen timestamps.
		existing := make(map[string]*metav1.Time, len(report.Spec.Findings))
		for i := range report.Spec.Findings {
			f := &report.Spec.Findings[i]
			existing[findingKey(f.VulnID, f.PackageName)] = f.FirstSeen
		}
		newFindings = newFindingsSince(rep.Findings, existing)
		stored, dropped := capFindings(rep.Findings, maxStoredFindings)
		report.Spec.Findings = toAPIFindings(stored, existing)
		if dropped > 0 {
			if report.Annotations == nil {
				report.Annotations = map[string]string{}
			}
			report.Annotations[truncatedAnnotation] = strconv.Itoa(dropped)
		} else {
			delete(report.Annotations, truncatedAnnotation)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Update status subresource.
	critical, high, medium, low, unknown := scanner.Summarize(rep.Findings)
	report.Status = heimdallv1alpha1.VulnerabilityReportStatus{
		GeneratedAt: &metav1.Time{Time: rep.GeneratedAt},
		Summary: heimdallv1alpha1.SeveritySummary{
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
			Unknown:  unknown,
		},
	}
	return newFindings, r.Status().Update(ctx, report)
}

// maxStoredFindings keeps a VulnerabilityReport well below etcd's ~1.5 MiB
// object limit (a finding is roughly 300 bytes). The status summary still
// counts every finding.
const maxStoredFindings = 3000

// truncatedAnnotation records how many lower-severity findings were left out
// of a report because of maxStoredFindings.
const truncatedAnnotation = "heimdall.ulfhedinn.dev/truncated-findings"

// capFindings returns at most limit findings, keeping the most severe, and the
// number dropped.
func capFindings(in []scanner.Finding, limit int) ([]scanner.Finding, int) {
	if len(in) <= limit {
		return in, 0
	}
	sorted := slices.Clone(in)
	slices.SortStableFunc(sorted, func(a, b scanner.Finding) int {
		return scanner.SeverityRank(b.Severity) - scanner.SeverityRank(a.Severity)
	})
	return sorted[:limit], len(in) - limit
}

// findingKey identifies a finding within one image: the same CVE can affect
// several packages.
func findingKey(vulnID, pkg string) string { return vulnID + "|" + pkg }

// newFindingsSince returns the findings whose key is not in existing.
func newFindingsSince(findings []scanner.Finding, existing map[string]*metav1.Time) []scanner.Finding {
	var out []scanner.Finding
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		k := findingKey(f.VulnID, f.PackageName)
		if _, ok := existing[k]; ok || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

func (r *ImageScanReconciler) updateInventoryStatus(ctx context.Context, inv *heimdallv1alpha1.ImageInventory, rep *scanner.Report) error {
	critical, high, medium, low, _ := scanner.Summarize(rep.Findings)
	return r.updateStatus(ctx, inv.Name, func(fresh *heimdallv1alpha1.ImageInventory) {
		r.applyScanStatus(fresh, inv.Spec.ImageRef, critical, high, medium, low)
	})
}

// updateStatus re-reads the inventory and applies mutate to its status,
// retrying on write conflicts (the pod reconciler updates the same object).
func (r *ImageScanReconciler) updateStatus(ctx context.Context, name string, mutate func(*heimdallv1alpha1.ImageInventory)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		fresh := &heimdallv1alpha1.ImageInventory{}
		if err := r.Get(ctx, types.NamespacedName{Name: name}, fresh); err != nil {
			return err
		}
		mutate(fresh)
		return r.Status().Update(ctx, fresh)
	})
}

func (r *ImageScanReconciler) applyScanStatus(fresh *heimdallv1alpha1.ImageInventory, imageRef string, critical, high, medium, low int) {
	fresh.Status.LastScannedAt = &metav1.Time{Time: r.now()}
	fresh.Status.CriticalCount = critical
	fresh.Status.HighCount = high
	fresh.Status.MediumCount = medium
	fresh.Status.LowCount = low
	fresh.Status.LastError = ""
	fresh.Status.ScanResult = heimdallv1alpha1.ScanResultVulnerable
	if critical+high+medium+low == 0 {
		fresh.Status.ScanResult = heimdallv1alpha1.ScanResultClean
	}
	fresh.Status.Conditions = setCondition(fresh.Status.Conditions, metav1.Condition{
		Type:    "Scanned",
		Status:  metav1.ConditionTrue,
		Reason:  "ScanCompleted",
		Message: fmt.Sprintf("scanned %s", imageRef),
	})
}

func (r *ImageScanReconciler) markError(ctx context.Context, inv *heimdallv1alpha1.ImageInventory, scanErr error) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Error(scanErr, "scan failed", "digest", inv.Spec.ImageDigest)

	updateErr := r.updateStatus(ctx, inv.Name, func(fresh *heimdallv1alpha1.ImageInventory) {
		fresh.Status.LastError = truncate(scanErr.Error(), 512)
		fresh.Status.ScanResult = heimdallv1alpha1.ScanResultError
		fresh.Status.LastScannedAt = &metav1.Time{Time: r.now()}
		fresh.Status.Conditions = setCondition(fresh.Status.Conditions, metav1.Condition{
			Type:    "Scanned",
			Status:  metav1.ConditionFalse,
			Reason:  "ScanFailed",
			Message: truncate(scanErr.Error(), 256),
		})
	})
	if updateErr != nil {
		logger.Error(updateErr, "update error status")
		return ctrl.Result{}, updateErr
	}
	// The error is recorded on the inventory; retry on the normal schedule
	// rather than hammering a registry that is failing.
	return ctrl.Result{RequeueAfter: r.Interval}, nil
}

func reportNameForDigest(digest string) string {
	trimmed := strings.TrimPrefix(digest, "sha256:")
	sum := sha1.Sum([]byte(trimmed))
	return "report-" + hex.EncodeToString(sum[:10])
}

// toAPIFindings converts scanner findings to API findings, preserving FirstSeen
// timestamps for vulnerabilities already present in the report.
func toAPIFindings(in []scanner.Finding, existing map[string]*metav1.Time) []heimdallv1alpha1.Finding {
	now := &metav1.Time{Time: time.Now()}
	out := make([]heimdallv1alpha1.Finding, 0, len(in))
	for _, f := range in {
		firstSeen := now
		if t, ok := existing[findingKey(f.VulnID, f.PackageName)]; ok && t != nil {
			firstSeen = t
		}
		out = append(out, heimdallv1alpha1.Finding{
			VulnID:      f.VulnID,
			Severity:    heimdallv1alpha1.Severity(f.Severity),
			PackageName: f.PackageName,
			Version:     f.Version,
			FixedIn:     f.FixedIn,
			Title:       f.Title,
			PrimaryURL:  f.PrimaryURL,
			Target:      f.Target,
			FirstSeen:   firstSeen,
		})
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ClientSecretResolver implements registry.PodSecretResolver so a controller client
// can be dropped directly into the credential chain if desired.
type ClientSecretResolver struct{ Client client.Client }

// SecretsForPod implements registry.PodSecretResolver.
func (s *ClientSecretResolver) SecretsForPod(ctx context.Context, namespace, name string) ([]corev1.Secret, error) {
	if s == nil || s.Client == nil {
		return nil, nil
	}
	var pod corev1.Pod
	if err := s.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &pod); err != nil {
		return nil, err
	}
	out := make([]corev1.Secret, 0, len(pod.Spec.ImagePullSecrets))
	for _, ref := range pod.Spec.ImagePullSecrets {
		var secret corev1.Secret
		if err := s.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &secret); err != nil {
			continue
		}
		out = append(out, secret)
	}
	return out, nil
}
