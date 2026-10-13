package controller

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

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

	timeout := r.Interval / 2
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	report, err := r.Scanner.Scan(ctx, scanner.Request{
		ImageRef:    inv.Spec.ImageRef,
		ImageDigest: inv.Spec.ImageDigest,
		Auth:        auth,
		Timeout:     timeout,
	})
	if err != nil {
		return r.markError(ctx, &inv, err)
	}

	if err := r.upsertReport(ctx, &inv, report); err != nil {
		return r.markError(ctx, &inv, fmt.Errorf("persist report: %w", err))
	}

	if err := r.updateInventoryStatus(ctx, &inv, report); err != nil {
		return r.markError(ctx, &inv, fmt.Errorf("update inventory status: %w", err))
	}

	if r.Alerter != nil {
		if alertErr := r.Alerter.Notify(ctx, report); alertErr != nil {
			// Alert failures are logged, not fatal.
			logger.Error(alertErr, "alert dispatch")
		}
	}

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
// resolver on top of the base chain, scoped to the first pod using this
// image (needed so we can resolve namespaced secrets).
func (r *ImageScanReconciler) credentialProviderFor(_ context.Context, inv *heimdallv1alpha1.ImageInventory) registry.CredentialProvider {
	if len(inv.Spec.Pods) == 0 || r.Creds == nil {
		return r.Creds
	}
	// If the base chain contains a PullSecretProvider, create a scoped copy.
	if chain, ok := r.Creds.(*registry.Chain); ok {
		pod := inv.Spec.Pods[0]
		providers := make([]registry.CredentialProvider, 0, len(chain.Providers))
		for _, p := range chain.Providers {
			if ps, ok := p.(*registry.PullSecretProvider); ok {
				providers = append(providers, ps.WithPod(pod.Namespace, pod.Name))
				continue
			}
			providers = append(providers, p)
		}
		return registry.NewChain(providers...)
	}
	return r.Creds
}

func (r *ImageScanReconciler) upsertReport(ctx context.Context, inv *heimdallv1alpha1.ImageInventory, rep *scanner.Report) error {
	report := &heimdallv1alpha1.VulnerabilityReport{}
	report.Name = reportNameForDigest(inv.Spec.ImageDigest)

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
		report.Spec.Findings = toAPIFindings(rep.Findings)
		return nil
	})
	if err != nil {
		return err
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
	return r.Status().Update(ctx, report)
}

func (r *ImageScanReconciler) updateInventoryStatus(ctx context.Context, inv *heimdallv1alpha1.ImageInventory, rep *scanner.Report) error {
	// Re-fetch to avoid stale status writes.
	fresh := &heimdallv1alpha1.ImageInventory{}
	if err := r.Get(ctx, types.NamespacedName{Name: inv.Name}, fresh); err != nil {
		return err
	}
	critical, high, medium, low, _ := scanner.Summarize(rep.Findings)
	fresh.Status.LastScannedAt = &metav1.Time{Time: r.now()}
	fresh.Status.CriticalCount = critical
	fresh.Status.HighCount = high
	fresh.Status.MediumCount = medium
	fresh.Status.LowCount = low
	fresh.Status.LastError = ""
	switch {
	case critical+high+medium+low == 0:
		fresh.Status.ScanResult = heimdallv1alpha1.ScanResultClean
	default:
		fresh.Status.ScanResult = heimdallv1alpha1.ScanResultVulnerable
	}
	fresh.Status.Conditions = setCondition(fresh.Status.Conditions, metav1.Condition{
		Type:    "Scanned",
		Status:  metav1.ConditionTrue,
		Reason:  "ScanCompleted",
		Message: fmt.Sprintf("scanned %s", inv.Spec.ImageRef),
	})
	return r.Status().Update(ctx, fresh)
}

func (r *ImageScanReconciler) markError(ctx context.Context, inv *heimdallv1alpha1.ImageInventory, scanErr error) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Error(scanErr, "scan failed", "digest", inv.Spec.ImageDigest)

	fresh := &heimdallv1alpha1.ImageInventory{}
	if getErr := r.Get(ctx, types.NamespacedName{Name: inv.Name}, fresh); getErr != nil {
		return ctrl.Result{}, scanErr
	}
	fresh.Status.LastError = truncate(scanErr.Error(), 512)
	fresh.Status.ScanResult = heimdallv1alpha1.ScanResultError
	fresh.Status.LastScannedAt = &metav1.Time{Time: r.now()}
	fresh.Status.Conditions = setCondition(fresh.Status.Conditions, metav1.Condition{
		Type:    "Scanned",
		Status:  metav1.ConditionFalse,
		Reason:  "ScanFailed",
		Message: truncate(scanErr.Error(), 256),
	})
	if updateErr := r.Status().Update(ctx, fresh); updateErr != nil {
		logger.Error(updateErr, "update error status")
	}
	// Backoff: controller-runtime will exponentially retry.
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, scanErr
}

func reportNameForDigest(digest string) string {
	trimmed := strings.TrimPrefix(digest, "sha256:")
	sum := sha1.Sum([]byte(trimmed))
	return "report-" + hex.EncodeToString(sum[:10])
}

func toAPIFindings(in []scanner.Finding) []heimdallv1alpha1.Finding {
	out := make([]heimdallv1alpha1.Finding, 0, len(in))
	for _, f := range in {
		out = append(out, heimdallv1alpha1.Finding{
			VulnID:      f.VulnID,
			Severity:    heimdallv1alpha1.Severity(f.Severity),
			PackageName: f.PackageName,
			Version:     f.Version,
			FixedIn:     f.FixedIn,
			Title:       f.Title,
			PrimaryURL:  f.PrimaryURL,
			Target:      f.Target,
			FirstSeen:   &metav1.Time{Time: time.Now()},
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

// SecretsForPod implements registry.PodSecretResolver so a controller client
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
