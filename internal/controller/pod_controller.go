// Package controller contains the reconcilers that maintain Heimdall's CRDs.
package controller

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
)

// PodReconciler watches Pod objects cluster-wide, extracts the unique image
// references in use (including init, ephemeral, and sidecar containers),
// resolves their digests from container statuses, and reconciles
// ImageInventory records.
type PodReconciler struct {
	client.Client

	// InventoryNamePrefix prefixes the generated ImageInventory name. Defaults
	// to "img-".
	InventoryNamePrefix string
}

// ContainerSpec is an internal projection of a pod's container entries
// (regardless of their location in the pod spec).
type ContainerSpec struct {
	Name   string
	Image  string
	Digest string
	Kind   string // "container" | "initContainer" | "ephemeralContainer"
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=heimdall.ulfhedinn.dev,resources=imageinventories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=heimdall.ulfhedinn.dev,resources=imageinventories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=heimdall.ulfhedinn.dev,resources=vulnerabilityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=heimdall.ulfhedinn.dev,resources=vulnerabilityreports/status,verbs=get;update;patch

// Reconcile implements reconcile.Reconciler.
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("pod", req.NamespacedName.String())

	var pod corev1.Pod
	err := r.Get(ctx, req.NamespacedName, &pod)
	if apierrors.IsNotFound(err) {
		// Pod was deleted: remove its reference from every inventory record.
		if cleanupErr := r.cleanupDeletedPod(ctx, req.NamespacedName); cleanupErr != nil {
			return ctrl.Result{}, cleanupErr
		}
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	// Collect all containers with resolved digests. Containers whose image
	// has not yet been pulled will have an empty digest; we skip them for now
	// — the controller will reconcile again when the status changes.
	containers := ExtractContainers(&pod)
	for _, c := range containers {
		if c.Digest == "" {
			continue
		}
		if err := r.upsertInventory(ctx, &pod, c); err != nil {
			logger.Error(err, "upsert inventory", "image", c.Image, "digest", c.Digest)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler to the manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.InventoryNamePrefix == "" {
		r.InventoryNamePrefix = "img-"
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("pod-inventory").
		For(&corev1.Pod{}).
		Complete(r)
}

// ExtractContainers returns a flat list of all containers (including init,
// sidecar, and ephemeral) referenced by the pod, pairing each with the
// resolved image digest from the matching container status entry (if any).
func ExtractContainers(pod *corev1.Pod) []ContainerSpec {
	out := make([]ContainerSpec, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))

	statusMap := func(statuses []corev1.ContainerStatus) map[string]string {
		m := make(map[string]string, len(statuses))
		for _, s := range statuses {
			m[s.Name] = extractDigest(s.ImageID)
		}
		return m
	}

	containerStatuses := statusMap(pod.Status.ContainerStatuses)
	initStatuses := statusMap(pod.Status.InitContainerStatuses)
	ephemeralStatuses := statusMap(pod.Status.EphemeralContainerStatuses)

	for _, c := range pod.Spec.Containers {
		out = append(out, ContainerSpec{
			Name:   c.Name,
			Image:  c.Image,
			Digest: containerStatuses[c.Name],
			Kind:   "container",
		})
	}
	for _, c := range pod.Spec.InitContainers {
		out = append(out, ContainerSpec{
			Name:   c.Name,
			Image:  c.Image,
			Digest: initStatuses[c.Name],
			Kind:   "initContainer",
		})
	}
	for _, c := range pod.Spec.EphemeralContainers {
		out = append(out, ContainerSpec{
			Name:   c.Name,
			Image:  c.EphemeralContainerCommon.Image,
			Digest: ephemeralStatuses[c.Name],
			Kind:   "ephemeralContainer",
		})
	}
	return out
}

// extractDigest extracts the sha256 digest from a container status ImageID,
// which typically looks like `docker-pullable://repo@sha256:…` or
// `repo@sha256:…`.
func extractDigest(imageID string) string {
	idx := strings.LastIndex(imageID, "sha256:")
	if idx < 0 {
		return ""
	}
	digest := imageID[idx:]
	// Trim anything after whitespace just in case.
	if sp := strings.IndexAny(digest, " \t\n"); sp > 0 {
		digest = digest[:sp]
	}
	return digest
}

// inventoryNameForDigest returns a stable, DNS-1123-safe name for an
// ImageInventory keyed by digest.
func (r *PodReconciler) inventoryNameForDigest(digest string) string {
	trimmed := strings.TrimPrefix(digest, "sha256:")
	sum := sha1.Sum([]byte(trimmed))
	return r.InventoryNamePrefix + hex.EncodeToString(sum[:10])
}

func (r *PodReconciler) upsertInventory(ctx context.Context, pod *corev1.Pod, c ContainerSpec) error {
	name := r.inventoryNameForDigest(c.Digest)
	inv := &heimdallv1alpha1.ImageInventory{}
	inv.Name = name

	podRef := heimdallv1alpha1.PodRef{
		Namespace:     pod.Namespace,
		Name:          pod.Name,
		UID:           string(pod.UID),
		ContainerName: c.Name,
		ContainerKind: c.Kind,
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, inv, func() error {
		if inv.Labels == nil {
			inv.Labels = map[string]string{}
		}
		inv.Labels["heimdall.ulfhedinn.dev/digest-prefix"] = safeDigestLabel(c.Digest)
		// Label by pod namespace so cleanupDeletedPod can scope its list query.
		inv.Labels["heimdall.ulfhedinn.dev/pod-namespace"] = pod.Namespace
		inv.Spec.ImageRef = c.Image
		inv.Spec.ImageDigest = c.Digest
		inv.Spec.Pods = upsertPodRef(inv.Spec.Pods, podRef)
		return nil
	})
	if err != nil {
		return fmt.Errorf("create/update ImageInventory %s: %w", name, err)
	}

	// Status subresource: mark active, preserve scan counts, ensure Pending is set on first write.
	if err := r.ensureInventoryStatus(ctx, name); err != nil {
		return err
	}
	return nil
}

func (r *PodReconciler) ensureInventoryStatus(ctx context.Context, name string) error {
	var inv heimdallv1alpha1.ImageInventory
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &inv); err != nil {
		return err
	}
	changed := false
	if !inv.Status.Active {
		inv.Status.Active = true
		changed = true
	}
	if inv.Status.ScanResult == "" {
		inv.Status.ScanResult = heimdallv1alpha1.ScanResultPending
		changed = true
	}
	if !changed {
		return nil
	}
	return r.Status().Update(ctx, &inv)
}

func upsertPodRef(existing []heimdallv1alpha1.PodRef, ref heimdallv1alpha1.PodRef) []heimdallv1alpha1.PodRef {
	for i := range existing {
		if existing[i].UID == ref.UID && existing[i].ContainerName == ref.ContainerName {
			existing[i] = ref
			return existing
		}
	}
	return append(existing, ref)
}

// cleanupDeletedPod removes stale pod references from ImageInventory objects
// when a pod is deleted. It scopes the list to the relevant namespace via a
// label filter (Fix 8) and validates each ref's UID against the current pod
// so a re-created pod with the same name is never mistakenly removed (Fix 3).
func (r *PodReconciler) cleanupDeletedPod(ctx context.Context, key types.NamespacedName) error {
	// Determine the UID of any pod currently running with this namespace/name.
	// If the pod was immediately re-created it will have a different UID from
	// the stale refs we want to remove.
	var currentPod corev1.Pod
	currentUID := ""
	if err := r.Get(ctx, key, &currentPod); err == nil {
		currentUID = string(currentPod.UID)
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	var list heimdallv1alpha1.ImageInventoryList
	if err := r.List(ctx, &list, client.MatchingLabels{
		"heimdall.ulfhedinn.dev/pod-namespace": key.Namespace,
	}); err != nil {
		return err
	}
	for i := range list.Items {
		inv := &list.Items[i]
		filtered := make([]heimdallv1alpha1.PodRef, 0, len(inv.Spec.Pods))
		removed := false
		for _, p := range inv.Spec.Pods {
			if p.Namespace == key.Namespace && p.Name == key.Name {
				// Keep the ref only if its UID matches the currently-running pod
				// (i.e., the pod was re-created and this ref is for the new one).
				if currentUID != "" && p.UID == currentUID {
					filtered = append(filtered, p)
					continue
				}
				removed = true
				continue
			}
			filtered = append(filtered, p)
		}
		if !removed {
			continue
		}
		inv.Spec.Pods = filtered
		if err := r.Update(ctx, inv); err != nil {
			return fmt.Errorf("update inventory %s on pod delete: %w", inv.Name, err)
		}
		if len(filtered) == 0 && inv.Status.Active {
			inv.Status.Active = false
			inv.Status.Conditions = setCondition(inv.Status.Conditions, metav1.Condition{
				Type:    "Active",
				Status:  metav1.ConditionFalse,
				Reason:  "NoPodsRunningImage",
				Message: "last pod using this image was deleted",
			})
			if err := r.Status().Update(ctx, inv); err != nil {
				return fmt.Errorf("inactivate inventory %s: %w", inv.Name, err)
			}
		}
	}
	return nil
}

func setCondition(existing []metav1.Condition, c metav1.Condition) []metav1.Condition {
	if c.LastTransitionTime.IsZero() {
		c.LastTransitionTime = metav1.Now()
	}
	for i := range existing {
		if existing[i].Type == c.Type {
			if existing[i].Status != c.Status {
				existing[i] = c
			} else {
				existing[i].Reason = c.Reason
				existing[i].Message = c.Message
			}
			return existing
		}
	}
	return append(existing, c)
}

func safeDigestLabel(digest string) string {
	// Labels are 63 chars max; use the first 12 hex of the digest.
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}
