package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodRef identifies a Pod that is running a particular image.
type PodRef struct {
	// Namespace of the pod.
	Namespace string `json:"namespace"`
	// Name of the pod.
	Name string `json:"name"`
	// UID of the pod, used to disambiguate recreated pods with the same name.
	UID string `json:"uid"`
	// ContainerName is the name of the container inside the pod that is running this image.
	ContainerName string `json:"containerName"`
	// ContainerKind indicates which part of the pod spec the container came from.
	// +kubebuilder:validation:Enum=container;initContainer;ephemeralContainer
	ContainerKind string `json:"containerKind"`
}

// ImageInventorySpec defines the desired state of an ImageInventory record.
type ImageInventorySpec struct {
	// ImageRef is a human-readable image reference such as `registry/repo:tag`.
	ImageRef string `json:"imageRef"`

	// ImageDigest is the resolved sha256 digest of the image, including the `sha256:` prefix.
	// +kubebuilder:validation:Pattern=^sha256:[a-f0-9]{64}$
	ImageDigest string `json:"imageDigest"`

	// Pods is the current set of pods running this image. When empty, the inventory entry
	// is retained as historical data and marked inactive.
	// +optional
	Pods []PodRef `json:"pods,omitempty"`
}

// ScanResult is the summary verdict of the most recent scan.
// +kubebuilder:validation:Enum=Pending;Clean;Vulnerable;Error
type ScanResult string

const (
	ScanResultPending    ScanResult = "Pending"
	ScanResultClean      ScanResult = "Clean"
	ScanResultVulnerable ScanResult = "Vulnerable"
	ScanResultError      ScanResult = "Error"
)

// ImageInventoryStatus defines the observed state of an ImageInventory record.
type ImageInventoryStatus struct {
	// LastScannedAt is the timestamp of the most recent completed scan attempt.
	// +optional
	LastScannedAt *metav1.Time `json:"lastScannedAt,omitempty"`

	// ScanResult is the summary of the most recent scan.
	// +optional
	ScanResult ScanResult `json:"scanResult,omitempty"`

	// CriticalCount is the number of CRITICAL findings in the most recent scan.
	CriticalCount int `json:"criticalCount"`

	// HighCount is the number of HIGH findings in the most recent scan.
	HighCount int `json:"highCount"`

	// MediumCount is the number of MEDIUM findings in the most recent scan.
	// +optional
	MediumCount int `json:"mediumCount,omitempty"`

	// LowCount is the number of LOW findings in the most recent scan.
	// +optional
	LowCount int `json:"lowCount,omitempty"`

	// Active is true when at least one pod is currently running this image.
	Active bool `json:"active"`

	// LastError is the most recent scan error, if any.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// Conditions represent the current status of the inventory entry.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=iinv
// +kubebuilder:printcolumn:name="Image",type="string",JSONPath=".spec.imageRef"
// +kubebuilder:printcolumn:name="Digest",type="string",JSONPath=".spec.imageDigest",priority=1
// +kubebuilder:printcolumn:name="Pods",type="integer",JSONPath=".spec.pods[*]",priority=1
// +kubebuilder:printcolumn:name="Result",type="string",JSONPath=".status.scanResult"
// +kubebuilder:printcolumn:name="Critical",type="integer",JSONPath=".status.criticalCount"
// +kubebuilder:printcolumn:name="High",type="integer",JSONPath=".status.highCount"
// +kubebuilder:printcolumn:name="LastScan",type="date",JSONPath=".status.lastScannedAt"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ImageInventory tracks a unique container image observed on the cluster and summarizes the
// results of the most recent vulnerability scan.
type ImageInventory struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageInventorySpec   `json:"spec,omitempty"`
	Status ImageInventoryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageInventoryList is a collection of ImageInventory objects.
type ImageInventoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageInventory `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageInventory{}, &ImageInventoryList{})
}
