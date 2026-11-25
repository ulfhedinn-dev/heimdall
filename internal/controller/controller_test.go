package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := heimdallv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&heimdallv1alpha1.ImageInventory{}, &heimdallv1alpha1.VulnerabilityReport{}).
		WithObjects(objs...).
		Build()
}

func testPod(ns, name, uid string, containers map[string]string) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)}}
	for cname, digest := range containers {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: cname, Image: "nginx:1.27"})
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
			Name: cname, ImageID: "docker.io/library/nginx@" + digest,
		})
	}
	return pod
}

func TestExtractContainers(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{{Name: "app", Image: "app:v1"}, {Name: "pending", Image: "pending:v1"}},
			InitContainers: []corev1.Container{{Name: "init", Image: "init:v1"}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox"},
			}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses:          []corev1.ContainerStatus{{Name: "app", ImageID: "docker-pullable://app@" + digestA}},
			InitContainerStatuses:      []corev1.ContainerStatus{{Name: "init", ImageID: "init@" + digestB}},
			EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", ImageID: digestA}},
		},
	}
	got := ExtractContainers(pod)
	want := []ContainerSpec{
		{Name: "app", Image: "app:v1", Digest: digestA, Kind: "container"},
		{Name: "pending", Image: "pending:v1", Digest: "", Kind: "container"},
		{Name: "init", Image: "init:v1", Digest: digestB, Kind: "initContainer"},
		{Name: "debug", Image: "busybox", Digest: digestA, Kind: "ephemeralContainer"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d containers, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("container %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestExtractDigest(t *testing.T) {
	for in, want := range map[string]string{
		"docker-pullable://nginx@" + digestA: digestA,
		digestA + " trailing":                digestA,
		"nginx:1.27":                         "",
		"":                                   "",
	} {
		if got := extractDigest(in); got != want {
			t.Errorf("extractDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNamesAreStableAndDNSSafe(t *testing.T) {
	r := &PodReconciler{InventoryNamePrefix: "img-"}
	a1, a2, b := r.inventoryNameForDigest(digestA), r.inventoryNameForDigest(digestA), r.inventoryNameForDigest(digestB)
	if a1 != a2 || a1 == b || len(a1) != len("img-")+20 {
		t.Errorf("names: %q %q %q", a1, a2, b)
	}
	if reportNameForDigest(digestA) != "report-"+a1[len("img-"):] {
		t.Errorf("report name %q does not match inventory %q", reportNameForDigest(digestA), a1)
	}
	if got := safeDigestLabel(digestA); got != "aaaaaaaaaaaa" {
		t.Errorf("safeDigestLabel = %q", got)
	}
}

func TestUpsertPodRefAndSetCondition(t *testing.T) {
	refs := upsertPodRef(nil, heimdallv1alpha1.PodRef{UID: "1", ContainerName: "a", Name: "old"})
	refs = upsertPodRef(refs, heimdallv1alpha1.PodRef{UID: "1", ContainerName: "a", Name: "new"})
	refs = upsertPodRef(refs, heimdallv1alpha1.PodRef{UID: "1", ContainerName: "b"})
	if len(refs) != 2 || refs[0].Name != "new" {
		t.Fatalf("refs = %+v", refs)
	}

	conds := setCondition(nil, metav1.Condition{Type: "Scanned", Status: metav1.ConditionTrue, Reason: "A"})
	first := conds[0].LastTransitionTime
	conds = setCondition(conds, metav1.Condition{Type: "Scanned", Status: metav1.ConditionTrue, Reason: "B"})
	if len(conds) != 1 || conds[0].Reason != "B" || conds[0].LastTransitionTime != first {
		t.Fatalf("same-status update must keep transition time: %+v", conds)
	}
	conds = setCondition(conds, metav1.Condition{Type: "Scanned", Status: metav1.ConditionFalse, Reason: "C"})
	if conds[0].Status != metav1.ConditionFalse || conds[0].Reason != "C" {
		t.Fatalf("status change not applied: %+v", conds)
	}
}

func TestPodReconcilerBuildsInventoryAndCleansUp(t *testing.T) {
	ctx := context.Background()
	podA := testPod("web", "frontend", "uid-a", map[string]string{"nginx": digestA})
	podB := testPod("shop", "frontend", "uid-b", map[string]string{"nginx": digestA})
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "pending", UID: "uid-p"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "x:v1"}}},
	}
	c := newClient(t, podA, podB, pending)
	r := &PodReconciler{Client: c, InventoryNamePrefix: "img-"}

	for _, p := range []*corev1.Pod{podA, podB, pending} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}); err != nil {
			t.Fatal(err)
		}
	}

	var list heimdallv1alpha1.ImageInventoryList
	if err := c.List(ctx, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("got %d inventories, want 1 (shared digest, pending pod skipped)", len(list.Items))
	}
	inv := list.Items[0]
	if inv.Spec.ImageDigest != digestA || len(inv.Spec.Pods) != 2 {
		t.Fatalf("inventory = %+v", inv.Spec)
	}
	if !inv.Status.Active || inv.Status.ScanResult != heimdallv1alpha1.ScanResultPending {
		t.Fatalf("status = %+v", inv.Status)
	}

	// Delete the pod in the first namespace. Its ref must go even though the
	// last write came from a pod in another namespace.
	if err := c.Delete(ctx, podA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(podA)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: inv.Name}, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Spec.Pods) != 1 || inv.Spec.Pods[0].Namespace != "shop" || !inv.Status.Active {
		t.Fatalf("after first delete: pods=%+v active=%v", inv.Spec.Pods, inv.Status.Active)
	}

	if err := c.Delete(ctx, podB); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(podB)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: inv.Name}, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Spec.Pods) != 0 || inv.Status.Active {
		t.Fatalf("after last delete: pods=%+v active=%v", inv.Spec.Pods, inv.Status.Active)
	}
}

func TestCleanupKeepsRecreatedPod(t *testing.T) {
	ctx := context.Background()
	recreated := testPod("web", "frontend", "uid-new", map[string]string{"nginx": digestA})
	inv := &heimdallv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: "img-x"},
		Spec: heimdallv1alpha1.ImageInventorySpec{ImageRef: "nginx", ImageDigest: digestA, Pods: []heimdallv1alpha1.PodRef{
			{Namespace: "web", Name: "frontend", UID: "uid-old", ContainerName: "nginx"},
			{Namespace: "web", Name: "frontend", UID: "uid-new", ContainerName: "nginx"},
		}},
	}
	c := newClient(t, recreated, inv)
	r := &PodReconciler{Client: c}
	if err := r.cleanupDeletedPod(ctx, client.ObjectKeyFromObject(recreated)); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(inv), inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Spec.Pods) != 1 || inv.Spec.Pods[0].UID != "uid-new" {
		t.Fatalf("pods = %+v", inv.Spec.Pods)
	}
}

type fakeScanner struct {
	findings []scanner.Finding
	err      error
	calls    int
}

func (f *fakeScanner) Name() string    { return "fake" }
func (f *fakeScanner) Version() string { return "v0" }
func (f *fakeScanner) Scan(_ context.Context, req scanner.Request) (*scanner.Report, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &scanner.Report{
		ImageRef: req.ImageRef, ImageDigest: req.ImageDigest, Scanner: "fake", ScannerVersion: "v0",
		GeneratedAt: time.Now(), Findings: append([]scanner.Finding(nil), f.findings...),
	}, nil
}

type recordingAlerter struct {
	mu      sync.Mutex
	reports []*scanner.Report
}

func (a *recordingAlerter) Notify(_ context.Context, r *scanner.Report) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reports = append(a.reports, r)
	return nil
}

func testInventory(pods int) *heimdallv1alpha1.ImageInventory {
	inv := &heimdallv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: "img-test"},
		Spec:       heimdallv1alpha1.ImageInventorySpec{ImageRef: "nginx:1.27", ImageDigest: digestA},
	}
	for i := 0; i < pods; i++ {
		inv.Spec.Pods = append(inv.Spec.Pods, heimdallv1alpha1.PodRef{Namespace: "web", Name: "p", UID: "u", ContainerName: "c"})
	}
	return inv
}

func TestImageScanReconcilerScansReportsAndAlertsOnlyNewFindings(t *testing.T) {
	ctx := context.Background()
	inv := testInventory(1)
	c := newClient(t, inv)
	sc := &fakeScanner{findings: []scanner.Finding{
		{VulnID: "CVE-1", Severity: scanner.SeverityCritical, PackageName: "openssl"},
		{VulnID: "CVE-2", Severity: scanner.SeverityHigh, PackageName: "zlib"},
		{VulnID: "CVE-3", Severity: scanner.SeverityLow, PackageName: "zlib"},
	}}
	al := &recordingAlerter{}
	now := time.Now()
	r := &ImageScanReconciler{Client: c, Scheme: c.Scheme(), Scanner: sc, Alerter: al, Interval: time.Hour, Clock: func() time.Time { return now }}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: inv.Name}}

	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != time.Hour || sc.calls != 1 {
		t.Fatalf("res=%+v calls=%d", res, sc.calls)
	}

	var got heimdallv1alpha1.ImageInventory
	if err := c.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ScanResult != heimdallv1alpha1.ScanResultVulnerable || got.Status.CriticalCount != 1 || got.Status.HighCount != 1 || got.Status.LowCount != 1 {
		t.Fatalf("inventory status = %+v", got.Status)
	}

	var report heimdallv1alpha1.VulnerabilityReport
	if err := c.Get(ctx, types.NamespacedName{Name: reportNameForDigest(digestA)}, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Spec.Findings) != 3 || report.Status.Summary.Critical != 1 || report.Labels["heimdall.ulfhedinn.dev/image-inventory"] != inv.Name {
		t.Fatalf("report = %+v / %+v", report.Spec, report.Status)
	}
	if len(report.OwnerReferences) != 1 || report.OwnerReferences[0].Name != inv.Name {
		t.Fatalf("owner refs = %+v", report.OwnerReferences)
	}
	firstSeen := report.Spec.Findings[0].FirstSeen
	if len(al.reports) != 1 || len(al.reports[0].Findings) != 3 {
		t.Fatalf("first scan alerts = %+v", al.reports)
	}

	// Not due yet: no scan.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if sc.calls != 1 {
		t.Fatalf("scanned before interval elapsed")
	}

	// Next interval: one new finding appears; only it is alerted and
	// existing findings keep their FirstSeen time.
	now = now.Add(2 * time.Hour)
	sc.findings = append(sc.findings, scanner.Finding{VulnID: "CVE-4", Severity: scanner.SeverityCritical, PackageName: "libc"})
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if sc.calls != 2 || len(al.reports) != 2 || len(al.reports[1].Findings) != 1 || al.reports[1].Findings[0].VulnID != "CVE-4" {
		t.Fatalf("second scan alerts = %+v", al.reports[len(al.reports)-1])
	}
	if err := c.Get(ctx, types.NamespacedName{Name: reportNameForDigest(digestA)}, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Spec.Findings) != 4 || !report.Spec.Findings[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("findings after rescan = %+v", report.Spec.Findings)
	}
}

func TestImageScanReconcilerRecordsErrors(t *testing.T) {
	ctx := context.Background()
	inv := testInventory(1)
	c := newClient(t, inv)
	r := &ImageScanReconciler{Client: c, Scheme: c.Scheme(), Scanner: &fakeScanner{err: errors.New("registry unavailable")}, Interval: time.Hour}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: inv.Name}})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != time.Hour {
		t.Errorf("RequeueAfter = %v", res.RequeueAfter)
	}
	var got heimdallv1alpha1.ImageInventory
	if err := c.Get(ctx, client.ObjectKeyFromObject(inv), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ScanResult != heimdallv1alpha1.ScanResultError || got.Status.LastError != "registry unavailable" || got.Status.LastScannedAt == nil {
		t.Fatalf("status = %+v", got.Status)
	}
}

func TestImageScanReconcilerSkipsUnusedAndMissing(t *testing.T) {
	ctx := context.Background()
	inv := testInventory(0)
	c := newClient(t, inv)
	sc := &fakeScanner{}
	r := &ImageScanReconciler{Client: c, Scheme: c.Scheme(), Scanner: sc, Interval: time.Hour}
	for _, name := range []string{inv.Name, "does-not-exist"} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	if sc.calls != 0 {
		t.Fatalf("scanned an image with no pods")
	}
}

func TestRequeueAfter(t *testing.T) {
	now := time.Now()
	r := &ImageScanReconciler{Interval: time.Hour, Clock: func() time.Time { return now }}
	inv := testInventory(1)
	if !r.isDue(inv) || r.requeueAfter(inv) != 0 {
		t.Error("never-scanned inventory must be due immediately")
	}
	inv.Status.LastScannedAt = &metav1.Time{Time: now.Add(-50 * time.Minute)}
	if r.isDue(inv) || r.requeueAfter(inv) != 10*time.Minute {
		t.Errorf("requeueAfter = %v", r.requeueAfter(inv))
	}
	inv.Status.LastScannedAt = &metav1.Time{Time: now.Add(-59*time.Minute - 50*time.Second)}
	if r.requeueAfter(inv) != time.Minute {
		t.Errorf("requeueAfter floor = %v", r.requeueAfter(inv))
	}
}

func TestNewFindingsSince(t *testing.T) {
	ts := &metav1.Time{Time: time.Now()}
	existing := map[string]*metav1.Time{findingKey("CVE-1", "a"): ts}
	got := newFindingsSince([]scanner.Finding{
		{VulnID: "CVE-1", PackageName: "a"},
		{VulnID: "CVE-1", PackageName: "b"},
		{VulnID: "CVE-1", PackageName: "b"},
	}, existing)
	if len(got) != 1 || got[0].PackageName != "b" {
		t.Fatalf("got %+v", got)
	}
}

func TestCapFindings(t *testing.T) {
	in := []scanner.Finding{
		{VulnID: "l", Severity: scanner.SeverityLow},
		{VulnID: "c", Severity: scanner.SeverityCritical},
		{VulnID: "m", Severity: scanner.SeverityMedium},
		{VulnID: "h", Severity: scanner.SeverityHigh},
	}
	out, dropped := capFindings(in, 2)
	if dropped != 2 || len(out) != 2 || out[0].VulnID != "c" || out[1].VulnID != "h" {
		t.Fatalf("out=%+v dropped=%d", out, dropped)
	}
	if in[0].VulnID != "l" {
		t.Fatal("input must not be reordered")
	}
	if out, dropped := capFindings(in, 10); dropped != 0 || len(out) != 4 {
		t.Fatalf("under limit: out=%d dropped=%d", len(out), dropped)
	}
}
