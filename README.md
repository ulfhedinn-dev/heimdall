# Heimdall

> *"I see all. Nothing comes to pass that I do not watch."* — Heimdall, watcher of Asgard.

Heimdall is a small Kubernetes operator that keeps an inventory of every container image running on your cluster, scans each unique image digest for known CVEs with [Trivy](https://github.com/aquasecurity/trivy), stores the results as Kubernetes resources (`ImageInventory`, `VulnerabilityReport`), and posts newly found HIGH/CRITICAL vulnerabilities to Slack.

It is built for small clusters (it runs on Raspberry Pi): scans run one at a time with a pause between them.

[![CI](https://github.com/ulfhedinn-dev/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/ulfhedinn-dev/heimdall/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What it does

- **Pod watcher**: watches every `Pod` cluster-wide (regular, init, sidecar and ephemeral containers) and takes each container's image **digest** from the pod status. Containers whose image hasn't been pulled yet are picked up once they have a digest.
- **Inventory**: keeps one cluster-scoped `ImageInventory` per unique digest, listing every pod that uses it. When the last pod using a digest is deleted, the record is kept as history and marked inactive. It is no longer rescanned.
- **Scanner**: runs the Trivy library **in-process** (no `trivy` binary, no `exec`) against the registry, scanning OS packages and language dependencies. The result is one `VulnerabilityReport` per digest. For multi-arch images, the variant matching the operator's own architecture is scanned. Each digest is rescanned on an interval (default hourly), so new CVEs in the Trivy DB show up without a redeploy.
- **Alerts**: posts findings at or above a minimum severity (default HIGH) to a Slack incoming webhook. Only findings that weren't in the digest's previous report are sent. That state lives in the `VulnerabilityReport`, so restarts and rescans don't repeat old alerts.
- **Metrics**: Prometheus metrics on `:8080/metrics` (see [Metrics](#metrics)).
- **Registry credentials**: images are pulled anonymously unless credentials are found:
  - the pod's `imagePullSecrets` (`kubernetes.io/dockerconfigjson` and `kubernetes.io/dockercfg`), read on demand
  - `*.dkr.ecr.*.amazonaws.com`: **ECR** via the AWS SDK (IRSA), when `--ecr-enabled` is set. *Unit-tested only; not yet verified against a real EKS cluster.*
  - `gcr.io`, `*.pkg.dev`: **GCR / Artifact Registry** via Google Application Default Credentials / Workload Identity. *Unit-tested only; not yet verified against a real GKE cluster.*

## Install (Helm)

The chart is published to GHCR as an OCI artifact. The GHCR packages are private, so `helm registry login ghcr.io` with a token that has `read:packages` first, and give the cluster a matching pull secret (`imagePullSecrets`):

```bash
kubectl create namespace heimdall
kubectl -n heimdall create secret generic heimdall-slack \
  --from-literal=url='https://hooks.slack.com/services/…'

helm install heimdall oci://ghcr.io/ulfhedinn-dev/charts/heimdall \
  --version 0.1.0 \
  --namespace heimdall \
  --set slack.existingSecret=heimdall-slack
```

Or from a checkout: `helm install heimdall ./chart/heimdall …`.

Without a Slack webhook, Heimdall still inventories and scans; alerts are simply disabled. `slack.webhookUrl` can be set directly instead of `slack.existingSecret`, but that puts the URL in your Helm values.

Useful chart values (see [`values.yaml`](chart/heimdall/values.yaml) for all):

| Value | Default | Purpose |
| --- | --- | --- |
| `slack.existingSecret` | `""` | Secret with the webhook URL under key `url` |
| `slack.minSeverity` | `HIGH` | `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |
| `scan.intervalMinutes` | `60` | Rescan cadence per digest |
| `scan.cooldownSeconds` | `30` | Pause between consecutive scans |
| `scan.timeoutMinutes` | `10` | Upper bound per scan |
| `trivy.persistence.enabled` / `.size` | `true` / `6Gi` | PVC for the Trivy DB and cache; otherwise an `emptyDir`, and the DB is re-downloaded on every restart |
| `metrics.podAnnotations` | `false` | Add `prometheus.io/*` scrape annotations to the pod |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator `ServiceMonitor` |
| `ecr.enabled` / `ecr.region` | `false` | ECR credential provider (see above) |
| `gcr.enabled` | `true` | Google credential provider (see above) |

### On EKS (untested)

```bash
helm install heimdall oci://ghcr.io/ulfhedinn-dev/charts/heimdall --version 0.1.0 \
  --namespace heimdall --create-namespace \
  --set ecr.enabled=true \
  --set ecr.region=us-east-1 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/heimdall-scanner
```

The IAM role must allow `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` and `ecr:BatchCheckLayerAvailability`.

### On GKE (untested)

Annotate the service account with `iam.gke.io/gcp-service-account=<gsa>@<project>.iam.gserviceaccount.com`, bind it with Workload Identity, and grant the Google service account `roles/artifactregistry.reader`.

## Usage

```console
$ kubectl get imageinventories
NAME                       IMAGE                  RESULT       CRITICAL   HIGH   LASTSCAN   AGE
img-1f0c3a9e5b7d24c8e6a1   nginx:1.25.0           Vulnerable   20         266    12m        3h
img-8b2d4f6a0c1e3b5d7f9a   ghcr.io/org/api:v4.1   Clean        0          0      7m         3h

$ kubectl get vulnerabilityreports -l heimdall.ulfhedinn.dev/image-inventory=img-1f0c3a9e5b7d24c8e6a1 -o yaml
```

The short name `iinv` also works (`kubectl get iinv`).

## Custom resources

### `ImageInventory` (cluster-scoped)

One per unique image digest observed on the cluster.

```yaml
apiVersion: heimdall.ulfhedinn.dev/v1alpha1
kind: ImageInventory
metadata:
  name: img-1f0c3a9e5b7d24c8e6a1
spec:
  imageRef: nginx:1.25.0
  imageDigest: sha256:bb3a3f…
  pods:
    - namespace: web
      name: frontend-6b8f-abcde
      uid: 0d16f3f2-…
      containerName: nginx
      containerKind: container   # container | initContainer | ephemeralContainer
status:
  active: true
  scanResult: Vulnerable         # Pending | Clean | Vulnerable | Error
  criticalCount: 20
  highCount: 266
  mediumCount: 364
  lowCount: 314
  lastScannedAt: "2026-11-25T06:46:00Z"
  lastError: ""                  # set when scanResult is Error
```

### `VulnerabilityReport` (cluster-scoped)

Detailed findings for one digest, owned by its `ImageInventory`.

```yaml
apiVersion: heimdall.ulfhedinn.dev/v1alpha1
kind: VulnerabilityReport
metadata:
  name: report-1f0c3a9e5b7d24c8e6a1
  labels:
    heimdall.ulfhedinn.dev/image-inventory: img-1f0c3a9e5b7d24c8e6a1
spec:
  imageDigest: sha256:bb3a3f…
  imageRef: nginx:1.25.0
  scanner: trivy
  scannerVersion: v0.76.2
  vulnDBVersion: "2"
  findings:
    - vulnID: CVE-2024-1234
      severity: HIGH
      packageName: libxml2
      version: 2.9.14
      fixedIn: 2.9.15
      title: Heap buffer overflow in libxml2 …
      target: nginx:1.25.0 (debian 12.0)
      firstSeen: "2026-11-25T06:46:00Z"
status:
  generatedAt: "2026-11-25T06:46:00Z"
  summary: {critical: 20, high: 266, medium: 364, low: 314, unknown: 38}
```

Reports store at most 3000 findings, keeping the most severe, so they stay under etcd's object size limit. When findings are left out, the report gets a `heimdall.ulfhedinn.dev/truncated-findings` annotation with the count. The status summary always counts every finding.

## Metrics

Besides the standard controller-runtime metrics:

| Metric | Type | Labels |
| --- | --- | --- |
| `heimdall_scans_total` | counter | `result` = `success` \| `error` |
| `heimdall_scan_duration_seconds` | histogram | |
| `heimdall_alerts_total` | counter | `result` = `sent` \| `error` |
| `heimdall_image_vulnerabilities` | gauge | `inventory`, `image`, `severity` |

## Architecture

```
   Pods (all namespaces)
            │
            ▼
   ┌──────────────────────┐
   │ Pod reconciler       │──▶ ImageInventory (one per digest)
   │ containers → digests │
   └──────────────────────┘
            │
            ▼
   ┌──────────────────────┐     ┌───────────────┐
   │ Scan reconciler      │────▶│ Credentials   │ pull secrets / ECR / GCR
   │ interval, one scan   │     └───────────────┘
   │ at a time + cooldown │     ┌───────────────┐
   │                      │────▶│ Trivy library │──▶ VulnerabilityReport
   │                      │     └───────────────┘
   │                      │     ┌───────────────┐
   │                      │────▶│ Slack webhook │ new findings only
   └──────────────────────┘     └───────────────┘
```

## Configuration (operator flags)

| Flag | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--metrics-bind-address` | | `:8080` | Prometheus metrics endpoint |
| `--health-probe-bind-address` | | `:8081` | `/healthz` and `/readyz` |
| `--leader-elect` | | `false` | Leader election (for multiple replicas) |
| `--scan-interval` | | `1h` | Rescan cadence per digest |
| `--scan-timeout` | | `10m` | Upper bound per scan |
| `--scan-cooldown` | | `30s` | Pause between consecutive scans |
| `--scan-concurrency` | | `1` | Inventory records reconciled in parallel; Trivy scans always run one at a time |
| `--slack-webhook-url` | `HEIMDALL_SLACK_WEBHOOK` | | Slack incoming webhook URL; empty disables alerts |
| `--min-severity` | `HEIMDALL_MIN_SEVERITY` | `HIGH` | Minimum severity for alerts |
| `--trivy-cache-dir` | `TRIVY_CACHE_DIR` | `/var/cache/heimdall/trivy` | Trivy DB and cache |
| `--trivy-offline` | `TRIVY_OFFLINE` | `false` | Skip DB updates (needs a pre-populated cache) |
| `--ecr-enabled` | `HEIMDALL_ECR_ENABLED` | `false` | ECR credential provider |
| `--ecr-region` | `AWS_REGION` | *(from image hostname)* | Override the ECR region |
| `--gcr-enabled` | | `true` | Google credential provider |

## Known limitations (v0.1)

- **First scan alerts on everything.** When Heimdall is first installed, and whenever a new digest appears (for example after an image upgrade), all of that digest's findings at or above the minimum severity are sent. That's one Slack message per image, listing up to 10 findings.
- Pods deleted while Heimdall isn't running stay listed in their `ImageInventory` until another pod using the same digest changes.
- Trivy's vulnerability DB is large: about 1.8 GB on disk, refreshed daily. Scanning Java images adds the Java DB, about 1.6 GB, refreshed every few days. Both are downloaded from `mirror.gcr.io` (falling back to `ghcr.io`), so Heimdall needs internet access, or a pre-populated cache plus `--trivy-offline`.
- Only Slack is supported as an alert destination.
- Single replica; leader election exists but multi-replica operation isn't tested.

## Development

```bash
make all                # fmt, vet, lint (golangci-lint v2), test, build
make test               # unit tests (race detector on)
make smoke IMAGE=nginx:1.25.0   # one real Trivy scan through Heimdall's scanner
make e2e                # full end-to-end test in a throwaway kind cluster (docker + kind)
make generate manifests # regenerate deepcopy code and the chart CRDs from api/
make docker-build IMAGE_TAG=dev
make helm-lint
```

### Releases: continuous delivery

Every push runs CI (GitHub Actions): lint, unit tests, a generated-code check, Helm lint and the kind end-to-end test.

**Every merge to `main` that passes CI is released.** The version comes from the [Conventional Commits](https://www.conventionalcommits.org/) since the last tag ([`hack/next-version.sh`](hack/next-version.sh)). With squash merges, use the PR title:

| Commit | Release |
| --- | --- |
| `feat!: …` / `BREAKING CHANGE:` footer | major (`1.4.2` → `2.0.0`) |
| `feat: …` | minor (`1.4.2` → `1.5.0`) |
| anything else (`fix:`, `chore:`, `docs:` …) | patch (`1.4.2` → `1.4.3`) |

A release builds and pushes `ghcr.io/ulfhedinn-dev/heimdall:X.Y.Z` (plus `X.Y`, `latest` and `sha-…`) for `linux/amd64` and `linux/arm64`. It also pushes the chart, versioned `X.Y.Z`, to `oci://ghcr.io/ulfhedinn-dev/charts/heimdall`, tags the commit `vX.Y.Z` and creates a GitHub release. Nobody edits versions by hand.

The same image tags and chart are then copied to the owner's Zot registry (`registry.ulfhedinn.net/heimdall`, `oci://registry.ulfhedinn.net/charts/heimdall`) by [`hack/mirror-to-zot.sh`](hack/mirror-to-zot.sh), which is what the highland cluster pulls. This needs the `ZOT_PUSH_PASSWORD` repository secret (Zot user `heimdall-ci`). Zot sits behind a Cloudflare tunnel that rejects request bodies over 100 MB, so layers are uploaded in 50 MB chunks. If this step fails, no tag or release is created; re-run the failed job.

**Out-of-band / hotfix release:** branch from the release tag (`git switch -c hotfix/1.4.x v1.4.2`), fix, push, then push a tag `v1.4.3` on that branch. CI publishes that exact version.

## Project layout

```
heimdall/
├── cmd/operator/            # entrypoint
├── api/v1alpha1/            # CRD Go types + generated deepcopy
├── internal/
│   ├── controller/          # Pod + ImageScan reconcilers, metrics
│   ├── registry/            # Credential providers (pull secrets / ECR / GCR)
│   ├── scanner/             # Scanner interface + Trivy implementation
│   └── alert/               # Slack webhook alerter
├── chart/heimdall/          # Helm chart (CRDs generated from api/)
├── hack/                    # e2e test, CRD generation, smoke scan, Zot copy
├── Dockerfile               # Distroless, multi-arch
└── .github/workflows/ci.yml # Lint, test, e2e, build, push to GHCR, release
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
