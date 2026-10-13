# Heimdall

> *"I see all. Nothing comes to pass that I do not watch."* — Heimdall, watcher of Asgard.

Heimdall is a Kubernetes operator that **sees every container image running on your cluster** and continuously scans each unique one for CVEs. Findings land in native Kubernetes resources (`ImageInventory`, `VulnerabilityReport`) and new HIGH/CRITICAL issues can be posted to Slack as they appear.

[![CI](https://github.com/ulfhedinn-dev/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/ulfhedinn-dev/heimdall/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ulfhedinn-dev/heimdall)](https://goreportcard.com/report/github.com/ulfhedinn-dev/heimdall)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What it does

- **Pod watcher** — observes every `Pod` cluster-wide (regular, init, sidecar, and ephemeral containers) and resolves each container's image **digest** from the pod's status.
- **Inventory** — maintains one `ImageInventory` custom resource per unique image digest. The spec lists every pod using that digest; the status carries the latest scan summary.
- **Scanner** — runs the [Trivy](https://github.com/aquasecurity/trivy) scanning library **in-process** (no `exec`), producing a `VulnerabilityReport` per digest.
- **Alerts** — posts newly discovered HIGH/CRITICAL findings to a Slack incoming webhook (with per-digest de-duplication so you aren't paged repeatedly for the same CVE).
- **Pluggable registry auth** — auto-detects the right credential source by hostname:
  - `*.dkr.ecr.*.amazonaws.com` → **ECR** via the AWS SDK (IRSA-friendly)
  - `gcr.io`, `*.pkg.dev` → **GCR / Artifact Registry** via Google ADC / Workload Identity
  - Everything else → the pod's `imagePullSecrets`

## Install (Helm)

```bash
helm install heimdall ./chart/heimdall \
  --namespace heimdall --create-namespace \
  --set slack.webhookUrl=https://hooks.slack.com/services/XXX/YYY/ZZZ \
  --set slack.minSeverity=HIGH \
  --set scan.intervalMinutes=60
```

### On EKS

```bash
helm install heimdall ./chart/heimdall \
  --namespace heimdall --create-namespace \
  --set ecr.enabled=true \
  --set ecr.region=us-east-1 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/heimdall-scanner \
  --set slack.webhookUrl=$SLACK_WEBHOOK_URL
```

The IAM role must allow:

```json
{
  "Effect": "Allow",
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchCheckLayerAvailability"
  ],
  "Resource": "*"
}
```

### On GKE

```bash
helm install heimdall ./chart/heimdall \
  --namespace heimdall --create-namespace \
  --set serviceAccount.annotations."iam\.gke\.io/gcp-service-account"=heimdall@project-id.iam.gserviceaccount.com
```

Bind the Google service account to the Kubernetes service account with Workload Identity and give it `roles/artifactregistry.reader`.

## Usage

```bash
# What's running on the cluster?
kubectl get imageinventories

NAME                 IMAGE                            RESULT       CRITICAL  HIGH  LASTSCAN
img-9ab1cf...        nginx:1.27                       Vulnerable   0         3     12m
img-33bcea...        ghcr.io/jón/api:v4.1             Clean        0         0     7m

# Dig into a specific report
kubectl get vulnerabilityreports -l heimdall.ulfhedinn.dev/image-inventory=img-9ab1cf... -o yaml
```

## Custom resources

### `ImageInventory` (cluster-scoped)

Tracks a unique image digest observed on the cluster.

```yaml
apiVersion: heimdall.ulfhedinn.dev/v1alpha1
kind: ImageInventory
metadata:
  name: img-9ab1cf1a2b
spec:
  imageRef: nginx:1.27
  imageDigest: sha256:bb3a3f...
  pods:
    - namespace: web
      name: frontend-6b8f-abcde
      uid: 0d16f3f2-...
      containerName: nginx
      containerKind: container
status:
  active: true
  scanResult: Vulnerable
  criticalCount: 0
  highCount: 3
  lastScannedAt: "2026-10-13T06:46:00Z"
```

### `VulnerabilityReport` (cluster-scoped)

Detailed CVE findings for one digest.

```yaml
apiVersion: heimdall.ulfhedinn.dev/v1alpha1
kind: VulnerabilityReport
metadata:
  name: report-9ab1cf1a2b
spec:
  imageDigest: sha256:bb3a3f...
  imageRef: nginx:1.27
  scanner: trivy
  scannerVersion: v0.57.1
  findings:
    - vulnID: CVE-2024-1234
      severity: HIGH
      packageName: libxml2
      version: 2.9.14
      fixedIn: 2.9.15
      title: Heap buffer overflow in libxml2 ...
status:
  generatedAt: "2026-10-13T06:46:00Z"
  summary: {critical: 0, high: 3, medium: 2, low: 7, unknown: 0}
```

## Architecture

```
                              ┌─────────────────────────┐
                              │  Pod watcher (reconciler)│
   Pods (all namespaces) ───▶│  extract containers      │───▶ ImageInventory CRD
                              │  resolve digest          │     (one per digest)
                              └─────────────────────────┘
                                                              │
                                                              ▼
                                                 ┌─────────────────────────┐
                                                 │  Scan reconciler         │
                                                 │  interval + concurrency  │
                                                 │  dedupe inflight digests │
                                                 └─────────────────────────┘
                                                              │
                             ┌────────────────────────────────┼──────────────┐
                             ▼                                ▼              ▼
                     ┌──────────────┐                 ┌──────────────┐  ┌─────────────┐
                     │ Credential   │                 │ Trivy        │  │ Slack       │
                     │ chain (ECR / │ ───(auth) ───▶ │ scanner lib  │  │ alerter     │
                     │ GCR / secret)│                 │ (in-process) │  │ (dedupe)    │
                     └──────────────┘                 └──────────────┘  └─────────────┘
                                                              │
                                                              ▼
                                                   VulnerabilityReport CRD
```

## Configuration

| Flag                           | Env                       | Default                       | Purpose                                           |
| ------------------------------ | ------------------------- | ----------------------------- | ------------------------------------------------- |
| `--metrics-bind-address`       |                           | `:8080`                       | Prometheus metrics endpoint                       |
| `--health-probe-bind-address`  |                           | `:8081`                       | Liveness/readiness endpoints                      |
| `--leader-elect`               |                           | `false`                       | Enable leader election (multi-replica)            |
| `--scan-interval`              |                           | `1h`                          | Rescan cadence per digest                         |
| `--scan-concurrency`           |                           | `3`                           | Max parallel image scans                          |
| `--slack-webhook-url`          | `HEIMDALL_SLACK_WEBHOOK`  |                               | Slack incoming webhook URL                        |
| `--min-severity`               | `HEIMDALL_MIN_SEVERITY`   | `HIGH`                        | Floor for alerting                                |
| `--trivy-cache-dir`            | `TRIVY_CACHE_DIR`         | `/var/cache/heimdall/trivy`   | Trivy DB + layer cache                            |
| `--trivy-offline`              | `TRIVY_OFFLINE`           | `false`                       | Skip DB updates (needs pre-populated cache)       |
| `--ecr-enabled`                | `HEIMDALL_ECR_ENABLED`    | `false`                       | Turn on the ECR credential provider               |
| `--ecr-region`                 | `AWS_REGION`              | *(parsed from image hostname)*| Override ECR region                               |

## Development

```bash
# Install dev dependencies
make $(bin)/controller-gen $(bin)/golangci-lint

# Build the binary
make build

# Full local check (fmt, vet, lint, test, build)
make all

# Build & load image into local Docker
make docker-build IMAGE_TAG=dev

# Render the Helm chart
make helm-template
```

## Project layout

```
heimdall/
├── cmd/operator/            # entrypoint
├── api/v1alpha1/            # CRD Go types + deepcopy
├── internal/
│   ├── controller/          # Pod + ImageScan reconcilers
│   ├── registry/            # Credential providers (ECR / GCR / secret)
│   ├── scanner/             # Scanner interface + Trivy impl
│   └── alert/               # Slack webhook alerter
├── chart/heimdall/          # Helm chart
├── Dockerfile               # Distroless multi-arch
├── Makefile                 # Standard targets
├── .github/workflows/ci.yml # Lint, test, build, push to GHCR, release
└── .goreleaser.yml          # Multi-platform binary releases
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
