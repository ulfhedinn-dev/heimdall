#!/usr/bin/env bash
# End-to-end test: installs Heimdall into a kind cluster next to a known
# vulnerable workload and a fake Slack webhook, then checks that the image is
# discovered, scanned, reported, alerted on and exposed as metrics, and that
# deleting the workload deactivates its inventory record.
#
# Requires docker, kind, kubectl and helm. Set KEEP_CLUSTER=1 to keep the
# cluster afterwards, or IMAGE=<ref> to test a pre-built image instead of
# building one.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${KIND_CLUSTER:-heimdall-e2e}
IMAGE=${IMAGE:-}
VULN_IMAGE=${VULN_IMAGE:-nginx:1.25.0}
TIMEOUT=${E2E_TIMEOUT:-600}

log() { printf '\n=== %s\n' "$*"; }

created=0
cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    log "FAILED — diagnostics"
    kubectl get pods -A -o wide || true
    kubectl get imageinventories -o wide || true
    kubectl -n heimdall logs deploy/heimdall --tail=200 || true
    kubectl -n e2e logs deploy/webhook --tail=50 || true
  fi
  if [[ $created -eq 1 && -z "${KEEP_CLUSTER:-}" ]]; then
    kind delete cluster --name "$CLUSTER" || true
  fi
  exit $status
}
trap cleanup EXIT

# wait_for <description> <command…>: retries the command until it succeeds.
wait_for() {
  local desc=$1; shift
  local deadline=$((SECONDS + TIMEOUT))
  until "$@" >/dev/null 2>&1; do
    if (( SECONDS > deadline )); then
      echo "timed out waiting for: $desc" >&2
      return 1
    fi
    sleep 5
  done
  echo "ok: $desc"
}

if ! kind get clusters | grep -qx "$CLUSTER"; then
  log "Creating kind cluster $CLUSTER"
  kind create cluster --name "$CLUSTER" --wait 120s
  created=1
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

if [[ -z "$IMAGE" ]]; then
  IMAGE=heimdall:e2e
  log "Building $IMAGE"
  docker build -t "$IMAGE" --build-arg VERSION=e2e .
fi
kind load docker-image "$IMAGE" --name "$CLUSTER"

log "Deploying fake Slack webhook and vulnerable workload ($VULN_IMAGE)"
kubectl apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: e2e}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: webhook, namespace: e2e}
data:
  server.py: |
    import http.server, sys
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            print("WEBHOOK " + body.decode(), flush=True)
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    http.server.HTTPServer(("", 8080), H).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: webhook, namespace: e2e}
spec:
  selector: {matchLabels: {app: webhook}}
  template:
    metadata: {labels: {app: webhook}}
    spec:
      containers:
        - name: webhook
          image: python:3.13-alpine
          command: [python, -u, /app/server.py]
          ports: [{containerPort: 8080}]
          volumeMounts: [{name: app, mountPath: /app}]
      volumes: [{name: app, configMap: {name: webhook}}]
---
apiVersion: v1
kind: Service
metadata: {name: webhook, namespace: e2e}
spec:
  selector: {app: webhook}
  ports: [{port: 8080}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: vulnerable, namespace: e2e}
spec:
  selector: {matchLabels: {app: vulnerable}}
  template:
    metadata: {labels: {app: vulnerable}}
    spec:
      containers:
        - name: nginx
          image: $VULN_IMAGE
YAML
kubectl -n e2e rollout status deploy/webhook --timeout=180s
kubectl -n e2e rollout status deploy/vulnerable --timeout=180s

log "Installing Heimdall ($IMAGE)"
helm upgrade --install heimdall chart/heimdall \
  --namespace heimdall --create-namespace \
  --set image.repository="${IMAGE%:*}" \
  --set image.tag="${IMAGE##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --set slack.webhookUrl=http://webhook.e2e.svc:8080/ \
  --set scan.cooldownSeconds=2 \
  --set scan.intervalMinutes=60 \
  --wait --timeout 180s

inventory_for() {
  kubectl get imageinventories -o jsonpath="{range .items[?(@.spec.imageRef==\"$1\")]}{.metadata.name}{end}"
}

log "Waiting for discovery"
wait_for "ImageInventory for $VULN_IMAGE" bash -c "[[ -n \$(kubectl get imageinventories -o jsonpath='{.items[?(@.spec.imageRef==\"$VULN_IMAGE\")].metadata.name}') ]]"
INV=$(inventory_for "$VULN_IMAGE")
echo "inventory: $INV"

log "Waiting for scan"
wait_for "$INV scanned as Vulnerable" bash -c "[[ \$(kubectl get imageinventory $INV -o jsonpath='{.status.scanResult}') == Vulnerable ]]"
kubectl get imageinventory "$INV" -o wide

REPORT=$(kubectl get vulnerabilityreports -l "heimdall.ulfhedinn.dev/image-inventory=$INV" -o jsonpath='{.items[0].metadata.name}')
FINDINGS=$(kubectl get vulnerabilityreport "$REPORT" -o jsonpath='{.spec.findings[*].vulnID}' | wc -w | tr -d ' ')
HIGH=$(kubectl get vulnerabilityreport "$REPORT" -o jsonpath='{.status.summary.high}')
CRITICAL=$(kubectl get vulnerabilityreport "$REPORT" -o jsonpath='{.status.summary.critical}')
echo "report $REPORT: $FINDINGS findings stored, critical=$CRITICAL high=$HIGH"
if (( FINDINGS == 0 || HIGH + CRITICAL == 0 )); then
  echo "expected HIGH/CRITICAL findings in $VULN_IMAGE" >&2
  exit 1
fi

log "Checking alert delivery"
wait_for "Slack payload for $VULN_IMAGE" bash -c "kubectl -n e2e logs deploy/webhook | grep '^WEBHOOK' | grep -q '$VULN_IMAGE'"
kubectl -n e2e logs deploy/webhook | grep '^WEBHOOK' | grep "$VULN_IMAGE" | head -1 | cut -c1-300

log "Checking metrics"
metrics() { kubectl get --raw "/api/v1/namespaces/heimdall/services/heimdall-metrics:8080/proxy/metrics"; }
wait_for "heimdall_scans_total{result=\"success\"}" bash -c "kubectl get --raw /api/v1/namespaces/heimdall/services/heimdall-metrics:8080/proxy/metrics | grep -q 'heimdall_scans_total{result=\"success\"}'"
metrics | grep -E '^heimdall_(scans_total|alerts_total)' || true
metrics | grep "^heimdall_image_vulnerabilities{.*inventory=\"$INV\"" || true

log "Checking cleanup on pod deletion"
kubectl -n e2e delete deploy/vulnerable --wait=true
wait_for "$INV inactive" bash -c "[[ \$(kubectl get imageinventory $INV -o jsonpath='{.status.active}') == false ]]"

log "Inventory"
kubectl get imageinventories
echo
echo "E2E PASSED"
