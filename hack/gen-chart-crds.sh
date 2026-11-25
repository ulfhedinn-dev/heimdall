#!/usr/bin/env bash
# Regenerates chart/heimdall/templates/crds.yaml from the Go API types.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"${CONTROLLER_GEN:-bin/controller-gen}" crd paths="./api/..." output:crd:artifacts:config="$tmp"
{
  echo '{{- if .Values.installCRDs }}'
  for f in "$tmp"/heimdall.ulfhedinn.dev_imageinventories.yaml "$tmp"/heimdall.ulfhedinn.dev_vulnerabilityreports.yaml; do
    echo '---'
    sed -e '/^---$/d' \
        -e 's/^    controller-gen.kubebuilder.io\/version: \(.*\)$/    controller-gen.kubebuilder.io\/version: \1\n    helm.sh\/resource-policy: keep/' \
        -e 's/^  name: \(.*\)$/  labels:\n    {{- include "heimdall.labels" . | nindent 4 }}\n  name: \1/' "$f"
  done
  echo '{{- end }}'
} > chart/heimdall/templates/crds.yaml
