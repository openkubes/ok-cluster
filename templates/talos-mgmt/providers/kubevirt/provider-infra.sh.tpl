#!/usr/bin/env bash
# provider-infra.sh — KubeVirt/CAPK infrastructure preparation
# Implementation Profile: kubevirt
# Rendered from templates/talos-mgmt/providers/kubevirt/provider-infra.sh.tpl
# Sourced by bootstrap-mgmt.sh (Step 5); runs in that shell — set -euo pipefail
# and the log/ok/fail helpers are inherited. Content is byte-for-byte the original
# Step 4 CAPK wait + Step 5 external-infra secret block (behaviour unchanged).

# Wait for the CAPK infrastructure controller
kubectl wait deployment/capk-controller-manager \
  -n capk-system --for=condition=Available --timeout=300s
ok "CAPK infrastructure provider healthy"

# ok-infra kubeconfig secret for CAPK (external infrastructure pattern)
log "Creating ok-infra kubeconfig secret for CAPK..."
INFRA_KUBECONFIG="$${INFRA_KUBECONFIG_PATH:-$$HOME/.kube/ok-infra.yaml}"

if [[ ! -f "$$INFRA_KUBECONFIG" ]]; then
  fail "ok-infra kubeconfig not found at $$INFRA_KUBECONFIG — set INFRA_KUBECONFIG_PATH"
fi

kubectl -n capk-system create secret generic external-infra-kubeconfig \
  --from-file=kubeconfig="$$INFRA_KUBECONFIG" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n capk-system rollout restart deployment/capk-controller-manager
kubectl -n capk-system rollout status deployment/capk-controller-manager --timeout=120s

ok "ok-infra kubeconfig secret created"
