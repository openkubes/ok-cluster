#!/usr/bin/env bash
# install-observability.sh — install the ok-observability-standard profile on a
# workload cluster and run its Contract Test Gate (OK-79, ADR-Platform-018).
#
# ok-cluster INSTALLS the capability; it does not OWN it. All assets (profile,
# alerting rules, dashboards, contract test) come from the ok-observability repo
# (default: ../ok-observability). This script is the reference `install-storage`
# analogue for observability.
#
# Secrets model (Phase 1, Vault-ready): the Grafana/OpenSearch admin passwords
# are read from a git-ignored provider-values file and written into the
# Kubernetes Secret `ok-observability-credentials`. The charts consume that
# Secret (Grafana admin.existingSecret, OpenSearch secretKeyRef, Fluent Bit
# ${OPENSEARCH_PASSWORD}) — no plaintext password is ever passed to helm.
# Phase 2 will replace the "create Secret" step with an External-Secrets sync
# from the ok-shared Vault, with NO chart change.
#
# Required env (set by the Makefile target):
#   CLUSTER                cluster name (kubeconfig at $KUBECONFIG_PATH)
#   KUBECONFIG_PATH        path to the target cluster's kubeconfig
#   OK_OBSERVABILITY_PATH  path to the ok-observability repo checkout
#   OBSERVABILITY_VALUES   path to the provider-values file (see schema below)
#
# provider-values schema (git-ignored, per cluster):
#   grafanaAdminPassword: "..."
#   opensearchAdminPassword: "..."
set -euo pipefail

NAMESPACE="${OBSERVABILITY_NAMESPACE:-ok-observability}"
RELEASE="${OBSERVABILITY_RELEASE:-ok-observability-standard}"
SECRET_NAME="${OBSERVABILITY_SECRET:-ok-observability-credentials}"
PROFILE="${OK_OBSERVABILITY_PATH}/profiles/ok-observability-standard"

# --- preconditions --------------------------------------------------------
for bin in kubectl helm python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "❌ required binary '$bin' not on PATH"; exit 2; }
done
[ -n "${CLUSTER:-}" ]              || { echo "❌ CLUSTER is required"; exit 2; }
[ -f "${KUBECONFIG_PATH:-}" ]      || { echo "❌ kubeconfig not found: ${KUBECONFIG_PATH:-<unset>} — run 'make kubeconfig CLUSTER=${CLUSTER}' first"; exit 2; }
[ -d "$PROFILE" ]                  || { echo "❌ profile not found: $PROFILE — set OK_OBSERVABILITY_PATH to your ok-observability checkout"; exit 2; }
if [ ! -f "${OBSERVABILITY_VALUES:-}" ]; then
  echo "❌ provider-values file not found: ${OBSERVABILITY_VALUES:-<unset>}"
  echo "   Create a git-ignored file with:"
  echo "     grafanaAdminPassword: \"...\""
  echo "     opensearchAdminPassword: \"...\""
  echo "   and pass it via OBSERVABILITY_VALUES=<path> (or place it at the default path)."
  exit 2
fi

export KUBECONFIG="$KUBECONFIG_PATH"

echo "━━━ install-observability: ${RELEASE} → ${CLUSTER} (ns ${NAMESPACE}) ━━━"

# --- read passwords from provider-values ----------------------------------
read_val() { python3 -c "import sys,yaml; print(yaml.safe_load(open('$OBSERVABILITY_VALUES')).get('$1',''))"; }
GRAFANA_PASSWORD="$(read_val grafanaAdminPassword)"
OPENSEARCH_PASSWORD="$(read_val opensearchAdminPassword)"
[ -n "$GRAFANA_PASSWORD" ]    || { echo "❌ grafanaAdminPassword empty in $OBSERVABILITY_VALUES"; exit 2; }
[ -n "$OPENSEARCH_PASSWORD" ] || { echo "❌ opensearchAdminPassword empty in $OBSERVABILITY_VALUES"; exit 2; }

# --- [1/6] namespace + Pod Security Admission labels ----------------------
echo "  [1/6] namespace ${NAMESPACE} + PSA privileged labels (node-exporter/fluent-bit need host access)"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  pod-security.kubernetes.io/audit=privileged \
  --overwrite

# --- [2/6] credentials Secret (idempotent) --------------------------------
# Charts read from this Secret; it must exist BEFORE the pods start. Later a
# Vault sync (External Secrets) will produce the SAME Secret with no chart change.
echo "  [2/6] Secret ${SECRET_NAME} (grafana-admin-user/password, opensearch-admin-password)"
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-literal=grafana-admin-user=admin \
  --from-literal=grafana-admin-password="$GRAFANA_PASSWORD" \
  --from-literal=opensearch-admin-password="$OPENSEARCH_PASSWORD" \
  --dry-run=client -o yaml | kubectl apply -f -

# --- [3/6] helm dependency build + install ---------------------------------
# `build` reuses the existing Chart.lock and does NOT refresh every configured
# helm repo (that repo refresh is the slow part of `update`). Fall back to
# `update` only on first run when the lock/vendored charts don't exist yet.
echo "  [3/6] helm dependency build (no repo refresh) + install"
helm dependency build "$PROFILE" 2>/dev/null || helm dependency update --skip-refresh "$PROFILE"
# NOTE: no --wait. The Prometheus/Alertmanager StatefulSets are created
# asynchronously by the Operator, so --wait both blocks silently for minutes AND
# doesn't actually cover them. Step 5 does a visible readiness wait instead.
helm upgrade --install "$RELEASE" "$PROFILE" \
  --namespace "$NAMESPACE" \
  -f "$PROFILE/values.yaml" \
  -f "${OK_OBSERVABILITY_PATH}/alerting/alertmanager-values.yaml" \
  ${OBSERVABILITY_HELM_VALUES:+-f "$OBSERVABILITY_HELM_VALUES"} \
  --timeout "${HELM_TIMEOUT:-10m}"

# --- [4/6] alerting rules + dashboards (bare manifests) -------------------
echo "  [4/6] apply PrometheusRules + dashboards"
kubectl -n "$NAMESPACE" apply -f "${OK_OBSERVABILITY_PATH}/alerting/prometheus-rules.yaml"
kubectl -n "$NAMESPACE" apply -f "${OK_OBSERVABILITY_PATH}/dashboards/"

# --- [5/6] visible readiness wait -----------------------------------------
# Poll every pod's READY column and print which ones are still coming up, so the
# wait is transparent (unlike a silent helm --wait). Ready = numerator ==
# denominator in the READY column; Completed one-shot pods are ignored.
echo "  [5/6] waiting for pods to become Ready"
deadline=$(( $(date +%s) + ${OBSERVABILITY_READY_TIMEOUT:-420} ))
while :; do
  notready=$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null \
    | awk '{n=split($2,a,"/"); if (n==2 && a[1]!=a[2] && $3!="Completed") print $1"("$2","$3")"}' \
    | paste -sd" " -)
  [ -z "$notready" ] && { echo "    ✅ all pods Ready"; break; }
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "    ⚠️  not Ready after ${OBSERVABILITY_READY_TIMEOUT:-420}s, continuing to gate anyway: $notready"
    break
  fi
  echo "    ⏳ $notready"
  sleep 15
done

# --- [6/6] gated Contract Test (ADR-Platform-018 readiness gate) ----------
# The install is complete ONLY when the gate passes (OK-79). The gate uses the
# current kube-context (= this cluster, via KUBECONFIG) and the same passwords.
echo "  [6/6] running Contract Test Gate (make new is complete only when this passes)"
GATE="${OK_OBSERVABILITY_PATH}/tests/contract-test.sh"
[ -x "$GATE" ] || { echo "❌ contract test not executable: $GATE"; exit 1; }
GRAFANA_PASSWORD="$GRAFANA_PASSWORD" \
OPENSEARCH_PASSWORD="$OPENSEARCH_PASSWORD" \
CONTRACT_TEST_NAMESPACE="$NAMESPACE" \
  "$GATE"

echo ""
echo "✅ install-observability complete on ${CLUSTER} — profile deployed and Contract Test Gate PASSED."
