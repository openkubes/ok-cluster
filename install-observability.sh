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
# This file-based step is the OFFLINE-RECONCILABLE profile (edge/air-gapped, and
# any cluster with no Vault mount yet). Datacenter-envelope clusters instead have
# the Secret populated from Vault on ok-shared by a VaultStaticSecret — see
# ok-observability/implementations/vault-secrets-operator/ (ADR-Platform-025) —
# with NO chart change; only who populates the Secret differs. The two profiles
# coexist by envelope, they are not sequential phases (Secret Contract,
# ADR-Platform-011). Skip this step where VSO owns the Secret.
#
# Required env (set by the Makefile target):
#   CLUSTER                cluster name (kubeconfig at $KUBECONFIG_PATH)
#   KUBECONFIG_PATH        path to the target cluster's kubeconfig
#   OK_OBSERVABILITY_PATH  path to the ok-observability repo checkout
#   OBSERVABILITY_VALUES   path to the provider-values file (see schema below)
#
# Optional env (forwarded to the gate; unset => the gate's own default):
#   OK_OBSERVABILITY_REF              assert which ok-observability revision may
#                                     be consumed (see "provenance" below)
#   CONTRACT_TEST_TIMEOUT             per-check async timeout, seconds
#   CONTRACT_TEST_RECEIVER_CAPTURE_URL  capture endpoint that upgrades the alert
#                                     check from "fired" to "delivered"
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

# --- provenance: consumed revisions (ADR-Platform-024) --------------------
# A readiness result is only reproducible if the revisions it consumed are
# known, so both are resolved and printed as gate evidence. The sibling-checkout
# mechanism is TRANSITIONAL until a real pin lands (OK-109): setting
# OK_OBSERVABILITY_REF asserts which ok-observability revision this run may
# consume and fails loudly on mismatch. It deliberately does NOT check the
# sibling repo out — silently mutating someone's working tree mid-install is
# worse than refusing to run.
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sha_of()   { git -C "$1" rev-parse HEAD 2>/dev/null || echo "unknown"; }
state_of() { [ -z "$(git -C "$1" status --porcelain 2>/dev/null)" ] && echo clean || echo DIRTY; }
OK_CLUSTER_SHA="$(sha_of "$_here")";               OK_CLUSTER_STATE="$(state_of "$_here")"
OBSERVABILITY_SHA="$(sha_of "$OK_OBSERVABILITY_PATH")"; OBSERVABILITY_STATE="$(state_of "$OK_OBSERVABILITY_PATH")"

if [ -n "${OK_OBSERVABILITY_REF:-}" ]; then
  # -q --verify: without it, rev-parse echoes an unresolvable arg back on stdout
  # and $want ends up non-empty garbage, misreporting "does not resolve" as a mismatch.
  want="$(git -C "$OK_OBSERVABILITY_PATH" rev-parse -q --verify "${OK_OBSERVABILITY_REF}^{commit}" 2>/dev/null || true)"
  [ -n "$want" ] || { echo "❌ OK_OBSERVABILITY_REF='${OK_OBSERVABILITY_REF}' does not resolve in $OK_OBSERVABILITY_PATH"; exit 2; }
  if [ "$want" != "$OBSERVABILITY_SHA" ]; then
    echo "❌ ok-observability pin mismatch"
    echo "   requested OK_OBSERVABILITY_REF=${OK_OBSERVABILITY_REF} -> ${want}"
    echo "   checkout  ${OK_OBSERVABILITY_PATH} is at ${OBSERVABILITY_SHA}"
    echo "   Check out the requested revision yourself, then re-run."
    exit 2
  fi
fi

echo "━━━ install-observability: ${RELEASE} → ${CLUSTER} (ns ${NAMESPACE}) ━━━"
echo "  consumed ok-cluster:       ${OK_CLUSTER_SHA} (${OK_CLUSTER_STATE})"
echo "  consumed ok-observability: ${OBSERVABILITY_SHA} (${OBSERVABILITY_STATE})${OK_OBSERVABILITY_REF:+ [pinned ${OK_OBSERVABILITY_REF}]}"
[ "$OK_CLUSTER_STATE" = clean ] && [ "$OBSERVABILITY_STATE" = clean ] || \
  echo "  ⚠️  a consumed checkout is DIRTY — this run is not reproducible conformance evidence"

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
# Charts read from this Secret; it must exist BEFORE the pods start. On
# datacenter clusters a Vault sync (Vault Secrets Operator, ADR-Platform-025)
# produces the SAME Secret with the same keys instead of this step.
#
# Credential-handling invariant (ADR-Platform-024): secret values MUST NOT be
# exposed via process arguments, shell tracing, stdout/stderr, logs, or temp
# files with unsafe perms. So NOT `--from-literal=<key>=<value>` (that puts the
# value in kubectl's argv, visible in `ps`/`set -x`). Instead: write values to
# 0600 files in a umask-077 temp dir and feed them via `--from-file`; wipe the
# dir immediately and on any exit. The rendered Secret YAML is piped straight to
# `kubectl apply` and never echoed/tee'd/logged.
echo "  [2/6] Secret ${SECRET_NAME} (grafana-admin-user/password, opensearch-admin-password)"
_old_umask="$(umask)"; umask 077
_cred_dir="$(mktemp -d)"
trap 'rm -rf "$_cred_dir"' EXIT INT TERM
printf '%s' "admin"                 > "$_cred_dir/grafana-admin-user"
printf '%s' "$GRAFANA_PASSWORD"     > "$_cred_dir/grafana-admin-password"
printf '%s' "$OPENSEARCH_PASSWORD"  > "$_cred_dir/opensearch-admin-password"
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-file=grafana-admin-user="$_cred_dir/grafana-admin-user" \
  --from-file=grafana-admin-password="$_cred_dir/grafana-admin-password" \
  --from-file=opensearch-admin-password="$_cred_dir/opensearch-admin-password" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf "$_cred_dir"; trap - EXIT INT TERM; umask "$_old_umask"

# --- [3/6] helm dependency build + install ---------------------------------
# `build` reuses the existing Chart.lock and does NOT refresh every configured
# helm repo (that repo refresh is the slow part of `update`). Fall back to
# `update` only on first run when the lock/vendored charts don't exist yet.
echo "  [3/6] helm dependency build (no repo refresh) + install"
# The profile is a TWO-level umbrella (profile -> implementations/* -> upstream),
# and `helm dependency build` resolves only ONE level: building just the profile
# packages the wrappers with an empty charts/, which renders to NOTHING and would
# install an empty release. The capability repo owns how its charts are built, so
# use its `deps` target; fall back to the old single-level build for checkouts
# that predate it.
if make -C "$OK_OBSERVABILITY_PATH" -n deps >/dev/null 2>&1; then
  make -C "$OK_OBSERVABILITY_PATH" deps
else
  echo "    (no 'make deps' in the capability repo — falling back to single-level build)"
  helm dependency build "$PROFILE" 2>/dev/null || helm dependency update --skip-refresh "$PROFILE"
fi

helm_values=( -f "$PROFILE/values.yaml" -f "${OK_OBSERVABILITY_PATH}/alerting/alertmanager-values.yaml" )
if [ -n "${OBSERVABILITY_HELM_VALUES:-}" ]; then
  helm_values+=( -f "$OBSERVABILITY_HELM_VALUES" )
fi

# Guard: refuse to install a render that does not reference the credentials Secret.
# An empty/partial render is otherwise a SILENT success — helm happily installs a
# release containing nothing and the failure only surfaces later as a confusing
# gate timeout.
if [ "$(helm template "$RELEASE" "$PROFILE" --namespace "$NAMESPACE" "${helm_values[@]}" 2>/dev/null | grep -c "$SECRET_NAME")" -eq 0 ]; then
  echo "❌ rendered profile contains no reference to Secret ${SECRET_NAME} — refusing to install."
  echo "   Chart dependencies are probably unbuilt at the inner umbrella level."
  echo "   Run: make -C ${OK_OBSERVABILITY_PATH} deps"
  exit 1
fi

# NOTE: no --wait. The Prometheus/Alertmanager StatefulSets are created
# asynchronously by the Operator, so --wait both blocks silently for minutes AND
# doesn't actually cover them. Step 5 does a visible readiness wait instead.
helm upgrade --install "$RELEASE" "$PROFILE" \
  --namespace "$NAMESPACE" \
  "${helm_values[@]}" \
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
# Forwarded as shell prefix assignments, NOT `env VAR=val` — prefix assignments
# reach the child's environment without appearing in its argv (ADR-024 credential
# invariant). CONTRACT_TEST_* are optional: the gate reads them as ${VAR:-default},
# so forwarding an empty value is identical to not setting it.
GRAFANA_PASSWORD="$GRAFANA_PASSWORD" \
OPENSEARCH_PASSWORD="$OPENSEARCH_PASSWORD" \
CONTRACT_TEST_NAMESPACE="$NAMESPACE" \
CONTRACT_TEST_TIMEOUT="${CONTRACT_TEST_TIMEOUT:-}" \
CONTRACT_TEST_RECEIVER_CAPTURE_URL="${CONTRACT_TEST_RECEIVER_CAPTURE_URL:-}" \
  "$GATE"

echo ""
echo "✅ install-observability complete on ${CLUSTER} — profile deployed and Contract Test Gate PASSED."
echo "   evidence: ok-cluster ${OK_CLUSTER_SHA} (${OK_CLUSTER_STATE}) · ok-observability ${OBSERVABILITY_SHA} (${OBSERVABILITY_STATE})"
if [ -z "${CONTRACT_TEST_RECEIVER_CAPTURE_URL:-}" ]; then
  echo "   note: alert guarantee verified as FIRED only — set CONTRACT_TEST_RECEIVER_CAPTURE_URL"
  echo "         to verify DELIVERY. This pass is the documented weaker form."
fi
