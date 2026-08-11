#!/usr/bin/env bash
# install-observability.sh — install the standard observability profile or its
# scoped metrics component on a workload cluster (OK-79/OK-138, ADR-Platform-018).
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
#   OK_OBSERVABILITY_PATH  path to the ok-observability repo checkout/object store
#   OBSERVABILITY_VALUES   path to the provider-values file (see schema below)
#
# Secret source (OK-117) — which mechanism populates the credentials Secret:
#   OBSERVABILITY_SECRET_SOURCE  file (default) | vault
#     file  — this script writes the Secret from OBSERVABILITY_VALUES. The
#             offline-reconcilable profile; required env is OBSERVABILITY_VALUES.
#     vault — a VaultStaticSecret (VSO) syncs it from the central Vault, applied and
#             waited on BEFORE the helm release. Requires VSO installed
#             (`make install-vso`) and, per cluster, the Vault auth mount/role, the
#             ServiceAccount and the CA secret. No provider-values file is used;
#             the gate's passwords are read back from the materialised Secret.
#     Vault-path env: VAULT_ADDR, VAULT_TLS_SERVER_NAME, VAULT_CA_SECRET, KV_MOUNT,
#     KV_PATH, VAULT_ROLE, VSO_SERVICE_ACCOUNT, REFRESH_AFTER, VSS_SYNC_TIMEOUT.
#
# Optional env:
#   OBSERVABILITY_COMPONENTS            standard (default) | metrics
#   OK_OBSERVABILITY_REF              revision to materialise and consume
#   OK_OBSERVABILITY_MODE             pinned (default) | worktree
#   OK_OBSERVABILITY_CACHE            materialised-tree cache root (default:
#                                     ${XDG_CACHE_HOME:-$HOME/.cache}/ok-cluster/
#                                     ok-observability)
# Forwarded to the gate (unset => the gate's own default):
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
OBSERVABILITY_SOURCE_PATH="${OK_OBSERVABILITY_PATH:-}"
OBSERVABILITY_MODE="${OK_OBSERVABILITY_MODE:-pinned}"
OBSERVABILITY_COMPONENTS="${OBSERVABILITY_COMPONENTS:-standard}"
_materialise_tmp=""
_cred_dir=""

cleanup() {
  [ -z "$_materialise_tmp" ] || rm -rf -- "$_materialise_tmp"
  [ -z "$_cred_dir" ] || rm -rf -- "$_cred_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- preconditions --------------------------------------------------------
# Validate the requested operation before inspecting the host toolchain or
# touching cluster inputs. This keeps invalid intent deterministic and
# fail-closed on every supported caller platform.
case "$OBSERVABILITY_MODE" in
  pinned|worktree) ;;
  *) echo "❌ OK_OBSERVABILITY_MODE='$OBSERVABILITY_MODE' is not one of: pinned worktree"; exit 2 ;;
esac
case "$OBSERVABILITY_COMPONENTS" in
  standard|metrics) ;;
  *) echo "❌ OBSERVABILITY_COMPONENTS='$OBSERVABILITY_COMPONENTS' is not one of: standard metrics"; exit 2 ;;
esac
if [ "$OBSERVABILITY_COMPONENTS" = metrics ]; then
  [ "$NAMESPACE" = ok-observability ] || {
    echo "❌ metrics mode requires OBSERVABILITY_NAMESPACE=ok-observability"
    exit 2
  }
  [ "$RELEASE" = ok-observability-standard ] || {
    echo "❌ metrics mode requires OBSERVABILITY_RELEASE=ok-observability-standard"
    exit 2
  }
fi
for bin in kubectl helm python3 git make tar flock; do
  command -v "$bin" >/dev/null 2>&1 || { echo "❌ required binary '$bin' not on PATH"; exit 2; }
done
[ -n "${CLUSTER:-}" ]              || { echo "❌ CLUSTER is required"; exit 2; }
[ -f "${KUBECONFIG_PATH:-}" ]      || { echo "❌ kubeconfig not found: ${KUBECONFIG_PATH:-<unset>} — run 'make kubeconfig CLUSTER=${CLUSTER}' first"; exit 2; }
[ -d "$OBSERVABILITY_SOURCE_PATH" ] || { echo "❌ ok-observability checkout not found: ${OBSERVABILITY_SOURCE_PATH:-<unset>} — set OK_OBSERVABILITY_PATH"; exit 2; }
if [ "$OBSERVABILITY_MODE" = pinned ] && [ -z "${OK_OBSERVABILITY_REF:-}" ]; then
  echo "❌ OK_OBSERVABILITY_REF is required in pinned mode"
  echo "   Set it to a locally available commit/tag, or explicitly opt into the"
  echo "   non-reproducible working tree with OK_OBSERVABILITY_MODE=worktree."
  exit 2
fi
# OK-117: which mechanism populates the credentials Secret. Validated against the
# allowed set so a typo fails loudly instead of silently selecting a profile — the
# same class of defect as OK-119's TYPE default.
if [ "$OBSERVABILITY_COMPONENTS" = standard ]; then
  SECRET_SOURCE="${OBSERVABILITY_SECRET_SOURCE:-file}"
  case " ${OBSERVABILITY_SECRET_SOURCES:-file vault} " in
    *" $SECRET_SOURCE "*) ;;
    *) echo "❌ OBSERVABILITY_SECRET_SOURCE='$SECRET_SOURCE' is not one of: ${OBSERVABILITY_SECRET_SOURCES:-file vault}"; exit 2 ;;
  esac

  # The provider-values file is a precondition of the FILE profile only. Requiring it
  # on the vault path would force a datacenter cluster to supply passwords it never
  # uses — the Secret comes from Vault there.
  if [ "$SECRET_SOURCE" = file ] && [ ! -f "${OBSERVABILITY_VALUES:-}" ]; then
    echo "❌ provider-values file not found: ${OBSERVABILITY_VALUES:-<unset>}"
    echo "   Create a git-ignored file with:"
    echo "     grafanaAdminPassword: \"...\""
    echo "     opensearchAdminPassword: \"...\""
    echo "   and pass it via OBSERVABILITY_VALUES=<path> (or place it at the default path)."
    echo "   Or select the datacenter profile: OBSERVABILITY_SECRET_SOURCE=vault"
    exit 2
  fi

  if [ "$SECRET_SOURCE" = vault ]; then
    command -v envsubst >/dev/null 2>&1 || {
      echo "❌ envsubst is required to render the VaultStaticSecret template (gettext package)"
      exit 2
    }
  fi
fi

export KUBECONFIG="$KUBECONFIG_PATH"

# --- provenance: consumed revisions (ADR-Platform-024) --------------------
# A pinned run resolves the requested commit in the sibling repository, archives
# that object into a SHA-keyed cache, builds its chart dependencies there once,
# and consumes only that materialised tree. The source checkout's HEAD and dirty
# state are informational: neither can alter the pinned render.
#
# The cache is per-user state rather than repo state: dependencies are derived
# build products, not source, and a stable XDG cache survives repeated installs.
# flock serialises builders for a SHA; the completed tree is renamed into place
# atomically, and an interrupted builder leaves only a trap-cleaned temp dir.
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sha_of()   { git -C "$1" rev-parse HEAD 2>/dev/null || echo "unknown"; }
# --untracked-files=no on purpose: DIRTY must mean "tracked code was modified",
# which is what threatens reproducibility. Counting untracked files made every
# FRESH-cluster run report DIRTY, because `make new` renders an untracked
# <cluster>/ directory — i.e. it fired exactly when the clean marker mattered
# most (OK-109 Part 1 evidence, ok-cluster f67aa1a).
tracked_state_of() {
  local status
  status="$(git -C "$1" status --porcelain --untracked-files=no 2>/dev/null)" || { echo unknown; return; }
  [ -z "$status" ] && echo clean || echo DIRTY
}
worktree_state_of() {
  local status
  status="$(git -C "$1" status --porcelain 2>/dev/null)" || { echo unknown; return; }
  [ -z "$status" ] && echo clean || echo DIRTY
}
build_observability_deps() {
  local tree="$1"
  local profile="$tree/profiles/ok-observability-standard"
  if make -C "$tree" -n deps >/dev/null 2>&1; then
    make -C "$tree" deps
  else
    echo "    (no 'make deps' in the capability revision — falling back to single-level build)"
    helm dependency build "$profile" 2>/dev/null || helm dependency update --skip-refresh "$profile"
  fi
}
build_metrics_deps() {
  local tree="$1"
  local profile="$tree/implementations/prometheus"
  helm dependency build "$profile"
}

OK_CLUSTER_SHA="$(sha_of "$_here")"
OK_CLUSTER_STATE="$(tracked_state_of "$_here")"
SOURCE_OBSERVABILITY_SHA="$(sha_of "$OBSERVABILITY_SOURCE_PATH")"
SOURCE_OBSERVABILITY_STATE="$(worktree_state_of "$OBSERVABILITY_SOURCE_PATH")"

if [ "$OBSERVABILITY_MODE" = pinned ]; then
  # -q --verify: without it, rev-parse echoes an unresolvable arg back on stdout
  # and the variable ends up non-empty garbage.
  OBSERVABILITY_SHA="$(git -C "$OBSERVABILITY_SOURCE_PATH" rev-parse -q --verify "${OK_OBSERVABILITY_REF}^{commit}" 2>/dev/null || true)"
  if [ -z "$OBSERVABILITY_SHA" ]; then
    echo "❌ OK_OBSERVABILITY_REF='${OK_OBSERVABILITY_REF}' is not present in $OBSERVABILITY_SOURCE_PATH"
    echo "   Fetch that revision into the local ok-observability checkout, then re-run."
    exit 2
  fi

  if [ -n "${OK_OBSERVABILITY_CACHE:-}" ]; then
    _cache_root="$OK_OBSERVABILITY_CACHE"
  elif [ -n "${XDG_CACHE_HOME:-}" ]; then
    _cache_root="${XDG_CACHE_HOME}/ok-cluster/ok-observability"
  elif [ -n "${HOME:-}" ]; then
    _cache_root="${HOME}/.cache/ok-cluster/ok-observability"
  else
    echo "❌ cannot choose an observability cache: set OK_OBSERVABILITY_CACHE, XDG_CACHE_HOME, or HOME"
    exit 2
  fi
  _cache_suffix=""
  _cache_marker_value="$OBSERVABILITY_SHA"
  if [ "$OBSERVABILITY_COMPONENTS" = metrics ]; then
    # A metrics-only cache is separate because it intentionally builds only the
    # standalone Prometheus wrapper. It must never make a later standard install
    # mistake the full two-level dependency closure for ready.
    _cache_suffix="-metrics"
    _cache_marker_value="${OBSERVABILITY_SHA}:metrics"
  fi
  _cache_tree="${_cache_root}/${OBSERVABILITY_SHA}${_cache_suffix}"
  _cache_marker="${_cache_tree}/.ok-cluster-cache-ready"
  mkdir -p "${_cache_root}/locks"
  chmod 700 "$_cache_root" "${_cache_root}/locks"
  exec 9>"${_cache_root}/locks/${OBSERVABILITY_SHA}.lock"
  flock 9

  _cache_assets_ready=false
  if [ "$OBSERVABILITY_COMPONENTS" = standard ]; then
    [ -x "${_cache_tree}/tests/contract-test.sh" ] && _cache_assets_ready=true
  else
    [ -f "${_cache_tree}/implementations/prometheus/values.yaml" ] &&
      [ -f "${_cache_tree}/alerting/prometheus-rules.yaml" ] &&
      _cache_assets_ready=true
  fi
  if [ -f "$_cache_marker" ] &&
     [ "$(< "$_cache_marker")" = "$_cache_marker_value" ] &&
     [ "$_cache_assets_ready" = true ]; then
    OBSERVABILITY_CACHE_RESULT="reused"
  else
    echo "  materialising ok-observability ${OBSERVABILITY_SHA} and building cached dependencies"
    _materialise_tmp="$(mktemp -d "${_cache_root}/.${OBSERVABILITY_SHA}.tmp.XXXXXX")"
    git -C "$OBSERVABILITY_SOURCE_PATH" archive "$OBSERVABILITY_SHA" | tar -x -C "$_materialise_tmp"
    if [ "$OBSERVABILITY_COMPONENTS" = standard ]; then
      [ -d "${_materialise_tmp}/profiles/ok-observability-standard" ] || {
        echo "❌ pinned revision ${OBSERVABILITY_SHA} has no ok-observability-standard profile"
        exit 2
      }
      [ -x "${_materialise_tmp}/tests/contract-test.sh" ] || {
        echo "❌ contract test is not executable in pinned revision ${OBSERVABILITY_SHA}"
        exit 2
      }
      build_observability_deps "$_materialise_tmp"
    else
      [ -f "${_materialise_tmp}/implementations/prometheus/values.yaml" ] || {
        echo "❌ pinned revision ${OBSERVABILITY_SHA} has no Prometheus implementation"
        exit 2
      }
      [ -f "${_materialise_tmp}/alerting/prometheus-rules.yaml" ] || {
        echo "❌ pinned revision ${OBSERVABILITY_SHA} has no Prometheus rules"
        exit 2
      }
      build_metrics_deps "$_materialise_tmp"
    fi
    printf '%s\n' "$_cache_marker_value" > "${_materialise_tmp}/.ok-cluster-cache-ready"
    # The published cache is a read-only derived object. This prevents an
    # accidental edit from recreating the working-tree provenance hole.
    chmod -R a-w "$_materialise_tmp"
    if [ -L "$_cache_tree" ]; then
      rm -- "$_cache_tree"
    elif [ -e "$_cache_tree" ]; then
      chmod -R u+w "$_cache_tree"
      rm -rf -- "$_cache_tree"
    fi
    mv "$_materialise_tmp" "$_cache_tree"
    _materialise_tmp=""
    OBSERVABILITY_CACHE_RESULT="built"
  fi
  flock -u 9
  exec 9>&-

  OK_OBSERVABILITY_PATH="$_cache_tree"
  OBSERVABILITY_STATE="pinned archive"
else
  OK_OBSERVABILITY_PATH="$OBSERVABILITY_SOURCE_PATH"
  OBSERVABILITY_SHA="$SOURCE_OBSERVABILITY_SHA"
  OBSERVABILITY_STATE="WORKTREE ${SOURCE_OBSERVABILITY_STATE}; NON-REPRODUCIBLE"
fi

if [ "$OBSERVABILITY_COMPONENTS" = standard ]; then
  PROFILE="${OK_OBSERVABILITY_PATH}/profiles/ok-observability-standard"
else
  PROFILE="${OK_OBSERVABILITY_PATH}/implementations/prometheus"
fi
[ -d "$PROFILE" ] || { echo "❌ profile not found: $PROFILE"; exit 2; }
PROMETHEUS_RULES="${OK_OBSERVABILITY_PATH}/alerting/prometheus-rules.yaml"
if [ "$OBSERVABILITY_COMPONENTS" = metrics ]; then
  [ -f "$PROMETHEUS_RULES" ] || { echo "❌ Prometheus rules not found: $PROMETHEUS_RULES"; exit 2; }
fi
if [ "$OBSERVABILITY_COMPONENTS" = standard ] && [ "$SECRET_SOURCE" = vault ]; then
  VSS_TEMPLATE="${OK_OBSERVABILITY_PATH}/implementations/vault-secrets-operator/vault-secret-sync.template.yaml"
  [ -f "$VSS_TEMPLATE" ] || {
    echo "❌ VaultStaticSecret template not found: $VSS_TEMPLATE"
    echo "   The selected capability revision predates OK-117. Select a newer revision, or"
    echo "   use OBSERVABILITY_SECRET_SOURCE=file."
    exit 2
  }
fi

echo "━━━ install-observability: ${RELEASE} → ${CLUSTER} (ns ${NAMESPACE}) ━━━"
echo "  consumed ok-cluster:       ${OK_CLUSTER_SHA} (${OK_CLUSTER_STATE})"
if [ "$OBSERVABILITY_MODE" = pinned ]; then
  echo "  consumed ok-observability: ${OBSERVABILITY_SHA} (${OBSERVABILITY_STATE}; cache ${OBSERVABILITY_CACHE_RESULT})"
  echo "  source checkout only:      ${SOURCE_OBSERVABILITY_SHA} (${SOURCE_OBSERVABILITY_STATE}; not rendered)"
  [ "$OK_CLUSTER_STATE" = clean ] || \
    echo "  ⚠️  ok-cluster is DIRTY — this run is not reproducible conformance evidence"
else
  echo "  consumed ok-observability: ${OBSERVABILITY_SHA} (${OBSERVABILITY_STATE})"
  echo "  ⚠️  WORKING-TREE ESCAPE HATCH ACTIVE — ignored, untracked, and modified files may be rendered"
  echo "  ⚠️  this run is NOT reproducible conformance evidence; OK_OBSERVABILITY_REF is not applied"
fi

if [ "$OBSERVABILITY_COMPONENTS" = metrics ]; then
  # Metrics is deliberately not the full ADR-018 contract profile. It creates no
  # credential Secret or Vault resource, and it does not apply dashboards,
  # OpenSearch assets, or the full contract gate. Capability-owned Prometheus
  # rules remain part of this metrics-and-alerting component.
  echo "  selected component: metrics (Prometheus + Alertmanager only)"
  if [ "$OBSERVABILITY_MODE" = worktree ]; then
    build_metrics_deps "$OK_OBSERVABILITY_PATH"
  fi

  echo "  [1/5] namespace ${NAMESPACE} + PSA privileged labels (node-exporter needs host access)"
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace "$NAMESPACE" \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/warn=privileged \
    pod-security.kubernetes.io/audit=privileged \
    --overwrite

  # The standalone wrapper's vendored defaults contain a self-consistent local
  # Alertmanager receiver. Do not layer alerting/alertmanager-values.yaml here:
  # its receiver-list override retains the upstream nested `null` route and the
  # operator correctly rejects that merged config. A real receiver remains a
  # Provider Value supplied through OBSERVABILITY_HELM_VALUES.
  metrics_values=( -f "$PROFILE/values.yaml" )
  if [ -n "${OBSERVABILITY_HELM_VALUES:-}" ]; then
    metrics_values+=( -f "$OBSERVABILITY_HELM_VALUES" )
  fi
  echo "  [2/5] structural render guard"
  helm template "$RELEASE" "$PROFILE" \
    --namespace "$NAMESPACE" \
    "${metrics_values[@]}" \
    | python3 "${_here}/scripts/verify_observability_metrics.py" \
        render-guard \
        --values "$PROFILE/values.yaml" \
        --forbidden-secret "$SECRET_NAME"

  # Keep the standard release identity: installing the standard profile later is
  # an upgrade of this release, not a second owner contending for the same objects.
  echo "  [3/5] Helm upgrade + capability-owned PrometheusRules"
  helm upgrade --install "$RELEASE" "$PROFILE" \
    --namespace "$NAMESPACE" \
    "${metrics_values[@]}" \
    --timeout "${HELM_TIMEOUT:-10m}"
  kubectl -n "$NAMESPACE" apply -f "$PROMETHEUS_RULES"

  echo "  [4/5] waiting for Prometheus + Alertmanager and metrics pods to become Ready"
  kubectl -n "$NAMESPACE" wait --for=condition=Available \
    prometheus/ok-observability-prometheus \
    --timeout="${OBSERVABILITY_READY_TIMEOUT:-420}s"
  kubectl -n "$NAMESPACE" wait --for=condition=Available \
    alertmanager/ok-observability-alertmanager \
    --timeout="${OBSERVABILITY_READY_TIMEOUT:-420}s"
  deadline=$(( $(date +%s) + ${OBSERVABILITY_READY_TIMEOUT:-420} ))
  while :; do
    notready=$(kubectl -n "$NAMESPACE" get pods -o json | python3 -c '
import json, sys
pods = json.load(sys.stdin).get("items", [])
for pod in pods:
    statuses = pod.get("status", {}).get("containerStatuses") or []
    phase = pod.get("status", {}).get("phase")
    if phase == "Succeeded":
        continue
    if not statuses or not all(status.get("ready") is True for status in statuses):
        print(pod.get("metadata", {}).get("name", "<unnamed>"))
' | paste -sd" " -)
    [ -z "$notready" ] && { echo "    ✅ all metrics pods Ready"; break; }
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "    ⚠️  not Ready after ${OBSERVABILITY_READY_TIMEOUT:-420}s, continuing to scoped verification: $notready"
      break
    fi
    echo "    ⏳ $notready"
    sleep 15
  done

  echo "  [5/5] verifying zot target and zot metric sample through Prometheus"
  python3 "${_here}/scripts/verify_observability_metrics.py" live \
    --namespace "$NAMESPACE" \
    --service ok-observability-prometheus \
    --target-namespace zot \
    --target-service zot \
    --metric-regex 'zot_.+' \
    --timeout "${OBSERVABILITY_METRICS_VERIFY_TIMEOUT:-180}"

  echo ""
  echo "✅ install-observability metrics complete on ${CLUSTER} — zot target and sample verified."
  echo "   evidence: ok-cluster ${OK_CLUSTER_SHA} (${OK_CLUSTER_STATE}) · ok-observability ${OBSERVABILITY_SHA} (${OBSERVABILITY_STATE})"
  exit 0
fi

# --- read passwords from provider-values (FILE profile only) ---------------
# On the vault path the Secret is authored by VSO, so the values are read back
# from the materialised Secret after it syncs (see [2/6]) — there is no
# provider-values file to read.
if [ "$SECRET_SOURCE" = file ]; then
  read_val() { python3 -c "import sys,yaml; print(yaml.safe_load(open('$OBSERVABILITY_VALUES')).get('$1',''))"; }
  GRAFANA_PASSWORD="$(read_val grafanaAdminPassword)"
  OPENSEARCH_PASSWORD="$(read_val opensearchAdminPassword)"
  [ -n "$GRAFANA_PASSWORD" ]    || { echo "❌ grafanaAdminPassword empty in $OBSERVABILITY_VALUES"; exit 2; }
  [ -n "$OPENSEARCH_PASSWORD" ] || { echo "❌ opensearchAdminPassword empty in $OBSERVABILITY_VALUES"; exit 2; }
else
  # VSO's CRDs must be registered before we can apply its resources. Checking here
  # turns "no matches for kind VaultStaticSecret" into an actionable instruction.
  kubectl get crd vaultstaticsecrets.secrets.hashicorp.com >/dev/null 2>&1 || {
    echo "❌ VaultStaticSecret CRD not registered on ${CLUSTER}."
    echo "   Run: make install-vso CLUSTER=${CLUSTER}"
    exit 2
  }
fi

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
if [ "$SECRET_SOURCE" = file ]; then
echo "  [2/6] Secret ${SECRET_NAME} from provider-values (offline profile)"
_old_umask="$(umask)"; umask 077
_cred_dir="$(mktemp -d)"
printf '%s' "admin"                 > "$_cred_dir/grafana-admin-user"
printf '%s' "$GRAFANA_PASSWORD"     > "$_cred_dir/grafana-admin-password"
printf '%s' "$OPENSEARCH_PASSWORD"  > "$_cred_dir/opensearch-admin-password"
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-file=grafana-admin-user="$_cred_dir/grafana-admin-user" \
  --from-file=grafana-admin-password="$_cred_dir/grafana-admin-password" \
  --from-file=opensearch-admin-password="$_cred_dir/opensearch-admin-password" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf -- "$_cred_dir"; _cred_dir=""; umask "$_old_umask"
else
# Datacenter profile: VSO authors the Secret from Vault. The template is owned by
# the capability repo (ok-cluster installs, does not own) and rendered per cluster.
# The explicit envsubst variable list is required, not stylistic: a bare envsubst
# substitutes every ${VAR} in the input and would blank unrelated placeholders.
# VAULT_ROLE may be unused by an older template — a listed-but-absent variable is a
# harmless no-op, so this works against both template revisions.
echo "  [2/6] Secret ${SECRET_NAME} via VaultStaticSecret (VSO, datacenter profile)"
echo "        vault=${VAULT_ADDR} mount=kubernetes/${CLUSTER} kv=${KV_MOUNT}/${KV_PATH}"
CLUSTER="$CLUSTER" \
OBS_NAMESPACE="$NAMESPACE" \
SECRET_NAME="$SECRET_NAME" \
VAULT_ADDR="${VAULT_ADDR}" \
VAULT_TLS_SERVER_NAME="${VAULT_TLS_SERVER_NAME}" \
VAULT_CA_SECRET="${VAULT_CA_SECRET}" \
KV_MOUNT="${KV_MOUNT}" \
KV_PATH="${KV_PATH}" \
VAULT_ROLE="${VAULT_ROLE:-$VSO_SERVICE_ACCOUNT}" \
VSO_SERVICE_ACCOUNT="${VSO_SERVICE_ACCOUNT}" \
REFRESH_AFTER="${REFRESH_AFTER}" \
  envsubst '$CLUSTER $OBS_NAMESPACE $SECRET_NAME $VAULT_ADDR $VAULT_TLS_SERVER_NAME $VAULT_CA_SECRET $KV_MOUNT $KV_PATH $VAULT_ROLE $VSO_SERVICE_ACCOUNT $REFRESH_AFTER' \
  < "$VSS_TEMPLATE" | kubectl apply -f -

# ORDERING IS THE DELIVERABLE (ADR-025 criterion 7): the Secret must exist before
# the Helm release, because OpenSearch 2.12+ refuses to start without the admin
# password at first boot. Waiting here — not after helm — is what makes this
# fresh-install ordering rather than a migration.
echo "        waiting for VaultStaticSecret to report SecretSynced (before helm)"
kubectl -n "$NAMESPACE" wait --for=condition=SecretSynced \
  "vaultstaticsecret/${SECRET_NAME}" --timeout="${VSS_SYNC_TIMEOUT:-120}s" || {
    echo "❌ VaultStaticSecret did not sync. Common causes:"
    echo "   - Vault auth mount kubernetes/${CLUSTER} or role ${VAULT_ROLE:-$VSO_SERVICE_ACCOUNT} missing (VaultConfig XR)"
    echo "   - ServiceAccount ${VSO_SERVICE_ACCOUNT} absent in ${NAMESPACE}"
    echo "   - CA secret ${VAULT_CA_SECRET} absent in ${NAMESPACE}, or ${VAULT_ADDR} unreachable"
    echo "   - no credentials at ${KV_MOUNT}/${KV_PATH}"
    kubectl -n "$NAMESPACE" get vaultstaticsecret "${SECRET_NAME}" -o wide 2>/dev/null || true
    exit 1
  }

# The gate needs the admin passwords to query Grafana and OpenSearch. On this path
# Vault is the source of truth, so read them back from the materialised Secret.
# Captured into shell variables — never argv, never echoed (ADR-024 invariant).
GRAFANA_PASSWORD="$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o jsonpath='{.data.grafana-admin-password}' | base64 -d)"
OPENSEARCH_PASSWORD="$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o jsonpath='{.data.opensearch-admin-password}' | base64 -d)"
[ -n "$GRAFANA_PASSWORD" ] && [ -n "$OPENSEARCH_PASSWORD" ] || {
  echo "❌ Secret ${SECRET_NAME} synced but a password key is empty — check the Vault KV payload keys"
  exit 1
}
echo "        ✅ ${SECRET_NAME} materialised by VSO"
fi

# --- [3/6] helm dependency build + install ---------------------------------
# Pinned mode built dependencies before publishing the cache, so repeated runs
# do not download charts again. Worktree mode retains the immediate-edit workflow
# and therefore rebuilds dependencies from that mutable checkout each run.
echo "  [3/6] helm dependencies + install"
# The profile is a TWO-level umbrella (profile -> implementations/* -> upstream),
# and `helm dependency build` resolves only ONE level: building just the profile
# packages the wrappers with an empty charts/, which renders to NOTHING and would
# install an empty release. The capability repo owns how its charts are built, so
# use its `deps` target; fall back to the old single-level build for checkouts
# that predate it.
if [ "$OBSERVABILITY_MODE" = pinned ]; then
  echo "    using dependencies from ${OBSERVABILITY_CACHE_RESULT} SHA-keyed cache"
else
  build_observability_deps "$OK_OBSERVABILITY_PATH"
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
