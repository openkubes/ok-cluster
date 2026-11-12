#!/usr/bin/env bash
# Manual disposable-cluster conformance. Never invoke from an installation workflow.
set -euo pipefail

readonly CLUSTER=ok226-admission-conformance
readonly CONTEXT="kind-${CLUSTER}"
readonly NS=openkubes-authority
readonly POLICY=deploy/ok226-authority-freeze-candidate.yaml

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
log() { printf 'OK226: %s\n' "$*"; }
command -v kind >/dev/null || fail 'kind is required'
command -v kubectl >/dev/null || fail 'kubectl is required'
[[ ${OK226_ALLOW_DISPOSABLE_KIND:-} == 'yes' ]] || fail 'Set OK226_ALLOW_DISPOSABLE_KIND=yes to create an isolated Kind cluster'
[[ -r "$POLICY" ]] || fail 'Run from the ok-cluster repository root'
if kind get clusters | grep -Fxq "$CLUSTER"; then
  fail "Kind cluster $CLUSTER already exists; refusing to use or delete it"
fi

created=0
cleanup() {
  if [[ "$created" == 1 ]]; then
    log 'Removing disposable Kind cluster created by this script'
    kind delete cluster --name "$CLUSTER" || printf 'WARNING: manual Kind cleanup required\n' >&2
  fi
}
trap cleanup EXIT
log 'Creating a new disposable Kind cluster; no existing context is used'
kind create cluster --name "$CLUSTER" --wait 120s
created=1
k() { kubectl --context "$CONTEXT" --request-timeout=15s "$@"; }

k get nodes >/dev/null || fail 'Fresh cluster API unavailable'
# Test-only identity created before the freeze; bootstrap ownership is NOT certified.
k create namespace "$NS"
k -n "$NS" create configmap ok226-test-fence --from-literal=state=ACTIVE
k -n "$NS" create configmap ok226-test-record --from-literal=state=ORIGINAL
k -n "$NS" create serviceaccount ok226-test-executor
k -n "$NS" create serviceaccount ok226-test-observer

ns_uid=$(k get namespace "$NS" -o jsonpath='{.metadata.uid}')
fence_uid=$(k -n "$NS" get configmap ok226-test-fence -o jsonpath='{.metadata.uid}')
record_uid=$(k -n "$NS" get configmap ok226-test-record -o jsonpath='{.metadata.uid}')
[[ -n "$ns_uid" && -n "$fence_uid" && -n "$record_uid" ]] || fail 'Precondition UIDs are missing'

log 'Installing deny-only candidate on newly created disposable cluster'
k apply -f "$POLICY"
k get validatingadmissionpolicy ok226-authority-record-freeze >/dev/null
k get validatingadmissionpolicybinding ok226-authority-record-freeze >/dev/null
k get validatingadmissionpolicy ok226-authority-namespace-freeze >/dev/null
k get validatingadmissionpolicybinding ok226-authority-namespace-freeze >/dev/null

# A Forbidden RBAC error does NOT demonstrate admission. Require exact policy marker.
expect_admission_denied() {
  local description="$1" policy_name="$2" out code
  shift 2
  set +e
  out=$(k "$@" 2>&1)
  code=$?
  set -e
  if [[ $code -eq 0 ]]; then fail "$description unexpectedly succeeded"; fi
  if [[ "$out" != *"$policy_name"* ]]; then
    printf 'Unexpected rejection for %s: %s\n' "$description" "$out" >&2
    fail 'Not proven to be rejected by expected admission policy'
  fi
  log "PASS admission denies $description"
}

expect_admission_denied 'new Authority ConfigMap' ok226-authority-record-freeze \
  -n "$NS" create configmap ok226-test-new --from-literal=state=UNAUTHORIZED
expect_admission_denied 'update Authority record' ok226-authority-record-freeze \
  -n "$NS" patch configmap ok226-test-record --type=merge -p '{"data":{"state":"TAMPERED"}}'
expect_admission_denied 'delete Authority record' ok226-authority-record-freeze \
  -n "$NS" delete configmap ok226-test-record --wait=false
expect_admission_denied 'delete Fence' ok226-authority-record-freeze \
  -n "$NS" delete configmap ok226-test-fence --wait=false
expect_admission_denied 'modify Authority namespace' ok226-authority-namespace-freeze \
  label namespace "$NS" ok226-test-probe=modified
expect_admission_denied 'delete Authority namespace' ok226-authority-namespace-freeze \
  delete namespace "$NS" --wait=false

# RBAC assertions are separate from admission assertions.
for actor in ok226-test-executor ok226-test-observer; do
  for verb in create update patch delete; do
    allowed=$(k auth can-i "$verb" configmaps -n "$NS" \
      --as="system:serviceaccount:${NS}:${actor}" 2>/dev/null || true)
    [[ "$allowed" == no ]] || fail "${actor} unexpectedly can ${verb} ConfigMaps"
  done
  log "PASS RBAC denies ${actor} ConfigMap mutations"
done

[[ $(k get namespace "$NS" -o jsonpath='{.metadata.uid}') == "$ns_uid" ]] || fail 'Authority namespace UID drift'
[[ $(k -n "$NS" get configmap ok226-test-fence -o jsonpath='{.metadata.uid}') == "$fence_uid" ]] || fail 'Fence UID drift'
[[ $(k -n "$NS" get configmap ok226-test-record -o jsonpath='{.metadata.uid}') == "$record_uid" ]] || fail 'Record UID drift'
[[ $(k -n "$NS" get configmap ok226-test-record -o jsonpath='{.data.state}') == ORIGINAL ]] || fail 'Record was modified'
if k -n "$NS" get configmap ok226-test-new >/dev/null 2>&1; then fail 'Unapproved object was created'; fi
log 'PASS identity and state unchanged; all scoped negative tests passed'
log 'Note: privileged admission-policy removal, rollback and cluster-admin bypass are NOT certified'
