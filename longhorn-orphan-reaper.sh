#!/usr/bin/env bash
# longhorn-orphan-reaper.sh — find/clean orphaned Longhorn volumes (OK-118)
#
# Background: ok-storage-block uses reclaimPolicy: Retain by design (protects
# VM disks from accidental data loss on PVC delete — see ok-storage repo,
# ADR-Platform-009). `make teardown` already cleans up Retain-policy PVs and
# their Longhorn volumes for PVCs still present in the torn-down cluster's
# namespace at teardown time. But CDI's own transient import artifacts
# (prime-*/*-scratch PVCs, created during a KubeVirt VM disk import) are
# deleted by CDI itself *before* teardown ever runs — so `make teardown`
# never sees them, and they never get cleaned up.
#
# Left unchecked this accumulates orphaned Longhorn volumes that eat the
# per-disk scheduling budget (storageScheduled vs storageMaximum minus
# storageReserved) until Longhorn can no longer place new replicas AT ALL —
# silently, until some unrelated fresh cluster's VM disk gets stuck
# ImportScheduled/Pending indefinitely. 61 such orphans (some 3+ weeks old,
# several in namespaces that no longer exist at all) were found and cleaned
# up manually on 2026-07-27; this script is the repeatable version of that
# cleanup. See docs/longhorn-orphaned-volumes.md for the full incident + the
# diagnostic this was built from.
#
# "Orphaned" here = a Longhorn Volume with status.state == detached AND
# status.kubernetesStatus.lastPVCRefAt set (its PVC is gone) AND that
# timestamp is older than MIN_AGE_HOURS. The age gate exists because a
# volume can legitimately show this exact signature for a few minutes during
# an in-flight CDI import (its prime/scratch PVC cycles through
# create -> use -> delete) — without it, this script could delete a volume
# that's mid-provisioning for a cluster being built RIGHT NOW.
#
# Usage:
#   ./longhorn-orphan-reaper.sh                      # dry-run, list only
#   CONFIRM=yes ./longhorn-orphan-reaper.sh           # actually delete
#   MIN_AGE_HOURS=1 ./longhorn-orphan-reaper.sh       # tighter/looser age gate
#   EXCLUDE_NAMESPACES=ok-obs-verify,ok-foo ./longhorn-orphan-reaper.sh
#
# Config via env:
#   KUBECONFIG_FILE     default: $HOME/.kube/ok-infra.yaml (the Longhorn host cluster)
#   LONGHORN_NAMESPACE  default: longhorn-system
#   MIN_AGE_HOURS       default: 24 -- only touch orphans older than this
#   EXCLUDE_NAMESPACES  default: "" -- comma-separated namespaces to never touch
#   CONFIRM             default: "" -- must be "yes" to actually delete anything
#
# Dependencies: kubectl, jq, date (GNU or BSD both supported).
set -euo pipefail

KUBECONFIG_FILE="${KUBECONFIG_FILE:-$HOME/.kube/ok-infra.yaml}"
LONGHORN_NAMESPACE="${LONGHORN_NAMESPACE:-longhorn-system}"
MIN_AGE_HOURS="${MIN_AGE_HOURS:-24}"
EXCLUDE_NAMESPACES="${EXCLUDE_NAMESPACES:-}"
CONFIRM="${CONFIRM:-}"

for bin in kubectl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: '$bin' required" >&2; exit 2; }
done

K() { kubectl --kubeconfig "${KUBECONFIG_FILE}" "$@"; }

to_epoch() {
  # Accepts RFC3339 (e.g. 2026-07-27T11:51:17Z). GNU date and BSD date (macOS)
  # take this differently -- try GNU first, fall back to BSD syntax.
  local ts="$1"
  if date -u -d "$ts" +%s 2>/dev/null; then
    return 0
  fi
  date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s 2>/dev/null || echo 0
}

echo "→ Scanning Longhorn volumes in ${LONGHORN_NAMESPACE} (kubeconfig: ${KUBECONFIG_FILE})"
echo "  min age: ${MIN_AGE_HOURS}h · exclude namespaces: [${EXCLUDE_NAMESPACES:-none}] · mode: $( [ "${CONFIRM}" = "yes" ] && echo DELETE || echo DRY-RUN )"
echo

RAW_JSON="$(K -n "${LONGHORN_NAMESPACE}" get volumes.longhorn.io -o json)"

NOW="$(date -u +%s)"
MIN_AGE_SECONDS=$(( MIN_AGE_HOURS * 3600 ))

TOTAL_BYTES=0
KEPT=0
TO_DELETE=()

while IFS=$'\t' read -r NAME NS PVC SIZE LASTREF; do
  [ -z "${NAME}" ] && continue

  if [ -n "${EXCLUDE_NAMESPACES}" ] && [[ ",${EXCLUDE_NAMESPACES}," == *",${NS},"* ]]; then
    echo "  SKIP    ${NAME}  (namespace ${NS} excluded)"
    continue
  fi

  REF_EPOCH="$(to_epoch "${LASTREF}")"
  AGE_SECONDS=$(( NOW - REF_EPOCH ))
  AGE_H=$(( AGE_SECONDS / 3600 ))

  if [ "${REF_EPOCH}" -eq 0 ] || [ "${AGE_SECONDS}" -lt "${MIN_AGE_SECONDS}" ]; then
    echo "  KEEP    ${NAME}  ns=${NS} pvc=${PVC} age=${AGE_H}h (< ${MIN_AGE_HOURS}h threshold)"
    KEPT=$((KEPT + 1))
    continue
  fi

  SIZE_GI=$(( SIZE / 1073741824 ))
  echo "  ORPHAN  ${NAME}  ns=${NS} pvc=${PVC} size=${SIZE_GI}Gi age=${AGE_H}h"
  TOTAL_BYTES=$(( TOTAL_BYTES + SIZE ))
  TO_DELETE+=("${NAME}")
done < <(echo "${RAW_JSON}" | jq -r '
  .items[]
  | select(.status.state=="detached")
  | select(.status.kubernetesStatus.lastPVCRefAt != "" and .status.kubernetesStatus.lastPVCRefAt != null)
  | [.metadata.name, (.status.kubernetesStatus.namespace // "?"), (.status.kubernetesStatus.pvcName // "?"), (.spec.size // 0), .status.kubernetesStatus.lastPVCRefAt]
  | @tsv
')

TOTAL_GI=$(( TOTAL_BYTES / 1073741824 ))
echo
echo "----"
echo "orphans found (>= ${MIN_AGE_HOURS}h old): ${#TO_DELETE[@]}"
echo "phantom scheduling budget: ~${TOTAL_GI}Gi"
echo "kept (too young / excluded): ${KEPT}"

if [ "${#TO_DELETE[@]}" -eq 0 ]; then
  echo "RESULT: nothing to do."
  exit 0
fi

if [ "${CONFIRM}" != "yes" ]; then
  echo
  echo "DRY-RUN only. Re-run with CONFIRM=yes to actually delete the ${#TO_DELETE[@]} volume(s) above."
  exit 0
fi

echo
echo "→ Deleting ${#TO_DELETE[@]} orphaned volume(s)..."
for name in "${TO_DELETE[@]}"; do
  echo "  deleting ${name}"
  K -n "${LONGHORN_NAMESPACE}" delete volumes.longhorn.io "${name}" --ignore-not-found
done
echo "RESULT: reaped ${#TO_DELETE[@]} orphaned Longhorn volume(s), freed ~${TOTAL_GI}Gi of scheduling budget."
