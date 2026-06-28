#!/usr/bin/env bash
# upgrade-cluster.sh — Blue/Green Kubernetes version upgrade for OpenKubes clusters
# Strategy: deploy new cluster, migrate workloads, teardown old cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTERS_DIR="${SCRIPT_DIR}/ok-workload-clusters"

CLUSTER="${CLUSTER:-}"
K8S_VERSION="${K8S_VERSION:-}"
TALOS_VERSION="${TALOS_VERSION:-}"
DRY_RUN="${DRY_RUN:-false}"

if [[ -z "$CLUSTER" || -z "$K8S_VERSION" ]]; then
  echo "Usage: make upgrade CLUSTER=ok3 K8S_VERSION=v1.35.0 [TALOS_VERSION=v1.13.4]"
  exit 1
fi

CLUSTER_DIR="${CLUSTERS_DIR}/${CLUSTER}"
CFG="${CLUSTER_DIR}/cluster-config.yaml"

if [[ ! -f "$CFG" ]]; then
  echo "ERROR: No cluster-config.yaml for '${CLUSTER}'"
  exit 1
fi

CLUSTER_TYPE=$(python3 -c "import yaml,sys; c=yaml.safe_load(open('${CFG}')); print(c.get('type','ubuntu'))")
BLUE_CLUSTER="${CLUSTER}"
GREEN_CLUSTER="${CLUSTER}-green"

echo "═══════════════════════════════════════════════════════════"
echo "  Blue/Green Upgrade: ${BLUE_CLUSTER} → ${GREEN_CLUSTER}"
echo "  K8s: ${K8S_VERSION}$([ -n "${TALOS_VERSION}" ] && echo "  Talos: ${TALOS_VERSION}")"
echo "  Dry-run: ${DRY_RUN}"
echo "═══════════════════════════════════════════════════════════"

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  [DRY-RUN] $*"
  else
    echo "  ▶ $*"
    eval "$@"
  fi
}

# ── Phase 1: Provision green cluster ─────────────────────────────────────────
echo ""
echo "── Phase 1: Provision green cluster ──"

# Clone config, bump versions
python3 - <<PYEOF
import yaml, copy
with open('${CFG}') as f:
    cfg = yaml.safe_load(f)
green = copy.deepcopy(cfg)
green['name'] = '${GREEN_CLUSTER}'
green['versions']['kubernetes'] = '${K8S_VERSION}'
$(if [[ -n "$TALOS_VERSION" ]]; then echo "green['versions']['talos'] = '${TALOS_VERSION}'"; fi)
# Reset network to auto so render.py allocates new IPs/CIDRs
green['network'] = {'endpoint': 'auto', 'podCIDR': 'auto', 'serviceCIDR': 'auto'}
import os, pathlib
gdir = pathlib.Path('${CLUSTERS_DIR}/${GREEN_CLUSTER}')
gdir.mkdir(parents=True, exist_ok=True)
with open(gdir / 'cluster-config.yaml', 'w') as f:
    yaml.dump(green, f, default_flow_style=False, sort_keys=False)
print(f"  ✔ Wrote {gdir}/cluster-config.yaml")
PYEOF

run "python3 '${SCRIPT_DIR}/render.py' render --cluster '${GREEN_CLUSTER}'"

if [[ "$CLUSTER_TYPE" == "talos" ]]; then
  run "make bootstrap CLUSTER='${GREEN_CLUSTER}'"
else
  run "make install CLUSTER='${GREEN_CLUSTER}'"
fi

# ── Phase 2: Wait for green to be Ready ──────────────────────────────────────
echo ""
echo "── Phase 2: Wait for green cluster Ready ──"
if [[ "$DRY_RUN" != "true" ]]; then
  echo "  Waiting for KubeVirtCluster '${GREEN_CLUSTER}' to be provisioned..."
  kubectl --kubeconfig ~/.kube/ok-mgmt.yaml \
    wait cluster/"${GREEN_CLUSTER}" \
    --for=condition=Ready \
    --timeout=15m \
    -n default
fi

# ── Phase 3: Workload migration ───────────────────────────────────────────────
echo ""
echo "── Phase 3: Workload migration ──"
echo ""
echo "  Stateless workloads (GitOps):"
echo "  → Update ArgoCD/Flux target cluster to '${GREEN_CLUSTER}' and sync."
echo "  → Or: kubectl --context=${GREEN_CLUSTER} apply -k <your-app-dir>"
echo ""
echo "  Stateful workloads (app-native):"
echo "  → Follow per-app backup/restore runbook before proceeding."
echo ""
read -rp "  Confirm workloads migrated to ${GREEN_CLUSTER}? [y/N] " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
  echo "Upgrade paused. Green cluster '${GREEN_CLUSTER}' is still running."
  echo "Re-run with: make upgrade CLUSTER=${CLUSTER} K8S_VERSION=${K8S_VERSION}"
  exit 0
fi

# ── Phase 4: Swap blue → green ────────────────────────────────────────────────
echo ""
echo "── Phase 4: Promote green → canonical name ──"

# Persist new version in blue config for record
run "python3 - <<'PYEOF'
import yaml
with open('${CFG}') as f:
    cfg = yaml.safe_load(f)
cfg['versions']['kubernetes'] = '${K8S_VERSION}'
$(if [[ -n "$TALOS_VERSION" ]]; then echo "cfg['versions']['talos'] = '${TALOS_VERSION}'"; fi)
with open('${CFG}', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
PYEOF"

# ── Phase 5: Teardown blue ────────────────────────────────────────────────────
echo ""
echo "── Phase 5: Teardown old blue cluster ──"
if [[ "$CLUSTER_TYPE" == "talos" ]]; then
  run "make teardown CLUSTER='${BLUE_CLUSTER}'"
else
  run "make clean CLUSTER='${BLUE_CLUSTER}'"
fi

# Rename green → blue (manifest level)
run "mv '${CLUSTERS_DIR}/${GREEN_CLUSTER}' '${CLUSTERS_DIR}/${BLUE_CLUSTER}-upgraded-$(date +%Y%m%d)'"

echo ""
echo "✅ Upgrade complete: ${CLUSTER} is now running ${K8S_VERSION}"
echo "   Green cluster manifests archived at: ${CLUSTER}-upgraded-$(date +%Y%m%d)"
