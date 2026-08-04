#!/usr/bin/env bash
# new-cluster.sh — scaffold a new cluster-config.yaml and render initial manifests
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ok-linux is the source of truth for these defaults.
# See: https://github.com/openkubes/ok-linux/blob/main/profiles/kubevirt/profile.yaml
# Verified against the running ok1-talos cluster (ok-linux v0.1.0).
# Keep these in sync with render.py's OK_LINUX_DEFAULT_* constants.
OK_LINUX_DEFAULT_PROFILE="kubevirt"
OK_LINUX_DEFAULT_SCHEMATIC_ID="ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515"
OK_LINUX_DEFAULT_TALOS_VERSION="v1.9.6"
OK_LINUX_PATH="${OK_LINUX_PATH:-${SCRIPT_DIR}/../ok-linux}"

CLUSTER="${CLUSTER:-}"
TYPE="${TYPE:-ubuntu}"
HA="${HA:-false}"
WORKERS="${WORKERS:-1}"
K8S_VERSION="${K8S_VERSION:-v1.34.1}"
TALOS_VERSION="${TALOS_VERSION:-${OK_LINUX_DEFAULT_TALOS_VERSION}}"
OS_PROFILE="${OS_PROFILE:-${OK_LINUX_DEFAULT_PROFILE}}"
OS_SCHEMATIC_ID="${OS_SCHEMATIC_ID:-${OK_LINUX_DEFAULT_SCHEMATIC_ID}}"
PROVIDER="${PROVIDER:-kubevirt}"
ARCHITECTURE="${ARCHITECTURE:-amd64}"
CP_CORES="${CP_CORES:-2}"
CP_MEMORY="${CP_MEMORY:-4Gi}"
if [[ "$TYPE" == "flatcar" ]]; then
  CP_DISK="${CP_DISK:-50Gi}"
else
  CP_DISK="${CP_DISK:-20Gi}"
fi
WORKER_CORES="${WORKER_CORES:-2}"
WORKER_MEMORY="${WORKER_MEMORY:-4Gi}"
WORKER_DISK="${WORKER_DISK:-}"
if [[ -z "$WORKER_DISK" ]]; then
  if [[ "$TYPE" == "flatcar" ]]; then
    WORKER_DISK="50Gi"
  else
    WORKER_DISK="15Gi"
  fi
fi
NODE_SELECTOR="${NODE_SELECTOR:-${NODE:-}}"   # OK-82: NODE= accepted as alias
SCHEDULING_PROFILE="${SCHEDULING_PROFILE:-}"
START_IP="${START_IP:-}"   # OK-83: optional override for MetalLB IP allocation
if [[ "$TYPE" == "flatcar" ]]; then
  GOLDEN_IMAGE_STORAGE_CLASS="${GOLDEN_IMAGE_STORAGE_CLASS:-ok-storage-block}"
else
  GOLDEN_IMAGE_STORAGE_CLASS="${GOLDEN_IMAGE_STORAGE_CLASS:-local-path}"
fi

if [[ -z "$CLUSTER" ]]; then
  echo "ERROR: CLUSTER is required."
  exit 1
fi

# The OK-136 Talos KubeVirt path uses reviewed provider profiles rather than a
# free-form node selector. Existing ok-infra behavior remains the default.
if [[ "$TYPE" == "talos" ]]; then
  if [[ -z "$SCHEDULING_PROFILE" ]]; then
    if [[ -n "$NODE_SELECTOR" && "$NODE_SELECTOR" != "ok-infra" ]]; then
      echo "ERROR: Talos NODE_SELECTOR=${NODE_SELECTOR} is not a reviewed implicit profile."
      echo "       Select an explicit profile, for example SCHEDULING_PROFILE=ok-gpu."
      exit 1
    fi
    SCHEDULING_PROFILE="ok-infra"
  fi
  if [[ "$SCHEDULING_PROFILE" != "ok-infra" && "$SCHEDULING_PROFILE" != "ok-gpu" ]]; then
    echo "ERROR: unsupported Talos SCHEDULING_PROFILE=${SCHEDULING_PROFILE}"
    exit 1
  fi
  if [[ -n "$NODE_SELECTOR" && "$NODE_SELECTOR" != "$SCHEDULING_PROFILE" ]]; then
    echo "ERROR: SCHEDULING_PROFILE=${SCHEDULING_PROFILE} requires NODE_SELECTOR=${SCHEDULING_PROFILE}"
    exit 1
  fi
  NODE_SELECTOR="$SCHEDULING_PROFILE"
  echo "  INFO: Talos KubeVirt provider profile ${SCHEDULING_PROFILE} uses ok-storage-block"
elif [[ -n "$SCHEDULING_PROFILE" ]]; then
  echo "ERROR: SCHEDULING_PROFILE is currently supported only for ordinary Talos KubeVirt clusters"
  exit 1
fi
if [[ "$TYPE" == "talos-mgmt" && -z "$NODE_SELECTOR" ]]; then
  NODE_SELECTOR="ok-gpu"
  echo "  INFO: Talos management path defaults to ok-gpu"
fi
if [[ "$TYPE" == "flatcar" && -z "$NODE_SELECTOR" ]]; then
  NODE_SELECTOR="ok-infra"
  echo "  INFO: constrained Flatcar profile pins KubeVirt scheduling to ok-infra"
fi

CP_REPLICAS=1
[[ "$HA" == "true" ]] && CP_REPLICAS=3

if [[ "$TYPE" == "flatcar" ]]; then
  python3 "${SCRIPT_DIR}/profile_resolvers/flatcar.py" preflight-new \
    --ok-linux-path "${OK_LINUX_PATH}" \
    --cluster "${CLUSTER}" \
    --provider "${PROVIDER}" \
    --architecture "${ARCHITECTURE}" \
    --kubernetes-version "${K8S_VERSION}" \
    --control-plane-replicas "${CP_REPLICAS}" \
    --control-plane-cores "${CP_CORES}" \
    --control-plane-memory "${CP_MEMORY}" \
    --control-plane-disk "${CP_DISK}" \
    --worker-replicas "${WORKERS}" \
    --worker-cores "${WORKER_CORES}" \
    --worker-memory "${WORKER_MEMORY}" \
    --worker-disk "${WORKER_DISK}" \
    --node-selector "${NODE_SELECTOR}" \
    --golden-image-storage-class "${GOLDEN_IMAGE_STORAGE_CLASS}"
fi

CLUSTER_DIR="${SCRIPT_DIR}/${CLUSTER}"
CFG="${CLUSTER_DIR}/cluster-config.yaml"

if [[ -d "$CLUSTER_DIR" ]]; then
  echo "ERROR: Cluster '${CLUSTER}' already exists. Use 'make clean CLUSTER=${CLUSTER}' first."
  exit 1
fi

# OK-102 follow-up: the check above only looks at the local render directory.
# On a checkout that never received a previous 'make e2e' post-commit push
# (or after a fresh clone), the directory can be absent while the Cluster
# object still exists live in the API -- scaffolding a new one in that case
# would re-render fresh values (e.g. a new MetalLB IP via render.py next-ip)
# and re-apply them against an already-running cluster. Refuse in that case.
INFRA_KUBECONFIG="${INFRA_KUBECONFIG:-$HOME/.kube/ok-infra.yaml}"
if command -v kubectl >/dev/null 2>&1 && [[ -f "$INFRA_KUBECONFIG" ]]; then
  if kubectl --kubeconfig "$INFRA_KUBECONFIG" get cluster "${CLUSTER}" -n "${CLUSTER}" >/dev/null 2>&1; then
    echo "ERROR: Cluster '${CLUSTER}' already exists in the API (namespace ${CLUSTER} on"
    echo "       $INFRA_KUBECONFIG), even though no local render directory was found."
    echo "       This usually means another checkout rendered it and its manifests were"
    echo "       never pushed/committed here. Refusing to scaffold a new one to avoid"
    echo "       re-rendering colliding values (e.g. a different MetalLB IP) against a"
    echo "       live cluster."
    echo "       Fix: pull/sync the missing render directory from wherever it was"
    echo "       created, or run 'make teardown CLUSTER=${CLUSTER}' first if it should"
    echo "       genuinely be destroyed and recreated."
    exit 1
  fi
else
  echo "  WARN: kubectl or $INFRA_KUBECONFIG not available -- skipping live-cluster existence check."
fi

mkdir -p "$CLUSTER_DIR"

# OK-83: next-ip is MetalLB-aware (queries live LB allocations on the mgmt
# cluster). Warnings on stderr stay visible; hard errors abort the scaffold.
NEXT_IP=$(START_IP="${START_IP}" python3 "${SCRIPT_DIR}/render.py" next-ip --cluster "${CLUSTER}")
NODE_DISPLAY="${NODE_SELECTOR:-any}"

echo "Creating cluster: ${CLUSTER}"
if [[ "$TYPE" == talos* ]]; then
  echo "  type=${TYPE}  HA=${HA}  cp=${CP_REPLICAS}  workers=${WORKERS}  next-ip=${NEXT_IP}  node=${NODE_DISPLAY}  os-profile=${OS_PROFILE}"
elif [[ "$TYPE" == "flatcar" ]]; then
  echo "  type=flatcar  provider=${PROVIDER}  arch=${ARCHITECTURE}  cp=1  workers=1  next-ip=${NEXT_IP}  node=${NODE_DISPLAY}  profile=flatcar-kubevirt"
else
  echo "  type=${TYPE}  HA=${HA}  cp=${CP_REPLICAS}  workers=${WORKERS}  next-ip=${NEXT_IP}  node=${NODE_DISPLAY}"
fi

cat > "$CFG" <<YAML
# OpenKubes cluster config — generated by new-cluster.sh
name: ${CLUSTER}
type: ${TYPE}
$(if [[ "$TYPE" == "flatcar" ]]; then echo "provider: ${PROVIDER}"; fi)

controlPlane:
  replicas: ${CP_REPLICAS}
  cores: ${CP_CORES}
  memory: ${CP_MEMORY}
$(if [[ "$TYPE" == "flatcar" || "$TYPE" == "talos" ]]; then echo "  disk: ${CP_DISK}"; fi)

workers:
  replicas: ${WORKERS}
  cores: ${WORKER_CORES}
  memory: ${WORKER_MEMORY}
  disk: ${WORKER_DISK}

versions:
  kubernetes: ${K8S_VERSION}
$(if [[ "$TYPE" == talos* ]]; then echo "  talos: ${TALOS_VERSION}"; fi)
$(if [[ "$TYPE" == talos* ]]; then cat <<OSBLOCK

# OS layer — owned by ok-linux (github.com/openkubes/ok-linux)
# schematic_id is verified via: make build PROFILE=${OS_PROFILE} (in ok-linux repo)
os:
  distribution: ok-linux
  profile: ${OS_PROFILE}
  schematic_id: ${OS_SCHEMATIC_ID}
OSBLOCK
fi)
$(if [[ "$TYPE" == "talos" ]]; then cat <<TALOSPROVIDERBLOCK

# Reviewed KubeVirt scheduling/storage profile — owned by ok-linux.
providerProfile:
  name: ${SCHEDULING_PROFILE}
TALOSPROVIDERBLOCK
fi)
$(if [[ "$TYPE" == "flatcar" ]]; then cat <<FLATCARBLOCK

# Constrained OS input — fully materialized and validated by the isolated
# Flatcar resolver from ok-linux/profiles/flatcar-kubevirt/profile.yaml.
os:
  profile: flatcar-kubevirt
  architecture: ${ARCHITECTURE}

# The Flatcar profile owns the supported clone-target storage contract;
# ok-cluster implements it with KubeVirt/CDI.
providerProfile:
  goldenImageStorageClass: ${GOLDEN_IMAGE_STORAGE_CLASS}
FLATCARBLOCK
fi)

network:
  endpoint: auto
  podCIDR: auto
  serviceCIDR: auto

nodeSelector: "${NODE_SELECTOR}"

upgrade:
  strategy: blue-green
  workloadMigration:
    stateless: gitops
    stateful: app-native
YAML

echo "  ✔ ${CFG}"
echo ""
echo "Rendering manifests..."
START_IP="${START_IP}" python3 "${SCRIPT_DIR}/render.py" render --cluster "${CLUSTER}"

echo ""
echo "Done. Next steps:"
if [[ "$TYPE" == talos* ]]; then
  echo "  make bootstrap CLUSTER=${CLUSTER}"
elif [[ "$TYPE" == "flatcar" ]]; then
  echo "  make flatcar-preflight CLUSTER=${CLUSTER} FLATCAR_INFRA_KUBECONFIG=<path> FLATCAR_CILIUM_CHART=<path>"
  echo "  make install-flatcar CLUSTER=${CLUSTER} FLATCAR_INFRA_KUBECONFIG=<path> FLATCAR_CILIUM_CHART=<path> FLATCAR_APPLY=yes"
else
  echo "  make install CLUSTER=${CLUSTER}"
fi
