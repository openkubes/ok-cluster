#!/usr/bin/env bash
# new-cluster.sh — scaffold a new cluster-config.yaml and render initial manifests
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_DIR=""

cleanup_ok76_staging() {
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
    rm -rf "$STAGING_DIR"
  fi
}

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
OK76_REQUIRE_LIVE_METALLB_INVENTORY="${OK76_REQUIRE_LIVE_METALLB_INVENTORY:-false}"
START_IP="${START_IP:-}"   # OK-83: optional override for MetalLB IP allocation
REGISTRY_TRUST="${REGISTRY_TRUST:-false}"
REGISTRY_HOST="${REGISTRY_HOST:-registry.ok-shared.internal}"
REGISTRY_CA_SECRET_NAMESPACE="${REGISTRY_CA_SECRET_NAMESPACE:-cert-manager}"
REGISTRY_CA_SECRET_NAME="${REGISTRY_CA_SECRET_NAME:-ok-shared-internal-ca}"
REGISTRY_CA_SECRET_KEY="${REGISTRY_CA_SECRET_KEY:-ca.crt}"
REGISTRY_SERVICE_NAMESPACE="${REGISTRY_SERVICE_NAMESPACE:-ok-shared}"
REGISTRY_SERVICE_NAME="${REGISTRY_SERVICE_NAME:-ok-shared-ingress}"
REGISTRY_TALOSCONFIG_SECRET_NAMESPACE="${REGISTRY_TALOSCONFIG_SECRET_NAMESPACE:-}"
REGISTRY_TALOSCONFIG_SECRET_NAME="${REGISTRY_TALOSCONFIG_SECRET_NAME:-}"
REGISTRY_TALOSCONFIG_SECRET_KEY="${REGISTRY_TALOSCONFIG_SECRET_KEY:-talosconfig}"
if [[ "$TYPE" == "flatcar" ]]; then
  GOLDEN_IMAGE_STORAGE_CLASS="${GOLDEN_IMAGE_STORAGE_CLASS:-ok-storage-block}"
else
  GOLDEN_IMAGE_STORAGE_CLASS="${GOLDEN_IMAGE_STORAGE_CLASS:-local-path}"
fi

if [[ -z "$CLUSTER" ]]; then
  echo "ERROR: CLUSTER is required."
  exit 1
fi

if [[ "$REGISTRY_TRUST" != "false" && "$REGISTRY_TRUST" != "true" ]]; then
  echo "ERROR: REGISTRY_TRUST must be exactly true or false"
  exit 1
fi
if [[ "$REGISTRY_TRUST" == "true" ]]; then
  if [[ "$TYPE" != "talos" ]]; then
    echo "ERROR: REGISTRY_TRUST=true is supported only for TYPE=talos"
    exit 1
  fi
  if [[ "$REGISTRY_HOST" != "registry.ok-shared.internal" ]]; then
    echo "ERROR: REGISTRY_HOST must be registry.ok-shared.internal"
    exit 1
  fi
  REGISTRY_TALOSCONFIG_SECRET_NAMESPACE="${REGISTRY_TALOSCONFIG_SECRET_NAMESPACE:-${CLUSTER}}"
  REGISTRY_TALOSCONFIG_SECRET_NAME="${REGISTRY_TALOSCONFIG_SECRET_NAME:-${CLUSTER}-talosconfig}"
  for value in REGISTRY_CA_SECRET_NAMESPACE REGISTRY_CA_SECRET_NAME \
    REGISTRY_SERVICE_NAMESPACE REGISTRY_SERVICE_NAME; do
    if [[ -z "${!value}" ]]; then
      echo "ERROR: ${value} is required when REGISTRY_TRUST=true"
      exit 1
    fi
  done
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
  if [[ "$SCHEDULING_PROFILE" != "ok-infra" && "$SCHEDULING_PROFILE" != "ok-gpu" && "$SCHEDULING_PROFILE" != "ok-gpu-single-replica" ]]; then
    echo "ERROR: unsupported Talos SCHEDULING_PROFILE=${SCHEDULING_PROFILE}"
    exit 1
  fi
  PROFILE_NODE_SELECTOR="$SCHEDULING_PROFILE"
  PROFILE_STORAGE_CLASS="ok-storage-block"
  if [[ "$SCHEDULING_PROFILE" == "ok-gpu-single-replica" ]]; then
    PROFILE_NODE_SELECTOR="ok-gpu"
    PROFILE_STORAGE_CLASS="ok-storage-block-gpu-test"
  fi
  if [[ -n "$NODE_SELECTOR" && "$NODE_SELECTOR" != "$PROFILE_NODE_SELECTOR" ]]; then
    echo "ERROR: SCHEDULING_PROFILE=${SCHEDULING_PROFILE} requires NODE_SELECTOR=${PROFILE_NODE_SELECTOR}"
    exit 1
  fi
  NODE_SELECTOR="$PROFILE_NODE_SELECTOR"
  echo "  INFO: Talos KubeVirt provider profile ${SCHEDULING_PROFILE} uses ${PROFILE_STORAGE_CLASS}"
elif [[ -n "$SCHEDULING_PROFILE" ]]; then
  echo "ERROR: SCHEDULING_PROFILE is currently supported only for ordinary Talos KubeVirt clusters"
  exit 1
fi
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" != "true" && "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" != "false" ]]; then
  echo "ERROR: OK76_REQUIRE_LIVE_METALLB_INVENTORY must be exactly true or false"
  exit 1
fi
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" && \
      ( "$TYPE" != "talos" || "$PROVIDER" != "kubevirt" || "$SCHEDULING_PROFILE" != "ok-infra" ) ]]; then
  echo "ERROR: live allocation inventory enforcement is supported only for the Talos/KubeVirt ok-infra reference profile"
  exit 1
fi
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" && \
      ( -z "${INFRA_KUBECONFIG:-}" || -z "${OKB_KUBECONFIG:-}" || \
        "$INFRA_KUBECONFIG" != "$OKB_KUBECONFIG" ) ]]; then
  echo "ERROR: strict allocation inventory requires the same explicit management kubeconfig for cluster and Service checks."
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
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" ]]; then
  for STALE_STAGING_DIR in "${SCRIPT_DIR}"/.ok76-"${CLUSTER}".*; do
    if [[ -e "$STALE_STAGING_DIR" ]]; then
      echo "ERROR: a prior incomplete OK-76 staging directory exists for '${CLUSTER}'; refusing to retry or remove it automatically."
      exit 1
    fi
  done
fi

# OK-102 follow-up: the check above only looks at the local render directory.
# On a checkout that never received a previous 'make e2e' post-commit push
# (or after a fresh clone), the directory can be absent while the Cluster
# object still exists live in the API -- scaffolding a new one in that case
# would re-render fresh values (e.g. a new MetalLB IP via render.py next-ip)
# and re-apply them against an already-running cluster. Refuse in that case.
INFRA_KUBECONFIG="${INFRA_KUBECONFIG:-$HOME/.kube/ok-infra.yaml}"
if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl is required to verify that Cluster '${CLUSTER}' is absent; refusing to scaffold."
  exit 1
fi
if [[ ! -f "$INFRA_KUBECONFIG" || ! -r "$INFRA_KUBECONFIG" ]]; then
  echo "ERROR: a readable management kubeconfig is required to verify Cluster '${CLUSTER}' is absent; refusing to scaffold."
  exit 1
fi

# --ignore-not-found makes a confirmed 404 the only successful empty result.
# Authentication, authorization, TLS, transport, timeout, missing API/CRD and
# malformed output must all stop before the local cluster directory is made.
if ! EXISTING_CLUSTER=$(kubectl --kubeconfig "$INFRA_KUBECONFIG" \
    get clusters.cluster.x-k8s.io "${CLUSTER}" -n "${CLUSTER}" \
    --ignore-not-found -o name); then
  echo "ERROR: could not verify Cluster '${CLUSTER}' absence through the management API; refusing to scaffold."
  exit 1
fi
if [[ -n "$EXISTING_CLUSTER" ]]; then
  echo "ERROR: Cluster '${CLUSTER}' already exists or the absence check returned ambiguous output; refusing to scaffold."
  exit 1
fi

# OK-83: next-ip is MetalLB-aware (queries live LB allocations on the mgmt
# cluster). Warnings on stderr stay visible; hard errors abort the scaffold.
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" ]]; then
  NEXT_IP=$(START_IP="${START_IP}" python3 "${SCRIPT_DIR}/render.py" next-ip --cluster "${CLUSTER}" --require-live-inventory)
else
  NEXT_IP=$(START_IP="${START_IP}" python3 "${SCRIPT_DIR}/render.py" next-ip --cluster "${CLUSTER}")
fi

# Do not create any cluster scaffold until the required live checks and network
# allocation query have both succeeded.
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" ]]; then
  STAGING_DIR=$(mktemp -d "${SCRIPT_DIR}/.ok76-${CLUSTER}.XXXXXX")
  trap cleanup_ok76_staging EXIT
  CLUSTER_DIR="$STAGING_DIR"
  CFG="${CLUSTER_DIR}/cluster-config.yaml"
else
  mkdir -p "$CLUSTER_DIR"
fi
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
$(if [[ "$TYPE" == "talos" && "$REGISTRY_TRUST" == "true" ]]; then cat <<REGISTRYTRUSTBLOCK

# Opt-in registry trust. CA, resolved address and talosconfig are runtime-only.
registryTrust:
  enabled: true
  host: ${REGISTRY_HOST}
  caSecret:
    namespace: ${REGISTRY_CA_SECRET_NAMESPACE}
    name: ${REGISTRY_CA_SECRET_NAME}
    key: ${REGISTRY_CA_SECRET_KEY}
  address:
    serviceNamespace: ${REGISTRY_SERVICE_NAMESPACE}
    serviceName: ${REGISTRY_SERVICE_NAME}
  talosconfigSecret:
    namespace: ${REGISTRY_TALOSCONFIG_SECRET_NAMESPACE}
    name: ${REGISTRY_TALOSCONFIG_SECRET_NAME}
    key: ${REGISTRY_TALOSCONFIG_SECRET_KEY}
REGISTRYTRUSTBLOCK
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
if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" ]]; then
  START_IP="${START_IP}" python3 "${SCRIPT_DIR}/render.py" render --cluster "${CLUSTER}" --cluster-dir "${CLUSTER_DIR}" --require-live-inventory
else
  START_IP="${START_IP}" python3 "${SCRIPT_DIR}/render.py" render --cluster "${CLUSTER}"
fi

if [[ "$OK76_REQUIRE_LIVE_METALLB_INVENTORY" == "true" ]]; then
  if [[ -e "${SCRIPT_DIR}/${CLUSTER}" ]]; then
    echo "ERROR: Cluster '${CLUSTER}' appeared during scaffolding; preserving existing path and refusing to publish generated files."
    exit 1
  fi
  STAGING_BASENAME="$(basename "$STAGING_DIR")"
  mv -n "$STAGING_DIR" "${SCRIPT_DIR}/${CLUSTER}"
  if [[ -d "${SCRIPT_DIR}/${CLUSTER}/${STAGING_BASENAME}" ]]; then
    # If another writer created the destination between the check and rename,
    # BSD/GNU mv may place our stage inside it. Point the trap only at our
    # uniquely named temporary directory; never remove the competing target.
    STAGING_DIR="${SCRIPT_DIR}/${CLUSTER}/${STAGING_BASENAME}"
    echo "ERROR: Cluster '${CLUSTER}' appeared during scaffold publication; existing path is preserved."
    exit 1
  fi
  if [[ -d "$STAGING_DIR" || ! -f "${SCRIPT_DIR}/${CLUSTER}/cluster-config.yaml" ]]; then
    echo "ERROR: could not atomically publish the completed scaffold; staged files were not applied to infrastructure."
    exit 1
  fi
  STAGING_DIR=""
  trap - EXIT
  CLUSTER_DIR="${SCRIPT_DIR}/${CLUSTER}"
  CFG="${CLUSTER_DIR}/cluster-config.yaml"
fi

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
