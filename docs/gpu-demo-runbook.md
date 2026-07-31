# Talos and Flatcar GPU demo runbook

This runbook creates disposable 1-control-plane/1-worker clusters on `ok-gpu`
with 50 GiB boot disks. The opt-in profile uses one Longhorn replica and is
therefore **not highly available**. It is intended only for the OpenKubes meetup
demo. Golden Images remain immutable on `ok-storage-block`; only the per-cluster
clone PVCs use `ok-storage-block-gpu-test`.

The demo profile is not the OK-128 benchmark envelope. Do not compare its
timings with the recorded `ok-infra`/`ok-storage-block` benchmark evidence.

## 1. Offline preparation

Use matching `feature/gpu-demo-*` revisions of the sibling repositories and a
free `START_IP` from the infrastructure network.

```bash
cd /Users/arash/temp/kubernauts/ok/ok-cluster
make prepare-cilium-chart
make verify-cilium-chart
make gpu-demo-test
```

The chart is stored at `.tools/cilium-1.19.6.tgz`. Acquisition is idempotent and
verifies the pinned SHA-256 before atomically publishing the cache file.

## 2. Enable demo storage (separate Runtime-GO)

First run the offline and read-only checks:

```bash
cd /Users/arash/temp/kubernauts/ok/ok-storage
make verify
make gpu-demo-verify KUBECONFIG_FILE="$HOME/.kube/ok-infra.yaml"
```

`gpu-demo-verify` is expected to fail before first installation because the
dedicated tag and StorageClass do not exist yet. After an explicit Runtime-GO:

```bash
GPU_DEMO_APPLY=yes make gpu-demo-apply \
  KUBECONFIG_FILE="$HOME/.kube/ok-infra.yaml"

make gpu-demo-verify \
  KUBECONFIG_FILE="$HOME/.kube/ok-infra.yaml"
```

The apply operation merges the `openkubes-gpu-demo` tag into the Longhorn node
`ok-gpu`, preserving any existing node tags, and applies only the dedicated
StorageClass.

## 3. Record the Talos video

Choose and approve a currently unused infrastructure IP:

```bash
cd /Users/arash/temp/kubernauts/ok/ok-cluster
export DEMO_START_IP=<free-approved-ip>

make new \
  CLUSTER=meetup-talos \
  TYPE=talos \
  WORKERS=1 \
  CP_DISK=50Gi \
  WORKER_DISK=50Gi \
  DEMO_PROFILE=gpu-single-replica \
  START_IP="$DEMO_START_IP"

make talos-golden-preflight \
  CLUSTER=meetup-talos \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"

/usr/bin/time -p make bootstrap \
  CLUSTER=meetup-talos \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"
```

Verify scheduling, clone storage, disk size, nodes, and Cilium:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n meetup-talos get vmi -o wide

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n meetup-talos get pvc \
  -o custom-columns=NAME:.metadata.name,SIZE:.spec.resources.requests.storage,SC:.spec.storageClassName,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/meetup-talos.yaml" get nodes -o wide
kubectl --kubeconfig "$HOME/.kube/meetup-talos.yaml" get pods -A
kubectl --kubeconfig "$HOME/.kube/meetup-talos.yaml" \
  -n kube-system get daemonset cilium
```

After an explicit Talos Cleanup-GO, delete the Talos cluster before creating
Flatcar:

```bash
make teardown \
  CLUSTER=meetup-talos \
  CONFIRM=yes \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get namespace meetup-talos --ignore-not-found
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get pvc -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,SC:.spec.storageClassName \
  | grep ok-storage-block-gpu-test || true
```

The shared Talos Golden Image in `ok-images` is deliberately preserved.

## 4. Record the Flatcar video

Re-check that the selected IP is free before reusing it:

```bash
cd /Users/arash/temp/kubernauts/ok/ok-cluster

make new \
  CLUSTER=meetup-flatcar \
  TYPE=flatcar \
  WORKERS=1 \
  CP_DISK=50Gi \
  WORKER_DISK=50Gi \
  DEMO_PROFILE=gpu-single-replica \
  START_IP="$DEMO_START_IP"

make flatcar-preflight \
  CLUSTER=meetup-flatcar \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"

/usr/bin/time -p make install-flatcar \
  CLUSTER=meetup-flatcar \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_WORKLOAD_KUBECONFIG="$HOME/.kube/meetup-flatcar.yaml" \
  FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz" \
  FLATCAR_APPLY=yes
```

Verify the result:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n meetup-flatcar get vmi -o wide

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n meetup-flatcar get pvc \
  -o custom-columns=NAME:.metadata.name,SIZE:.spec.resources.requests.storage,SC:.spec.storageClassName,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/meetup-flatcar.yaml" get nodes -o wide
kubectl --kubeconfig "$HOME/.kube/meetup-flatcar.yaml" get pods -A
kubectl --kubeconfig "$HOME/.kube/meetup-flatcar.yaml" \
  -n kube-system get daemonset cilium
```

After an explicit Flatcar Cleanup-GO:

```bash
FLATCAR_TEARDOWN=yes make teardown-flatcar \
  CLUSTER=meetup-flatcar \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_WORKLOAD_KUBECONFIG="$HOME/.kube/meetup-flatcar.yaml"
```

## 5. Remove demo storage (separate Cleanup-GO)

The removal guard refuses to proceed while any PVC, PV, or Longhorn volume uses
the demo class or its dedicated tag. After an explicit storage Cleanup-GO:

```bash
cd /Users/arash/temp/kubernauts/ok/ok-storage

GPU_DEMO_REMOVE=yes make gpu-demo-remove \
  KUBECONFIG_FILE="$HOME/.kube/ok-infra.yaml"
```

This deletes only `ok-storage-block-gpu-test` and removes only the
`openkubes-gpu-demo` tag from `ok-gpu`. It does not delete a Golden Image or
change `ok-storage-block`.
