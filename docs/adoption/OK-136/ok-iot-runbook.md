# `ok-iot` Talos-on-`ok-gpu` runbook

This runbook creates, verifies, records evidence for, and removes the persistent
Talos workload-cluster test used by OK-136. The reviewed production contract is:

- scheduling profile and KubeVirt node: `ok-gpu`;
- control plane: 2 vCPU, 4 GiB memory, 20 GiB boot disk;
- worker: 4 vCPU, 8 GiB memory, 30 GiB boot disk;
- boot clones: Longhorn `ok-storage-block`, two replicas;
- source: the existing immutable Talos v1.9.6 Golden PVC in `ok-images`;
- Kubernetes v1.34.1 and the locally verified Cilium 1.19.6 chart.

This is not the historical `gpu-single-replica` meetup profile and does not use
`ok-storage-block-gpu-test`. The Golden Image contains no cluster credentials;
Talos configuration, bootstrap secrets and the workload kubeconfig are created
dynamically for each cluster.

## Prerequisites

Use sibling `ok-cluster` and `ok-linux` checkouts below the common workspace:

```bash
cd "$HOME/temp/kubernauts/ok/ok-cluster"
git switch feature/ok-136-gpu-scheduling-contract
git status --short --branch

git -C ../ok-linux switch feature/ok-136-gpu-scheduling-contract
git -C ../ok-linux status --short --branch
```

Required tools and inputs are `make`, `python3`, `kubectl`, `helm`, management
kubeconfig `$HOME/.kube/ok-infra.yaml`, and working KubeVirt, CDI and Longhorn
services on the management cluster.

Acquire or reuse the pinned chart. Both commands fail closed unless its SHA-256
is `21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179`:

```bash
make prepare-cilium-chart
make verify-cilium-chart
```

For an offline, pre-downloaded chart:

```bash
make prepare-cilium-chart \
  CILIUM_CHART_SOURCE=/absolute/path/to/cilium-1.19.6.tgz
```

## 1. Create and render `ok-iot`

After a previous guarded teardown has removed the local directory, recreate it
with the reviewed profile and role-specific resources:

```bash
cd "$HOME/temp/kubernauts/ok/ok-cluster"

make new \
  CLUSTER=ok-iot \
  TYPE=talos \
  SCHEDULING_PROFILE=ok-gpu \
  CP_CORES=2 \
  CP_MEMORY=4Gi \
  CP_DISK=20Gi \
  WORKER_CORES=4 \
  WORKER_MEMORY=8Gi \
  WORKER_DISK=30Gi
```

`make new` selects an unused endpoint and renders immediately. If
`ok-iot/cluster-config.yaml` is edited later, regenerate derived manifests:

```bash
make render CLUSTER=ok-iot
```

Rendering is local only; it creates no Kubernetes resources. Inspect the
resolved endpoint, profile and resources before continuing:

```bash
sed -n '1,140p' ok-iot/cluster-config.yaml
grep -nE 'cores:|guest:|storage:|ok-gpu|ok-storage-block' \
  ok-iot/cluster-base.yaml
```

## 2. Run the read-only management preflight

```bash
make talos-golden-preflight \
  CLUSTER=ok-iot \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"
```

Continue only after `PASS`. The guard checks namespace, endpoint and kubeconfig
collisions; `ok-gpu` readiness and available CPU/memory; the exact Golden PVC;
KubeVirt `ExpandDisks`; and sufficient eligible Longhorn capacity for two
replicas of both boot volumes. Longhorn capacity is not host `df` output: the
guard applies the live minimum-free-space and over-provisioning settings to
each disk's reserved, already scheduled, maximum and available bytes.

## 3. Bootstrap and measure warm provisioning

The Golden Image is already published, so this measures repeatable warm
provisioning rather than its one-time public download and publication:

```bash
/usr/bin/time -p make bootstrap \
  CLUSTER=ok-iot \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"
```

The lifecycle applies CAPI/Talos/KubeVirt resources, creates local CDI clones,
writes `$HOME/.kube/ok-iot.yaml`, installs the verified local Cilium chart and
waits for every workload node to become Ready.

## 4. Verify the workload and infrastructure state

```bash
kubectl --kubeconfig "$HOME/.kube/ok-iot.yaml" get nodes -o wide
kubectl --kubeconfig "$HOME/.kube/ok-iot.yaml" get pods -A
kubectl --kubeconfig "$HOME/.kube/ok-iot.yaml" \
  -n kube-system get daemonset cilium

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-iot get vmi \
  -o custom-columns=NAME:.metadata.name,NODE:.status.nodeName,CPU:.spec.domain.cpu.cores,MEMORY:.spec.domain.memory.guest,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-iot get pvc \
  -o custom-columns=NAME:.metadata.name,SIZE:.spec.resources.requests.storage,SC:.spec.storageClassName,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-iot get datavolume \
  -o custom-columns=NAME:.metadata.name,SOURCE:.spec.source.pvc.name,SC:.spec.storage.storageClassName,PHASE:.status.phase
```

Expected state:

| Role | KubeVirt node | CPU | Memory | Disk | StorageClass |
|---|---|---:|---:|---:|---|
| control plane | `ok-gpu` | 2 | 4Gi | 20Gi | `ok-storage-block` |
| worker | `ok-gpu` | 4 | 8Gi | 30Gi | `ok-storage-block` |

Both workload nodes must be Ready, both VMIs Running, both PVCs Bound, both
DataVolumes Succeeded, and Cilium must report two Ready agents. Each Longhorn
volume must additionally be `healthy`, contain two running replica objects,
and place those replicas on two distinct Longhorn nodes. `degraded` is not an
accepted production result even when the VM and workload node are Ready.

Record the normalized runtime evidence:

```bash
make talos-golden-runtime-evidence \
  CLUSTER=ok-iot \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"
```

The evidence is written below `docs/adoption/OK-130/.evidence/`. It records
observed CAPI, Node and Cilium milestones; the duration is evidence, not an SLO.

## 5. Guarded cleanup

Cleanup is destructive and must be explicitly approved for the exact cluster:

```bash
unset KUBECONFIG

make teardown \
  CLUSTER=ok-iot \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"
```

Review the cluster name and enumerated PVs, then answer `y`. The command removes
the CAPI cluster, namespace, clone authorization, cluster-owned retained PVs and
Longhorn volumes, workload kubeconfig, and local `ok-iot` render. It preserves
the shared Golden PVC.

Verify cleanup:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" get namespace ok-iot
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" get pv | grep ok-iot || true
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" get pv | grep Released || true

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-images get pvc \
  talos-v1-9-6-ce4c980550dd-461d72d30750-amd64

test ! -e ok-iot
```

Expected result: the namespace and all cluster-owned storage are absent, while
the immutable Golden PVC remains `Bound`.

## Troubleshooting

Inspect only the exact cluster namespace and management objects first:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-iot get cluster,machine,machinedeployment,kubevirtmachine,vmi,dv,pvc

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-iot get events --sort-by=.lastTimestamp
```

Do not switch to the single-replica test StorageClass, change the Golden-image
identity, or bypass the preflight to make a failed production run proceed.
If Longhorn reports `ReplicaSchedulingFailure`, inspect `storageReserved`,
`storageScheduled`, `storageMaximum`, `storageAvailable`, and the live
`storage-minimal-available-percentage` and
`storage-over-provisioning-percentage` settings before changing anything.
