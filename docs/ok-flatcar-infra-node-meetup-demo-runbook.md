# Flatcar on `ok-infra`: meetup demo runbook

This runbook creates, verifies, records, and removes the disposable
`ok-flatcar-infra-node-meetup-demo` workload cluster. It demonstrates the
exact constrained Flatcar production profile accepted by ADR-009 and the
unchanged ADR-Platform-016 OS contract:

- Flatcar stable `4593.2.4`, `amd64`, KubeVirt only
- Kubernetes `v1.34.1`
- topology: one control plane and one worker
- scheduling node: `ok-infra`
- control plane: 2 vCPU, 4 GiB memory, 50 GiB boot disk
- worker: 2 vCPU, 4 GiB memory, 50 GiB boot disk
- immutable Golden Image: `ok-images/flatcar-stable-4593-2-4-amd64-kubevirt`
- boot volumes: local CDI clones on Longhorn `ok-storage-block`
- bootstrap: dynamic CABPK Ignition through CAPK ConfigDrive
- Cilium: pinned chart `1.19.6`, verified before installation

This is the production-constrained Flatcar path. It does not use the
demonstration-only `gpu-single-replica` profile or
`ok-storage-block-gpu-test`.

## Safety and source-state requirement

The install and teardown commands mutate resources on `ok-infra`. They are
separately guarded by `FLATCAR_APPLY=yes` and `FLATCAR_TEARDOWN=yes`.

The Flatcar lifecycle fails closed unless both `ok-cluster` and `ok-linux`
are clean and their exact HEAD commits are present on a remote. Therefore the
generated cluster directory must temporarily be committed and pushed before
the management preflight. It must be deleted by the guarded teardown and its
deletion committed before this documentation branch is merged. The runtime
directory must never remain on `main`.

The teardown deletes the workload cluster, namespace, cluster-owned clone
PVCs/PVs and Longhorn volumes, temporary CDI snapshots, clone authorization,
the workload kubeconfig, and the local render directory. It preserves the
shared Flatcar Golden Image in `ok-images`.

## Prerequisites

Run from the `ok-cluster` checkout:

```bash
cd "$HOME/temp/kubernauts/ok/ok-cluster"
git status --short --branch
```

Required local tools and inputs:

- `make`, `python3`, `kubectl`, `helm`, `clusterctl`, `/usr/bin/time`, and
  optionally `vhs` plus `ffmpeg` for recording
- `ok-linux` checked out next to `ok-cluster`
- management kubeconfig at `$HOME/.kube/ok-infra.yaml`
- no existing `$HOME/.kube/ok-flatcar-infra-node-meetup-demo.yaml`
- reachable and healthy `ok-infra`
- CAPI/CABPK/KCP `v1.13.3`, CAPK `v0.11.2`, and KubeVirt `v1.8.1`
- KubeVirt `ExpandDisks`, CDI, Longhorn, and the reviewed Flatcar Golden Image
- sufficient Longhorn capacity for two 50 GiB clone targets

Verify the immutable source and target StorageClass:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-images get pvc flatcar-stable-4593-2-4-amd64-kubevirt

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get storageclass ok-storage-block
```

## 1. Acquire and verify the pinned Cilium chart

```bash
make prepare-cilium-chart
make verify-cilium-chart
```

The supported target downloads exactly Cilium `1.19.6` from the authoritative
Helm repository and verifies SHA-256
`21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179`.
A valid cached artifact is reused from:

```text
$HOME/temp/kubernauts/ok/ok-cluster/.tools/cilium-1.19.6.tgz
```

For a pre-downloaded or offline artifact:

```bash
make prepare-cilium-chart \
  CILIUM_CHART_SOURCE=/absolute/path/to/cilium-1.19.6.tgz
```

The digest verification remains mandatory.

## 2. Scaffold and render the exact Flatcar profile

Confirm that the name, workload kubeconfig, and fixed endpoint are unused:

```bash
test ! -e ok-flatcar-infra-node-meetup-demo
test ! -e "$HOME/.kube/ok-flatcar-infra-node-meetup-demo.yaml"

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-flatcar-infra-node-meetup-demo \
  get cluster ok-flatcar-infra-node-meetup-demo
```

The Kubernetes command must return `NotFound`.

Create the local configuration and rendered manifests:

```bash
make new \
  CLUSTER=ok-flatcar-infra-node-meetup-demo \
  TYPE=flatcar \
  START_IP=192.168.100.212
```

The isolated Flatcar resolver rejects changes to topology, CPU, memory, disk,
provider, architecture, versions, scheduling, Golden Image, storage, or
bootstrap semantics outside the accepted profile.

Inspect the resolved configuration and VM resources:

```bash
sed -n '1,120p' \
  ok-flatcar-infra-node-meetup-demo/cluster-config.yaml

grep -nE 'cores:|guest:|storage:|storageClassName:|kubernetes.io/hostname:' \
  ok-flatcar-infra-node-meetup-demo/cluster-v2.yaml
```

Expected role resources:

```text
control plane: cores 2, guest memory 4Gi, storage 50Gi
worker:        cores 2, guest memory 4Gi, storage 50Gi
node:          ok-infra
StorageClass:  ok-storage-block
```

## 3. Commit and push the temporary runtime render

The runtime render is evidence input, not a permanent `main` artifact:

```bash
git add ok-flatcar-infra-node-meetup-demo
git commit -m "demo: materialize Flatcar meetup cluster"
git push

git status --short --branch
git branch -r --contains HEAD
```

Continue only when the worktree is clean and the remote contains `HEAD`.
Verify the sibling `ok-linux` checkout the same way:

```bash
git -C ../ok-linux status --short --branch
git -C ../ok-linux branch -r --contains HEAD
```

## 4. Run the guarded management preflight

```bash
make flatcar-preflight \
  CLUSTER=ok-flatcar-infra-node-meetup-demo \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"
```

Continue only after `PASS constrained Flatcar production preflight`. The
preflight validates source provenance, the exact support profile, rendered
objects, absence of secrets and SSH inputs, provider versions, KubeVirt
features, Golden-Image identity, target StorageClass, node placement, clone
authorization, and the digest-pinned local Cilium chart.

## 5. Install and measure warm provisioning

The immutable Golden Image is already published. This measures repeatable
warm cluster provisioning and excludes the one-time public artifact
publication.

```bash
/usr/bin/time -p make install-flatcar \
  CLUSTER=ok-flatcar-infra-node-meetup-demo \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz" \
  FLATCAR_APPLY=yes
```

The guarded lifecycle:

1. repeats the production preflight;
2. creates the namespace and exact CAPI/CABPK/CAPK resources;
3. clones the immutable Golden Image into role-owned boot volumes;
4. creates `$HOME/.kube/ok-flatcar-infra-node-meetup-demo.yaml`;
5. boots the control plane from dynamic Ignition;
6. installs the verified local Cilium chart;
7. waits for the control plane and worker to become Ready;
8. verifies the Flatcar OS image, Kubernetes version, and KubeVirt provider ID.

A controlled 2026-07-30 run of the same supported lifecycle completed in
`188.22` seconds. This is an observed baseline, not a service-level guarantee.

### Meetup recording result (2026-08-02)

The approved meetup recording completed successfully with:

```text
real 297.86
user 10.53
sys  3.48
```

Both Flatcar Nodes reached Ready and Cilium reached desired/current/ready
`2/2/2`. This is another single observed warm run, not an SLO. The terminal
recording preserves the exact POSIX result.

## 6. Verify the workload cluster

```bash
kubectl --kubeconfig \
  "$HOME/.kube/ok-flatcar-infra-node-meetup-demo.yaml" \
  get nodes -o wide

kubectl --kubeconfig \
  "$HOME/.kube/ok-flatcar-infra-node-meetup-demo.yaml" \
  get pods -A

kubectl --kubeconfig \
  "$HOME/.kube/ok-flatcar-infra-node-meetup-demo.yaml" \
  -n kube-system get daemonset cilium
```

Expected state:

- one Ready control-plane node and one Ready worker
- Flatcar `4593.2.4` and Kubernetes `v1.34.1`
- all system Pods Running
- Cilium desired/current/ready `2/2/2`

## 7. Verify KubeVirt placement and boot clones

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-flatcar-infra-node-meetup-demo get vmi \
  -o custom-columns=NAME:.metadata.name,NODE:.status.nodeName,CPU:.spec.domain.cpu.cores,MEMORY:.spec.domain.memory.guest,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-flatcar-infra-node-meetup-demo get datavolume \
  -o custom-columns=NAME:.metadata.name,DV_REQUEST:.spec.storage.resources.requests.storage,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-flatcar-infra-node-meetup-demo get pvc \
  -o custom-columns=NAME:.metadata.name,PVC_REQUEST:.spec.resources.requests.storage,CAPACITY:.status.capacity.storage,SC:.spec.storageClassName,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-images get pvc flatcar-stable-4593-2-4-amd64-kubevirt
```

Expected result:

| Role | Node | CPU | Memory | Declared disk | PVC capacity | StorageClass | State |
|---|---|---:|---:|---:|---:|---|---|
| control plane | `ok-infra` | 2 | 4Gi | 50Gi | 53Gi | `ok-storage-block` | Running/Bound |
| worker | `ok-infra` | 2 | 4Gi | 50Gi | 53Gi | `ok-storage-block` | Running/Bound |

The DataVolumes retain the exact profile request of `50Gi`. CDI accounts for
filesystem overhead by expanding the resulting PVC request to `56908316672`
bytes, reported by Kubernetes as `53Gi` capacity. This is storage backing for
the declared 50 GiB virtual boot disk, not a profile change.

The shared 15 GiB Golden Image remains `Bound`; the larger clone capacities
are enabled by the reviewed KubeVirt `ExpandDisks` contract.

## 8. Record the terminal demo

The git-ignored VHS tape is prepared at:

```text
.tools/ok-meetup-video/ok-flatcar-infra-node-meetup-demo.tape
```

The planned 2:29 meetup cut has an English subtitle track at:

```text
.tools/ok-meetup-video/ok-flatcar-infra-node-meetup-demo-meetup-cut-en.srt
```

Run it only after the runtime render is committed and pushed, the worktree is
clean, and explicit runtime approval has been given:

```bash
vhs .tools/ok-meetup-video/ok-flatcar-infra-node-meetup-demo.tape
```

The tape records the real install duration. Post-processing may accelerate
only the waiting interval; the displayed POSIX `real` value must remain the
unmodified runtime evidence. The SRT assumes an exact 2:29 final cut and must
be checked against the resulting edit before it is uploaded.

The approved recording produced:

| Artifact | Duration | SHA-256 |
|---|---:|---|
| master MP4 | 339.800 s | `be3359bb6127ab50b97cfdf3010b10fdcad71e6fea428523a48ceb69a9b3aa07` |
| meetup-cut MP4 | 149.040 s | `71d0cbf022cfe7721153aa4c20b09bc3fc794d3921e990d44fdaee10446943bc` |
| meetup-cut MP4 with soft English subtitles | 149.040 s | `0e5ba1fffa232e9e086c977d4c965c3a00b197be6adc432df9ef98334dfc5374` |
| English SRT | 149.000 s | `21f3178a5f6656a2d52d809354fdfada645f19319a995e1c9a0d7c80257a221d` |

The cut keeps seconds `0–30` and `290–339.8` at normal speed. Only seconds
`30–290`, the provisioning wait, are accelerated approximately 3.76 times.
The visible `real 297.86` result is unchanged.

## 9. Guarded teardown

```bash
make teardown-flatcar \
  CLUSTER=ok-flatcar-infra-node-meetup-demo \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_TEARDOWN=yes
```

Verify cleanup and Golden-Image preservation:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get namespace ok-flatcar-infra-node-meetup-demo

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get pv | grep ok-flatcar-infra-node-meetup-demo || true

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-images get pvc flatcar-stable-4593-2-4-amd64-kubevirt
```

The namespace and cluster-owned volumes must be absent. The Golden Image must
remain `Bound`.

## 10. Remove the temporary render from branch history tip

The teardown removes the local runtime directory. Record that deletion before
opening or merging a documentation PR:

```bash
git add -u ok-flatcar-infra-node-meetup-demo
git commit -m "chore: remove Flatcar meetup runtime render"
git push

git status --short --branch
test ! -e ok-flatcar-infra-node-meetup-demo
```

The final branch diff against `main` must contain documentation only, never
the disposable runtime cluster directory or generated video files.
