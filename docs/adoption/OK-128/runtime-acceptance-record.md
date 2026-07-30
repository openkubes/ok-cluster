# OK-128 controlled provisioning benchmark

**Status:** PASS

**Completed:** 2026-07-30

**Classification:** two sequential single-run observations; no SLO claim

## Controlled inputs

- infrastructure: KubeVirt on `ok-infra`, scheduling node `ok-infra`
- topology: one control-plane and one worker, 2 vCPU, 4 GiB RAM and
  20 GiB disk per VM
- architecture: `amd64`
- Kubernetes: `v1.34.1`
- Cilium: local chart `1.19.6`, SHA-256
  `21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179`
- order: Flatcar, verified cleanup, then Talos
- `ok-cluster`:
  `0f4f5ff046d119aa5be346fb438b32e4f07af374`
- `ok-linux`:
  `97c36d766b6422315ee975dfb453545350ce2025`

Both source repositories were clean and present on a remote before each run.
The management node had 22 running VMIs and 66 scheduled pods before each
run, and 24 running VMIs and 68 scheduled pods at the end of each run.

## Observed warm provisioning

| Milestone | Flatcar | Talos |
|---|---:|---:|
| CAPI Cluster created | 7 s | 3 s |
| API reachable and control plane registered | 96 s | 212 s |
| first Node Ready | 129 s | 255 s |
| all Nodes Ready | 180 s | 264 s |
| Cilium DaemonSet available | 185 s | 259 s |
| Cilium operator available | 119 s | 250 s |
| CAPI Cluster Available | 181 s | 265 s |
| lifecycle command completed | 189 s | 263 s |
| common observer completed | 189 s | 265 s |
| POSIX `real` | 188.22 s | 264.04 s |
| POSIX `user` | 8.17 s | 8.45 s |
| POSIX `sys` | 2.70 s | 3.23 s |

The server-derived Kubernetes transitions and the observer-derived milestones
are intentionally not forced into table order. For example, a server-side
Node Ready transition can predate the next one-second API observation. Every
milestone was inside the common wrapper's start/completion bounds, and first
Node Ready did not follow all Nodes Ready.

Talos completed its supported `make bootstrap` lifecycle at 263 seconds. CAPI
reported the asynchronous `Available` transition two seconds later, so the
common wrapper completed at 265 seconds. The separate lifecycle timestamp and
POSIX timing preserve the exact operator-command duration.

## Golden Images and storage

Flatcar cloned:

- `ok-images/flatcar-stable-4593-2-4-amd64-kubevirt`
- UID `8e2a4094-3ef1-437f-b4e1-b9b2fb511119`
- artifact digest
  `sha256:49b72cf26d27d4747d6252c64582f17fdbd7d629993beebbcf997794333a978a`
- OS identity
  `sha256:afd862491620adbaeb3c25aa82ae89a3bd748ae5976cf66fbf9613a732ba35bb`
- Golden source storage `ok-storage-block`; validated clone target
  `local-path`

Talos cloned:

- `ok-images/talos-v1-9-5-ce4c980550dd-9bb07c3a5857-amd64`
- UID `004796a1-0d2f-4775-ae71-b0ef79ee04a0`
- Talos `v1.9.5`, schematic
  `ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515`
- artifact digest
  `sha256:9bb07c3a585745dd888f6f30f3c5df9c69bf6752171a3058f84ad2ed11dec4f7`
- OS identity
  `sha256:62a75f2e872a386ee70fe27158b6e235515d7c0a73f28ce8d95a8547236f1495`
- Golden source and clone target storage `ok-storage-block`

Both Talos DataVolumes traversed CDI smart-clone snapshots and Longhorn
resize, then reached `Succeeded` without a snapshot purge or manual runtime
intervention. No public image import occurred during either warm run.

## Cold publication boundary

Cold Golden-Image publication is not included in any warm timer above. The
previous accepted publication evidence records 231.297 seconds for Flatcar
and 57.816 seconds for Talos. Those one-time measurements remain in
[`OK-130/runtime-acceptance-record.md`](../OK-130/runtime-acceptance-record.md);
this record measures only repeatable cluster provisioning from existing
Golden PVCs.

## Cleanup and secret handling

After each final run:

- the cluster namespace and cluster-owned clone RBAC were absent;
- no cluster-owned CDI snapshot remained;
- clone PVCs, retained PVs and their underlying volumes were removed;
- the shared Golden PVC remained `Bound` with its original UID.

The active workload kubeconfig paths were removed after cleanup. Generated
kubeconfigs and bootstrap Secrets were never added to Git. Both sanitized
command logs, both raw JSON records, cleanup JSON, Markdown and CSV passed the
observer's fail-closed secret scan and a second independent scan before
publication.

Three earlier executions were excluded from the comparison: one transport
interruption and two observer-validation failures exposed assumptions about
clusterctl context names and asynchronous milestone ordering. The resulting
guards were fixed, offline-tested, committed and pushed before both final
runs. No timing from an excluded execution appears in this record.

## Evidence

- [`flatcar-2.json`](evidence/flatcar-2.json) and
  [`flatcar-2.log`](evidence/flatcar-2.log)
- [`talos-2.json`](evidence/talos-2.json) and
  [`talos-2.log`](evidence/talos-2.log)
- [`flatcar-2-cleanup.json`](evidence/flatcar-2-cleanup.json) and
  [`talos-2-cleanup.json`](evidence/talos-2-cleanup.json)
- [`comparison.md`](evidence/comparison.md) and
  [`comparison.csv`](evidence/comparison.csv)
