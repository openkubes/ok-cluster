# OK-130 Talos Golden-Image runtime acceptance

**Status:** PASS for Golden publication, warm provisioning and replacement
convergence; continuous workload API availability during replacement did not
pass.

**Completed:** 2026-07-30

## Accepted Talos identity

- Talos: `v1.9.5`
- architecture: `amd64`
- Golden PVC:
  `ok-images/talos-v1-9-5-ce4c980550dd-9bb07c3a5857-amd64`
- Golden PVC UID: `004796a1-0d2f-4775-ae71-b0ef79ee04a0`
- artifact digest:
  `sha256:9bb07c3a585745dd888f6f30f3c5df9c69bf6752171a3058f84ad2ed11dec4f7`
- OS identity:
  `sha256:62a75f2e872a386ee70fe27158b6e235515d7c0a73f28ce8d95a8547236f1495`
- storage: `ok-storage-block`, `Filesystem`, `ReadWriteOnce`
- infrastructure KubeVirt: `v1.8.1`, `ExpandDisks` active

The control-plane and worker DataVolumes both cloned this PVC locally. No
public image import occurred. KubeVirt logged pre-start expansion of the
control-plane `disk.img` to `19779289088` bytes, allowing Talos to create its
dynamic EPHEMERAL volume from the requested boot-PVC capacity.

## Cold publication and warm provisioning

Chart acquisition and verification happened before both warm timers. Both
clusters used the exact local Cilium `1.19.6` chart with SHA-256
`21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179`,
one control-plane and one worker, and scheduling on `ok-infra`.

| Milestone | Talos | Flatcar |
|---|---:|---:|
| One-time Golden Image publication | 57.816 s | 231.297 s |
| Namespace to CAPI Available | 261.000 s | 173.000 s |
| Namespace to all Nodes Ready | 259.000 s | 172.000 s |
| Namespace to Cilium Ready | 275.029 s | 179.615 s |
| Public image imports during warm run | 0 | 0 |

The Flatcar cold-publication duration is derived from its recorded
`started_at` and `completed_at` timestamps. The Talos publisher records its
mutation duration directly. The warm lifecycle implementations record the
same three server-derived milestones.

These are single acceptance runs, not a statistical performance benchmark.
They compare supported end-to-end profile behavior; Talos and Flatcar retain
their separate image, bootstrap and target-storage semantics.

## Runtime result

The disposable Talos cluster reached:

- CAPI Available;
- two Kubernetes Nodes Ready with `kubevirt://` ProviderIDs;
- Cilium `1.19.6` deployed, with two ready agents and one ready operator.

The disposable Flatcar cluster reached its existing G1 and G3 acceptance
gates with two Ready Nodes, digest-bound Cilium images and metadata-only
bootstrap Secret evidence.

No Secret value was recorded in either runtime evidence file. A targeted scan
found no private key, kubeconfig credential, token or password material.

## Cleanup result

Both disposable clusters, their clone authorization, boot-volume PVCs/PVs,
underlying clone volumes and ephemeral workload kubeconfigs were removed.
The shared Talos and Flatcar Golden-Image PVCs retained their original UIDs and
remained `Bound`. The KubeVirt `ExpandDisks` setting remains declarative
infrastructure configuration.

## Source state

- `ok-cluster`: `feature/ok-130-talos-golden-image`
- Talos expansion implementation: `06bd823`
- comparable Flatcar timing implementation: `9e0fe47`
- exact Flatcar cleanup ownership guard: `f8ddb09`
- `ok-linux`: `feature/ok-130-talos-golden-image` at `97c36d7`
- `ok-storage`: `feature/ok-130-longhorn-local-snapshot` at `134f333`

No pull request or Jira transition was performed as part of this acceptance
run.

## Talos v1.9.6 identity replacement

On 2026-07-30, the same disposable 1+1 cluster was changed from the accepted
v1.9.5 identity above to the reviewed direct patch successor:

- Talos: `v1.9.6`
- schematic:
  `ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515`
- artifact digest:
  `sha256:461d72d30750b9e18cf0656239e0274764b1e391bde5bbc41084a887b8a55ed5`
- OS identity:
  `sha256:7f5dd4276432f522727a50e604538b6befc0cac51ee2b90d4b1ccbfcac774a2d`
- new immutable Golden PVC:
  `ok-images/talos-v1-9-6-ce4c980550dd-461d72d30750-amd64`
- new Golden PVC UID: `60b69267-e507-416a-b5a8-835bb0232ce6`

The v1.9.5 Golden PVC retained its original UID and remained `Bound`; the
publisher did not overwrite it. Control-plane and worker replacement
DataVolumes both cloned the v1.9.6 Golden PVC and reached `Succeeded`. The
final Nodes were:

- `ok130-talos-replacement-cp-7f5dd4276432-cgrsx`
- `ok130-talos-replacement-workers-bl6f4-bn7bn`

Both reported `Talos (v1.9.6)`, Kubernetes `v1.34.1`, kernel
`6.12.25-talos`, and were Ready. Cilium subsequently converged to two ready
agents and one ready operator. The final read-only warm evidence passed with
`public_import_count: 0`.

The first apply also exposed that `TalosConfigTemplate.spec` is immutable.
The static worker bootstrap template name attempted an in-place v1.9.5 to
v1.9.6 mutation and the admission webhook correctly rejected it. Worker
bootstrap templates and their MachineDeployment references are now
Talos-version-bound, so the corrected apply created a new immutable template
without leaking the KubeVirt Golden-Image identity into the shared Talos
bootstrap contract.

This was replacement convergence, but not a clean continuous-availability
result. Management events record control-plane drain timeouts at
18:29:40 UTC and a refused connection to the workload API at 18:29:53 UTC,
followed by `SuccessfulDrainNode` at 18:30:17 UTC. The runtime observer also
encountered the refused API connection. The exact outage duration was not
captured, so no duration is inferred after the fact. The replacement
eventually converged with distinct old/new identities, but this run must not
be cited as proof of uninterrupted API service.

After the final evidence capture, teardown removed the disposable namespace,
clone Role and RoleBinding, workload kubeconfig, both replacement PVs and
their Longhorn volumes. No cluster-owned CDI snapshot remained. A cleanup-v2
verification passed for PVs
`pvc-904f9633-c750-42fb-8a81-16a5574de27b` and
`pvc-1692a11a-d3c6-4edb-81f4-7d544fe3fd40`. Both shared Golden PVCs remained
`Bound` with their original UIDs.

The v1.9.6 replacement source is on
`feature/ok-130-talos-v1-9-6-replacement` in both `ok-linux` and
`ok-cluster`. The owning `ok-linux` pin is commit `b499694`; final
`ok-cluster` commit IDs are intentionally not self-referenced from this
record.
