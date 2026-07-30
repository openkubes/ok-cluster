# OK-130 Talos Golden-Image runtime acceptance

**Status:** PASS

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
