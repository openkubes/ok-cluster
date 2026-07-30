# OK-130 Talos Golden-Image consumer evidence

The `ok-linux` `kubevirt` profile owns the exact Talos artifact identity and
publication PVC. This repository consumes only the materialized identity.
Flatcar profile semantics and the shared OS capability contract are unchanged.
The completed live result is recorded in
[runtime-acceptance-record.md](runtime-acceptance-record.md).

## Offline acceptance

```bash
make ok130-test OK_LINUX_PATH=../ok-linux
python3 tests/ok106_contract_test.py
python3 tests/flatcar_promotion_test.py
python3 tests/ok125_flatcar_render_test.py
```

The OK-130 test proves:

- unreviewed Talos version/schematic inputs fail closed;
- OpenStack and `talos-mgmt` rendering remain independent;
- control-plane and worker use the same `ok-images` PVC;
- clone targets use `ok-storage-block`;
- the only cross-namespace permission is
  `create` on `cdi.kubevirt.io/datavolumes/source`;
- machine templates and boot volumes carry the Talos identity;
- no supported KubeVirt Talos render contains an HTTP/registry qcow2 source;
- `TalosControlPlane` and `TalosConfigTemplate` remain the dynamic
  machine-configuration and secret authority;
- cleanup deletes exact consumer RBAC and re-verifies the shared PVC;
- the v1.8.1 infrastructure KubeVirt installation must have `ExpandDisks`
  active; otherwise the lifecycle fails before creating clone resources.

## Guarded runtime

`make talos-golden-preflight` is read-only and must pass before the existing
`make bootstrap` applies a workload Talos manifest. It verifies that
`ok-infra` is Ready and schedulable, KubeVirt is exactly v1.8.1 and Deployed
with `ExpandDisks`, then checks the Golden PVC and clone authorization.
Filesystem CDI snapshot clones copy the Golden PVC's `disk.img` virtual size;
the gate makes KubeVirt expand that image to each target PVC's requested
capacity before Talos creates its dynamic EPHEMERAL volume. The guarded,
idempotent infrastructure reconciliation is:

```bash
make configure-kubevirt-expand-disks \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  KUBEVIRT_EXPAND_DISKS_APPLY=yes
```

It validates the single deployed KubeVirt installation and exact v1.8.1
version, preserves existing configuration and feature gates, and uses an
atomic resource-version test. Live publication, bootstrap and teardown require
separate user approval. Teardown removes the consumer Role/RoleBinding after
the consumer namespace and verifies that the shared Golden PVC retains its
UID, digest and identity. It captures the consumer DataVolume UIDs before
deletion and removes only CDI temporary snapshots in `ok-images` that carry
one of those exact UIDs and reference the expected Golden PVC.

After an approved cluster run, `make talos-golden-runtime-evidence
CLUSTER=<name>` records separate namespace-to-CAPI-Available,
namespace-to-all-Nodes-Ready and end-to-end-Cilium-Ready intervals as
`mode: warm-provisioning`. It verifies the local chart digest, Helm release,
Talos/KubeVirt Node identity and every runtime boot DataVolume clone, then
records `public_import_count: 0`. No Secret object or value is read into
evidence. This evidence stays separate from `ok-linux`'s one-time
`mode: cold-publication` timing.

The guarded Flatcar `ok125-node-ready` evidence records the same
namespace-to-CAPI-Available, namespace-to-all-Nodes-Ready and
end-to-end-Cilium-Ready fields. Both warm timers begin only after the shared
chart has been verified locally, so the two OS paths can be compared without
including chart acquisition or either Golden Image's one-time publication.

The pinned Cilium chart must be acquired before starting the comparable warm
provisioning timer:

```bash
make prepare-cilium-chart
make verify-cilium-chart
```

Talos `install-cni` re-verifies and installs that local chart rather than
updating a Helm repository during provisioning. Flatcar consumes the same
bytes only through its still-explicit
`FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"` input. This keeps
chart acquisition outside both OK-128 timing windows without merging Talos
and Flatcar lifecycle semantics.
