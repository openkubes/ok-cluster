# OK-130 Talos Golden-Image consumer evidence

The `ok-linux` `kubevirt` profile owns the exact Talos artifact identity and
publication PVC. This repository consumes only the materialized identity.
Flatcar profile semantics and the shared OS capability contract are unchanged.

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
- cleanup deletes exact consumer RBAC and re-verifies the shared PVC.

## Guarded runtime

`make talos-golden-preflight` is read-only and must pass before the existing
`make bootstrap` applies a workload Talos manifest. It verifies that
`ok-infra` is Ready and schedulable before checking the Golden PVC and clone
authorization. Live publication, bootstrap and teardown require separate user
approval. Teardown removes the consumer Role/RoleBinding after the consumer
namespace and verifies that the shared Golden PVC retains its UID, digest and
identity.

After an approved cluster run, `make talos-golden-runtime-evidence
CLUSTER=<name>` records separate namespace-to-CAPI-Available,
namespace-to-all-Nodes-Ready and end-to-end-Cilium-Ready intervals as
`mode: warm-provisioning`. It verifies the local chart digest, Helm release,
Talos/KubeVirt Node identity and every runtime boot DataVolume clone, then
records `public_import_count: 0`. No Secret object or value is read into
evidence. This evidence stays separate from `ok-linux`'s one-time
`mode: cold-publication` timing.

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
