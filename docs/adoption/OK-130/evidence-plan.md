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
`make bootstrap` applies a workload Talos manifest. Live publication,
bootstrap and teardown require separate user approval. Teardown removes the
consumer Role/RoleBinding after the consumer namespace and verifies that the
shared Golden PVC retains its UID, digest and identity.

After an approved cluster run, `make talos-golden-runtime-evidence
CLUSTER=<name>` records the namespace-to-CAPI-Available interval as
`mode: warm-provisioning`. It also proves every runtime boot DataVolume cloned
the same Golden PVC and records `public_import_count: 0`. This evidence is
kept separate from `ok-linux`'s one-time `mode: cold-publication` timing.
