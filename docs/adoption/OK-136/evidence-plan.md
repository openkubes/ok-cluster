# OK-136 configurable KubeVirt scheduling evidence plan

OK-136 introduces an explicit production scheduling profile for ordinary Talos
workload clusters on `ok-gpu`. It does not turn the historical
`gpu-single-replica` meetup profile or `ok-storage-block-gpu-test` into a
production contract. Flatcar remains constrained to its independently owned
and validated `ok-infra` profile.

## Contract boundary

1. `ok-linux` owns the reviewed Talos KubeVirt provider profiles. The existing
   `ok-infra` profile remains the default; the new `ok-gpu` profile is an
   explicit opt-in.
2. Both profiles consume the stable `ok-storage-block` contract. The immutable
   Talos Golden PVC stays in `ok-images` and keeps its existing artifact
   identity, digest and claim name.
3. `ok-cluster` rejects free-form Talos KubeVirt scheduling. An explicit
   `NODE_SELECTOR` must match the selected reviewed provider profile.
4. The `ok-gpu` provider identity is included in immutable KubeVirt machine,
   DataVolume and bootstrap-template names. Selecting it never rewrites an
   existing `ok-infra` machine template in place.
5. CPU, memory and disk inputs remain role-specific cluster inputs. They are
   never baked into the shared Golden Image.
6. Talos machine configuration, Cilium inputs, certificates, tokens and
   workload kubeconfigs remain dynamic and outside committed manifests.

## Executable offline evidence

From clean sibling checkouts on the OK-136 branches:

```sh
cd ../ok-linux
make ok130-profile-test

cd ../ok-cluster
make ok136-test
python3 -m py_compile \
  profile_resolvers/talos.py \
  scripts/talos_golden_lifecycle.py \
  render.py
```

The suite must prove:

- omitted scheduling selects the unchanged `ok-infra` production profile;
- `SCHEDULING_PROFILE=ok-gpu` materializes exactly `nodeSelector: ok-gpu` and
  clone target `ok-storage-block`;
- free-form or mismatched node/storage inputs fail closed;
- the Golden artifact identity and source PVC are byte-identical across both
  scheduling profiles;
- CP and worker resource sizes remain independently configurable;
- CP and worker boot DataVolumes are local CDI clones using
  `ok-storage-block`;
- `ok-gpu` uses new immutable provider-bound template names while legacy
  `ok-infra` template names remain unchanged;
- Flatcar and non-KubeVirt semantics are not broadened;
- rendered manifests contain no public VM source, credentials, private keys,
  SSH input or committed Kubernetes Secrets.

## Guarded management preflight

Using an explicit `ok-infra` kubeconfig, the read-only preflight must verify:

- the selected KubeVirt scheduling node exists, is Ready and schedulable;
- requested CP/worker CPU and memory fit the node's allocatable capacity after
  current Pod requests, or fail with the observed/requested bound;
- KubeVirt v1.8.1 is deployed with `ExpandDisks`;
- `ok-storage-block` is Longhorn-backed, two-replica, expandable,
  `Retain`/`Immediate`, and has no node-tag restriction;
- CDI selects the reviewed local `ok-storage-block-snapshot` clone path;
- at least two Ready and schedulable Longhorn nodes have enough available
  capacity for all requested boot volumes after applying the live reserved,
  scheduled, minimum-free-space and over-provisioning scheduler bounds;
- the selected node is an eligible Longhorn attachment/storage node;
- the exact Talos Golden PVC is Bound with its reviewed UID, digest and OS
  identity;
- cluster namespace, endpoint, clone RBAC and workload-kubeconfig collisions
  are absent.

The preflight is read-only. It must not create, patch or delete cluster or
storage resources.

## Runtime acceptance for `ok-iot`

Live mutation requires a separate Runtime-GO. The intended reviewed input is:

```sh
make new \
  CLUSTER=ok-iot \
  TYPE=talos \
  SCHEDULING_PROFILE=ok-gpu \
  CP_DISK=<approved-size> \
  WORKER_DISK=<approved-size>

make talos-golden-preflight \
  CLUSTER=ok-iot \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"
```

After Runtime-GO, bootstrap and prove:

1. the CP and worker VMIs both run on `ok-gpu`;
2. both DataVolumes clone the existing Talos Golden PVC, reach `Succeeded`,
   and use `ok-storage-block` with zero public image imports;
3. the requested CPU, memory and disk sizes are visible in KubeVirt/PVC state;
4. the two workload Nodes report Talos v1.9.6 and Kubernetes v1.34.1 and become
   Ready;
5. Cilium 1.19.6 reaches two Ready agents and a Ready operator;
6. Longhorn volumes are `healthy` with two running replica objects on distinct
   Longhorn nodes; a merely requested replica count or `degraded` volume fails;
7. runtime evidence records CAPI, Node and Cilium milestones as observations,
   not an SLO.

## Cleanup acceptance

Cleanup requires a separate Cleanup-GO. Guarded teardown must remove the
`ok-iot` namespace, cluster-owned clone PVCs, retained PVs, Longhorn volumes,
temporary CDI snapshots, clone RBAC, workload kubeconfig and local render.
It must then re-verify that the shared Talos Golden PVC remains Bound with the
same UID, digest and OS identity.

## Stop conditions

Do not bootstrap when the production `ok-storage-block` contract cannot place
two replicas with sufficient capacity, when `ok-gpu` lacks bounded CPU or
memory capacity, or when any provider/profile input is not represented by the
reviewed `ok-linux` source of truth. Do not substitute the demonstration-only
single-replica StorageClass to bypass a production preflight failure.
