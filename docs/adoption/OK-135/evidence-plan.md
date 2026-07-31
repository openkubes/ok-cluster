# OK-135 Flatcar Longhorn clone-target evidence plan

OK-135 changes only the constrained Flatcar/KubeVirt consumer profile. The
verified Flatcar Golden Image, its digest and its immutable `ok-images` PVC do
not change. Talos and ADR-Platform-016 remain unchanged.

## Contract and acceptance gates

1. `ok-linux` profile revision 4 owns the exact `ok-storage-block` Longhorn,
   RWO filesystem, `Retain`/`Immediate`, expansion and `ExpandDisks` contract.
   Revisions 2 and 3 remain reserved by the historical OK-125 replacement
   evidence.
2. The `ok-cluster` resolver rejects `local-path` and every other override.
   Rendered CP/worker boot DataVolumes use `ok-storage-block`; immutable
   KubeVirtMachineTemplate, DataVolume and KubeadmConfigTemplate names include
   both the unchanged OS identity and profile revision.
3. The read-only management preflight requires KubeVirt v1.8.1 with only
   `ExpandDisks`, the exact Longhorn StorageClass, the
   `ok-storage-block-snapshot` class, and CDI snapshot clone strategy.
4. Cross-namespace clone RBAC remains limited to `datavolumes/source:create`
   for the consumer namespace's default ServiceAccount. Ignition/bootstrap
   Secrets remain dynamic and no credential enters the Golden Image or
   rendered manifests.
5. Teardown identifies clone PVs and temporary snapshots before deletion,
   validates their ownership/source, removes retained PVs and same-named
   Longhorn volumes plus CDI snapshots and RBAC, and verifies the shared Golden
   PVC identity remains Bound.

## Executable offline evidence

From clean sibling `ok-cluster` and `ok-linux` checkouts on their OK-135
branches:

```sh
cd ../ok-linux
make ok125-static

cd ../ok-cluster
make ok135-test
python3 -m py_compile \
  profile_resolvers/flatcar.py \
  scripts/flatcar_lifecycle.py \
  scripts/provisioning_benchmark.py
```

Review `git diff --check`, render assertions, negative storage override tests,
and scan the changed files for private keys, tokens, passwords, inline Secrets,
public image fetches and SSH inputs. Generated `.evidence` files are not
runtime acceptance.

## Guarded management and runtime evidence

Runtime work needs a separate explicit Runtime GO. After both implementation
branches are reviewed, committed, pushed and clean:

```sh
make prepare-cilium-chart
make new CLUSTER=ok135-flatcar TYPE=flatcar WORKERS=1 \
  K8S_VERSION=v1.34.1 PROVIDER=kubevirt ARCHITECTURE=amd64 \
  NODE_SELECTOR=ok-infra START_IP=<approved-ip>

make flatcar-preflight CLUSTER=ok135-flatcar \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"
```

After explicit Runtime GO, run `install-flatcar`, verify one Ready CP and one
Ready worker, Cilium, DataVolume source/phase, PVC/PV StorageClass, requested
and guest disk capacity, Longhorn volume identity, and absence of credentials
in manifests/evidence. Repeat with an explicitly supported disk-size case only
if the constrained envelope is deliberately expanded and reviewed.

For the fair warm replay, run the OK-128 observer sequentially for Flatcar and
Talos with identical 1+1, CPU, memory, 20 GiB, Cilium and
`ok-storage-block` inputs. Record both durations as observations, not an SLO;
cold Golden publication remains excluded.

Cleanup requires a second explicit approval:

```sh
FLATCAR_TEARDOWN=yes make teardown-flatcar CLUSTER=ok135-flatcar \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_WORKLOAD_KUBECONFIG="$HOME/.kube/ok135-flatcar.yaml"
```

Then verify namespace, clone PVCs/PVs, Longhorn volumes, CDI snapshots, clone
RBAC and local workload kubeconfig are absent, while the Flatcar Golden PVC
has the same UID, digest annotation and Bound phase.
