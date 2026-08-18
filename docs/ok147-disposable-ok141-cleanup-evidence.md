# OK-147 disposable-ok141 cleanup closure

**Date:** 2026-08-18  
**Result:** `CLOSURE_PASS`  
**Purpose:** establish a clean, independently verified baseline before the
first live OK-147 runner create/converge/observe execution.

## Safety boundary

The cleanup used the verified Kubernetes v1.34.1 client with digest:

```text
sha256:bb211f2b31f2b3bc60562b44cc1e3b712a16a98e9072968ba255beb04cefcfdf
```

Every delete targeted one exact resource. All material objects were read
immediately before deletion and bound through UID and resourceVersion
preconditions. Propagation was foreground. No wildcard selection, force
delete, finalizer edit, arbitrary namespace cleanup or manual VM/PVC deletion
was used.

The first local Phase-1 invocation stopped before its first delete because the
JSON parser was not present in the escalated `PATH`. The corrected candidate
bound the parser by absolute path and was then run once. No post-mutation retry
was performed in any phase.

## Ordered cleanup

1. On `ok-shared`, the three exact disposable observability Applications were
   deleted, followed by the exact Argo cluster-registration Secret. All four
   exact reads subsequently returned absent.
2. On `ok-mgmt`, the disposable Cilium HelmChartProxy was deleted while the
   workload API was still available. Its finalizer and derived
   HelmReleaseProxy completed and both objects became absent.
3. The authoritative CAPI Cluster was deleted on `ok-mgmt`. CAPI/CAPK removed
   the control-plane and worker Machines and their provider graph. No VM, VMI
   or PVC was deleted manually.
4. The provider graph converged from six KubeVirt/storage runtime objects to
   zero in approximately 30 seconds.
5. The exact Golden-Image RoleBinding and Role were deleted from `ok-images`,
   followed by the dedicated `disposable-ok141` namespaces on `ok-mgmt` and
   `ok-infra`.
6. The namespace deletion released two Longhorn-backed VM-disk PVs. Both had
   reclaim policy `Retain`, phase `Released`, no backup source and detached
   backends. The two PVs and then their exact Longhorn volumes were deleted
   with preconditions.

## Final absence proof

The final read-only closure found zero matches for `disposable-ok141` in:

- CAPI Cluster, KubevirtCluster, TalosControlPlane, MachineDeployment and
  Machine resources on `ok-mgmt`;
- CAAPH HelmChartProxy and HelmReleaseProxy resources;
- KubeVirt VirtualMachines and VirtualMachineInstances on `ok-infra`;
- namespaced Services and PVCs, cluster-scoped PV claim references and the
  associated Longhorn Volume, Engine and Replica graph;
- the external Golden-Image Role and RoleBinding;
- Argo CD Applications and the cluster-registration Secret on `ok-shared`; and
- the `disposable-ok141` namespace on both `ok-mgmt` and `ok-infra`.

The original disposable workload and its two retained VM disks are now
irrecoverable from this environment. Recovery is by a fresh declarative
rebuild, consistent with the accepted DEV rebuild-on-loss model.

## Consequence for the next run

The historical OK-141 evidence remains in Git, but its private credentials and
runtime receipts are not reusable. The next OK-147 execution must bind a fresh
contract/request, signed grants, short-lived credentials, target identity and
activation package to the published runner image. This cleanup authorizes none
of those future mutations by itself.
