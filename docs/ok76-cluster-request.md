# OK-76 ClusterRequest mapping

`cli.openkubes.io/v1alpha1` `ClusterRequest` is a read-only Make-preview input.
Its `talos-kubevirt-reference` profile is intentionally distinct from the
existing Runner `Cluster` Intent profile `talos-kubevirt-mvp`: the Make profile
allows unresolved `auto` network allocation and 1–10 workers, while the Runner
Intent requires explicit endpoint/Pod/Service CIDRs and describes a fixed
one-control-plane/one-worker MVP. These profiles target the same Talos/KubeVirt
family but are not interchangeable contracts.

`metadata.name` maps directly to Runner Intent `metadata.name`. The three network
field names also correspond, but this request accepts only `auto`; the Runner
Intent requires explicit endpoint/Pod/Service values, so there is no value-level
mapping until an operator resolves them. The profile identifiers have a
conceptual platform-family relationship, not a conversion. `ClusterRequest`
topology and Kubernetes/Talos versions are preview-only and have no corresponding
Runner Intent fields. Optional Runner management/infrastructure kubeconfig
references have no `ClusterRequest` equivalents. No conversion, authorization,
or Runner execution is implemented.

The Runner `talos-kubevirt-mvp` is narrower: it fixes one control plane and one
worker, 2 cores and 4Gi memory per VM, 20Gi disks for both, and Kubernetes
v1.34.1; it also requires explicit network values. The Make reference profile
uses a 15Gi worker disk, allows the bounded 1–10 worker request, carries a Talos
version, and lets Make resolve network values. Therefore the two profile IDs
must remain distinct.

The plan's fixed sizing values are sourced from the current Make workflow:
`new-cluster.sh` defaults CP/worker cores to 2, memory to 4Gi, Talos CP disk to
20Gi and worker disk to 15Gi; `render.py` has matching fallback values. The
reference profile fixes the Talos/KubeVirt `ok-infra` scheduling profile and
ok-linux kubevirt OS profile. These are preview details, not reservations or
runtime verification.

## Community Preview provisioning constraint

Only one cluster provisioning operation may run against the management
cluster's shared network allocation pool at a time. This single-writer rule
also covers provisioning performed outside the OpenKubes CLI, including direct
Make workflows. The current live inventory check observes allocated addresses;
it is not an atomic IP reservation. Concurrent independent provisioning can
therefore still select the same address and cause a collision. This is an
operational Community Preview limitation, not a technical concurrency
guarantee: operators must coordinate all provisioning against that pool.

## M2b provision/destroy topology contract

M2b operator provisioning supports **same-plane only**: the explicitly selected
management Kubernetes API also hosts KubeVirt/CDI/Longhorn. No external
`infraClusterSecretRef` is accepted in the resolved config, render or live
KubevirtCluster. This does not add split-plane provisioning. Existing split-plane
CLI destruction retains its distinct-plane checks and schema-2 contract.

Provision now requires `ok cluster provision --topology same-plane -f <request>
--workload-kubeconfig <private-dir>/<name>.yaml`. Set `TALOS_INFRA_KUBECONFIG`
explicitly to the reviewed private kubeconfig. Context, HTTPS endpoint, CA trust
and live `kube-system` UID must remain stable across both confirmation gates.
Neither ambient kubeconfig selection nor auth plugins/impersonation are allowed.
The original Make/profile revisions and Cilium chart digest remain pinned; the
reviewed same-plane lifecycle extension is separately content-pinned in the CLI.
Rebuild the CLI from the reviewed final commit; an old binary is insufficient.

Before apply, `.same-plane-lifecycle.json` privately preserves the original
resolved config, Secret-free render, content hashes and public API identity.
The opt-in Make bootstrap (`TALOS_LIFECYCLE_TOPOLOGY=same-plane`, always passed
by the CLI) revalidates immediately before apply and captures original Cluster
and namespace UIDs in `.same-plane-provisioned.json` immediately afterward,
before waiting for provisioning. All these files must be retained. A failed
capture/apply requires operator review; no reconstruction, replay or automatic
recovery is provided. The existing interrupted pre-apply scaffold must not be
regenerated: separately review the updated preflight and continuation command
before any live continuation. The old approved command is not grandfathered in.

After independent provision verification and **separate deletion approval**, use:

```text
ok cluster destroy <name> --topology same-plane \
  --management-kubeconfig <reviewed-kubeconfig> \
  --provider-kubeconfig <same-reviewed-kubeconfig> \
  --lifecycle-root <reviewed-ok-cluster> --cluster-dir <original-render-dir> \
  --ok-linux-path <pinned-ok-linux>
```

The two explicit selections must match context, cluster reference, endpoint, CA
and live plane UID; merely naming files alike is insufficient. Destruction
requires the original public artifacts and original applied UIDs. Schema 3
records those identities, the namespace UID, Golden identity, and each PVC UID,
PV UID/claimRef, Longhorn CSI volumeHandle and Longhorn volume UID. It never
reinterprets schema 1 or 2 or adopts replacement storage. Namespace-layout
schema annotation `1` remains unchanged. Records are persisted/read back before
deletes; every mutation revalidates API/artifact/resource identity. Normal CAPI
foreground reconciliation precedes namespace deletion; finalizers are never
stripped. Storage requires released PVs, detached Longhorn volumes, stopped
engines and no PVC/CSI/ticket consumers. Longhorn failures are fatal. Bounded
backend observation (at most ten minutes) must prove PV, volume, engine,
replica, snapshot and attachment CR absence before independent repeated absence
reads permit a complete receipt. Local evidence is always preserved. Schema-3
records cannot be pruned by the legacy receipt-prune command.

Operators must arrange usable cleanup credentials outside the target namespace
for the entire test, verify controller readiness and two-replica capacity for the
selected Golden Image, install/verify the durable management ledger separately,
and coordinate exclusive allocation access. Preflight checks current cleanup
permissions; it cannot guarantee future credentials, controller health or
exclusive access by external operators. No credentials/RBAC are installed or
repaired by this flow. Golden Images and foreign snapshots/storage are excluded.
Logical Kubernetes absence is independently checked; physical storage-device
forensics are not asserted by a CR receipt.

Required live acceptance remains **Provision → Verify → Destroy → Verify absence**.
Offline regression success does not authorize a live run or demonstrate live
acceptance. No live provisioning resumes until this updated contract and test
results have been independently reviewed.
