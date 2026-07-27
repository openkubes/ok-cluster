# Longhorn orphaned volumes — `longhorn-orphan-reaper.sh`

> **Symptom:** a fresh cluster's VM disk PVC stays `Pending` indefinitely; the
> CDI importer pod hangs `ContainerCreating`; `kubectl describe pvc` shows
> `FailedAttachVolume ... volume ... is not ready for workloads`, or Longhorn
> reports `robustness: faulted` with condition
> `ReplicaSchedulingFailure: disks are unavailable;insufficient storage;precheck new replica failed` —
> **even though `df -h` on the node shows plenty of free disk space.**
>
> Root cause discovered and fixed live: [OK-118](https://kubernauts.atlassian.net/browse/OK-118).

## Why this happens

`ok-storage-block` (the default Longhorn StorageClass, see the `ok-storage`
repo / [ADR-Platform-009](../../openkubes/architecture/decisions/ADR-Platform-009-storage-contract.md))
uses `reclaimPolicy: Retain` **by design** — it protects VM disks from
accidental data loss if a PVC is deleted. `make teardown` already cleans up
Retain-policy PVs and their Longhorn volumes, but only for PVCs still present
in the torn-down cluster's namespace *at teardown time*.

KubeVirt's CDI (Containerized Data Importer) creates its own transient
`prime-*` / `prime-*-scratch` PVCs while importing a VM disk image. CDI
deletes these itself once the import completes — **before `make teardown`
ever runs** — so `make teardown`'s cleanup loop (which reads
`kubectl get pvc -n $CLUSTER`) never sees them. The underlying Longhorn
`Volume` object is left behind: the k8s PVC is gone
(`status.kubernetesStatus.lastPVCRefAt` gets set), but the Volume itself
survives forever.

## Why it's silent until it isn't

Longhorn's scheduler tracks committed replica size (`storageScheduled`) per
disk, separately from actual on-disk usage. Every orphaned volume still
counts against that budget. Once `storageScheduled` exceeds
`storageMaximum - storageReserved` (a per-disk threshold, default reserves
~30%), Longhorn refuses to schedule **any new replica** on that disk — even
though the physical disk is nearly empty. This surfaces as a completely
unrelated-looking failure on whatever cluster happens to be provisioned next.

On 2026-07-27, **61 orphaned volumes** were found accumulated across the
fleet — some over 3 weeks old, several in namespaces that no longer exist at
all (`ok1-talos`, `ok2-rmf`, `ok3-openclaw`) — accounting for ~900GB of
phantom scheduling budget. That was enough to fully block new replica
placement on `ok-infra` and stall an unrelated cluster's control-plane disk
for 75+ minutes before the cause was traced back here.

## Diagnose

```bash
kubectl --kubeconfig ~/.kube/ok-infra.yaml -n longhorn-system get volumes.longhorn.io -o json | jq -r '
  .items[]
  | select(.status.state=="detached")
  | select(.status.kubernetesStatus.lastPVCRefAt != "" and .status.kubernetesStatus.lastPVCRefAt != null)
  | .metadata.name'
```

Any hit here is a candidate orphan — cross-check its `status.kubernetesStatus.namespace`
against `kubectl get ns` and `kubectl get pvc -n <ns>` to confirm the PVC is
really gone, not just mid-flight.

## Clean up — `longhorn-orphan-reaper.sh`

```bash
# Dry-run: list orphans older than 24h (default), nothing is deleted
./longhorn-orphan-reaper.sh

# Actually delete
CONFIRM=yes ./longhorn-orphan-reaper.sh

# Tighter/looser age gate, protect a specific in-flight cluster's namespace
MIN_AGE_HOURS=1 EXCLUDE_NAMESPACES=ok-obs-verify ./longhorn-orphan-reaper.sh
```

The `MIN_AGE_HOURS` gate (default 24h) exists because a volume can briefly
show the exact same "detached + `lastPVCRefAt` set" signature while a cluster
is actively being provisioned right now (CDI's prime/scratch PVCs cycle
through create → use → delete within minutes) — without the age gate, this
script could delete a volume that belongs to a build in progress.

## Structural fix — not done here

A dedicated `ok-storage-block-ephemeral` StorageClass (`reclaimPolicy: Delete`)
for throwaway/verify clusters was considered but deliberately **not** built as
part of this fix — it would extend the documented `ok-storage` contract
(new class in the `ok-storage` repo, README/ADR-Platform-009 update, its own
verify test), which is a bigger decision than a cleanup script. Tracked as a
follow-on option in [OK-118](https://kubernauts.atlassian.net/browse/OK-118)
if the reaper script turns out not to be enough on its own.
