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
