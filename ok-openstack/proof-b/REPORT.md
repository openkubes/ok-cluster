# OK-106 Proof B — CAPO/Talos workload provisioning (reviewable spike)

**Surface:** native ok-cluster template path (`make`/`render.py` + `templates/talos`), per decision. **Scope:** static render only — no provisioning, no XRD/runner change, no real OpenStack env.

**Base:** branch `ok-106-capo-provider-selection` @ `631e2df` (Proof A). Proof B adds one render.py hunk + one new template.

## Key architectural result

The native talos workload path already uses **`TalosControlPlane`** (not Kubeadm). So the Kubeadm→Talos concern never applied here — it lived only in the historical `capi-platform-v4.2` runner. Proof B therefore only had to swap the **infrastructure** objects:

| provider-neutral core (identical) | KubeVirt infra | OpenStack infra |
|---|---|---|
| Cluster, TalosControlPlane, TalosConfigTemplate, MachineDeployment | KubevirtCluster, KubevirtMachineTemplate | OpenStackCluster, OpenStackMachineTemplate |

Rendered kind sets are exactly parallel:
- **openstack:** Namespace, Cluster, OpenStackCluster, TalosControlPlane, TalosConfigTemplate, MachineDeployment, OpenStackMachineTemplate ×2
- **kubevirt:** Namespace, Cluster, KubevirtCluster, TalosControlPlane, TalosConfigTemplate, MachineDeployment, KubevirtMachineTemplate ×2

## endpointIP TODO — resolved

KubeVirt used a MetalLB LoadBalancer service (`endpointIP`). OpenStack uses **Octavia** via `OpenStackCluster.spec.apiServer.managedLoadBalancer.enabled: true` — no `endpointIP` needed. This is the concrete Proof-B resolution of the endpoint model.

## What changed

- `render.py` (1 hunk): for `type: talos`, a non-kubevirt `provider:` renders its self-contained manifest set from `templates/talos/providers/<provider>/` instead of the KubeVirt base. `provider: kubevirt` (default) leaves `templates/talos` **untouched** — zero regression. Plus OpenStack Provider Values added to the render context (image, flavors, external network, cloud, sshKey, DNS, subnet, credentials secret) with defaults.
- `templates/talos/providers/openstack/cluster.yaml.tpl` (new): the CAPO/Talos manifest, field shapes grounded in CAPO v1beta2 upstream (`identityRef`, `flavor.filter`/`image.filter`, `sshKeyName`, `apiServer.managedLoadBalancer`).

## Static validation — 11/11 PASS (kind-parsed, comment/image-URL false positives excluded)

Valid multi-doc YAML (both); openstack kind set exactly as expected; **no** Kubevirt/Kubeadm kinds; **no** `endpointIP`/`metallb` fields; has Octavia `managedLoadBalancer` + `identityRef`; no inline Secret (credentials stay out-of-band); kubevirt regression render still yields KubevirtCluster + TalosControlPlane, no OpenStack kinds.

## Deliberate spike trade-offs (review)

- **Non-DRY:** the openstack file duplicates the provider-neutral core rather than sharing it with `cluster-base.yaml.tpl`. Chosen for zero risk to the KubeVirt path and single-file reviewability. A DRY factoring (shared core + infra fragment) is a follow-up once the proof is accepted.
- Credentials: `identityRef` references an out-of-band Secret (`<cluster>-cloud-config`); no credential API invented (consistent with Proof A's CAPO fragment).

## Explicitly NOT done

- No provisioning; no real OpenStack tenant touched.
- OpenStack cloud-provider (OCCM) + Cinder CSI = separate capability contracts (marked TODO in the template).
- Talos bootstrap delivery on OpenStack (config drive) validated only at provisioning time (Proof B+).
- XRD/Composition/`KubeVirtClusterClaim` naming untouched (other surface).

## Files

- `diff-render-vs-631e2df2ba50.patch` — the render.py hunk.
- `source-changes/` — patched render.py + new openstack template.
- `rendered/openstack/cluster.yaml`, `rendered/kubevirt/cluster-base.yaml` — the two rendered outputs.
