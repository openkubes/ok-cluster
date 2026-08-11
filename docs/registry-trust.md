# Talos registry trust (`registry.ok-shared.internal`)

This is an opt-in Talos building block. It gives every node in one cluster the
same two settings:

```yaml
machine:
  registries:
    config:
      registry.ok-shared.internal:
        tls:
          ca: <base64-encoded ok-shared-internal-ca>
  network:
    extraHostEntries:
    - ip: <discovered ingress address>
      aliases:
      - registry.ok-shared.internal
```

The committed fragment contains placeholders only. The CA, concrete address,
and Talos client configuration are read at execution time and kept in memory or
anonymous file descriptors.

## Why this shape

`machine.registries.config` is the trust decision. `extraHostEntries` is the
temporary name-resolution mechanism until internal DNS exists. A registry
mirror would mean "redirect this image namespace to a different endpoint"; it
does not express trust, does not copy artifacts, and a literal-IP mirror would
break the registry certificate's hostname and Traefik Host/SNI routing.

Use the ingress address published for `ok-shared` on the infrastructure
cluster, not the Traefik ClusterIP inside `ok-shared`. A kubelet pull originates
in the node host namespace; ClusterIP reachability there depends on Cilium's
service programming and is not a portable inter-cluster contract. The
infrastructure ingress path is the established host/SNI path and is usable by
all consuming clusters. The tooling discovers the address in this order:

1. `REGISTRY_ADDRESS` operator override;
2. one IPv4 answer from DNS;
3. exactly one IPv4 address in the configured infrastructure Service status.

When that address moves, existing static host entries remain stale until this
target is rerun. Real DNS removes that reconciliation requirement. A mirror
pointed at a literal address would also need reconfiguration when it moves.

## New clusters

Opt in while scaffolding:

```bash
make new CLUSTER=<consumer> TYPE=talos REGISTRY_TRUST=true
make bootstrap CLUSTER=<consumer>
```

`bootstrap` fetches the CA and address, hydrates both the `TalosControlPlane`
and worker `TalosConfigTemplate` patches in memory, and applies that manifest to
ok-infra. A cluster without `registryTrust.enabled: true` still applies its
original committed manifest byte-for-byte. Existing parent-level registry and
host-entry patches are merged without losing mirrors, auth, or unrelated
aliases. A nested patch under either owned parent is rejected with a request to
consolidate it first, because appending a parent operation would make the result
order-dependent.

## Existing `ok-shared`: Arash-only runtime procedure

The commands below require Talos node access. They have not been run by the
author of this change and must not be treated as acceptance evidence until
Arash runs them.

Prerequisites are `~/.kube/ok-shared.yaml`, `~/.kube/ok-infra.yaml`, and
`talosctl` v1.9.5. The target dynamically selects every CAPI Machine in
namespace `ok-shared` (the control plane and all workers); do not patch only the
node chosen for the proof Pod, because rescheduling must retain the
cluster-level capability. Replacement-node handling is called out after the
apply step because the existing worker bootstrap template is immutable.

1. Review the exact hydrated patch and prove the TLS/SNI route before any Talos
   call:

   ```bash
   make talos-registry-trust-review CLUSTER=ok-shared
   ```

   Expected: the registry `/v2/` probe succeeds and Talos v1.9.5 validates
   complete control-plane and worker configs. The command prints the exact
   runtime patch; it contains the public CA and discovered estate address, so
   review it but do not commit or attach it as a file.

2. Ask the live Talos API whether the exact change is accepted without reboot:

   ```bash
   make talos-registry-trust-dry-run CLUSTER=ok-shared
   ```

   The effective invocation uses anonymous descriptors, not secret files:

   ```text
   talosctl patch machineconfig \
     --talosconfig /proc/self/fd/<fd> \
     --nodes <one-discovered-machine-InternalIP> \
     --patch-file /proc/self/fd/<fd> \
     --mode no-reboot --dry-run
   ```

   Talos documents both `.machine.network` and `.machine.registries` as
   immediately applicable, but the live API response is authoritative. This
   target runs that invocation serially for every node and deliberately requests
   `no-reboot`: if any node rejects it or reports
   that a reboot is required, stop. Do not substitute `auto` or `reboot`; decide
   that live-cluster cost separately.

3. Apply once, behind the explicit gate. The target repeats the same
   `no-reboot` dry-run immediately before the real call:

   ```bash
   make talos-registry-trust-apply \
     CLUSTER=ok-shared \
     REGISTRY_TRUST_APPLY=yes
   ```

   After every node's dry-run passes, the final per-node invocations are
   identical to the text above without `--dry-run`.
   Expected: all four current CAPI Machines are reported patched without a
   reboot.

   This deliberately does not mutate the existing CAPI bootstrap objects:
   `TalosConfigTemplate.spec` is immutable, and changing the worker template
   reference would initiate a rollout. If a replacement Machine is created
   before this cluster is recreated from the opt-in manifest, rerun the same
   target for the newly discovered node. The target is idempotent. A failure
   midway leaves already reported nodes configured and later nodes unchanged;
   correct the reported failure and rerun to converge all nodes.

4. Read the configuration back from each discovered node. Keep the talosconfig
   in a pipe, not a file:

   ```bash
   nodes="$(kubectl --kubeconfig ~/.kube/ok-infra.yaml -n ok-shared \
     get machines -l cluster.x-k8s.io/cluster-name=ok-shared -o jsonpath='{range .items[*].status.addresses[?(@.type=="InternalIP")]}{.address}{","}{end}' | sed 's/,$//')"
   talosctl --talosconfig <(
     kubectl --kubeconfig ~/.kube/ok-infra.yaml -n ok-shared \
       get secret ok-shared-talosconfig -o jsonpath='{.data.talosconfig}' | base64 -d
   ) --nodes "$nodes" get machineconfig -o yaml |
     yq '.spec.machine | {registryCAConfigured: (.registries.config."registry.ok-shared.internal".tls.ca != null), extraHostEntries: [.network.extraHostEntries[] | select(.aliases[] == "registry.ok-shared.internal")]}'
   ```

   Before the application those two entries are absent. Afterwards every node
   must show the registry CA setting and exactly one alias mapping for the
   registry hostname.

## Kubelet-pull acceptance proof (Arash only)

Use a runnable image pushed into the registry and pin the Pod by digest. Before
creating the Pod, choose its node and prove that digest is absent from that
node's Talos image list:

```bash
NODE=<worker-kubernetes-node-name>
NODE_IP=<that-node-InternalIP>
IMAGE='registry.ok-shared.internal/openkubes/staging/ok138-kubelet-pull@sha256:<pushed-digest>'
images="$({ talosctl --talosconfig <(
  kubectl --kubeconfig ~/.kube/ok-infra.yaml -n ok-shared \
    get secret ok-shared-talosconfig -o jsonpath='{.data.talosconfig}' | base64 -d
) --nodes "$NODE_IP" images; })" || {
  echo 'could not prove the node image inventory' >&2
  exit 1
}
if grep -F 'sha256:<pushed-digest>' <<<"$images"; then
  echo 'digest is already cached; push/select another digest' >&2
  false
fi
```

The digest must come from the registry's own push result. Use a new run/repo or
new image config, and keep the push transcript. Record Zot's request counter or
log position before creating the Pod so a new manifest request can be
correlated with this pull.

```bash
cleanup() {
  kubectl --kubeconfig ~/.kube/ok-shared.yaml delete pod ok138-kubelet-pull \
    --ignore-not-found --wait=true
}
trap cleanup EXIT INT TERM
kubectl --kubeconfig ~/.kube/ok-shared.yaml create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ok138-kubelet-pull
  namespace: default
spec:
  nodeName: ${NODE}
  restartPolicy: Never
  containers:
  - name: proof
    image: ${IMAGE}
    command: ["sh", "-c", "sleep 600"]
EOF
kubectl --kubeconfig ~/.kube/ok-shared.yaml wait \
  --for=jsonpath='{.status.phase}'=Running pod/ok138-kubelet-pull --timeout=2m
image_id="$(kubectl --kubeconfig ~/.kube/ok-shared.yaml get pod ok138-kubelet-pull \
  -o jsonpath='{.status.containerStatuses[0].imageID}')"
test "${image_id##*@}" = 'sha256:<pushed-digest>'
kubectl --kubeconfig ~/.kube/ok-shared.yaml delete pod ok138-kubelet-pull --wait=true
trap - EXIT INT TERM
```

Pass requires all of: phase `Running`, `imageID` equal to the pushed digest, the
pre-check showing that digest was not cached on the selected node, and a new
correlated Zot request/metric. Delete the Pod afterward.

Failure is diagnostic:

- `dial tcp ... timeout`, `no route to host`, or `connection refused`: the
  chosen host-network ingress path is not reachable; this is the signal that
  the ingress-VIP choice is wrong for the node namespace.
- `x509: certificate signed by unknown authority`: the CA did not land or is
  not the issuer used by the registry.
- `x509` hostname/SAN error: traffic reached TLS through the wrong name/path.
- `401` or `403`: DNS/routing/TLS succeeded; fix image-pull authorization.
- `manifest unknown`: the repository or pushed digest is wrong.

Do not claim OK-138's workload-pull criterion from local validation, CAPI
hydration, a Talos dry-run, or a cached image. The criterion is met only by the
uncached real Pod proof above.
