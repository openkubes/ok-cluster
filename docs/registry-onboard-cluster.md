# Onboard a cluster to registry-default (zot) trust

This procedure onboards a **new consuming cluster** — one that is not `ok-shared` itself — to
`registry-default`'s TLS endpoint, so its kubelets can pull images from
`registry.ok-shared.internal` by digest.

It is the building block ADR-Platform-028 §4.11 records: onboarding is **opt-in per cluster**,
not a fleet-wide trust push. `docs/registry-trust.md` covers the Talos mechanism itself (the
CA/host-alias patch and its recreate/recovery considerations); this runbook is specifically about
applying that mechanism to a cluster other than `ok-shared`, which — before this runbook existed —
had never been exercised. `ok-ai` was the first cluster onboarded this way.

## Prerequisite: two kubeconfigs are not the same thing

`scripts/talos_registry_trust.py` needs two separate kubeconfigs, and conflating them is exactly
the bug this runbook exists to prevent recurring:

- **`REGISTRY_CA_KUBECONFIG`** — the cluster that hosts the registry and its CA. This is
  `ok-shared` for every onboarding, regardless of which cluster you are onboarding.
- **`TALOS_WORKLOAD_KUBECONFIG`** — the cluster you are onboarding (`--cluster`/`CLUSTER=`). Its
  Nodes are what get looked up to find each CAPI Machine's InternalIP.

For `ok-shared` onboarding itself these coincide, which is why the distinction went unnoticed for
every prior run. For any other cluster they do not, and passing the wrong one fails cleanly with
`kubectl get node` unable to find the workload cluster's node names — it does not silently patch
the wrong cluster, but it does mean **both flags must always be given explicitly** from this point
on.

## 1. Get the target cluster's kubeconfig onto `ok-infra`

The trust tooling runs from `ok-infra`, which already holds CAPI Machine data and Talos API
reachability for every managed cluster.

```bash
scp ~/.kube/<cluster>.yaml root@<ok-infra-ip>:/root/.kube/<cluster>.yaml
```

## 2. Add the `registryTrust` block to the cluster's config

Edit `<cluster>/cluster-config.yaml` (in `ok-cluster`, on your machine, then commit and push — the
tooling runs from `ok-infra`'s checkout, so it must `git pull` first):

```yaml
registryTrust:
  enabled: true
  host: registry.ok-shared.internal
  caSecret:
    namespace: cert-manager
    name: ok-shared-internal-ca
    key: ca.crt
  address:
    serviceNamespace: ok-shared
    serviceName: ok-shared-ingress
  talosconfigSecret:
    namespace: <cluster>
    name: <cluster>-talosconfig
    key: talosconfig
```

`caSecret` and `address` are always the same three values above — they point at where the registry
and its ingress actually live, not at the cluster being onboarded. Only `talosconfigSecret`
changes per cluster: it is read from `ok-infra` (the management cluster), where CAPI stores each
workload cluster's talosconfig as `<cluster>-talosconfig` in the `<cluster>` namespace. Confirm the
secret exists before editing the config:

```bash
kubectl --kubeconfig ~/.kube/ok-infra.yaml -n <cluster> get secret <cluster>-talosconfig
```

Commit, push, then on `ok-infra`:

```bash
root@ok-infra ~/ok-cluster # git pull
```

## 3. Review — offline, no Talos call

```bash
root@ok-infra ~/ok-cluster # make talos-registry-trust-review CLUSTER=<cluster> \
  REGISTRY_CA_KUBECONFIG=~/.kube/ok-shared.yaml
```

Confirms the CA is readable, the registry address resolves (DNS first, else the `ok-infra`-published
LoadBalancer address per `docs/registry-trust.md`), the TLS/SNI probe against `registry.ok-shared.internal`
succeeds, and the rendered patch validates against a Talos v1.9.5 control-plane and worker config.
`review` does not need `TALOS_WORKLOAD_KUBECONFIG` — it never looks up the target cluster's Nodes.

## 4. Dry-run — contacts every CAPI Machine's Talos API, mutates nothing

```bash
root@ok-infra ~/ok-cluster # make talos-registry-trust-dry-run CLUSTER=<cluster> \
  REGISTRY_CA_KUBECONFIG=~/.kube/ok-shared.yaml \
  TALOS_WORKLOAD_KUBECONFIG=~/.kube/<cluster>.yaml
```

This is the first step that resolves the target cluster's own Nodes, so
`TALOS_WORKLOAD_KUBECONFIG` is required from here on. Expect one line per CAPI Machine:
`Talos API accepted --mode=no-reboot dry-run for all N CAPI Machines`.

## 5. Apply — patches every node, no reboot

```bash
root@ok-infra ~/ok-cluster # make talos-registry-trust-apply CLUSTER=<cluster> \
  REGISTRY_CA_KUBECONFIG=~/.kube/ok-shared.yaml \
  TALOS_WORKLOAD_KUBECONFIG=~/.kube/<cluster>.yaml \
  REGISTRY_TRUST_APPLY=yes
```

Expect a `readback PASS node=<ip>: registry CA and host alias landed` line per node, then
`apply succeeded for all N CAPI Machines without reboot`.

## 6. Prove a pod can actually pull

TLS trust alone is not sufficient — `openkubes/machine/**` repositories still require the
`zot-machine` htpasswd credential. Create a pull secret on the newly-onboarded cluster from
`ok-shared`'s machine identity:

```bash
root@ok-infra ~/ok-cluster # MACHINE_USER=$(kubectl --kubeconfig ~/.kube/ok-shared.yaml -n zot \
  get secret zot-machine-identities -o jsonpath='{.data.machine-username}' | base64 -d)
MACHINE_PASS=$(kubectl --kubeconfig ~/.kube/ok-shared.yaml -n zot \
  get secret zot-machine-identities -o jsonpath='{.data.machine-password}' | base64 -d)
kubectl --kubeconfig ~/.kube/<cluster>.yaml -n default create secret docker-registry ok138-registry-pull \
  --docker-server=registry.ok-shared.internal \
  --docker-username="$MACHINE_USER" \
  --docker-password="$MACHINE_PASS"
```

Then deploy a pod pinned to a known digest, referencing the pull secret:

```bash
cat <<'EOF' | kubectl --kubeconfig ~/.kube/<cluster>.yaml -n default apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: registry-onboard-pull-proof
spec:
  restartPolicy: Never
  imagePullSecrets:
  - name: ok138-registry-pull
  containers:
  - name: proof
    image: registry.ok-shared.internal/<repository>@<digest>
    command: ["sleep", "3600"]
EOF
```

PASS criterion: `kubectl describe pod` shows a `Pulled` event for the exact reference, and
`status.containerStatuses[0].imageID` matches the digest byte-for-byte. The container does not need
to reach `Running` for this proof — a `StartError` from a minimal/scratch test image missing the
requested command (as happened onboarding `ok-ai`, where the conformance fixture image has no
`sleep` binary) does not invalidate the pull proof; only the `Pulling`/`Pulled` events and the
`imageID` readback matter here. Delete the pod once confirmed.

## What this does not prove

- Only `openkubes/machine/**` access is exercised here. `openkubes/human/**` pulls require the
  puller to hold central Keycloak `registry-writers`/`registry-readers` group membership; that is
  unrelated to node-level TLS trust and is not covered by this runbook.
- Per ADR-Platform-028 §4.11: CA rotation requires redistributing the root to every opted-in
  consumer, and replacement Machines (autoscaling, node replacement, reset) do not inherit trust
  and need this procedure rerun until the cluster is recreated from an opted-in manifest.
- Static host-entry resolution is interim; every opted-in cluster needs reconciling whenever the
  ingress address changes, until OK-57 delivers DNS for the internal zone.
