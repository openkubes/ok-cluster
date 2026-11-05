# `ok local` MVP safety contract

This document records the first implementation boundary for a local kind
cluster hosting the OpenKubes Console development/demo profile.

## PR 1: ownership and command foundation

The `ok` binary owns the command entry point. Local state is stored beneath
`<user-config-dir>/ok/local/clusters/<name>` in private directories (`0700`)
and files (`0600`). Each managed cluster will have its own kubeconfig at that
path. Local status and cleanup must pass both `--kubeconfig` and the exact
`kind-<name>` context; the user's global/current context is never used.

The ownership receipt contains a fresh 128-bit random owner identifier, the
`kube-system` namespace UID, and the exact node names/UIDs observed after
creation. The owner identifier is also injected as the
`cli.openkubes.io/local-owner` Kubernetes node label in the kind configuration.
The receipt alone never authorizes deletion: status/down compare the owner label,
all node UIDs, and namespace UID against the live API through the private
kubeconfig. A missing, malformed, changed, or unverified identity fails closed.

PR 1 adds the command surface and offline ownership checks. `ok local up` is
deliberately disabled until the separately reviewed Console integration in PR 2
can create the isolated kubeconfig and write the ownership receipt. `status`
can report only cluster ownership in PR 1; Console health and a retained local
URL arrive with PR 2. No kind cluster operation runs in CI.

## PR 2: Console integration

`ok local up` will invoke the existing
`ok-console/deploy/kubernetes/verify-local-kind.sh` and
`ok-console/deploy/kubernetes/overlays/local-kind` workflow. The profile uses
fixture/demo authentication and does not install production identity,
PostgreSQL, or production credentials. The verifier's clean-source-tree check
remains in force.

The verifier currently creates a cluster using the default kubeconfig behavior,
tests reachability through a short-lived loopback port-forward, and stops that
forwarder on exit. PR 2 must minimally add explicit isolated kubeconfig/config
input support and retain the verified cluster. The CLI will manage a loopback
forwarder with a process identity containing the owner ID, executable,
start-time identity, and argument digest. A PID is only a lookup hint: the CLI
must re-check the whole process identity before signaling it. `down` re-verifies
cluster ownership after user confirmation, stops only that verified forwarder,
and then uses kind to delete only the exact managed cluster.

Ambiguous partial installs are reported and retained for explicit inspection;
`up` does not replay an incomplete install automatically. No OK-147 CreateCluster
operation, privileged runner gate, Community Preview installer change, or
separate provisioning engine is part of this workflow.

## Commands

```text
ok local up [--name ok-local]
ok local status [--name ok-local] [--json]
ok local down [--name ok-local]
```

The profile and Console port are fixed for the MVP: `local-kind` and
`127.0.0.1:18787`. Cleanup requires an interactive `ok`/`no` confirmation.

## Verification boundary

Offline tests mock kind/kubectl command results and prove that absent state,
invalid state, unowned clusters, identity drift, or missing confirmation never
delete a cluster. CI must not create/delete kind clusters or deploy Console.
The first real kind/Console acceptance run is a separate operator action after
PR 2 is reviewed; this PR itself performs no live cluster operation.
