# `ok local` MVP safety contract

This document records the first implementation boundary for a local kind
cluster hosting the OpenKubes Console development/demo profile.

## PR 1: ownership and command foundation

The `ok` binary owns the command entry point. Local state is stored beneath
`<user-config-dir>/ok/local/clusters/<name>` in private directories (`0700`)
and files (`0600`). Each managed cluster will have its own kubeconfig at that
path. Local status and cleanup must pass both `--kubeconfig` and the exact
`kind-<name>` context; the user's global/current context is never used.

The ownership receipt contains a fresh 128-bit random owner identifier, a
Kind cluster name derived from the logical name and full owner ID, the Docker
context/Unix endpoint/daemon ID, exact Kind node container IDs/names/roles, the
`kube-system` namespace UID, and exact Kubernetes node names/UIDs. The owner ID
is injected as `cli.openkubes.io/local-owner` in the Kind node configuration.
The receipt alone never authorizes deletion: status/down recheck provider
identity, Kind's container labels and immutable container IDs, the owner label,
all node UIDs, and namespace UID through the isolated kubeconfig. Calls that
inspect or delete Kind resources pin `DOCKER_HOST` directly to the recorded
local Unix socket and force Kind's Docker provider, avoiding a mutable Docker
context-name lookup. A changed context, daemon, endpoint, container ID, or
Kubernetes identity fails closed.

The full random ID in the actual Kind name makes accidental reuse of a logical
name target a different cluster name. The final deletion still uses
`kind delete cluster --name <owner-derived-name>`: Kind offers no compare-and-
delete API accepting the expected node container IDs. There remains a narrow
race if an external actor with access to the same Docker daemon deletes and
recreates that exact owner-derived Kind name after the last identity check but
before Kind selects containers. Pinning the context, checking daemon and
container IDs immediately before delete, and using a 128-bit random name make
this an unlikely out-of-band race; the Kind CLI cannot eliminate it. The CLI
does not bypass Kind with direct `docker rm`, since that would duplicate
lifecycle behavior and could leave Kind resources inconsistent.

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
forwarder on exit. It does not yet create the owner-labeled node configuration
or PR 1 ownership receipt. PR 2 must add explicit config and isolated kubeconfig
inputs, use the owner-derived Kind name, and let `ok` retain the verified
cluster. Kind v0.33.0 on the current Apple Silicon workstation supports
`kind create cluster --config/--kubeconfig`, `kind get kubeconfig --name`, and
`kind delete cluster --kubeconfig/--name`. The Console repository has historical
evidence on Kind v0.17.0 and test mocks at v0.25.0, but no declared minimum
supported version. PR 2 must establish and test a minimum version before
claiming compatibility; the exact isolated-receipt integration is not yet
verified against those older versions.

The current verifier marks a cluster created only after `kind create` returns
success. If Kind partially creates nodes and then returns nonzero, its exit
trap will not delete them because the `created_cluster` flag is still false;
that leaves partial Docker containers without an ownership receipt today. PR 2
must persist a durable `CREATING` intent before invoking Kind and only recover
or clean up when provider, owner labels, and exact container IDs prove ownership.
Otherwise it must stop for manual inspection and must not replay `up`.
After successful create, the verifier's default exit cleanup deletes the cluster
unless `OK_CONSOLE_KEEP_CLUSTER=true`; the CLI integration must set this to
true. A failed Kind cleanup may remove only some nodes. The CLI must retain its
receipt, report incomplete cleanup, and avoid automatic retries. Because the
recorded container set will no longer match after a partial removal, PR 1's
`down` intentionally stops rather than issuing another name-based delete. The
remaining containers and Kind metadata require explicit manual inspection or a
separately reviewed recovery operation; no such recovery command is part of
this MVP.

The CLI will manage a loopback
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
delete a cluster. Regression tests also reject changed Docker contexts and
replacement container IDs, including a replacement observed after confirmation.
CI must not create/delete kind clusters or deploy Console.
The first real kind/Console acceptance run is a separate operator action after
PR 2 is reviewed; this PR itself performs no live cluster operation.
