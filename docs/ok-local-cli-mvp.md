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

PR 1 added the command surface and offline ownership checks. PR 2 enables the
local integration, but CI remains mock-only and does not create kind clusters.

## PR 2: Console integration

`ok local up` invokes the existing
`ok-console/deploy/kubernetes/verify-local-kind.sh` and
`ok-console/deploy/kubernetes/overlays/local-kind` workflow. The profile uses
fixture/demo authentication and does not install production identity,
PostgreSQL, or production credentials. The verifier's clean-source-tree check
remains in force. The CLI requires Docker, kind, kubectl, Bash 4.4+, and a
clean local `ok-console` checkout; select it with `OK_CONSOLE_DIR` or discover
it as a sibling of the current directory. Bash 4.4+ and Kind 0.33.0+ are
required for the CLI integration (Kind 0.33.0 is the oldest version verified
with the explicit config/kubeconfig flags). Git revision and clean-tree checks
run before writing state or contacting Docker, so a dirty Console tree
(including untracked files) blocks without leaving a run intent.

Before invoking the verifier, the CLI stores and fsyncs a private `CREATING`
intent, owner-specific Kind config and an absent isolated kubeconfig path. The
verifier accepts `OK_CONSOLE_KIND_CONFIG` and `OK_CONSOLE_KUBECONFIG` together,
exports the latter as `KUBECONFIG`, and passes both explicit paths to Kind. The
CLI passes `OK_CONSOLE_MIN_KIND_VERSION=0.33.0`, pins the Docker Unix endpoint
and forces the Docker provider. Read-only
inspection of Kind v0.33.0 on this workstation confirms the `create cluster
--config/--kubeconfig` options; older verifier environments were not verified.
No real cluster was created during implementation.

If Kind or the verifier fails after `CREATING` is durable, the CLI writes
`INCOMPLETE`, performs no retry and does not auto-delete. `status` reports this
state locally without cluster contact; `down` refuses because complete owner
evidence is not yet available. The operator must inspect partial Docker/Kind
resources manually. After verifier success, the CLI captures and validates
provider identity, exact owner-labeled node containers, isolated kubeconfig,
Kubernetes node UIDs and `kube-system` UID before advancing to `CLUSTER_READY`.

The verifier retains its short-lived health-check forwarder and exits without
deleting the cluster. The CLI then starts a persistent forwarder bound only to
`127.0.0.1:18787`, records owner ID, executable, process start time and command
digest, and checks `/health/live`, `/health/ready` and `/`. It prints the URL
only after all checks pass. `status` repeats ownership checks, verifies the
recorded process identity and health, and reports the URL only when healthy.
`down` requires a TTY and exact `ok` confirmation, stops only a forwarder whose
recorded identity matches, waits for that process to exit, rechecks ownership, then invokes Kind's name-based
delete and verifies cluster/container removal. Kind has no compare-and-delete
API; local PID verification also has a narrow check-to-signal race on platforms
without process-handle signaling. The CLI repeats the full identity check
immediately before signaling and treats a process that exits during cleanup as
absent; a tiny OS-level check-to-signal window remains documented.

If the recorded PID is provably absent (for example after reboot or unexpected
exit), `down` clears only the stale forward receipt and continues after
rechecking cluster ownership. If the PID exists but its start time, executable
or argument digest differs, it is classified as reused: the CLI never signals
it, clears the stale receipt and continues. If the PID exists but cannot be
inspected, deletion remains stopped until identity can be resolved.

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

Offline tests mock kind/kubectl results and prove that absent state, invalid
state, unowned clusters, identity drift, incomplete installs, verifier failure,
or missing confirmation never delete a cluster. Regression tests reject
changed Docker contexts and replacement container IDs. Console verifier tests
cover paired isolated paths, absent kubeconfig destination, explicit Kind
arguments, the minimum Kind version and KUBECONFIG routing.
CI must not create/delete kind clusters or deploy Console.
The first real kind/Console acceptance run is a separate operator action after
PR 2 is reviewed; this PR itself performs no live cluster operation.

### macOS verifier-test portability follow-up

On the M5 workstation, the full `ok200.test.ts` run on PR #150 had 10 failures
in the existing failure-capture tests. Running the same test file at its PR
base (`d68e486`) reproduced those temporary-directory/capture-path failures
and two additional failures caused by a test fixture hard-coding macOS system
Bash 3.2. PR #150 now resolves Bash from the active test PATH, fixing that
fixture issue. GitHub's complete `verify` workflow passes. The remaining local
failures expect `mktemp -d -t` artifacts under an overridden per-test `TMPDIR`,
while macOS places the capture artifacts under a different temporary root.
Recommend a separate Console test-portability change that injects the capture
directory or asserts its platform-specific path contract; this is unrelated to
isolated kubeconfig integration.
