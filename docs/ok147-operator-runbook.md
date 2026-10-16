# OK-147 bounded runner operator runbook

This runbook describes the historical execution profile and current security
gates of the bounded OK-147 runner.
It is an operational checklist, not standing authorization. Every live run must
bind one reviewed source revision, one immutable runner image, one activation
package digest and one separately approved execution window.

## Current execution gate

Private full-run manifest validation, preparation and live execution reject
unsupported certificate mode before Stage 1, API calls or grants. There is no
completing Stage 1–7 or Stage 1–12 / PlatformReady live workflow in this release.
Full-run activation Job launch is denied before API contact as well. Offline
snapshots/packages establish structural consistency, not execution readiness.
Bounded workload credential bootstrap, atomic recovery reservation and legacy
fencing remain open dependencies. ADR-030 item 9 remains OPEN.

## Scope

The runner performs one already-authorized `CreateCluster` transition and the
bounded post-runtime suffix. It is neither a long-running operator nor a
lifecycle source of truth. CAPI/CAPK, the selected Enablement mechanism and
GitOps remain the owners of convergence.

For the Bare-MVP completion mode, operators use the product CLI facade rather
than assembling stage commands manually:

```bash
ok cluster create requirements
ok cluster create manifest-template > /private/bare-run.template.json
ok cluster create plan-template > /private/staged-plan.template.json
ok cluster create --file /private/bare-run.json --dry-run
ok cluster create --file /private/bare-run.json --prepare
```

The canonical lifecycle command family is `ok cluster create` / `ok cluster destroy`.
`ok up` is an exact shorthand for `ok cluster create`, including its preparation
subcommands. For example:

```sh
ok up --file /private/bare-run.json --dry-run
ok up --file /private/bare-run.json --prepare
```

The shorthand only rewrites the command prefix. It does not infer a mode, use saved path-config credentials for create,
renew access, prompt for or implicitly grant live authority. Existing private JSON
manifest, Plan, digest, evidence and terminal-marker requirements are unchanged.
Live `ok up` still requires all of the `--live --execute` inputs described below.
Bare `ok up` displays help and performs no operation. There is no additional
`ok create cluster` spelling.

The manifest and seven-stage Plan templates are non-authorizing and
intentionally invalid until an authoritative renderer replaces every
placeholder and binds every referenced artifact. The Plan fixes
`authorizationState: NO-GO`. Do not hand-edit either template into a
substitute for reviewed renderer output.

For a new cluster the templates emit full-run manifest v3 and staged Plan v1.
They intentionally contain no `executionAttemptDigest`: Plan v2/manifest v4
is the additive recovery protocol for a previously consumed claim and must
bind reviewed predecessor or stopped evidence. Never manufacture that lineage
for a first run.

The manifest schema describes the seven-stage Bare-MVP boundary, but current
`--dry-run`, `--prepare` and `--live` reject its unsupported credential mode before
referenced inputs, stages or APIs are opened. No successful preparation receipt
is emitted. The twelve-stage workflow is also blocked. Templates and requirement
outputs remain non-authorizing structural interfaces; their historical stage
order and liveMutationAllowed fields do not establish runtime availability.

### Explicit lifecycle access paths

The local runner does not read an implicit management kubeconfig. Management
access is the exact endpoint, CA digest/CA file, bearer-token file and authority
identity bound by the private manifest. Provider access and the lifecycle-
derived guest access use separate absolute private kubeconfig paths. The guest
kubeconfig fields retain the historical schema, but the admin-Secret materializer
is disabled. The executor does not read that Secret or use its authority to
bootstrap a bounded credential. Templates
must not contain `~/.kube`, `$HOME` or another ambient fallback.

The repository-owned Talos lifecycle commands use the corresponding explicit
operator inputs `TALOS_INFRA_KUBECONFIG` and `GUEST_KUBECONFIG_DIR`. The Go
runner does not invoke those Make targets and must not reimplement their path,
resume or storage validation logic.

An unsupported manifest returns the explicit credential-policy error without a
successful --prepare receipt or a started executor. Do not interpret this as a
transient Stage-5 convergence failure. No new terminal marker is written for an
execution that did not start. Existing terminal evidence remains immutable.

The signer rejects all Stage-7/target-access issuance, including ordinary legacy
policies, because the old protocol lacks provenance distinguishing recovery.
Previously issued grants and old signer/executor deployments still need separately
authorized retirement/fencing. This fix alone does not revoke their authority.

## Friendly cluster YAML: offline intent and render only

This is a deliberately incomplete front end, not full-run preparation. It does
not replace the technical JSON manifest contract above. Start with:

```sh
ok up cluster-template > cluster.yaml
# Edit name and all network addresses; example addresses are not allocations.
ok up --file cluster.yaml --dry-run
ok up render --file cluster.yaml --output /private/new-render
```

The input is `cli.openkubes.io/v1alpha1`, kind `Cluster`, with `metadata.name`,
`spec.profile: talos-kubevirt-mvp` and explicit `spec.network.endpoint`, `podCIDR`
and `serviceCIDR`. See `examples/ok-cli-cluster.yaml`. The small profile fixes one
control plane and one worker, each with 2 cores, 4Gi memory and a 20Gi disk;
Kubernetes v1.34.1. Sizing overrides, other providers, automatic address allocation
and additional workers are not accepted in this first slice.

YAML fields are strict: unknown/duplicate keys, aliases/anchors, merge keys,
multiple documents and non-string values are rejected. The DNS name must be
non-reserved; explicit IPv4 endpoint and canonical non-overlapping IPv4 CIDRs
are required. No collision, IP availability or live profile/storage check is
claimed. Local syntactic validation returns `INTENT_VALIDATED_NO_GO`,
`runnerReady=false`, `apiContacted=false`, `authorizationConsumed=false`,
`mutationAllowed=false` and `collisionChecked=false`. It writes no files and
does not launch a child process.

The explicit `render` subcommand uses only the trusted lifecycle and ok-linux
paths (`--lifecycle-root` and `--ok-linux-path`, or saved local path configuration).
It does not read the referenced kubeconfig/credential contents. The small adapter
calls the existing owning `render.render_cluster` and
`profile_resolvers.talos.resolve_talos_config`; Go does not duplicate Talos,
Golden-image or storage validation. The online allocator/resolver, sockets and
child-process execution are disabled in that adapter. The output root must not
exist; failed/partial output is retained and never overwritten or retried.
All generated files, including shell helpers, are mode 0600; directories are
0700. Generated helpers are not run. The receipt binds rendered-file and owning
source/profile digests but remains `RENDERED_NO_GO` / `runnerReady=false`.

**Missing next step:** a reusable authoritative binder for Contract identity,
projection/fixture, seven-stage Plan, reviewed authority policies, private
credentials and independent evidence. The successful Candidate used one-off
operator helpers; those must not be replaced by copying old identities or by
loosening the runner's evidence requirements. Neither syntax validation nor
rendering supplies these bindings. Therefore friendly YAML `--prepare` and
`--live` fail closed without touching terminal markers or opening a runner.
No successful full-run preparation/provisioning is claimed.

Existing technical JSON inputs retain all previous modes and receipts (including
JSON manifests using a `.yaml`/`.yml` filename). No existing Candidate, receipt,
authority or terminal is rewritten by this front end. Interactive configuration,
live creation from friendly YAML and full binding remain separate follow-ups.

## Bare-MVP closure and ongoing provider access

Keep three different results separate in the operator handoff:

- **Execution outcome:** the exact seven-stage durable receipt chain verifies
  as completed. A successful process exit alone is not this proof.
- **Current convergence:** independently read the bound CAPI target and the
  profile-required workload/Enablement sources. Retain the observed generation,
  target identity and observation time. A later regression does not rewrite an
  earlier immutable receipt, but must prevent an unqualified current-health claim.
- **Access lifetime:** record the next known provider credential expiry in the
  private handoff, including its timezone. Current availability is not a promise
  that ongoing reconciliation will work after that deadline.

For `bare-cluster-mvp/v1`, completion ends after Stage 7. Do not require or imply
that Stages 8–12, GitOps registration, Platform applications or full aggregate
evaluation have run. Those belong to the separately bound full workflow below.

Following the PR #430 review, certificate execution and network-profile recovery
execution are disabled. The default lifecycle-derived create path is rejected before Stage 1,
which also blocks Stages 5–7 and downstream Stages 8–12 / PlatformReady.
Bounded credential bootstrap remains open. Offline recovery inspection is still
available, but `NEXT` grants no permission to execute. Do not work around the stop
with the CAPI admin kubeconfig, a new successor Plan, another grant or a local
STOP file. No atomic reservation/fencing protocol has been deployed.

See the [security follow-up contract](ok147-security-review-contract.md) for the
credential-bootstrap and source-ledger gate dependencies. Preserve original STOP
and terminal evidence. ADR-030 security acceptance item 9 remains open until the
fixes and evidence receive independent review; ADR-031 disaster-recovery
requirements are unchanged.

### Execution credentials are not lifecycle credential ownership

The external infrastructure kubeconfig installed for CAPK is an ongoing provider
dependency. It is not merely an executor capability that can stop working when
the local `ok` process exits. In contrast, the runner's management and ledger
credentials remain short-lived, isolated execution capabilities.

Current local `--dry-run`/`--prepare` validation does not establish that provider
access will remain valid for the cluster lifetime. A one-hour provider credential
can permit provisioning and then expire while the provider continues reconciling.
Bootstrap material may still exist and workload Nodes may remain Ready while
CAPI availability regresses because the provider can no longer authenticate.
Verify the active kubeconfig user, credential expiry and a narrowly scoped GET
using that actual provider identity before attributing such a failure to missing
bootstrap data. Never print tokens, bootstrap data or unredacted kubeconfigs.

The CLI is not a token-renewal controller. It must not silently increase token
lifetimes, rotate credentials, change RBAC, restart controllers, modify provider
references, invoke Talos bootstrap or replay a completed runner to repair access.
The lifecycle operator owns continuing provider credential validity and rotation;
see the [ownership boundary](ok147-provider-access-ownership.md). This assigns a
responsibility, not a new component. A concrete renewal mechanism, installation
authority and any changed provider input/Secret protocol still require separate
design and approval; this work implements none of them.

### Separately approved immutable-Secret recovery

An immutable provider Secret cannot be patched in place. If an explicitly
reviewed recovery chooses same-name replacement, preserve all references and
bind the current Secret UID/resourceVersion/data identity, replacement payload,
reference identities and credential deadline. Issuing a new credential and
applying the resulting replacement are separate approval boundaries. An expired
approved payload does not authorize issuing another credential under its digest.

Replacement is not atomic: at most one UID/resourceVersion-preconditioned
DELETE, an independent absence GET, then at most one CREATE. A successful empty
DELETE response is not itself an error; observed absence is the create gate.
Precondition or lifetime drift means STOP before deletion. A post-delete failure
means preserve the event journal and absence evidence, with no automatic retry,
rollback or delete replay. Observe convergence read-only after installing and
verifying the replacement; do not re-run provisioning.

Same-name Secret recovery and local one-shot orchestration used for an operator
handoff are not new product CLI commands or standing recovery authority. A
finite renewed credential supplies only a bounded MVP window, not durable
lifecycle access. Teardown and OK-197/OK-198 remain outside this change.

## Job-based activation path

The Job-based live activation is a separate expert deployment path. It is not
implicitly invoked by `ok cluster create --live`.

That launcher installs exactly four objects on `ok-mgmt`, in this order:

```text
immutable executor activation Secret
        -> immutable Evidence Authority Secret
        -> deny-by-default NetworkPolicy
        -> non-retrying Job
```

The launcher first verifies the exact execution Namespace, tokenless runtime
ServiceAccount and complete Ledger writer/admission boundary, then reads all
four activation-object names. A missing or changed prerequisite, existing
activation object or failed read stops before the first write. Once a write has
been attempted, an error or
uncertain response is preserved as `STOPPED_PARTIAL_OR_UNKNOWN`; do not retry,
update, patch, apply, delete or clean up under the same authorization.

## Manual stage-by-stage execution

The expert CLI can expose the same Bare-MVP prefix one stage at a time. Start
with `ok cluster stage run --help`; it lists the exact order across the `run`,
`observe` and `bind` command groups. Every invocation must consume the exact
durable receipt prefix from its predecessors. Each mutation-capable execute or
launch command requires its own explicit `--execute` gate and a separate
approval. This surface is intended for controlled diagnosis and recovery, not
as an authorization shortcut or a replay mechanism.

After a stopped or uncertain mutation, preserve its receipt and inspect the
durable state. Do not invoke the same mutation again merely because the CLI
returned an error.

### Recovery boundary

Three states are intentionally distinct:

1. A durable successful runner receipt prefix selects only the next bound
   stage. `ok cluster stage resume` verifies that prefix; it does not replay a
   completed mutation.
2. A separately reviewed Talos bootstrap that was interrupted after the CAPI
   manifests were applied may use the repository-owned `bootstrap-resume`
   workflow. It must receive its own authorization and explicit management and
   guest kubeconfig paths. Its preconditions compare the live Cluster with the
   render, and it never reapplies the infrastructure manifests.
3. A terminal runner receipt with a stopped, partial or unknown mutation is a
   STOP. Preserve the receipt, terminal marker and remote state. Do not run
   `ok cluster create --live` again and do not translate the error into
   `bootstrap-resume` without an independently reviewed recovery decision.

Teardown is not part of `ok cluster create`. It remains a separately
authorized lifecycle operation with its own durable recovery record; create
failure never implies permission to delete or clean up resources.

## Required inputs

Before preparation, record and independently review:

- the exact source commit and published runner image digest;
- the [image publication receipt](ok147-runner-publication-receipt.json),
  provenance attestation and pullback result;
- the private activation manifest and all seven predecessor receipts;
- the exact R, E, P, execution-fixture, Plan and target-identity digests;
- one current signed authorization for every externally authorized stage;
- one policy generated from the verified Plan by the
  [bounded DEV stage authority](ok147-bounded-stage-authority.md), plus its
  pinned public-key identity and durable create-only claim state;
- short-lived, isolated credentials for the ledger, management, workload,
  GitOps and authorization endpoints;
- the six exact `/32` egress destinations and ports: infrastructure,
  management, workload, Argo, authorization and independent evidence collector;
- the activation namespace, both Secret names, NetworkPolicy and Job names;
- independent observers, stop authority, recovery authority and evidence
  destination; and
- the tested recovery procedure for the DEV environment.

The first live run starts from the clean baseline recorded in the
[disposable-ok141 cleanup closure](ok147-disposable-ok141-cleanup-evidence.md).
Historical OK-141 credentials, receipts and runtime identities must not be
reused.

Secrets, tokens, Kubeconfigs, private keys, endpoints and private local paths
must never be copied into public receipts, logs, commits or pull requests.

The stage authority and independent evidence collector are different trust
domains. The former may sign an exact mutation decision; the latter must prove
real receiver delivery and autonomy. Neither may substitute static success for
the other's evidence.

Before preparing the full-run activation, install the authority only through
the two-step offline/live boundary documented in
[bounded DEV stage authority](ok147-bounded-stage-authority.md): first review
`authority stage launch prepare`, then separately authorize the single-use
`authority stage launch execute --execute`. The launcher proves all six exact
names absent before creating anything and cannot update, delete or retry.

## Preflight

1. Verify that the source commit, image digest, attestation and publication
   receipt all describe the same build.
2. Re-run the complete test suite and the offline activation-package tests.
3. Verify every private input is a regular `0600` file below an existing private
   directory and that every credential is current and narrowly scoped.
4. Run `full launch prepare` without installer credentials. Retain only its
   redaction-safe package receipt and exact four-object installation plan.
5. Compare the prepared package digest with the independently reviewed digest.
6. Verify by exact-name reads that Namespace `openkubes-execution-system`, the
   exact tokenless `ok147-contract-executor-runtime` ServiceAccount, Ledger
   writer ServiceAccount/Role/RoleBinding and fail-closed Ledger admission
   policy/binding exist. Then verify that both activation Secrets,
   NetworkPolicy and Job are absent. A missing prerequisite, missing observer
   or ambiguous result is a failed preflight.
7. Confirm that no unrelated lifecycle change or failure injection is active.

Preparation must not contact a cluster or consume the execution authorization.

## Single-use launch

Only after the preflight and explicit run authorization may the operator invoke
`full launch execute --execute` with:

- the exact expected package digest copied from the reviewed preparation;
- the bound `ok-mgmt` installer endpoint and CA digest;
- short-lived installer token and CA files; and
- the same immutable private activation inputs used during preparation.

The command rebuilds the package, verifies its identity before opening the
installer credential, repeats the complete prerequisite and absence preflight
and performs at most the four ordered creates. Preserve its public receipt even
when it stops.

## Observation and completion

Observe only the exact activation Job and the already-bound lifecycle,
Enablement and GitOps sources. Completion is not the Job exit code. A successful
outcome requires:

- the immutable ledger claim and current operation receipts;
- CAPI/provider observations correlated with R and current generations;
- Enablement convergence correlated with E and current NetworkReady evidence;
- GitOps desired/applied revision and capability evidence correlated with P;
- the bounded aggregate evaluator result; and
- one independently verifiable, redacted evidence bundle digest.

`Ready=True` is valid only when every profile-required source is current and
correlated. Missing, stale, conflicting or historical evidence yields
`Unknown` or `False` and never triggers repair by the evaluator.

## Stop conditions

Stop immediately and preserve state when any of the following occurs:

- an expected-absent object already exists;
- a digest, identity, authority, generation or revision differs;
- any create has an error or uncertain outcome;
- credentials, endpoints or private material appear in public output;
- an independent observer becomes unavailable;
- a second failure domain appears; or
- recovery would require force deletion, finalizer manipulation or an
  unreviewed mutation.

No automatic retry, rollback or cleanup is part of this run. Cleanup, deletion,
failure injection and executor-termination conformance require their own
preflight, digest and authorization.

### Explicit split-plane teardown (separate authorization)

`ok cluster create` does not delete clusters. The separate interactive entry
point is `ok cluster destroy <name>`. The published `ok destroy cluster <name>`
remains a compatibility alias with identical inputs, confirmation and outcomes;
`ok cluster delete` is not an alias.
Teardown stays owned by the existing Python lifecycle implementation, not by a
second implementation in Go. Do not use
`make clean`: it removes the local render directory and is not the durable,
split-plane cleanup path.

#### Interactive CLI entry point

##### Save local paths once

The standalone binary still uses the trusted Python lifecycle and ok-linux
checkout. To avoid repeating implementation paths, save them once:

```sh
ok config init \
  --lifecycle-root <trusted-current-ok-cluster-checkout> \
  --ok-linux-path <ok-linux-profile-checkout> \
  --clusters-dir <absolute-render-parent> \
  --management-kubeconfig <management-kubeconfig> \
  --provider-kubeconfig <separate-provider-kubeconfig>
ok config show
```

Initialization performs local path checks only. It requires all five path flags,
normalizes them to absolute paths, stores no credential contents and never
invokes the lifecycle or contacts a cluster. It is create-only: existing files
are not overwritten, and existing directory permissions are not changed.
This configuration is a convenience for path selection, not operation approval.

The default file is `<OS user configuration directory>/ok/config.json`:
`~/Library/Application Support/ok/config.json` on macOS, and
`$XDG_CONFIG_HOME/ok/config.json` (or `~/.config/ok/config.json`) on Linux.
The file/directory must be private (0600/0700 or stricter); configuration file
and immediate parent symlinks are rejected. `ok config init`, `ok config show`
and `ok cluster destroy` (also `ok destroy cluster`) accept `--config <file>` for an explicit location.
Use a new private location to prepare a replacement configuration; init has no
overwrite/force switch. The strict `ok-cli-paths/v1` JSON schema rejects unknown,
duplicate, missing, relative or unsupported-format fields.

After setup, from any directory:

```sh
ok cluster destroy <approved-old-candidate>
```

Omitted flags use the saved paths. `clustersDir` is the parent of retained
cluster directories, not the lifecycle source checkout; the selected target is
exactly `<clustersDir>/<name>`. Explicit flags override individual saved paths,
and `--cluster-dir` overrides that target's retained directory. The confirmation
dialog displays the actual resolved paths and configuration file. A malformed
existing configuration stops before the dialog; an explicitly selected missing
file never falls back. With all five original path flags supplied explicitly,
no default configuration is read. With no saved file, original path defaults
and explicit kubeconfig requirements remain available.

Create and expert runner commands do **not** read this configuration: their
manifest-bound credentials, authority boundaries and receipt contracts are
unchanged. No credentials are renewed or rotated automatically.

Run from a trusted, current ok-cluster checkout, or select one explicitly:

```sh
ok cluster destroy <approved-old-candidate> \
  --lifecycle-root <trusted-ok-cluster-checkout> \
  --cluster-dir <absolute-render-parent>/<approved-old-candidate> \
  --management-kubeconfig <management-kubeconfig> \
  --provider-kubeconfig <provider-kubeconfig>
```

The cluster name comes before flags. The CLI displays the exact target,
kubeconfig paths, lifecycle checkout and retained local directory, then asks:

```text
Type ok to delete, or no to cancel [no]:
```

Only an explicit lowercase `ok` followed by Enter launches one lifecycle
invocation. `no` or an empty answer cancels without starting the lifecycle or
contacting an API. EOF, invalid answers and Ctrl+C cannot start teardown.
Interactive terminal input is mandatory: there is no piped confirmation,
`--yes`, `--force` or credential renewal. Both kubeconfig paths are explicitly
supplied or explicitly saved by `ok config init`; no default kubectl context is
selected. This is a separate destroy authorization
boundary, not a reuse or broadening of create-run authority or old plan approvals.
Organizational deletion approval is still required before confirming a target.

This first CLI bridge requires Python 3 with PyYAML, kubectl and a trusted,
current lifecycle checkout. The binary does not bundle that runtime or download
one. Without saved configuration, `--lifecycle-root` defaults to the current directory; `--cluster-dir`
defaults to `<lifecycle-root>/<name>`. `--ok-linux-path` can select the profile
checkout, defaulting to the lifecycle checkout's sibling `ok-linux` directory.
The first CLI surface supports split-plane teardown only. Existing expert
single-plane `make teardown` calls remain unchanged.

The CLI passes `--preserve-local` unconditionally and streams the lifecycle
owner's output. It does not manufacture a successful operation receipt from a
child exit code. The owner retains its durable identity, storage and convergence
checks. Child failures propagate as non-zero exit codes with no automatic retry.
Interruption is not rollback: preserve the incomplete durable state and inspect
it before any separately authorized retry. Separately installed runner authorities
are not removed.

#### Expert lifecycle entry point

After a separately reviewed cleanup inventory and explicit deletion approval,
the lifecycle entry point supports:

```sh
make teardown CLUSTER=<approved-old-candidate> \
  CLUSTERS_DIR=<absolute-render-parent> \
  TALOS_INFRA_KUBECONFIG=<absolute-management-kubeconfig> \
  TALOS_TEARDOWN_PROVIDER_KUBECONFIG=<absolute-provider-kubeconfig> \
  TALOS_TEARDOWN_PRESERVE_LOCAL=yes CONFIRM=yes
```

This is a **destructive execution**, not a preview or a digest-verifying
approval tool. Do not substitute `ok-cli-mvp-3`, the successful reference run,
for an approved old candidate. The command does not issue credentials, start
the create runner, repair finalizers or remove separately installed runner
authorities. Shared Golden images and unrelated snapshots are preserved.

Routing is explicit:

- Management: CAPI Cluster, management namespace and durable teardown ConfigMap
  in `kube-system`.
- Provider: candidate namespace, DataVolumes/PVC inventory, retained PV cleanup,
  existing Longhorn cleanup, clone RBAC and proven cluster-owned CDI snapshots.
- Local: split-plane teardown **always preserves** the render directory,
  manifests, receipts and terminal evidence. Single-plane callers can opt in
  with `TALOS_TEARDOWN_PRESERVE_LOCAL=yes` / `--preserve-local`; their previous
  default behavior is otherwise unchanged.

An external `infraClusterSecretRef` requires the explicit provider argument.
The provider argument is teardown-only; other lifecycle modes are unchanged.
Its nested `kind: Secret` is a reference, not an embedded Secret resource.
Manifest validation checks parsed resource kinds (including Secrets inside
Kubernetes Lists) rather than rejecting this reference as a text match. Actual
Secret/SecretList resources, unresolved inputs, remote image sources and private
key markers remain forbidden; no credentials are materialized by this check.
Both kubeconfigs must exist and identify distinct planes. The narrowly extended
schema-2 record binds each plane's `kube-system` UID and the provider namespace
UID in addition to the existing management Cluster/namespace provenance. It
also pins the inventoried Retain PV and Longhorn UIDs (or explicitly observed
Longhorn absence). Retries never adopt a same-name replacement volume; late
inventory entries require persisted provenance before namespace deletion. UIDs
are checked again at storage cleanup and deletes retain server-side
preconditions. The record contains no credentials.
Existing single-plane schema-1 records remain readable
and writable unchanged; switching schema/plane routing on a retry is refused,
not migrated automatically. Older lifecycle code rejects schema-2 records.
Reading `kube-system` on both planes therefore requires explicit RBAC access;
absence or denial stops before any delete.
Cleanup identities must remain usable after deleting the candidate namespaces:
do not assume a create-runner ServiceAccount inside a target namespace can
observe deletion or finish storage cleanup after its own identity is removed.
Any required independent cleanup authority needs separate approval; this code
does not issue or broaden credentials.

Before the first delete, inventory and identities must persist and read back
exactly. CAPI deletion/observed absence precedes namespace deletion. Provider
inventory is refreshed and persisted before deleting the provider namespace;
management namespace deletion follows provider namespace absence. Read errors,
UID changes, failed writes or deletes return non-zero and leave the durable
record incomplete. Completion requires observed absence and successful cleanup,
not merely a successful command invocation. A separately authorized operator
retry uses that record; there is no automatic replay or retry of runner stages.
Completed split-plane records cannot be reused for a new same-name generation.
Split-plane completion also requires observed Longhorn volume absence using
UID/resourceVersion-preconditioned deletion; a storage read/delete error keeps
the record incomplete. Backing storage is not deleted after an uncertain PV
operation. The legacy single-plane best-effort Longhorn behavior is unchanged.

The plane UID binding does not grant authority or turn this command into a
generic recovery controller. Full candidate-authority removal, richer ledger
RBAC/retention policy (OK-197), and readiness expansion (OK-198) remain outside
this change. A live cleanup still needs its own current inventory, bounded
authorization and review of the existing storage cleanup contract.

Offline verification: `make ok186-lifecycle-test` runs both the existing
single-plane lifecycle checks and the split-plane integration tests against
fake executables and independent simulated API states. Fixture rendering mocks
the MetalLB allocation lookup before any subprocess environment is installed;
it must not fall back to the operator's real management kubeconfig. Regression
tests cover replaced storage, late inventory, interrupted teardown, retained
evidence and that offline fixture boundary.
`make ok-cli-offline-smoke` also exercises the real CLI with a simulated terminal
and the real lifecycle against fake API states: confirmation, cancellation,
EOF/interrupt, piped input, durable completion and non-zero failure propagation.

## Closure record

The final redacted record must bind the source commit, image digest, activation
package digest, Plan, R/E/P, target identity, grants, stage receipts, source
observations, aggregate result and evidence-bundle digest. It must also state
whether the run completed, stopped before mutation or preserved partial/unknown
state.
