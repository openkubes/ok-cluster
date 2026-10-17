# OK-147 bounded runner operator runbook

This runbook describes the first live execution of the bounded OK-147 runner.
It is an operational checklist, not standing authorization. Every live run must
bind one reviewed source revision, one immutable runner image, one activation
package digest and one separately approved execution window.

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

Both commands are offline: they read and validate the referenced private
artifacts, including credential and TLS material, but construct no network
client, contact no API, execute no stage and consume no authorization. They
accept only the explicit Plan-bound `bare-cluster-mvp/v1` completion mode,
which terminates after the exact Stage 1-7 prefix. The prepare receipt's
`manifestDigest` is the identity that must be reviewed and copied into a
separately approved live invocation. An omitted or different completion mode
fails closed.

Bare-MVP manifests do not require post-runtime material for Stages 8-12.
Target-credential, GitOps, Platform application, Observability credential and
collector activation sections may be omitted; they are not opened or
validated in this completion mode. Every Stage 1-7 projection, profile,
credential, authority, output destination and artifact remains mandatory and
is verified offline.

### Explicit lifecycle access paths

The local runner does not read an implicit management kubeconfig. Management
access is the exact endpoint, CA digest/CA file, bearer-token file and authority
identity bound by the private manifest. Provider access and the lifecycle-
derived guest access use separate absolute private kubeconfig paths. The guest
kubeconfig path is the same immutable destination across network observation,
runtime binding and target access; it is populated create-only from the CAPI-
owned Secret only after the durable lifecycle receipt prefix exists. Templates
must not contain `~/.kube`, `$HOME` or another ambient fallback.

The repository-owned Talos lifecycle commands use the corresponding explicit
operator inputs `TALOS_INFRA_KUBECONFIG` and `GUEST_KUBECONFIG_DIR`. The Go
runner does not invoke those Make targets and must not reimplement their path,
resume or storage validation logic.

The redaction-safe receipt states `apiContacted: false`,
`authorizationConsumed: false` and `mutationAllowed: false`. For `--prepare`,
its `nextAction` requires separate live approval and binds the next command to
the emitted `manifestDigest`; it is guidance, not authorization.

After separate approval, the local live form is:

```bash
ok cluster create --file /private/bare-run.json \
  --live --execute \
  --expected-manifest-digest sha256:<reviewed-digest> \
  --independent-evidence-public-key /private/evidence.pub \
  --terminal-marker /private/run-01/executor-terminal
```

The CLI re-verifies the manifest and exact digest before opening the bounded
runner. The marker path must be absent and private; it records terminal
consumption even when execution stops. Never treat `--prepare` output as live
authorization. This command runs the Stage 1-7 executor directly in the local
`ok` process. It contacts the APIs bound by the private manifest and does not
install the four Job-activation wrapper objects described below.

## Friendly cluster YAML: normal guided workflow

After `ok config init` has saved trusted lifecycle/profile source paths:

```sh
ok up --file cluster.yaml --dry-run
ok up --file cluster.yaml --prepare
ok up --file cluster.yaml
```

The first command retains the existing offline intent-only check: no credential
reads without explicit YAML target references, no state files or reservation.
Explicit references are locally inspected as described below. `--prepare` manages
local preparation without requiring a terminal and never offers live confirmation.
The normal command requires a terminal, but no longer asks for Contract/runtime
paths. It compiles a fresh Contract using the versioned Contract recipe and the
existing owning profile resolver, canonicalizer and projection verifier, then
builds the existing seven-stage plan. `stageauthority.FromPlan` derives the exact
bounded **policy request**, not a grant, installed policy, RBAC or signed outcome.
No historical Candidate is renamed and no authority/credential is invented.
Saved config supplies only the two source paths, not management/provider access.

Without platform inputs the result is `AWAITING_PLATFORM_AUTHORITY`, nonzero
NO-GO with `runnerReady=false`. The Contract, stage artifacts and policy request
are complete locally, not authorized for execution. Repeating the command checks
the same immutable artifacts and reports the same request digest; it does not
rerender. The CLI currently has **no platform issuer/broker integration**. This
change automates preparation, not the external decision to grant new authority.

The platform operator separately reviews/deploys the exact bounded policy and
provides existing private runtime references through this private create-only
handoff at `<managed-run>/platform-handoff.json` (paths/digests are examples):

```json
{
  "format": "ok-cli-platform-handoff/v1",
  "requestDigest": "sha256:<exact-platform-preparation-request-bytes>",
  "runtimeInputsPath": "/private/platform/candidate-runtime-inputs.json",
  "runtimeInputsDigest": "sha256:<exact-private-runtime-input-bytes>"
}
```

This local descriptor is **not an authorization grant or deployment attestation**.
It must bind `<managed-run>/platform-preparation-request.json` exactly and cannot
select a different YAML, plan or implicit administrator kubeconfig. Authority and
independent evidence keys remain distinct; the existing full-run verifier and
target/CA checks must accept the supplied references. No secret/key/token content
is copied into request metadata. Do not use a previous Candidate's manifest or
outcome as the handoff. No broker command, TokenRequest, refresh, port-forward or
policy installation is executed by preparation.

After the separate handoff, the same short command completes only the local
runner manifest through the existing owner and reports `PREPARED_NOT_AUTHORIZED`.
`--prepare` still never executes. An unflagged terminal invocation delegates to
the existing explicit `ok/no` confirmation and single-use executor below. The
handoff-start fence prevents retry of an incomplete manifest materialization;
the existing execution-start fence prevents automatic replay of cluster actions.
Binary/YAML/static input drift and partial preparation stop without overwrite or
repair. All prior evidence remains retained. A request is not readiness evidence.

Once a verified platform handoff exists, the CLI displays cluster name, profile/sizing, endpoint/CIDRs, authority identities,
private evidence location, manifest digest and independent evidence key identity.
It describes the prerequisite/RBAC and resource mutations and asks you to confirm
separately reviewed name/IP absence, authority deployment and approval of that
exact plan. It does not perform an online collision check or reservation. Only
`ok` followed by Enter starts the **existing** runner. Empty/no/invalid answers,
EOF, interruption or piped input cannot start it. You do not need `--prepared-dir`,
`--execute`, digest or marker flags for this guided form. Scripts keep the expert
workflow below; there is deliberately no non-interactive auto-yes option.

Preparation and evidence are retained privately under
`<OS user configuration directory>/ok/runs/<cluster-name>` (macOS:
`~/Library/Application Support/ok/runs/<name>`; Linux:
`$XDG_CONFIG_HOME/ok/runs/<name>` or `~/.config/ok/runs/<name>`). This is persistent
application state, **not a disposable cache**. Existing files/permissions are
never overwritten, cleaned or loosened. The normal `config.json` schema and
contents are unchanged. No credential contents are copied into managed metadata.

If you cancel before starting, an existing complete preparation may be reverified
and shown for a fresh confirmation by the same short command; it is not rendered
again. Semantic YAML drift, changed private references or a changed evidence key
fail closed. Incomplete preparation is retained for expert review, not retried.
The inputs are rechecked after confirmation before any executor is opened.

Immediately before delegating, the CLI create-only records and syncs
`execution-started.json` and its directory ancestry. This local fence permits at
most one guided start, including simultaneous confirmations. It is not a success
receipt. Once it exists, later short invocations stop before credential reads or
prompts, even if execution failed/interrupted before a terminal marker appeared.
Do not remove this state to bypass STOP; recovery requires separate evidence and
authorization through the existing expert boundary. No automatic retry, rollback,
resume, credential renewal or policy installation is introduced. The normal
runner owns the terminal marker, immutable outcomes and convergence evidence.
Only its existing durable success contract determines success, not confirmation,
local preparation or a command invocation. No separate guided success is fabricated.
Managed storage does not change teardown discovery: the existing expert teardown
can select the retained render at `<managed-run>/preparation/<name>` through
`--cluster-dir`. This change does not register new destroy defaults, authorize
cleanup or remove managed evidence/start fences.

### Optional explicit management/infra kubeconfig references

The friendly YAML may identify the target APIs using local files:

```yaml
apiVersion: cli.openkubes.io/v1alpha1
kind: Cluster
metadata:
  name: my-cluster
spec:
  management:
    kubeconfig: ~/.kube/ok-mgmt.yaml
  infrastructure:
    kubeconfig: ~/.kube/ok-infra.yaml
  profile: talos-kubevirt-mvp
  network:
    endpoint: 192.0.2.10
    podCIDR: 10.42.0.0/16
    serviceCIDR: 10.96.0.0/20
```

Addresses are examples, not allocations. Both target references are optional for
compatibility, but must be supplied together. A file with exactly one context is
unambiguous even without `current-context`; with multiple contexts add
`context: <explicit-name>` inside that reference. The CLI does not silently use
the current context in a multi-context file. It never switches/writes any context,
merges `$KUBECONFIG`, runs exec/auth-provider plugins or invokes kubectl to select
a target. Cluster/user references and unique context/cluster/user names must be
valid. Authentication contents are not returned, imported, copied or logged.
These are **target references**, not administrator credentials for the runner.

`~/` expands only for the outer reference path. Other relative reference paths
are relative to the YAML file, not the shell working directory. Kubeconfig files
must be private regular non-symlink files, at most 1 MiB. The selected cluster must
use direct HTTPS, exactly one embedded CA bundle or CA file, and no insecure TLS,
proxy or TLS-server-name override. Relative CA file paths resolve against the
kubeconfig directory; CA files are bounded regular non-symlink files. This reader
inspects identity only; it proves neither authentication/RBAC nor live availability.

`--dry-run` reports selected context/cluster, endpoint and semantic CA trust digest
under optional `targets`, keeping all mutation/contact/authorization flags false.
With references it does read the explicit private files in memory, but opens no
network client. The same target inspection occurs before render/preparation;
ambiguity rejects before output creation. Old YAML without references retains its
normalized digest and no-credential-read intent-only dry-run behavior.

The static binding receipt additionally records the selected non-secret targets.
Its raw digest is bound by the local fixture and existing manifest/plan chain.
Full handoff and YAML execution require endpoint/complete CA trust-set equality
with the existing management/infrastructure writer and observer runtime bindings.
The existing provider-access credential's effective current-context must also
target the selected infra API and trust set. Explicit YAML contexts do not rewrite
or override that credential file. Disagreements stop without a successful handoff
or executor. A changed selected context/cluster/endpoint/trust set after preparation
fails closed, including rechecks after guided approval. PEM formatting/order or
duplicate certificates do not change the trust set; adding a different trusted
certificate does. The Contract/projection still owns logical authority roles;
context labels are not authority and do not override those roles.

Existing restricted runtime-reference, Stage Authority, ledger and independent
evidence inputs remain required. No admin credential conversion, credential
renewal, RBAC expansion, publication or lifecycle duplication is introduced.
The guided confirmation displays the selected contexts and API endpoints. Stored
general-config management/provider paths are still not implicit access sources.

### Propose endpoint and CIDRs before preparation

The `cluster-template` addresses are examples, **not allocations**. Change the
name first (for example `ok-cli-arash-test-1`). For a read-only observed proposal,
include both YAML kubeconfig references above and explicitly opt into API reads:

```sh
ok up network-suggest --file cluster.yaml --online --output cluster.proposed.yaml
```

This separate command lists Services and CAPI Clusters in both selected planes
and MetalLB IPAddressPools in the infra plane. The sole applicable IPv4 pool is
used; if ambiguous, select `--pool metallb-system/<pool-name>`. Pools with
service/namespace allocation selectors are rejected until consumer-aware
selection is supported. Pools with `autoAssign: false` require explicit selection;
`avoidBuggyIPs` is respected. Existing static credentials are required: selected
exec/auth-provider plugins are rejected **before either API is contacted**, and
no TokenRequest or renewal is performed. Authorization/RBAC, timeout, missing
CRD and malformed inventory failures stop; there is no local-only fallback.

Local `clustersDir/<name>/cluster-config.yaml` files and retained managed
`<user-config>/ok/runs/<name>/preparation/<name>/cluster-config.yaml` files are
also considered. Deleted clusters' retained files conservatively keep their
values excluded. Known endpoints, LoadBalancer addresses, Service cluster IPs
and CAPI `clusterNetwork` CIDRs are combined. CIDR selection belongs to the
existing renderer, not a new Go allocator: `/16` Pod networks from `10.32.0.0/11`
and `/20` Service networks from `10.96.0.0/12`. The proposal checks subnet,
supernet and cross-role overlaps, including known addresses and the endpoint
pool itself. These are current recipe policies, not universal networking defaults.

Legacy local `auto` fields are not allocations and are never silently ignored.
Offline mode stops and names the source file and unresolved fields. Online mode
retains every concrete local value and resolves only `auto` fields from an
observed CAPI Cluster whose **name and namespace both equal the local config's
name**, following the existing renderer/lifecycle convention. Required IPv4
endpoint/Pod/Service values must be present. UID/resourceVersion and source-plane
evidence are recorded in `sources[].autoResolution`; no local file is rewritten.
Missing, malformed, wrong-namespace or ambiguous observations stop without an
output YAML. A resource absent from both APIs is **not** evidence of unused
addresses. Duplicate observations through two contexts selecting the same API/CA
and UID are accepted only when the resolved values agree. Different APIs/UIDs or
changing resolved values stop. Concrete local and observed allocations both
remain excluded even if they differ. This does not adopt a cluster or transfer
authority; all proposal/no-reservation limitations below still apply.

For a strictly offline, local-inventory-only proposal, supply an explicitly
approved endpoint range (example below is site-specific, not a default):

```sh
ok up network-suggest --file cluster.yaml \
  --endpoint-pool 192.168.100.200-192.168.100.254 --output cluster.proposed.yaml
```

Offline never reads kubeconfigs, runs auth plugins or contacts an API. Saved
configuration supplies **only** lifecycleRoot/clustersDir; explicit
`--lifecycle-root` and `--clusters-dir` may replace them. It never silently uses
saved management/provider credential paths. Neither mode invokes renderer
online-resolve, applies resources, reserves an address, prepares a runner or
changes the source YAML. The optional output is a new private 0600 YAML file;
existing files, including the input, are never overwritten. Target references
are made absolute so moving the proposed YAML cannot change their meaning.
Without `--output`, only the JSON proposal is printed.

JSON `ok-cli-network-proposal/v1` records exact before/proposed network values,
source paths/API-list digests, selected targets, pools, observation time and
limitations. `apiContacted`/`observedCollisionCheckCompleted` reflect online mode;
`globalAvailabilityProven`, `reservationCreated`, `authorizationConsumed`,
`mutationAllowed` and `runnerReady` remain false. **This is a snapshot, not a
reservation or global proof of availability.** DHCP, external hosts, untracked
preparations, DNS endpoints and other management planes need separate inventory;
DNS-based CAPI endpoints currently stop online proposals rather than being
treated as absent. Concurrent creators can still race. Review source coverage
and recheck allocations before separately authorized live execution.

Review `cluster.proposed.yaml`, then run:

```sh
ok up --file cluster.proposed.yaml --dry-run
ok up --file cluster.proposed.yaml
```

The latter still requires the existing reviewed Contract/private runtime inputs
for the **new exact values**, installed bounded authorities and explicit `ok`.
No evidence or authority from a previous Candidate is reused automatically;
proposal success is never provisioning success. Normal offline `--dry-run` and
all existing live/teardown contracts remain unchanged.

### Expert offline intent/render workflow

Without explicit private runtime inputs, this front end produces only static
preparation. It does not replace the technical JSON manifest contract above. Start with:

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
The Python renderer does not read kubeconfig/credential contents; Go inspects only
explicit YAML target references before delegation. The small adapter
calls the existing owning `render.render_cluster` and
`profile_resolvers.talos.resolve_talos_config`; Go does not duplicate Talos,
Golden-image or storage validation. The online allocator/resolver, sockets and
child-process execution are disabled in that adapter. The output root must not
exist; failed/partial output is retained and never overwritten or retried.
All generated files, including shell helpers, are mode 0600; directories are
0700. Generated helpers are not run. The receipt binds rendered-file and owning
source/profile digests but remains `RENDERED_NO_GO` / `runnerReady=false`.

### Static Contract/projection binding (still NO-GO)

An operator can now provide an explicit fresh reviewed Contract:

```sh
ok up --file cluster.yaml --prepare \
  --contract /private/reviewed-contract.yaml \
  --output /private/new-binding
```

By default, preparation performs static binding and derives fresh credential-free
stage artifacts and a verified seven-stage plan, not full-run prepare. It exits non-zero even
after writing valid partial artifacts.
No separate binding command is required. The previous `ok up bind` spelling is
retained only for compatibility with its existing static-only receipt/exit behavior;
it is not an additional operator step. No old Candidate,
Contract identity, UID, resourceVersion or operation outcome is renamed/copied.
The supplied Contract must already have exactly the YAML name/namespace, and
its metadata must contain only those two fields. The operator, not this command,
supplies enablement/platform intent and authority-domain semantics absent from
the friendly YAML; no reviewed or live authorization is inferred from the file.

The existing Go Contract canonicalizer uses the owning checkout's versioned
`internal/contract/testdata/ok141-contract-v3.schema.json` (the existing bounded
MVP schema, not a new general production API) to compute `R`. There is no
arbitrary-schema override. The local adapter checks the normalized Contract
against the resolved recipe: Kubernetes version, infrastructure/provider profile,
Secret references, topology/sizing, pod/service CIDRs and OS/Golden-image identity.
Only then does the existing renderer produce its Contract projection. The Go
`projection.Verify` owner independently verifies its `R`, identity, authority map
and artifacts. Storage logic is not reimplemented in Go.

Output adds `contract.yaml`, `contract.schema.json`, `contract.canonical.json`,
the `projection/` artifacts and `binding-receipt.json`. The receipt binds normalized
YAML intent digest, Contract/schema/R and verified projection. Explicit endpoint
selection is carried by the normalized YAML and rendered projection, not invented
as a new Contract field. Original files remain unchanged; output is create-only,
private and failures retain partial output without replay. No kubeconfig contents,
tokens, grants, client certificates or existing stage receipts are imported.

The static snapshot in `binding-receipt.json` remains
`CONTRACT_PROJECTION_BOUND_NO_GO`; its missing-bindings list describes that earlier
step and is never rewritten when preparation advances.

`--prepare` additionally writes, internally and create-only:

- `runner-recipe.json`: a private copy of the versioned Talos/KubeVirt recipe from
  the trusted lifecycle checkout. Contract E/P revisions must match this recipe.
- `execution-fixture.json` (`ok-cli-local-execution-fixture/v2`): binds the verified
  static receipt, recipe digest, Contract identity/R and local CLI binary digest.
  Embedded version/revision are build metadata, not source attestation or proof of
  a published image. `unknown`/development metadata is recorded honestly. This is
  a content identity, not a unique attempt ID or authorization.
- `provider-access-policy.json`: produced and validated by the existing submission
  policy owner, bound to this fixture digest, Contract/R and verified projection's
  management/provider authorities. It describes only the exact immutable Secret
  shape; it contains no credential data and neither materializes nor creates a Secret.
- `enablement.yaml`, `network-profile.json`, `target-access.yaml`: fresh artifacts
  from the reviewed recipe. Existing submission/network owners verify the emitted
  files. Cilium semantics and all 16 target-access objects retain the happy-run
  rules/scopes; no RBAC is installed. HRP identity is derived for the new Cluster.
- `lifecycle-observation.json`, `runtime-binding-requirements.json`: fresh static
  requirements, not runtime evidence, successful convergence or a fabricated UID.
- `staged-plan.json`, `verified-staged-plan.json`: ordinary seven-stage NO-GO plan
  and its verified binding. The existing stageplan owner constructs and re-loads
  it with all eight input digests. No retry/attempt/recovery identity or deferred
  network mode is inferred. Worker-readiness contracts are not expanded.
- `preparation-receipt.json` (`ok-cli-cluster-preparation/v2`): the current partial
  preparation snapshot, with the static receipt, fixture and policy digests and
  plan semantic/raw digests, raw artifact digests and remaining missing bindings.
  This JSON is also emitted on stdout. Network stage input uses the owning
  semantic profile digest, not the raw JSON file digest.

Without explicit runtime inputs, the preparation state is `STATIC_PLAN_BOUND_NO_GO`, not `PREPARED` or
provisioning success. `runnerReady=false`, `apiContacted=false`,
`authorizationConsumed=false` and `mutationAllowed=false`. There is no
`manifestDigest`; neither fixture nor preparation receipt is accepted as a
full-run manifest. YAML `--prepare` returns an explicit incomplete
error (non-zero) and never emits `PREPARED` or a live approval digest. The new
preparation inputs are rejected for JSON, dry-run and live modes. YAML `--live`
without an existing `--prepared-dir` remains blocked. Existing technical JSON
execution is unchanged.

These static artifacts alone cannot prove private runtime bindings. They must not
be completed by copying historical Candidate identities/outcomes or loosening the
runner's evidence requirements. Static-only preparation cannot satisfy
`--prepared-dir`: a verified full-run manifest/fixture binding is required.

### Explicit local handoff to the existing runner

To complete local preparation, an operator may explicitly provide references to
already existing, separately provisioned credentials and trust files:

```sh
ok up --file cluster.yaml --prepare \
  --contract /private/reviewed-contract.yaml \
  --output /private/new-preparation \
  --runtime-inputs /private/approved-runtime-inputs.json
```

Use `examples/ok-cli-runtime-inputs.json` as the shape reference, not a runnable
configuration. The selected JSON must be a regular non-symlink file, exactly 0600,
at most 64 KiB. All references are explicit absolute paths. Unknown/duplicate
fields, historical manifests/plans/grants, output overrides and runtime target
identities are not accepted. This flag is only accepted for YAML `--prepare`, not
JSON, dry-run, live, render or the compatibility binding subcommand.

The document supplies:

- Separate infrastructure, management, ledger and Stage Authority connection/trust
  references. No credential is inferred from saved config, issued, rotated or copied.
- The existing provider-access kubeconfig path. It is verified/materialized only
  in memory by the existing owner; no Secret is written or submitted.
- A distinct independent evidence public key. Both evidence and Stage Authority
  Ed25519 public keys are locally parsed. The evidence key ID is recorded as a
  preflight pin, not an extension of the existing technical manifest's live gates;
  the operator must still explicitly select the independently reviewed key at live time.

The shared token/CA parser validates local file material without constructing an
HTTP client. Four bearer identities must be distinct and private; authority CA
digests must match the supplied references. This is **not** online authentication,
token lifetime/RBAC validation, or proof that a matching Stage Authority policy is
installed. Existing runtime verification still runs again at execution time.

Only the runner-owned manifest builder creates the fresh v3 technical manifest,
with fixed private runtime/receipt/authorization destinations under this output
directory. The CLI then calls the existing full-run manifest verifier. Failure
retains partial output and returns non-zero, never a successful handoff receipt.
There is no overwrite, automatic replay, grant request or network client.

On successful local verification:

- `full-run-manifest.json` is the normal technical input accepted by the existing
  runner; no alternate lifecycle execution path is introduced.
- `runner-handoff-receipt.json` (`ok-cli-cluster-runner-handoff/v1`) and stdout
  report `PREPARED_NOT_AUTHORIZED`, the existing verifier's manifest digest,
  static-preparation/runtime-reference digests and independent evidence key ID.
- `runnerReady=true` means **locally verified input handoff only**. `apiContacted`,
  `authorizationConsumed`, `mutationAllowed`, `authorityDeploymentVerified` and
  `liveAuthorized` remain false. Exit zero is not provisioning success.
- The earlier `preparation-receipt.json` remains its immutable static-only v2
  snapshot; it is not rewritten to change the result of that earlier phase.
- The handoff receipt additionally supplies `nextCommands.dryRun` and
  `nextCommands.liveAfterApproval` as argument arrays, not shell strings. Both
  select the generated technical JSON manifest through the existing `ok up`
  runner path. The live hint includes the verified manifest digest, explicitly
  selected independent evidence key path and absolute `executor-terminal` path
  under this private preparation directory. Spaces and shell metacharacters
  remain literal argument data; never join these arrays into `eval` or a shell
  command. The CLI does not execute either hint. Their presence is not approval.
  Only run the live hint after separately reviewing authority deployment and
  granting approval for this exact digest. Do not repeat it after STOP; no
  automatic retry/resume or new terminal marker is implied. If inputs change,
  the normal runner verification still applies; these hints do not pin a file's
  future contents or prove credential validity or convergence.

Review authority deployment separately and obtain explicit live approval for the
generated technical manifest digest. The existing technical JSON live workflow,
independent evidence argument, terminal marker, immutable outcomes and convergence
gates remain unchanged. No live cluster test
or successful provisioning claim is implied by this handoff.

### Reuse a preparation with friendly YAML

The friendly YAML may now select its existing preparation explicitly, without
another render or Contract/profile lookup:

```sh
ok up --file cluster.yaml --prepared-dir /private/preparation --dry-run
```

This is full local runner-input verification, not just YAML syntax validation.
It reads referenced local credential/trust material but opens no network client,
requests no grant and writes no output. Omit `--prepared-dir` to retain the original
intent-only dry-run. No saved config or runtime-input defaults are consulted here.

Only after separate review and explicit live approval for the generated digest:

```sh
ok up --file cluster.yaml --prepared-dir /private/preparation --live --execute \
  --expected-manifest-digest sha256:<approved-manifest-digest> \
  --independent-evidence-public-key /private/reviewed-evidence.pub \
  --terminal-marker /absolute/private-dir/executor-terminal
```

Use the independently reviewed evidence key selected for preparation. The marker
must be absent in an existing private directory; all original technical JSON live
gates remain mandatory. This command can mutate the cluster; **preparation and this
documentation are not authorization to run it**. `ok cluster create` is equivalent.

The selected directory and fixed local files must be private and non-symlink.
The owning manifest verifier checks the full-run inputs, and its verified plan
must anchor the exact `execution-fixture.json` bytes. The fixture in turn binds
`binding-receipt.json`, whose normalized intent digest must equal the current YAML.
Changes to name, endpoint, CIDRs or profile fail closed. Comment/format changes
are allowed when normalized intent is identical. Missing/static-only/foreign or
modified fixtures do not become runnable merely by editing an output receipt.
The CLI never executes command hints from receipts or trusts them as authority.

This only resolves the existing technical manifest, then delegates to the same
runner with the caller's explicit digest, evidence key and marker. It adds no
lifecycle implementation, credential renewal, rebinding, automatic retry, rollback,
bootstrap-resume or bypass of receipt/convergence checks. A non-zero/incomplete/STOP
result is preserved; do not repeat with a new marker to replay a mutating stage.
Recovery still needs its separate evidence and authorization. Recovery-attempt
manifests are not accepted by this first-run YAML path. `--prepared-dir` is rejected
for `--prepare`, technical JSON and mixed preparation flags (`--output`, `--contract`,
`--runtime-inputs`, source/config paths). Original technical JSON modes remain valid.

OS selection remains `spec.profile`. Only the Talos/KubeVirt recipe is currently
enabled for this bounded preparation path. Flatcar resolver/templates and Ubuntu
templates exist but do not yet supply a full runner projection/bootstrap/convergence
contract; those profiles fail closed, never fall back to Talos. See
`profiles/cli/README.md` for the scope and baseline provenance.

Existing technical JSON inputs retain all previous modes and receipts (including
JSON manifests using a `.yaml`/`.yml` filename). No existing Candidate, receipt,
authority or terminal is rewritten by this front end. Interactive configuration
is available through `ok config init`. Deployed-authority verification remains an
operator responsibility; the CLI does not infer it from local preparation.

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

If an explicitly approved recovery inherits the original four receipts and
completes Stages 5–7 under the recovery binding, describe it as a **recovered
Bare-MVP completion**. Preserve the source full-run STOP and terminal marker;
do not relabel it as a successful fresh, single-invocation `cluster create` run.
The narrow recovery formats and paired flags are described in the README.

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
checkout. To avoid repeating implementation paths, save them once. On a terminal,
run `ok config init`: it asks for the five paths, shows their normalized values,
and saves only after you type `ok`. Empty input, `no`, EOF or interruption cancels
without creating the configuration directory. Enter literal paths (spaces are
accepted, without shell quoting); prompted `~/` expands to your home directory.
No repository or credential is downloaded or discovered automatically.
Use `--interactive` with some path flags to prompt only for the missing paths.
For scripts, supply all five flags without interactive mode:

```sh
ok config init \
  --lifecycle-root <trusted-current-ok-cluster-checkout> \
  --ok-linux-path <ok-linux-profile-checkout> \
  --clusters-dir <absolute-render-parent> \
  --management-kubeconfig <management-kubeconfig> \
  --provider-kubeconfig <separate-provider-kubeconfig>
ok config show
```

Initialization performs local path checks only. It requires all five paths,
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

YAML preparation may use saved lifecycle/ok-linux source paths, but does not
infer runtime credentials from this configuration. Expert runner manifest-bound
credentials, authority boundaries and receipt contracts are unchanged.
No credentials are renewed or rotated automatically.

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
