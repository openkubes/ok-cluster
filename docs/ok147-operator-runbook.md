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

**Current credential-policy limitation:** the v3/v4 execution manifest and its
lifecycle-derived workload client certificate are disabled until a bounded
workload credential bootstrap is reviewed. This also blocks the real #450 YAML
runner handoff: supplying a matching `platform-handoff.json` cannot produce
`PREPARED_NOT_AUTHORIZED`, a create confirmation, or a live run. Static local
Contract/plan/policy-request preparation remains available and non-authorizing.
Generic bearer-token input and management/provider/ledger TokenRequests are not
substitutes for an approved workload credential bootstrap. The historical
happy-run evidence is retained, not a claim of current security acceptance.

Direct pre-runtime/full-run constructors enforce the same policy before Stage 1,
including the disabled materializer's zero value. Rejections preserve the policy
error through YAML handoff/prepared/managed wrappers. No fallback, replay,
credential renewal, signing-policy relaxation or legacy-grant retirement is
performed by these code checks.

The runner performs one already-authorized `CreateCluster` transition and the
bounded post-runtime suffix. It is neither a long-running operator nor a
lifecycle source of truth. CAPI/CAPK, the selected Enablement mechanism and
GitOps remain the owners of convergence.

### Product UX direction (not additional authority)

The user-facing goal is `ok cluster create --file cluster.yaml` and
`ok cluster destroy <name>`, each with one understandable plan and an explicit
`ok`/`no` confirmation. Internal digests, runtime references, short-lived access
and connectivity should not become recurring manual user tasks. Make remains a
useful development interface to the same lifecycle owners; the CLI must add
consistent intent validation, local state discovery and actionable results, not
another lifecycle implementation.

Managed destroy discovery below is one delivered step, **not complete create
automation**. Automatic creation currently still stops at
`AWAITING_PLATFORM_AUTHORITY` without a separately supplied handoff. Next, an
explicit platform setup must establish who may issue which bounded credentials
and grants. Only within that delegation can preparation, temporary connectivity
and access renewal become automatic. A kubeconfig path alone does not establish
that authority. No issuer, standing delegation or automatic renewal is installed
by this change.

A future Installer Operator could reconcile installation requests and launch or
adopt a UID/generation-bound runner operation. The runner remains a bounded
executor: controller reconciliation must inspect durable outcomes, not replay
potentially mutating operations after an error or missing response. Terminal
STOP requires separately authorized recovery; command/Job completion alone is
not provisioning success. CAPI and existing lifecycle owners retain convergence
ownership. This is a design direction, not a new CRD/controller or authority
contract implemented here.

### Workload credential bootstrap: review proposal, not an enabled feature

Status: **DESIGN ONLY / NO-GO**. This section does not approve an issuer,
certificate identity, lifetime, RBAC installation or execution. The security
contract from [PR #437](https://github.com/openkubes/ok-cluster/pull/437), merged at
`main@b1ecf24`, remains authoritative; its post-merge independent review and
ADR-030 security acceptance are not implied complete by the merge. No accepted
security requirement is changed here. Even matching platform inputs cannot make
the current v3/v4 YAML runner handoff executable. Do not implement preparation
automation that works around that gate.

#### MVP decision: one runner path for CLI and future Console self-service

The operator confirmed retaining the bounded runner as the shared execution
path, with `ok-console` self-service in view. This supersedes the earlier idea of
deferring bootstrap by introducing a local trusted-operator mode. **Do not build
that second mode or silently wrap Make after a runner denial.** Make remains
development/operator tooling, not an alternate production authority contract.
Its lifecycle-generated workload admin access must not enter the bounded runner.

The simplification target is the user workflow, not removing authority checks:
one separately authorized platform setup, then understandable create/destroy
requests under that delegation. Users must not have recurring CSR, token,
digest, port-forward or handoff-file chores. A user confirmation submits a
reviewed operation; it does not grant the platform new rights or authorize an
arbitrary issuer request. CLI and Console may differ in authentication and
presentation, not runner grants, stage order or success evidence.

Local Console source inspection at
[`72a816e3e0bb9ca1eb9d67e0432b7e6e27da2e5b`](https://github.com/openkubes/ok-console/tree/72a816e3e0bb9ca1eb9d67e0432b7e6e27da2e5b)
confirmed that its BFF exposes read-only platform resources; authentication
session mutations are not cluster create/destroy endpoints. The inspected
`bff/README.md` and `contracts/security/v0alpha1/README.md` describe point-of-use
environment/tenant/permission checks and a browser-safe session projection.
This is source evidence, not a deployed-state observation. Console mutation
integration is future work, not enabled by this decision or a login session.

Before self-service integration, a reviewed server-side operation boundary must
authenticate the caller, verify scope at the point of use and submit only typed,
bound operations under explicit platform delegation. The browser receives
redacted status/evidence, never Kubernetes credentials, signing keys, reusable
stage grants or an arbitrary shell/Kubernetes proxy. CLI possession of a local
kubeconfig must not become a second authorization policy. No new Console route,
permission name or public operation schema is defined here. Existing managed
CLI teardown remains unchanged; its future Console integration must preserve
its separate plan, ownership and recovery contract rather than use create stages.

**Minimum for a safe runner MVP** (requirements, not implemented deployment):

| Required boundary | Existing evidence | Work still needed before activation |
| --- | --- | --- |
| Authenticated operation/plan and platform delegation | Existing stage plans/grants; #437 denies unsupported provenance | Bind verified caller scope, exact plan/attempt/target and authoritative predecessor outcomes. A supplied matching digest or frontend permission is not proof of authority. Resolve Stage-7 plan provenance separately. |
| Bounded workload access | #455 offline checks; #456 request/result authentication | Establish the reviewed platform issuer task, real source UID/RV/owner/CA checks and in-task CA/key correspondence. Per-role rights, lifetime and stage budget must match the accepted profile. No CAPI-admin fallback or CA key in CLI/runner. |
| Durable one-use issuance | #456 claims/results; #457 create-only adapter with fake TLS tests | Prove the selected store domain, writer isolation and enforced protection against deletion/replacement before signing. A claim with no authenticated result stays STOP. Fake API success is not deployment proof. |
| Required network observation and fixed probe | Existing collector/probe adapters; offline observer profile | Establish bounded Pod discovery and mediated fixed-probe authority, including Pod replacement races. A fixed command in Go alone does not restrict a stolen exec credential. Do not drop the probe. |
| Exact target-access installation | Existing renderer/plan checks for the fixed Stage-7 object set | Enforce the reviewed bodies and privilege boundary at the platform/API boundary, not merely in CLI validation. No blanket bind/escalate or reduced object set under the existing completion label. |
| Explicit integration and evidence-driven completion | Seven-stage runner orchestration, durable receipts, explicit management/infra targets | Review the next manifest/adapter revision, role-specific access wiring and end-to-end negative tests before changing any gate. All required convergence/probe/receipt evidence remains necessary. |

These are not six new services. Request authentication, bounded issuance and
fixed tasks may be implemented by one narrowly reviewed platform integration;
separate capabilities and trust boundaries must still be enforced. A bootstrap
access result is not a stage grant; a successful stage invocation is not cluster
success. Merely implementing both observer credentials cannot complete Stage 7.

**Defer without weakening that minimum:** a new Installer Operator/controller,
new CRDs, a generic multi-provider issuer, Ubuntu/Flatcar execution, Console
mutation UI/endpoints in this slice, automatic issuance renewal, automatic
recovery/takeover/replay, generic retention/garbage-collection machinery and
OK-197/OK-198. Keep the existing narrow Talos/KubeVirt MVP profile and exact
completion contract. The Console-compatible operation seam is a design
constraint now, not permission to implement its full service here.

For the initial no-recovery profile, retain issuance records instead of adding a
cleanup controller. Do not build automatic disaster recovery as a prerequisite
to a first run, but do not declare datastore rollback/fork risks solved: the
trusted administration/storage boundary and enforced stop after continuity loss
still require independent acceptance. No silent empty-store adoption, namespace
recreation or domain rebinding. Full recovery can wait; fail-closed behavior
and the accepted threat boundary cannot.

Implementation order: (1) review concrete platform task/delegation, authoritative
evidence and store-enforcement contracts together; (2) offline negative proofs
for their adapters, including probe/installer boundaries; (3) separately approved
installation and bounded enforcement validation; (4) explicit runner revision
and end-to-end offline proof, then separate live approval for one Candidate;
(5) future Console submission/status integration through the same operation
boundary. Do not activate a partially supported profile or re-enable a gate on
the strength of this design decision. Existing historical happy-run evidence,
Candidate files and immutable terminal outcomes remain unchanged.

#### Concrete platform tasks: offline contract proposal

This inventory makes the shared-runner minimum reviewable; it defines neither
HTTP routes nor a new public schema, executable task registry or deployable Job.
The labels below describe fixed capabilities, not caller-selected commands.
One platform integration may own them, but must not expose their union as a
credential to a runner, CLI user or browser. Actual issuer image/spec/identity,
request-window policy and enforcement/recovery boundaries remain unapproved.

Every future request must be authenticated under platform delegation and match
independently verified operation/plan/attempt, target Cluster UID, API/CA trust,
policy and authoritative predecessor evidence. Bind caller environment/tenant
scope at the operation boundary; never infer it from submitted fields or a
matching digest. The task owner must verify current authority at point of use.
No client can choose an image, ServiceAccount, key path, shell command, arbitrary
resource path, API endpoint, Pod selector or RBAC body outside that bound plan.
Public source/CA identity is not authority to read its signing key.

| Fixed task | Exact allowed input/action | Result allowed back across its boundary |
| --- | --- | --- |
| Observer access | Existing #456 signed request for exactly `network-observer` after the successful Stage-4 prefix or `runtime-observer` after Stage 5. Verify the exact CSR and local profile, source namespace/name/UID/RV/Cluster owner, CA fingerprint and public/private-key correspondence inside the privileged task. Claim the #456 slot before signing, check source identity immediately before use, then persist the bound authenticated result before delivery. | The existing signed candidate result contains the public leaf certificate and exact request/slot/claim binding. Private client key stays with the runner; CA key never leaves the task. The public certificate is runtime transport material, not a browser result or a stage grant. Claim-only/unknown write stays STOP; no second issuance. |
| Cilium Pod discovery | Stage-5 target and four-receipt prefix; the platform performs only the fixed `kube-system` Cilium discovery, not a caller-chosen selector. Verify the bound DaemonSet/controller identity, selected Pod UID, expected node association and required container. Existing collection/evaluator size limits still apply. | A bounded allowlisted projection of agent identity/readiness required by the existing evaluator plus an authenticated binding to the target/sample. Never raw Pod objects/specs, environment variables, annotations, tokens or arbitrary Pod inventory. The current direct Pod LIST is not this mediated boundary. |
| Fixed Cilium probe | Same authorized Stage-5 observation window and platform-selected Pod identity; only `cilium-health status --probe --output json` in `kube-system`, container `cilium-agent`, with no stdin/TTY or caller arguments. Platform retains the exec capability. | Only the bounded probe evidence needed by the existing network evaluator, bound to the observed target, selected Pod UID and sample. Raw stdout/stderr is not a Console response. Missing or unauthenticated evidence cannot become success. |
| Target-access installation | Exact Stage-7 selection after six durable successful receipts, verified runtime target, separately authenticated plan provenance/grant and the renderer-owned sixteen-object artifact. Reuse existing plan/object checks; enforcement must also constrain accepted bodies and privileges at the platform/API boundary. No generic apply/patch/delete endpoint or blanket bind/escalate. | Durable per-object identity/content observations and the existing stage outcome/evidence semantics. No installer credential is returned to the runner/browser. A submitted body or HTTP success alone does not establish convergence; partial/unknown outcomes remain incomplete/STOP. |

The observer candidate message checks already exist. For discovery, probe and
installation, an authenticated request/result envelope and its exact delegation
to the existing adapters still need review; a boolean such as `authorized=true`
is not a substitute. Issuer request/result keys must not be repurposed as
Stage-Authority, independent-evidence or CA signing keys. Do not silently extend
#456 messages, stage grants or the current shared certificate manifest fields to
carry these other tasks. Role-specific runtime wiring needs its own reviewed
revision, not a flag that re-enables certificate mode globally.

**Accepted MVP platform trust boundary:** in [Suchit's independent review
decision](https://github.com/openkubes/ok-cluster/pull/452#issuecomment-6264742337),
platform administrators, CAPI/Enablement, the approved ArgoCD identity and the
privileged Cilium runtime are trusted. CLI, runner, Console and tenant workloads
remain outside that administrative boundary. Containing a compromised platform
controller or privileged Cilium runtime is out of scope for this MVP. That
residual risk matters because a successful network-observation receipt gates
runtime binding; trusted-source evidence is part of this model, not proof
against a compromised trusted runtime.

**Probe TOCTOU is an accepted limitation under that trust model, not an
additional activation blocker.** Existing
`KubernetesCiliumWebSocketExecutor` performs a Pod identity GET, then a name-based
exec, then another identity GET. The Kubernetes
[`PodExecOptions` at v0.35.5](https://github.com/kubernetes/api/blob/v0.35.5/core/v1/types.go#L6810-L6836)
does not provide a Pod-UID precondition: the fixed command may already have run
in a normal rollout replacement when the final GET detects a changed UID.
The post-exec check rejects that observation and returns no usable probe output.
It does not prevent the earlier stream from executing, and must not be
described as an atomic UID-bound execution guarantee.

The accepted scope is the existing fixed
`cilium-health status --probe --output json` action in a trusted Cilium runtime,
not arbitrary exec or configuration modification. It sends functional probe
traffic and updates health observations/metrics; it is not a read-only
Kubernetes API request. The [pinned Cilium command](https://github.com/cilium/cilium/blob/v1.19.6/cilium-health/cmd/status.go)
requests a synchronous connectivity probe rather than merely returning cached
status. Under the accepted platform trust boundary, allowing that fixed action
to run in a trusted replacement Pod while discarding its raced output is
acceptable. No Bash wrapper, UID environment projection, guarded framing
decoder or new prevention protocol is required for that race.

| Principal/path | Accepted MVP trust scope | Still required before activation |
| --- | --- | --- |
| Platform administrators, CAPI/Enablement, approved ArgoCD identity and privileged Cilium runtime | Trusted for their existing platform responsibilities, including Cilium and admission/RBAC integrity. Compromise containment of these trusted actors is out of scope. | Bind the actual approved platform identities and delegation to the selected profile. Existing object labels/names alone are not authorization. No existing Platform rights are silently removed. |
| CLI, runner, Console callers and tenant workloads | Outside platform administrative authority. No arbitrary command/image/Pod/endpoint selection or platform exec credential is delegated to them. | Authenticated operation/plan/attempt/target and fixed-task delegation; bounded discovery; effective negative-RBAC/indirect privilege-path checks for actual execution identities. A UI permission or code allowlist alone is not proof. |
| Trusted network observation used for runtime binding | Source evidence is evaluated under the accepted trusted-runtime model, not as evidence resistant to a compromised Cilium runtime. | Exact successful NetworkReady receipt, target/prefix binding and all unchanged convergence/evidence checks. UID drift discards the sample; process exit success or incomplete output cannot produce success. |

This decision does not enable mediated exec, discovery, authorization,
certificate issuance, store continuity/anti-delete enforcement, Stage-7 signing,
recovery or a live run. These gates remain closed as written. The new shared
task must not expose the union of platform privileges to the runner or Console.
The renderer-owned sixteen-object Stage-7 contract and ADR-030 item 9 OPEN are
unchanged; #458 remains a separate internal-denial follow-up. No resolver
allowlist is expanded by accepting this trust model.

Source-only writer review (2026-10-19): the current CLI profile grants
`ok147-argocd-manager` Services access, not Pod writes, through its `kube-system`
Role. Its cluster role grants CREATE/UPDATE/PATCH/DELETE on mutating/validating
webhook configurations. This is privileged platform authority
([Kubernetes guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#control-admission-webhooks)),
not automatically an unexpected tenant privilege under the accepted trust
model. Do not infer tenant isolation from the namespace Role alone, or silently
remove existing Platform permissions. Stage 7 follows initial network
observation; its grants must not be retroactively assumed present before Stage
5, or absent in a reused/partially configured target. No source review proves
the identity of every credential holder or the absence of future changes.

Separately authorized read-only follow-up on `ok-cli-mvp-3` (2026-10-19): the
existing CAPI guest kubeconfig was retrieved from the management plane and
stored privately; its endpoint matched the exact CAPI Cluster. The snapshot
contained nine `kube-system` Roles and RoleBindings each, 78 ClusterRoles and 57
ClusterRoleBindings. It confirmed the webhook-mutation ClusterRole and its
binding to `kube-system/ok147-argocd-manager`. No mutating/validating webhooks,
ValidatingAdmissionPolicies or policy bindings were present in that snapshot.
The Cilium DaemonSet used the digest-pinned 1.19.6 image. No Pod exec or Cilium
action was performed, no credential was issued/renewed, and no cluster resource
was changed. This limited projection does not enumerate all token holders,
arbitrary namespace roles, runtime image state or a fresh Candidate's Stage-5
frontier. Raw credentials and snapshots are not committed to this PR.

The earlier UID-guard candidate and its Bash/YAML fixtures, Python suite,
test-only Go decoder and dedicated CI step are removed following the review.
The accurate executor TOCTOU comment, changed-task-before-I/O regression and
empty-output assertion on UID drift remain. Historical experiment results do not
constitute activation evidence; actual platform-task authorization, discovery,
issuance and Stage-7 proofs remain outstanding.

Cleanup validation (Go 1.26.7/macOS amd64): all-package
`go test -mod=readonly ./... -count=1` and `go vet -mod=readonly ./...` PASS;
`go test -race -mod=readonly ./internal/runner -run
TestKubernetesCiliumWebSocketExecutor -count=10` PASS. The opt-in
`OK147_WEBSOCKET_INTEGRATION=yes` RemoteCommand-v5 test PASS three times against
only a local fake TLS server. CI YAML parsing and diff checks PASS; the removed
candidate has no remaining executable/CI references. These are offline proofs,
not live authorization, issuer installation or complete security acceptance.

Alternatives not selected: more pre/post GETs cannot make exec atomic; Kubelet
has a UID-specific route but accessing it through `nodes/proxy` brings broad
node-level authority ([Kubernetes guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes)).
Do not grant that right as a shortcut. A helper mounting host/Cilium sockets
would add another privileged boundary and is not selected here. Removing
`--probe` would substitute cached status for the required synchronous probe
([Cilium v1.19.6 source](https://github.com/cilium/cilium/blob/v1.19.6/cilium-health/cmd/status.go));
it is not an acceptable readiness shortcut under the current contract.

Observation polling is distinct from mutation replay. Preserve the existing
bounded convergence polling and evaluator Unknown/pending states for warmup.
Each collection permits only its fixed bounded reads/probe within the accepted
stage/credential window. Polling must not renew credentials, acquire a second
issuance slot, repeat installation or restart a stopped stage. Source identity,
authorization or evidence-integrity failure is not a transient warmup condition.

Offline acceptance cases, before selecting any runtime protocol:

1. Observer request/claim/result: existing #455–#457 wrong-role/key/source/CSR,
   concurrency, crash and lost-response tests, plus future authoritative-prefix
   and actual source/key adapters. Existing fixtures prove only their local scope.
2. Discovery: reject caller selectors, foreign controller/target/Pod/node,
   duplicate or oversized projections and raw spec/credential leakage. No
   discovery adapter or authenticated projection verifier is implemented here.
3. Probe: every changed namespace/container/command argument must stop before
   identity HTTP or stream construction. Post-exec UID drift must discard all
   output with no automatic retry. These regressions prove detection/discard,
   not prevention of an already-started fixed probe in a trusted replacement;
   that TOCTOU limit is accepted under the MVP platform trust boundary.
4. Installation: retain full artifact/prefix/grant/target/body negatives from
   `submission` and `runner`; future enforcement tests must also reject a
   credential holder submitting another body outside the Go adapter. Reject
   subset/success shortcuts, unknown writes and unsupported plan provenance.
5. End-to-end: no request/result may open a disabled #437 entry point or count
   task completion as full cluster success. Neither CLI nor Console gets a
   parallel authorization path. Live enforcement/issuance proofs remain NOT RUN.

#### Confirmed source boundaries

The pinned CLI profile uses the existing Talos/KubeVirt renderer. Its control
plane template already includes `cluster.inlineManifests` for local-path storage.
That is a possible **declarative bootstrap seam**, not an existing credential
issuer or permission to place credentials in rendered artifacts. The checked
local `ok-linux/profiles/kubevirt/profile.yaml` pins Talos v1.9.6; this is source
evidence, not verification of any deployed cluster/version.

| Runner boundary | Existing workload action | Constraint on a future access profile |
| --- | --- | --- |
| Stage 5: network observation | Read Nodes, exact Cilium workloads and Cilium Pods; execute the fixed Cilium health probe in a selected Pod | A probe is not a read-only API capability. Do not describe `pods/exec` permission as command-restricted RBAC; the fixed command is enforced by the adapter, not ordinary RBAC. Keep Pod identity checks and arbitrary-exec denial; trusted replacement execution with raced output discarded is an accepted MVP limitation, not atomic execution. |
| Stage 6: runtime binding | GET `kube-system` Namespace and `local-path` StorageClass; persist binding material and the stage receipt separately on the management plane | No workload storage sandbox or new write test is performed here. Keep workload observation rights separate from management evidence writes. |
| Stage 7: target access | Submit the fixed namespace, ServiceAccount and RBAC object set, including reviewed platform ClusterRole prerequisites | Role creation/binding has privilege-escalation implications. Exact manifest validation in Go is not proof that a stolen credential cannot submit another body. |

Sources: `internal/observation/network_collector.go`,
`internal/runner/cilium_websocket.go`, `internal/runner/runtime_binding_source.go`,
`internal/submission/target_access.go`, `profiles/cli/talos-kubevirt-mvp-v1.json`,
and `templates/talos/providers/kubevirt/cluster-base.yaml.tpl`.

The current full-run composition shares workload credential destinations between
these stages. A per-role credential split must therefore be an explicit reviewed
manifest/adapter change, not an undocumented widening of one observer identity.
Do not change stage order, completion/readiness evidence or use the Bare-MVP
label to omit any required probe. Stages 8–12 are not implicitly reopened by a
Stage-5–7 proposal.

#### Recommended integration sequence

1. Retain the merged #437 certificate/recovery gates and its independent-review
   follow-up; merging a mitigation does not approve a new issuance profile.
2. Agree the initial workload issuance profile and the existing platform owner
   that can enforce it. A narrowly scoped certificate issuer outside the runner
   is a candidate because the current manifest is certificate-shaped; an approved
   token bootstrap is an alternative, not already proven by TokenRequest support.
   The candidate below recommends an architecture for review, not an approved
   or implemented issuance option. A CSR or
   TokenRequest alone does not solve authenticated first access to the new API.
3. For certificate mode, review exact per-role CN, complete O/group set, trust
   root, clientAuth usage, target binding and maximum total validity, together
   with installed RBAC. No numeric TTL or accepted subject is invented here.
   The runner must never receive a CA signing key or use the retained CAPI admin
   kubeconfig to obtain the bounded credential. A signer with workload-CA access
   is itself a privileged platform authority whose key isolation, issuance
   restrictions, audit and compromise boundary require review; it is not made
   least-privilege merely by being called a broker.
4. Bind a typed issuance request/result to Contract/plan, execution attempt,
   observed target Cluster UID and API/CA identity, role and policy revision.
   Define the durable claim/outcome boundary before issuance: a lost response
   must not silently cause a second issuance or runner replay. Target recreation,
   predecessor drift, expired access or an indeterminate outcome stops the run.
5. Review bootstrap RBAC/admission installation through the existing renderer/
   lifecycle seam. Preserve Talos sysctls, user-namespace settings, kubelet bind
   mounts and storage identity. Never hide this as a new imperative Go renderer.
   Kubernetes `resourceNames` cannot constrain collection CREATE requests; named
   `escalate` rules must not be assumed to protect Role CREATE. Exact-content
   admission or an equivalently reviewed boundary is needed where body scope is
   security-critical. Do not replace this with wildcard or broad escalation.
6. Prove negative cases offline first: wrong issuer/subject/groups/target/CA,
   lifetime drift, cross-role use, extra RBAC bodies, arbitrary exec, concurrent
   duplicate requests, target recreation and crash after claim. Then obtain a
   **separate** approval for a bounded live issuance/deployment validation. Only
   reviewed supported profiles may be enabled; unsupported modes keep failing
   before Stage 1. Recovery/fencing and old-grant retirement remain separate.

#### Candidate A: platform-owned one-shot certificate issuer

**Recommended for feasibility/security review, not selected for execution.** A
fixed, digest-pinned, short-lived issuance Job on management workers would sign
one approved request per role. It would not be another cluster controller or a
long-running Installer Operator. The runner would retain its existing ephemeral
execution model and CAPI would retain lifecycle ownership.

Why investigate this first: a management-side signer could issue the first
bounded workload credential without authenticating to that workload API using
the prohibited CAPI admin kubeconfig. Upstream CABPT documents a Kubernetes CA
Secret separately from the Talos secret bundle and Talos API configuration.
That establishes a possible source seam, **not** that its deployed version,
actual owner, Secret identity/key layout or access permissions are verified.
The exact provider release and source must be pinned before implementation;
do not infer ownership from a `<cluster>-ca` name alone. Upstream maintenance
status is an integration risk to review, not authority to migrate providers.

The proposed trust boundaries are:

- The runner generates its own client private key and CSR locally/in its private
  execution volume. It never reads the CA private key, CAPI admin kubeconfig or
  Talos admin configuration; private keys never enter Contract/plan, public
  requests, receipts, Job arguments or logs.
- A separately authorized platform installer owns the exact Job spec, pinned
  image, ServiceAccount, key-source access and admission policy. Runner users do
  not receive arbitrary Job-create or Secret-read rights to invoke the signer.
  RBAC alone cannot constrain a Job-create body or which Secret it mounts.
- The signer's reviewed request surface must limit it to its target CA source
  and issuance coordination/result records. It must not mint stage grants,
  update desired state, rotate CAs or issue for another target.
  Possession of a CA key is nevertheless a high-privilege compromise boundary:
  a compromised signer could impersonate privileged users. The proposal does
  not claim RBAC can restrict what a process can sign with a key it possesses.
- The source must bind namespace/name, observed Secret UID, owner references,
  CA fingerprint and target Cluster UID to the verified lifecycle receipt
  prefix. Source identity/RV drift stops before signing. Result verification
  rejects wrong CA, subject/groups, EKU, validity or CSR public key before use.
  No CA key or another user's client private key is returned to the runner.

The future flow would be: verify issuer/profile/delegation wiring before Stage 1;
let the existing owners create/converge infrastructure; verify the authoritative
Stage-4 prefix and target UID; claim issuance, run the exact platform task once,
verify its result, then continue the existing required observations. An unknown
source contract or missing accepted profile still denies before Stage 1. This is a future
explicit manifest/profile revision, not a reinterpretation of current v3/v4.

Proposed identity separation for review (not an accepted CN allowlist):

| Capability | Proposed boundary |
| --- | --- |
| Network observation | Read-only workload identity; no exec, RBAC write, Secret read or token minting. |
| Fixed Cilium probe | Separate platform-mediated fixed-probe capability; no arbitrary command argument or raw exec credential returned to the user-facing CLI. Ordinary exec has no atomic target-UID precondition; fixed-probe execution in a trusted rollout replacement with output discarded on UID drift is an accepted MVP limitation. Mediated task authorization remains unimplemented and closed. |
| Runtime binding | Separate observer limited to the required Namespace/StorageClass reads; management persistence remains separate. |
| Target-access installation | Separate exact-body submission capability; RBAC/admission and privilege-escalation negatives must be proven before issuing usable installer access. No blanket `escalate`, `bind`, impersonation or wildcard alternative. |

For X.509 role identities, propose explicit User subjects with an exact empty
certificate O/group set (not a new shared group). Kubernetes' automatically
assigned authenticated group is distinct from certificate O. Subject templates
must be operation-specific and reject `system:` identities; exact templates
remain unapproved. If a fresh operation nonce is used, generate and bind it
**before** rendering/hashing: embedding a final plan digest in a subject already
inside the plan would create a circular identity. Target UID binding belongs in
the verified issuance request/result after lifecycle convergence, not guessed
inside a pre-rendered object.

An issuance slot must be keyed by accepted plan/attempt, target UID and role;
its immutable claim binds the exact CSR and policy revision. Do not put only the
CSR digest into the slot key: changing a CSR must not create another issuance
opportunity for the same operation/role. Concurrent tasks have one winner. An
issued result may be retrieved idempotently; claim-without-result remains
indeterminate with no automatic issuance retry, timeout takeover or runner
replay. The issuer's coordination backend needs its own reviewed narrow write
policy; existing immutable stage outcome records must not become mutable slots.

#### Issuer-record protection: bounded installation plan for review

**PLAN ONLY / NOT INSTALLED.** Merged #455 provides offline observer validation,
#456 separates request/result authority and one-use coordination, and #457 adds
an explicitly configured Kubernetes storage adapter. None is linked into the
CLI/runner, and none installs an issuer. The locally approved observer profile
does not constitute production security acceptance or deployment approval.
See [the adapter evidence](evidence/ok147-bootstrap-issuer-store/README.md).

The purpose is replay prevention, not preventing cluster deletion. A claim says
that the one issuance opportunity for plan/attempt/target/role is consumed. If
the process crashes after claiming, the durable state remains STOP, even if no
result was recorded. Deleting the claim and result could otherwise make the
same slot appear empty. Expiry of a certificate does not erase this history.
These records are not cluster-convergence evidence or authorization to repeat
an operation.

Proposed controls, restricted to a **separate issuer-storage domain**:

| Surface | Required protection before activation |
| --- | --- |
| Issuer writer | Dedicated platform identity: only required exact GETs and ConfigMap CREATE. No update, patch, delete/deletecollection, namespace mutation, RBAC/admission mutation, impersonation or Secret access through this storage role. The runner/user does not receive it. Other required signer capabilities need their own reviewed boundary. |
| New claim/result | Admission checks the reviewed writer, full slot/name relationship, immutable flag, exact record envelope, pinned domain/namespace identity and absence of owners. No arbitrary ConfigMap creation. Schema checks do not authenticate signed contents; the Authority still verifies signatures, predecessor evidence and time. |
| Existing records and fence | Deny UPDATE/PATCH and DELETE within the dedicated namespace, including deletion requests that omit an individual name. Protect metadata as well as data, preventing owner injection or removal of identity markers. No overwrite, TTL cleanup or automatic repair. |
| Storage namespace | Protect the exact namespace against deletion and identity/purpose drift; do not rely on removable object labels for policy coverage. Include collection-delete/finalization paths in the review and tests, rather than assuming ConfigMap protection covers namespace lifecycle. |
| Enforcement and writer identity | Runner/issuer may not alter policy/binding, service-account or RBAC definitions to bypass the controls. Their lifecycle belongs to separately authorized platform administration. Policy removal/reconfiguration is a security boundary, not ordinary cluster cleanup. |

Kubernetes immutable ConfigMaps still permit deletion/recreation
([ConfigMap documentation](https://kubernetes.io/docs/concepts/configuration/configmap/#configmap-immutable)).
RBAC permissions are additive, and `resourceNames` cannot restrict collection
CREATE requests ([RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)).
Consequently, omitting DELETE from one Role or validating bodies only in Go is
not sufficient enforcement. A candidate is built-in ValidatingAdmissionPolicy
with failurePolicy Fail and a Deny binding; exact capabilities/version and CEL
rules must be reviewed and tested before selecting an installable package
([admission documentation](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)).
No executable policy manifest or claim that these controls are deployed is
introduced here.

Installation order for a **future separately authorized** platform setup:

1. Prepare the exact object inventory, API-version prerequisites, protected
   names, dedicated identity, intended rules and package digest offline. Reject
   collisions rather than adopting similarly named objects. Do not invent UIDs
   or assert that the current management API supports the proposal.
2. After separate read-only approval, observe API capabilities and existing
   objects. After separate installation approval, establish restrictive
   policy/binding coverage before any issuance writer becomes usable. Keep the
   issuer disabled throughout bootstrap; missing enforcement means NO-GO.
3. Create the dedicated namespace and immutable fence through the narrowly
   reviewed platform installation path, not through an issuer exception. Record
   their actual UIDs and fence resourceVersion, bind API/CA trust and compute the
   exact domain identity. Installation exceptions must not remain a general
   replacement/delete capability. Enable only the reviewed narrow storage role.
4. Verify the exact installed definitions and negative cases using disposable
   fixtures under a separate bounded validation approval. Observed acceptance of
   CREATE is not proof that DELETE is denied, nor are fake-API tests proof of
   real admission enforcement. Partial installation, drift or an unknown write
   outcome stops; do not automatically roll back protections or start a signer.
5. Only after independent security review and the remaining bootstrap/probe/
   installer contracts may a separately authorized issuance integration be
   considered. Storage protection alone does not reopen #437 gates or prove a
   successful cluster run.

Acceptance matrix to implement/test before installation: allowed exact create
and historical read; wrong writer/body/domain/name; concurrent same-slot create;
record/fence update and delete; collection delete; namespace deletion and label/
UID drift; owner-reference injection/garbage-collection paths; enforcement
disablement; claim-only crash; lost write response; and normal Candidate teardown
leaving the issuer store untouched. Tests of hypothetical rules are not evidence
of the management cluster enforcing them. No live validation was run for this
plan.

**Limits and recovery:** these controls do not defend against an administrator
who can remove enforcement, direct datastore access or restoration/forking of an
old management snapshot with the same UIDs. Client-side pre/post checks are not
an atomic namespace-lifecycle fence. After such an event the issuer must remain
disabled; no automatic resume, empty-store adoption, domain rebinding or request
reissuance is allowed. A separately reviewed externally trustworthy continuity/
recovery mechanism is still required; this plan does not implement one. Initial
retention proposes no automatic record removal. Future retention/recovery and
administrative escape procedures need explicit review, not a hidden bypass.

`ok cluster destroy <name>` should continue to remove the authorized workload
cluster, not this independent history. No changes to existing execution-ledger
RBAC, teardown ownership, OK-197/OK-198, Candidate manifests or readiness contracts
are proposed. This is one-time platform work, not new recurring end-user prompts.

**Still blocking activation:** exact deployed CA ownership/key-source contract;
approved per-role subjects and RBAC/admission/probe restrictions; a justified
certificate lifetime and clock-skew policy; issuance-request authentication and
durable coordination; authenticated plan provenance before any Stage-7 signing
can return. An active numeric TTL remains UNSET/NO-GO (the review proposal below
is not an enabled default): the CLI's three-hour execution
timeout and the existing one-hour TokenRequest limit are not certificate-policy
approval. Renewal after expiry is a new authorized issuance decision, not an
implicit replay or automatic extension of a previous outcome.

The first local checkpoint is now present in #455: offline request/result
validation and negative fixtures, without a signing method, CA-key reader,
Job launcher, enabled certificate profile or live entry point. #456 and #457
add candidate authority/storage boundaries without activation. The next platform
task and adapters still require the concrete contracts above and a reviewed next
revision. Do not mix them into the accepted #437 mitigation or silently expand
a public CLI/runtime schema.

#### First observer profile: concrete decisions for review

**LOCALLY APPROVED CHECKS; no production issuer activation or live authority.**
The observer constraints below are implemented in the isolated #455 package;
#456 authenticates candidate request/result messages and #457 adds a fake-API-
tested storage adapter. None establishes deployed issuer/source/RBAC enforcement
or independent security acceptance of Candidate A. Production policy and
integration still need the reviewed platform contract. The synthetic ten-minute
test cap is not policy. The following table describes the local profile and
remaining production proposal, not enabled runtime defaults:

| Decision | Review proposal, not an active default |
| --- | --- |
| Identities | Separate exact CNs `ok147:<operation-nonce>:network-observer` and `ok147:<operation-nonce>:runtime-observer`; nonce is 32 lowercase hexadecimal characters generated before rendering/plan hashing. Empty certificate O/group set; no SANs; digitalSignature and clientAuth only. |
| Lifetime | Locally approved maximum total certificate validity 45 minutes, including at most 60 seconds of backdating. No acceptance before NotBefore or after NotAfter, and no automatic renewal. Production issuer activation remains subject to review. |
| Issuance timing | One distinct role slot per plan/attempt/target UID, issued just before the relevant stage after its authoritative predecessor prefix. Do not issue both roles before infrastructure convergence, share one credential between stages, or reinterpret the current v3/v4 shared credential fields. |
| Budget | The selected observation window must be at most 30 minutes. Initial issuer-result handoff plus scheduling must consume at most five minutes; check actual remaining certificate lifetime before stage entry. A missed budget stops without shortening observation, extending the certificate, reissuing or replaying. |
| Runtime observer | Only GET the `kube-system` Namespace and `local-path` StorageClass in the bound workload cluster. No workload writes, Secret access, TokenRequest, RBAC modification or exec. Management receipt persistence uses a distinct authority. |
| Network observer | LIST Nodes; GET `kube-system` DaemonSets `cilium`/`cilium-envoy` and Deployment `cilium-operator`. Recommend platform-mediated, fixed-selector Pod discovery instead of delegating raw Pod LIST to the runner/user. The current adapter's Cilium label selector is **not** an RBAC restriction: direct Pod LIST permits reading other Pods in that namespace. The mediated adapter/protocol must be reviewed before enablement; namespace-wide direct Pod LIST is not selected by this proposal. No exec, Secret access, TokenRequest or RBAC writes. |

Timing rationale: `cmd/ok/cluster_create_template.go` supplies 30-minute
lifecycle/network polling windows; `cmd/ok/cluster_intent_plan.go` supplies a
1,800-second observation budget. The direct runtime-binding source independently
allows 30 minutes (`internal/runner/runtime_binding_source.go`). A separate
Stage-6 Job fixture has a 180-second deadline; that does not shorten the direct
source contract. A proposed 45-minute cap leaves room for the selected 30-minute
observation, bounded initial handoff and backdating; remaining margin is an
operational proposal, not measured issuance latency or an existing entitlement.
Longer expert polling windows must remain unsupported by this initial profile
unless a separately reviewed policy changes it. No current polling limit changes.

The profile budget check needs to include the actual role-specific stage wrapper
overhead as well as polling and reject insufficient remaining lifetime. A
network observer credential does not replace the required functional Cilium
probe. Probe mediation/authorization and exact-body target-access
installation/admission are still separate unresolved capabilities; implementing
only these observers cannot claim complete automatic cluster creation.
The fixed probe's name/UID TOCTOU limit is accepted under the trusted-platform
model; no additional atomic-exec guard is a prerequisite for this MVP.

Platform task requirements remain: fixed reviewed image/spec/ServiceAccount;
authenticated request and predecessor evidence; source UID/RV/Cluster owner and
CA fingerprint checks; CA certificate/private-key public-key correspondence
checked **inside the privileged platform task**, never by exporting the signing
key to the CLI; atomic single-winner claim before signing and immutable result
persistence. Image digest, request authentication, coordination backend and
admission rules still need concrete review. No arbitrary Job-create or Secret
read is delegated to the runner/user, and a claim without a durable result stays
STOP/indeterminate. Do not start a real signing task based on this proposal.

A separately approved metadata-only observation on 2026-10-18 confirmed that one
existing test cluster's named CA Secret had exactly the corresponding Cluster
controller owner UID, using two GETs and no Secret data. Selected identities were
retained privately; raw metadata and annotations were not published. This is
point-in-time object-ownership evidence only, not proof of CA contents, signing
key correspondence, cross-read stability or rights for a new operation. The
observation grants no issuer installation, key access, credential issuance or
runner execution.

#### Deployed provider inventory and release-specific source check

The separately authorized read-only inventory completed on 2026-10-18 after
management API recovery. Each listed Deployment had one ready replica and a
Running/ready manager container with the following image identity. These are
point-in-time observations, not a compatibility certification or issuance grant.

| Namespace / Deployment | Declared manager image | Running container image digest |
| --- | --- | --- |
| `capi-system/capi-controller-manager` | `registry.k8s.io/cluster-api/cluster-api-controller:v1.13.4` | `sha256:7a70942e0b45ae59514ee03cf448b64dbd2d77ef2fd7104e6c104f1c6b6b2013` |
| `cabpt-system/cabpt-controller-manager` | `ghcr.io/siderolabs/cluster-api-talos-controller:v0.6.12` | `sha256:ff3f4fc7dada9c3a6ca310921ee68be3d50f6e714b42976d85965cf61180b788` |
| `cacppt-system/cacppt-controller-manager` | `ghcr.io/siderolabs/cluster-api-control-plane-talos-controller:v0.5.13` | `sha256:5196c77e1dd872ea75aacc264d7cc720944e824237c766143da541dd49bd342f` |

Scope was Deployment image references and Pod status/image IDs in these three
management namespaces only, using existing access. No Secret query, credential
issuance/renewal, resource mutation or workload API call was part of this
inventory. The preceding failed inventory observed an API discovery timeout;
that failure was not evidence of absent providers or expired credentials.

The matching [CABPT v0.6.12 source, `writeK8sCASecret`](https://github.com/siderolabs/cluster-api-bootstrap-provider-talos/blob/v0.6.12/controllers/secrets.go#L121-L153)
creates `<cluster>-ca` in the bootstrap config namespace, with a Cluster
controller owner reference and `tls.crt` / `tls.key` entries. Crucially, it returns
without validating an already existing Secret. Therefore a matching name and
running provider version do **not** prove actual owner, key layout, CA identity
or suitability as a signing source. The source check establishes a possible
integration seam only; no live CA Secret metadata or data was inspected.
Release-tag source inspection is not an image-to-source provenance attestation.

Remaining activation blockers above are unchanged. A future separately scoped
source-identity check must bind actual Cluster/Secret UID and owner references,
CA fingerprint and the durable lifecycle receipt prefix; it must not expose a
CA private key to the CLI or runner. Do not turn this inventory into implicit
permission for Secret reads, a signing Job, new RBAC or certificate issuance.

#### User experience after that contract is implemented

One explicit platform setup delegates the reviewed scope. Normal users still
use `ok cluster create --file cluster.yaml` and `ok cluster destroy <name>` with
one understandable confirmation. The CLI automates the internal preparation,
private credential references and temporary connectivity within that delegation;
users do not manage issuers, token files, digests or handoff JSON per cluster.
No extra end-user command, long-running Installer Operator, public CRD, automatic
retry or privileged bootstrap fallback is introduced by this design proposal.

Primary references: [Talos v1.9 machine configuration / inline manifests](https://docs.siderolabs.com/talos/v1.9/reference/configuration/v1alpha1/config),
[Kubernetes RBAC restrictions and escalation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
and [Kubernetes certificate requests and signers](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/).
For Candidate A: [CABPT CA/secret ownership documentation](https://github.com/siderolabs/cluster-api-bootstrap-provider-talos#operation)
and [Kubernetes X.509 user/group authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certs).
These upstream references must be matched to the deployed/pinned provider
release before being treated as implementation evidence.

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
are complete locally, not authorized for execution. In the normal interactive
command, this is presented as a short human-readable summary: local preparation
complete, cluster creation not started, platform access setup required. It does
not offer confirmation, print internal digests or ask for token/handoff paths.
`--prepare` retains its existing machine-readable JSON receipt and nonzero
exit status, including request identity and false safety/readiness fields.
This is presentation only, not a platform issuer, credential-policy decision or
promise that providing a handoff enables an otherwise unsupported workload
credential profile. Repeating the command checks
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
`ok cluster destroy <name>` discovers the retained render at
`<managed-run>/preparation/<name>` automatically. It checks private non-symlink
directories, the name-bound static binding/execution fixture, and both effective
kubeconfig targets (context, cluster, API endpoint and CA trust) locally. It never
loads create credentials or requires the old executable/unfinished create state.
Terminal outcomes and start fences remain untouched. A separate interactive
`ok` is still required before the existing teardown lifecycle can contact APIs.
Incomplete/changed managed metadata or conflicting legacy inventory stops without
fallback; `--cluster-dir` remains an explicit expert override after review.

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

Omitted flags use the saved paths. Without `--cluster-dir`, a managed `ok up` render
is discovered first, with its name and plane identities checked locally (and
rechecked after confirmation). If no managed run exists, `clustersDir` is the
parent of retained legacy cluster directories, not the lifecycle source checkout;
the legacy target is `<clustersDir>/<name>`. If both directories exist, selection
is ambiguous and stops; no precedence silently chooses a destructive target.
Explicit flags override individual saved paths, and `--cluster-dir` overrides
discovery with the existing expert routing contract. The confirmation
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
