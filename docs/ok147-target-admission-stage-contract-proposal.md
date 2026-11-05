# OK-147 target-admission activation stage — proposal only

Status: **PROPOSED / INDEPENDENT REVIEW REQUESTED / NOT ACCEPTED BY THE RUNNER**

This document records the smallest future contract needed to install the
target-admission service before Stage-7 writes. It adds no executable stage,
grant operation, CLI command, credential, or cluster authority. Existing plans
and grants remain unchanged.

## Why a distinct stage is required

The target-admission service must be active before the current `target-access`
stage creates the sixteen protected workload objects. Installing it as a side
effect of `target-access` would mean the admission boundary is absent during
the writes it is intended to constrain. The current seven-stage Bare-MVP plan
does not contain an installer or activation operation, so no current grant can
authorize this work.

## Decision register: approval versus implementation

The following seven decisions change the authority or execution contract. Each
remains **OPEN** and needs explicit human approval plus sufficient evidence
before implementation can enable activation:

| Decision | Approval needed | Why it gates implementation | Status |
| --- | --- | --- | --- |
| Target-side enforcement source | Select an independently trusted profile/bootstrap installation point; otherwise keep activation disabled. | Activation cannot install the guard that must constrain its own writes. The current profile does not prove an earlier installed target guard. | **OPEN** |
| Installer ownership and identity | Select the fixed-purpose controller/installer and its authentication, target scope, and server-side restriction. | Kubernetes RBAC cannot restrict collection `create` by name or body; the proposed set includes ClusterRole, ClusterRoleBinding and a cluster-scoped webhook. | **OPEN** |
| Signing and private material custody | Approve who signs the target-bound policy, how the public-key pin is delivered independently, and how TLS/policy material reaches the installer. | No CLI/runner signer or private-material handoff is defined; the current offline plan intentionally excludes these private objects. | **OPEN** |
| API-server source CIDR evidence | Approve an independent method to establish the source addresses the webhook Pod actually observes. | The endpoint IP is not evidence of the peer source address; forwarded headers are untrusted. | **OPEN** |
| Durable dispatch and STOP/recovery | Select the immutable claim/outcome store and the operator-owned recovery procedure for partial or ambiguous installation. | A set of Kubernetes writes is not transactional; retry, rollback or automatic cleanup would risk replay or widening an unknown partial state. | **OPEN** |
| Stage-plan compatibility | Approve a new stage-plan/grant version with activation before `target-access`, invalidating old-plan grants without a skip path. | The current Bare-MVP plan has seven stages and the full plan twelve; insertion changes them to eight and thirteen. | **OPEN** |
| Stage-5/Stage-7 relationship | Confirm whether the activation work is coupled to the reviewed Stage-5 non-exec evidence and Stage-7 controller boundary. | Credential issuance alone does not make `pods/exec` or the 16-object Stage-7 write enforceably least-privileged. | **OPEN** |

These statuses are not approvals. This owner review accepts the proposal for
continued design work only; it does not resolve any decision or authorize
activation, privileged execution, installer credentials, or an ADR-030 status
change.

Implementation work that is already safe and non-activating is limited to
maintaining the existing offline verifier/renderer and tests, documenting the
exact current-to-proposed inventory, and gathering review evidence. The merged
core's offline tests already check that the plan does not access an API, allow
mutation, or claim an active webhook. No new mutator, installer credential,
stage grant, or live integration is covered by the accepted current contract.

## Code-derived impact review (2026-11-05)

The local review confirms that this cannot safely be implemented as an
extension of the existing `target-access` writer:

- The current Bare-MVP plan contains seven stages and the full plan contains
  twelve. Inserting activation before `target-access` changes these to eight
  and thirteen, respectively, and shifts every later stage order. The plan,
  grant, expected-input and CLI-template versions must change deliberately;
  old plans and grants must not acquire an implicit skip path.
- `target-access` is already a bounded create-only writer for its exact
  sixteen-object projection. Reusing it for admission installation would
  broaden its contract. The activation stage needs a separately named and
  independently issued installer/controller authority, bound to the same
  verified target identity. Merely adding an authority label is not enough:
  its credential and server-side enforcement must be designed first.
- Ordinary Kubernetes RBAC cannot narrow collection `create` by
  `resourceNames` or request body. The six-object scaffold includes a
  `ClusterRole` and `ClusterRoleBinding`; the final webhook is cluster-scoped
  too. In particular, a generic `ClusterRoleBinding` create capability is
  security-sensitive. The target-side guard cannot be bootstrapped by the
  same installer operation it is meant to constrain. It must arrive through
  an earlier, independently trusted platform/profile authority, or this
  activation path must remain disabled.
- The existing `RenderInstallSet` and `BuildOfflineActivationPlan` bind six
  scaffold objects and a final `ValidatingWebhookConfiguration` (seven planned
  objects total). The Deployment also references three inputs that are not
  rendered or included in that plan: a policy Secret, a public-key-pin
  ConfigMap, and a serving-TLS Secret. A complete activation would therefore
  need ten writes. The three missing object bodies/material handoff contracts
  are not implemented. Their exact identities must be checked absent before
  any write, and their content digests must be bound in a versioned private
  activation request before a mutator can be designed.
- The signed policy's target UIDs and API-server source CIDRs cannot be
  reconstructed from a public runtime-binding receipt or inferred from the
  API endpoint. A confidential, authenticated controller handoff must carry
  the verified private binding; source CIDRs still require independent
  evidence of the actual peer address observed by the service.
- The repository already favors a bounded management-plane controller for
  Stage-7 installation and explicitly rejects broad client credentials as a
  least-privilege solution. Therefore activation should be designed together
  with that controller and the revised Stage-5/Stage-7 boundary, not shipped
  as a standalone workload writer. See
  [the bounded lifecycle credential contract](ok147-bounded-lifecycle-credential-contract.md).

The proposed ten-write identity inventory is:

| # | API version / kind | Namespace | Name | Current offline plan |
| ---: | --- | --- | --- | --- |
| 1 | `v1` Namespace | — | `ok147-target-admission-system` | scaffold |
| 2 | `v1` ServiceAccount | `ok147-target-admission-system` | `ok147-target-admission` | scaffold |
| 3 | `rbac.authorization.k8s.io/v1` ClusterRole | — | `ok147-target-admission-identity-reader` | scaffold |
| 4 | `rbac.authorization.k8s.io/v1` ClusterRoleBinding | — | `ok147-target-admission-identity-reader` | scaffold |
| 5 | `apps/v1` Deployment | `ok147-target-admission-system` | `ok147-target-admission` | scaffold |
| 6 | `v1` Service | `ok147-target-admission-system` | `ok147-target-admission` | scaffold |
| 7 | `v1` Secret | `ok147-target-admission-system` | `ok147-target-admission-policy` | absent from plan; private bundle |
| 8 | `v1` ConfigMap | `ok147-target-admission-system` | `ok147-target-admission-pin` | absent from plan; independent public-key pin |
| 9 | `v1` Secret | `ok147-target-admission-system` | `ok147-target-admission-tls` | absent from plan; private TLS material |
| 10 | `admissionregistration.k8s.io/v1` ValidatingWebhookConfiguration | — | `ok147-target-access.openkubes.io` | activation object |

## Review findings: mandatory design constraints (still unapproved)

### Trusted bootstrap boundary

The target guard must already be installed and verified by a separately
identified, independently trusted platform/bootstrap authority before any
activation installer credential or operation is made available. The activation
installer cannot establish the trust boundary that is supposed to constrain
that same install. Evidence must bind the installed guard and its policy to
the exact target identity and show that the guard is active before activation
begins.

The specific bootstrap authority, installation channel, guard identity,
verification evidence and ownership remain unresolved approval decisions. If
no such independently trusted and reviewable installation mechanism is
available, target-admission activation stays disabled: no activation grant,
installer credential, webhook registration or target mutation is permitted.
This prerequisite does not approve or select a bootstrap implementation.

### Exact object-content and authority binding

The ten-object inventory is an exact content contract, not just a list of
names and kinds. A future signed activation bundle must bind, for every object,
its API version, kind, namespace (or cluster scope), exact name, and a
`sha256:` digest of the canonical desired object content. It must also bind a
digest of the ordered ten-entry inventory and a versioned canonicalization
schema. The proposed canonicalization is deterministic JSON (JCS/RFC 8785)
over the complete desired object; the only excluded read-back fields may be a
fixed, reviewed list of API-server-generated metadata (`uid`,
`resourceVersion`, `generation`, `creationTimestamp`, `managedFields`) and the
server-maintained `status` subresource. No annotations, labels, owner
references, selectors, policy fields or other unrecognized fields may be
silently omitted. Defaults must be made explicit in the desired object; an
unexpected default, pruned field, or added field is a mismatch until the
versioned contract explicitly accounts for it.

For each write, the installer must verify the signed per-object digest before
dispatch. The already-installed independent target guard must also enforce the
same target-bound digest allowlist against each incoming create request, rather
than authorizing by name/kind alone. After each create, the installer reads the
exact object back and compares its canonical content digest. Success requires
all ten identities and digests to match. The guard and installer must obtain
the allowlist through independently verified trust inputs; the installer must
not be able to redefine the guard's accepted digests as part of activation.
Secret bytes are delivered only through the separately reviewed private-
material handoff; the public plan and receipts contain their content digests,
never Secret values. Digests bind content but do not provide confidentiality.
The policy signature must cover the inventory digest, target binding, image digest,
webhook CA digest and canonicalization version, with the public-key pin
delivered independently of the signed bundle.

Content hashing is paired with semantic allowlists so a correctly signed but
overbroad object cannot be accepted accidentally:

- **RBAC:** pin the exact `ClusterRole` rules, `ClusterRoleBinding.roleRef`,
  and every subject's kind, name and namespace. The reviewed allowlist must
  state permitted API groups, resources, verbs and any `resourceNames`; reject
  wildcard subjects/groups/resources/verbs and privilege-escalating verbs
  (`bind`, `escalate`, `impersonate`) unless a separately approved, narrowly
  justified contract explicitly requires one. The installer verifies both
  the signed object digest and the parsed allowlist before writing and after
  read-back. The exact principal and permission set remain an OPEN decision.
- **Webhook:** verify the exact service reference (namespace, name, path and
  port), CA-bundle digest, admission review versions, operations, API groups,
  resources and scopes, namespace/object selectors, match conditions,
  side-effects and timeout. Require `failurePolicy: Fail`; reject wildcard or
  broader-than-approved matching. Compare the signed content digest and
  semantic allowlist before registration and after read-back. The precise
  admission scope remains an OPEN decision.
- **Workload and service objects:** bind the image by immutable digest and
  verify the exact service account, pod security settings, ports, selectors,
  volumes and mount paths. The Secret and ConfigMap entries bind exact keys
  and content digests without exposing private values.

The digest schema, canonicalization rules, exact expected contents, RBAC
principal/permission allowlist, and webhook scope/configuration require
independent review and explicit approval before implementation can enforce
them. No digest or allowlist is being activated by this documentation change.

### Webhook availability, partial activation and recovery

`failurePolicy: Fail` means the API server rejects matching admission requests
when the webhook times out, is unreachable, or fails TLS/trust validation. This
is intentionally fail-closed and can interrupt API operations in the matched
scope. The final approved scope must therefore be the smallest exact set of
resources, operations and namespaces needed by Stage 7; availability objectives
and evidence must cover ready endpoints, API-server-to-service reachability,
TLS identity/CA rotation, latency/timeouts, replica placement and disruption
handling. The acceptable availability objective and corresponding replica /
capacity requirements remain OPEN; successful `kubectl` writes alone do not
establish webhook availability.

The service and its dependencies must be installed and independently probed
before the webhook configuration is created last. Before that final write,
partial scaffold or material installation is inert but still durable state:
record STOP/unknown and require separately authorized inspection; do not
replay, roll back, or automatically clean it up. If the webhook create or its
read-back is ambiguous, treat enforcement as **ACTIVE-UNKNOWN** and stop all
subsequent activation/Stage-7 writes until an independent observer establishes
the actual state. A failed response does not prove the webhook is absent.

There is no automatic fail-open path: never switch `failurePolicy` to `Ignore`,
delete the webhook, or widen its exclusions as recovery. A recovery path must
be pre-designed, independently authorized, and usable even when the webhook
service is unavailable. It may only inspect the exact target-bound activation
and, after separate operator authorization, either restore the verified
service/trust prerequisites or remove the exact webhook registration through
that independent platform authority. It must preserve evidence, verify the
post-recovery API object state and record a durable outcome. The recovery
principal, allowed recovery operations and evidence contract remain OPEN. If
that independent recovery capability is unavailable, activation remains
disabled.

The projected `kube-root-ca.crt` ConfigMap is supplied by Kubernetes and is
read-only input; it is not one of these ten writes. Rows 7–9 have identities in
the current renderer constants, but no reviewed content schema, private input
transport, object digest binding or installation attempt exists for them.

These are implementation gates, not deployment evidence. No target cluster
was contacted during this review.

## Handoff for independent review

This proposal is ready for an independent design/security review before any
runner implementation. Review should resolve the approval-gated decisions
above and decide the following contract questions rather than approve an
implementation that has not yet been defined:

1. Is a separate `target-admission-activation` stage the right lifecycle
   boundary, including the deliberate plan/grant version break and invalidation
   of all grants made against the old sequence?
2. What independently trusted mechanism installs and protects the target-side
   enforcement before this stage? If no such mechanism is available, confirm
   that activation remains disabled and identify the prerequisite that must be
   designed first.
3. Which fixed-purpose controller/installer identity and independently
   installed server-side guard can enforce the ten-object set despite
   Kubernetes RBAC's collection-create limits? The current offline plan binds
   only seven of those objects.
4. Which authenticated private handoff supplies target identity and serving
   material, and what independent evidence establishes the API-server source
   CIDRs seen by the webhook?
5. Does the STOP-on-ambiguity rule and no-replay boundary provide an acceptable
   recovery contract for partial installation, or is a separate recovery
   contract required before implementation?
6. What coordinated changes are required in the Stage-5/Stage-7 lifecycle
   contract, stage receipts, grant signer, and ADR-030? ADR-030 security
   acceptance item 9 must remain OPEN until its stated evidence is satisfied.

### Handoff scope

- Review only the proposed contract and its compatibility/security impact.
- Do not implement or enable a stage, issue grants/credentials, install policy,
  or contact a cluster as part of this review.
- Keep the existing target-access writer's sixteen-object boundary intact.
- Keep the current execution-open denial in force; this proposal is not runner
  acceptance or deployment evidence.
- After review, record each decision and unresolved prerequisite. Only then
  split implementation into versioned, reviewable changes with offline tests;
  any live installation remains separately authorized.

### Handoff baseline

The proposal was prepared on branch
`feat/OK-147-target-admission-contract-review` from
`f97ca68` (`feat(OK-147): add bounded handoff and target admission core`, the
then-current `origin/main`). It updates design documentation only. The code-
derived counts and object inventory above should be rechecked if the base
changes before review.

## Proposed position and identity

Insert one explicitly mutating stage between `runtime-binding` and
`target-access`:

| Field | Proposed value |
| --- | --- |
| Stage ID | `target-admission-activation` |
| Kind | `Submission` |
| Operation | `ActivateTargetAdmission` |
| Authority | a separate, independently issued target-admission installer/controller authority; never the Stage-7 workload writer |
| Required predecessor | successful `runtime-binding` receipt |
| Inputs | signed policy digest (including independently evidenced API-server source CIDRs), signer key fingerprint, webhook CA digest, immutable image digest, exact activation-plan digest, plus a separately specified private-material handoff |

The stage-plan schema/version and expected-input contract must change
deliberately. It must change the plan digest, invalidating grants prepared for
the old sequence; no compatibility fallback may silently skip the new stage.
The platform signer must issue a separate one-use grant bound to the new stage
digest and predecessor receipt. The installer must independently verify that
grant and consume its durable ledger claim before the first write.

## Proposed operation boundary

The eventual operation may perform only the following fixed protocol:

1. Verify the exact offline activation plan and signed policy bundle, with the
   public-key pin configured independently of both artifacts.
2. Verify the `runtime-binding` evidence joins the expected CAPI Cluster UID
   digest to the signed workload `kube-system` Namespace UID; keep raw UIDs
   private.
   Independently establish which source CIDRs the target API server presents
   to the webhook Pod; do not infer them from the API endpoint address or trust
   forwarded headers.
3. Recheck the exact API endpoint, Namespace UID and Kubernetes version at
   the write boundary. A prior read-only preflight receipt is not reusable.
4. Read all ten exact expected object identities and require the complete set
   absent before creating anything: the six scaffold objects, policy Secret,
   public-key-pin ConfigMap, serving-TLS Secret, and final webhook
   configuration. Their exact namespaces, names and content-binding rules must
   be frozen in the activation contract first. Conflicts, replacements, or
   partial pre-existing state are terminal stops; do not adopt, patch, delete,
   or retry.
5. Create only the six digest-pinned scaffold objects, then create the policy
   Secret, public-key-pin ConfigMap, and serving-TLS Secret from independently
   verified private/public inputs. Never place private data in a public plan,
   receipt, log, or source tree. These three object renderers and their private
   transport are future work, not part of the merged offline plan.
6. Verify the service becomes ready and its certificate is valid for the
   configured Service DNS name and pinned CA.
7. Recheck target identity/version, then create the exact
   `ValidatingWebhookConfiguration` last. Read it back and require exact
   identity/content before recording success.

This is one ledger operation but not a Kubernetes transaction. Every create
is at-most-once. On any ambiguous response, failed readback, or process loss,
the durable state is `STOPPED`/unknown and requires separately designed
recovery; the installer does not replay, roll back, or clean up. Success
requires evidence of all scaffold objects, readiness, active webhook
configuration and target identity—not a zero exit code alone.

## Authority and policy constraints

- The installer must be a purpose-built preconstructed mutator, never a
  generic `kubectl apply`, shell, or arbitrary-object endpoint.
- The installer/controller credential must be separately issued and guarded
  by enforcement installed independently before this operation. Do not infer
  that namespaced RBAC, `resourceNames`, or the current sixteen-object Stage-7
  writer can safely authorize the cluster-scoped RBAC and webhook creates.
- The signer key remains outside `ok-cli`, the runner and the workload writer.
- Webhook registration is the final write and uses `failurePolicy: Fail` with
  exact CEL name/scope conditions. If the API server cannot reach the service
  or its trust chain is invalid, activation fails closed and success is not
  recorded.
- The stage must not enable credential bootstrap, recovery, readiness
  expansion, or teardown. Those remain separate contracts.

## Required review before implementation

1. Approve the target guard installation point, installer owner/identity,
   signer and private material custody, source-CIDR evidence, and stage-plan
   version break.
2. Resolve the separate controller authority and independently installed
   target-side enforcement; the activation operation cannot bootstrap its own
   guard or reuse the Stage-7 writer.
3. Bind the complete ten-object write inventory, private material transport,
   exact RBAC/admission behavior and API-server source-CIDR evidence.
4. Review the partial-install stop/recovery boundary and public/private receipt
   schema, including the coordinated Stage-5/Stage-7 contract revision.
5. Only after those reviews, implement the versioned plan, stage, tests and
   installer in a separate change. A live installation still needs its own
   explicit approval.

No live target was queried or changed while writing this proposal.
