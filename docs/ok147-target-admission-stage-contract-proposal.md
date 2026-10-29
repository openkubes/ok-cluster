# OK-147 target-admission activation stage — proposal only

Status: **PROPOSED / NOT ACCEPTED BY THE RUNNER**

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

## Code-derived impact review (2026-10-29)

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
- The existing `RenderInstallSet` contains six scaffold objects, but its
  Deployment also references three not-yet-rendered inputs: a policy Secret,
  a public-key-pin ConfigMap, and a serving-TLS Secret. Together with the
  final `ValidatingWebhookConfiguration`, the complete activation would make
  ten create attempts, not six. All ten identities and exact bodies must be
  bound in the versioned plan and checked absent before the first write.
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

These are implementation gates, not deployment evidence. No target cluster
was contacted during this review.

## Handoff for independent review

This proposal is ready for an independent design/security review before any
runner implementation. The review should decide the following points rather
than approve an implementation that has not yet been defined:

1. Is a separate `target-admission-activation` stage the right lifecycle
   boundary, including the deliberate plan/grant version break and invalidation
   of all grants made against the old sequence?
2. What independently trusted mechanism installs and protects the target-side
   enforcement before this stage? If no such mechanism is available, confirm
   that activation remains disabled and identify the prerequisite that must be
   designed first.
3. What fixed-purpose controller/installer identity is permitted to create
   the ten-object set, and what server-side control makes those exact creates
   enforceable despite Kubernetes RBAC's collection-create limits?
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
then-current `origin/main`). The source tree is unchanged by this proposal.
The code-derived counts and object inventory above should be rechecked if the
base changes before review.

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
| Inputs | signed policy digest (including verified API-server source CIDRs), signer key fingerprint, webhook CA digest, immutable image digest, exact activation-plan digest |

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
   configuration. Conflicts, replacements, or partial pre-existing state are
   terminal stops; do not adopt, patch, delete, or retry.
5. Create only the six digest-pinned scaffold objects, then create the policy
   Secret, public-key-pin ConfigMap, and serving-TLS Secret from independently
   verified private/public inputs. Never place private data in a public plan,
   receipt, log, or source tree.
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

1. Review the stage ordering, immutable plan-version break and signer impact.
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
