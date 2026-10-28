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

## Proposed position and identity

Insert one explicitly mutating stage between `runtime-binding` and
`target-access`:

| Field | Proposed value |
| --- | --- |
| Stage ID | `target-admission-activation` |
| Kind | `Submission` |
| Operation | `ActivateTargetAdmission` |
| Authority | the exact workload authority already bound by the verified topology |
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
4. Read the exact expected object names and require the whole fixed set absent
   before creating anything. Conflicts, replacements, or partial pre-existing
   state are terminal stops; do not adopt, patch, delete, or retry.
5. Create only the six digest-pinned service scaffold objects, then create the
   signed policy and serving-TLS material from private in-memory inputs. Never
   place private data in a public plan, receipt, log, or source tree.
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
- The workload credential must be separately bounded to the exact object
  names, verbs and namespaces in this operation. Cluster-scoped objects
  (including the `ValidatingWebhookConfiguration`) need explicit separate
  authorization; do not infer that the current sixteen-object Stage-7 writer
  permission covers them.
- The signer key remains outside `ok-cli`, the runner and the workload writer.
- Webhook registration is the final write and uses `failurePolicy: Fail` with
  exact CEL name/scope conditions. If the API server cannot reach the service
  or its trust chain is invalid, activation fails closed and success is not
  recorded.
- The stage must not enable credential bootstrap, recovery, readiness
  expansion, or teardown. Those remain separate contracts.

## Required review before implementation

1. Review the stage ordering, immutable plan-version break and signer impact.
2. Review the exact workload RBAC and admission-policy interaction, especially
   ownership of cluster-scoped resources and the webhook's first activation.
3. Review the partial-install stop/recovery boundary and public/private receipt
   schema.
4. Only after those reviews, implement the stage, tests and installer in a
   separate change. A live installation still needs its own explicit approval.

No live target was queried or changed while writing this proposal.
