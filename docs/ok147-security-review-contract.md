# OK-147 / PR #430 security follow-up

Status: fail-closed mitigation for independent security review. ADR-030 security
acceptance item 9 remains OPEN. This document is implementation scope, not an ADR
amendment, live authorization or an ADR-031 disaster-recovery claim.

Review and ownership: [finding 14968](https://kubernauts.atlassian.net/browse/OK-147?focusedCommentId=14968),
[contract 14970](https://kubernauts.atlassian.net/browse/OK-147?focusedCommentId=14970),
[Suchit's acknowledgment 14971](https://kubernauts.atlassian.net/browse/OK-147?focusedCommentId=14971).
Codex implements; Suchit independently re-reviews. No overlapping branch was
reported by Suchit. No live cluster mutations or automatic merge are authorized.

## Certificate contract and bounded-bootstrap dependency

Offline inspection of the retained disposable-run workload certificate found
CN=kubernetes-admin, O=system:masters, clientAuth EKU, NotBefore
2026-10-15T07:13:25Z, NotAfter 2027-10-15T07:13:27Z: 365 days plus two seconds.
This is evidence about a retained local artifact, not the current live Secret.
No credential, certificate bytes, private key, private endpoint or token is
included in the repository fixtures or this document.

The local tutorial identifies CAPI v1.13.2; deployed-version verification remains
outstanding. That version's [kubeconfig generator](https://github.com/kubernetes-sigs/cluster-api/blob/v1.13.2/util/kubeconfig/kubeconfig.go)
sets the same admin subject/group. Its [certificate generator](https://github.com/kubernetes-sigs/cluster-api/blob/v1.13.2/util/certs/types.go)
uses the CA's NotBefore and issuance time plus
[DefaultCertDuration](https://github.com/kubernetes-sigs/cluster-api/blob/v1.13.2/util/certs/consts.go)
for NotAfter. A remaining-validity check therefore cannot stand in for total
certificate-lifetime validation or bounded identity.

The accepted executor certificate identity/group set is **empty**. No certificate
lifetime is accepted. A short-lived admin certificate is also rejected. The
parser cannot construct a transport. The lifecycle-derived materializer cannot
be constructed; its obsolete admin Cluster/Secret reader is removed. Public
manifest loading rejects before referenced inputs or Stage 1. ExecutionConfig
and full-run activation Job launch also deny before runtime capabilities or API
requests. Private structural inspection is confined to offline evidence/snapshot
builders and returns no executable capability.

**Open integration dependency: bounded workload credential bootstrap.** The default
lifecycle-derived Stage 1–7 path and downstream Stages 8–12 / PlatformReady cannot complete until an independently reviewed
issuer policy defines exact per-role CN, complete O/group allowlists, trusted
issuer/CA, clientAuth usage, target binding, corresponding least-privilege RBAC
and maximum NotAfter-minus-NotBefore. The cap must be justified by that issuance
contract. Neither CAPI's admin duration nor the separate one-hour TokenRequest
policy justifies inventing a certificate TTL. An approved token bootstrap is an
alternative requiring its own review; generic bearer-token input is not proof
of least privilege. The executor must not bootstrap itself with admin access.

## Recovery contract and atomic-gate dependency

Recovery bindings remain available for offline consistency inspection. STOP and
terminal artifacts remain untrusted for authorization even when their digests,
fields and receipt chain agree. The terminal marker must match the existing
writer's exact `TERMINAL\n` bytes; this does not authenticate it.

This release **disables recovery execution**, policy derivation and grant-request
preparation. It rejects at Stage 5–7 bundle loading and core observation, binding
and mutation operations, independently of ledger availability or claimed source
state. Job adapters carry the recovery fields into the same rejection boundary;
no runnable recovery package is emitted. Existing unrelated Stage-9/10 credential
recovery protocols are outside this network-profile recovery change.

**Open integration dependency: atomic authoritative reservation plus fencing.**
The existing immutable create/get ledger cannot atomically inspect multiple
source slots and reserve a successor. Recovery cannot be safely enabled by
reading an empty Stage-5 slot and then writing a different successor record.
Before enabling it, a separately versioned protocol must provide:

1. A deterministic management-ledger source-suffix gate binding source Plan,
   execution attempt, target UID digest and authoritative Stage-4 receipt.
2. One compare-and-swap arbitration point shared by ordinary source Stage-5 entry
   and recovery: OPEN to SOURCE_RUNNING or OPEN to RECOVERY_RESERVED. A reservation
   pins exactly one successor Plan, recovery binding and unique reservation ID.
3. Authoritative source-prefix/claim/outcome verification. Completed Stage 5,
   including terminal failures, existing source claims, conflicting reservations,
   missing/unreadable/malformed gate state and ambiguous migration state deny
   recovery. Historical source slots must also be rechecked after reservation.
4. Single-use deterministic per-reservation Stage 5–7 claims before any observer,
   binder or mutator call. Stage-7 issuance and consumption bind the same
   reservation; another grant cannot produce another execution.
5. Durable indeterminate state after a crash. No automatic release, timeout
   takeover or replay. Verified completions may be returned without execution.
6. Narrow, versioned admission/RBAC for gate transitions and a reviewed migration
   that fences old executors, grants and ledger writers. Absence of a legacy
   gate is never OPEN. New client code alone cannot fence old binaries.

No gate resources, updates, migration or fencing are implemented or applied by
this mitigation. Execution stays disabled until those requirements and their
race/crash tests are reviewed. This ledger coordinates execution, not lifecycle
desired state. ADR-031 authority restoration/fencing remains a separate concern.

## Requirements compatibility

`ok cluster create requirements` defaults to
`ok-cli-cluster-create-requirements/v1`, omitting providerAccessOwnership.
Explicit `--format ok-cli-cluster-create-requirements/v2` adds that descriptive
object. Other fields and their meaning are identical. Unsupported format values
fail without output or fallback. Golden wire fixtures cover both versions.

This corrects PR #430's unversioned v1 field addition. Consumers that used that
addition must request v2. Metadata does not enter manifests, authorization,
credential policies or bound digests, and does not claim rotation integration.

## Validation scope

The synthetic subject/group/lifetime cases exercise **blanket rejection** of all
certificate mode. They do not demonstrate individual CN, group, issuer or TTL
enforcement. No such approved profile exists. No real credential is copied into
fixtures. Public manifest loading and actual built CLI subprocess tests prove
rejection before Stage 1 for create/up, without preparation output, API requests,
mutations or grant requests. The materializer constructor and direct resolver
both deny; the old test that counted only its own management requests could not
establish zero earlier stages or grants and is replaced.

Recovery tests use valid offline lineage, assert denial at all suffix bundle
and core execution boundaries, run repeated/concurrent attempts with capabilities
that panic on any use, and forbid recovery Job input and grant preparation.
They verify missing authorizationState/sourcePlanDigest/successorPlanDigest/STOP
category/checkpoint regressions and rehashed arbitrary terminal bytes. These
prove blanket denial, **not** the unimplemented atomic reservation protocol.

Future enablement additionally requires source-completed/source-running cases,
ledger corruption/unavailability, legacy fencing, source-versus-recovery and
successor-versus-successor races, reservation/claim crash points and alternate
Stage-7 grants. ADR-030 negative-RBAC and credential expiry/rotation evidence
remain outstanding. No offline test establishes live RBAC conformance.

## Signer boundary and legacy authority exposure (S2)

The only in-repository stage-grant signing call is the stage-authority HTTP
service. `StageSigningBytes` constructs bytes but does not sign. CLI `authority
stage serve` uses that same service; independent-evidence signing produces
non-executable evidence, not Stage grants. Blocking `FromPlan` alone was
insufficient: old/external policies can be supplied with matching digests.

The HTTP service now unconditionally rejects a request if StageID is target-access,
StageOrder is 7, or Operation is CreateTargetAccess, before a claim or signature.
This applies to all policy formats and sources. The existing wire protocol has
no authenticated provenance that separates ordinary target access from recovery.
Consequently **ordinary Stage-7 signing is disabled too**. Supported earlier-stage
signing stays policy-bound, but the default manifest cannot start those stages.
Tests construct external full and legacy recovery-shaped policies, bypass policy
derivation, and assert repeated/concurrent HTTP 403, no signature and no claims.

This is a local code correction, not deployed revocation. Already issued grants
may remain trusted by old executors, and old running signers can still issue
under the old implementation. No current/live deployment or issuance inventory
was inspected. Do not infer that those authorities were retired by this PR.

Explicit proposed operational remediation, requiring separate authority:

1. Inventory recovery-derived policies, signing key IDs, grants and running
   signers/executors since 2026-10-15 using redacted issuance/claim evidence.
2. Suspend affected signer access and fence legacy executors/credentials before
   enabling any continuation; stopping issuance alone does not revoke grants.
3. Retire affected policy/key trust, rotate and pin approved signer keys and
   client trust roots, and verify old grants are rejected. Fence any old executor
   still retaining old trust or workload authority. Preserve audit evidence;
   do not automatically release an indeterminate execution.
4. Before selective Stage-7 signing returns, design reviewed authenticated Plan
   provenance at signer open/request verification, plus atomic recovery reservation
   and fencing. A caller-authored policy or source-plan flag is not provenance.

No key/token retirement, trust-root replacement, deployment, cluster mutation or
atomic-gate migration is performed here. These remain explicit dependencies.

## Review corrections and evidence limits

B1 establishes that the old path could mutate before denial and could not complete.
Recovery was disabled. It did **not** establish destroy as the only operational
exit; no such claim is made here. Do not infer authority to retry another Plan.

Suchit's corrected record (Jira 14978) reports non-root ordinary tests passing,
root runs failing only the permission-sensitive test, and no retained complete
non-root race transcript. Those review runs are not relabeled as non-root race
success. The new re-review evidence records its own effective UID, Go version,
command, complete output and exit status; it does not retroactively fill that gap.

Requirements/v1/v2 wire fixtures remain unchanged. Their historical
liveMutationAllowed/stage-order fields describe the operation schema, not current
availability. Certificate-bound --dry-run/--prepare/--live return an explicit
error, not a success receipt directing the operator to run Stage 1–7.
