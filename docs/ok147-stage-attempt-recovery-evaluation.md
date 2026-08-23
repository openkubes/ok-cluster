# OK-147 stage-attempt recovery evaluation

## Scope and authorization state

This checkpoint evaluates the fail-closed stop observed by the bounded full-run
executor after the R9 and R10 DEV attempts. It changes no Kubernetes object,
credential, staged plan, authority policy or runner protocol.

```text
Infrastructure mutation: NO-GO
Stage retry:             NO-GO
Claim deletion:          NO-GO
Authority rebind:        NO-GO
Full-run launch:         NO-GO
```

## Observed boundary

R9 obtained the normal Stage 1 authorization and then stopped before the stage
implementation because a provider-access policy was incorrectly supplied to
the `provider-prerequisites` stage. The resulting authority claim remained
durable, as required by the bounded stage-authority contract.

R10 used the repaired runner and reached the same Stage 1 authorization
request. The authority returned HTTP 409 before any stage or Cluster-lifecycle
mutation because the request digest had already been consumed. The four R10
launch-envelope objects were subsequently removed with UID and
resourceVersion preconditions. Exact-name checks found no `disposable-ok141`
lifecycle namespace on either management or infrastructure authority.

Redaction-safe correlation for this evaluation is:

```text
R10 package:                 sha256:bf15f86bfd7bf61d7f3513f817e6a7ce2b875f8a88dd57886c1064b6421396f6
Runner image:                sha256:bcc55acfcbfa1b6aa37d69ce18671ba0d41fdfe68eaa450c778ec1de38f050cb
Private executor log digest: sha256:7abd16d1cec62c05a6e6b67a1231fe5055046abd023bc9bcefce3b314f7e56fa
Private authority log digest: sha256:206b82d456c5a3ea7b19ec0e69cee88536476871f3076d0b19dda657ef949a87
Partial-state binding:       sha256:59d0f34a00f599bf506cc06754cc875b64f02e42b6d343f9922d3618fc115063
Cleanup outcome:             four exact objects ABSENT
```

The private logs, raw objects, UIDs, resourceVersions, credentials and
endpoints are not part of this checkpoint.

The result proves both intended and missing behavior:

```text
same Plan + same cursor + same stage
        -> same authorization request digest
        -> replay rejected across process and Job attempts

new Job name or new runner image alone
        -> does not create new stage authority
```

## Invariants that must remain true

1. A consumed request digest is never deleted or silently made reusable.
2. A caller-selected nonce must not create unlimited grants for the same
   reviewed experiment.
3. Runner image, Job name and wall-clock time are not policy authority.
4. A stopped attempt remains immutable evidence and is not overwritten.
5. A new attempt must be distinguishable before the first grant is issued.
6. R, E, P and FixtureDigest retain their existing meanings; an execution
   attempt must not be disguised as a semantic Contract change.
7. The authority remains a grant issuer only. It does not submit, observe,
   repair or clean up lifecycle resources.

## Rejected shortcuts

### Delete the existing claim

Deleting the create-only claim would erase replay evidence and make the same
authorization request usable again. It is not an acceptable normal recovery
mechanism.

### Add an arbitrary request nonce

A nonce controlled only by the caller would let that caller obtain an
unbounded sequence of grants for the same reviewed plan. A nonce is safe only
when its identity is independently reviewed and bound by the authority policy.

### Rotate only the Job or runner image

Those identities live outside the staged plan and grant payload. Treating them
as sufficient would leave the authority unable to distinguish an authorized
new experiment from replay.

### Reset or replace durable authority storage

Replacing the claim store would restore availability by discarding the
security property under test. It may exist only as separately authorized DEV
disaster recovery, never as the routine next-attempt path.

## Selected model: additive plan-v2 attempt identity

The next protocol revision should add one immutable
`executionAttemptDigest` to the staged execution plan. It identifies the exact
authorized execution attempt, not the desired Cluster semantics.

```text
R / E / P / FixtureDigest
        -> desired semantics and experiment definition

ExecutionAttemptDigest
        -> one reviewed permission to attempt that experiment

PlanDigest v2
        -> includes all identities above plus stages and authorities
```

The digest must be derived from a canonical, redaction-safe attempt document
that binds at least:

- attempt format and identifier;
- source FixtureDigest and staged-plan semantic identity;
- reviewed runner image digest;
- source activation-package digest (the immutable package from which this
  attempt is derived);
- bounded operational mode (`create + converge + observe` for this scope);
- explicit predecessor attempt and/or stopped-evidence digest when applicable;
- expiry or decision-window identity; and
- `maxAttempts: 1`.

The final activation package cannot be an input to this digest: it embeds the
plan that carries `ExecutionAttemptDigest`, which would create a circular hash
dependency. The final package is produced only after the attempt identity and
is then independently pinned by the launch candidate. Attempt format v2 makes
that ordering explicit; historical v1 remains verification-only.

The attempt document is not itself a grant. The authority policy must bind its
digest, and every normal stage authorization request and signed grant must
carry the resulting PlanDigest-v2 identity.

## Required fail-closed behavior

```text
same ExecutionAttemptDigest + same Stage 1 request
        -> first request may be signed
        -> every replay returns HTTP 409

new ExecutionAttemptDigest
        -> new PlanDigest-v2
        -> new reviewed authority policy
        -> new authorization request digest
        -> eligible for one separately authorized run

changed runner/package/stopped evidence without new attempt digest
        -> rejected before launch

caller-chosen or policy-unbound attempt digest
        -> rejected before authority claim
```

Later stages continue to bind the exact predecessor receipt. A new attempt
cannot splice receipts from an earlier attempt because those receipts bind a
different PlanDigest.

## Compatibility and migration

The historical `ok147-staged-execution-plan/v1` format and its evidence remain
verifiable. It is not reinterpreted and its consumed claims remain durable.

Future retry or repeated full-run work must use additive v2 formats:

```text
staged execution plan v2
stage authority policy v2
stage authorization request v2
stage authorization grant/receipt v2
```

There is no automatic conversion of a v1 plan into an authorized v2 attempt.
The conversion produces a new PlanDigest and requires a new explicit authority
checkpoint.

## Implementation checkpoint

Implemented by the additive checkpoint documented in
[`ok147-execution-attempt-v2-implementation.md`](ok147-execution-attempt-v2-implementation.md).

The implementation follow-up must prove offline:

1. identical attempt inputs produce the same `ExecutionAttemptDigest`;
2. any bound input change produces a different digest;
3. plan v2 rejects missing, malformed, foreign or mismatched attempt identity;
4. request and signed grant identities change with the attempt;
5. a same-attempt replay remains HTTP 409 across authority restart;
6. receipts from attempt A cannot satisfy attempt B predecessors;
7. plan-v1 fixtures remain reproducible and verifiable; and
8. no new runner-owned lifecycle reconciliation is introduced.

## Current classification

```text
Observed R10 stop:          expected fail-closed replay protection
Automatic retry:           rejected
Claim deletion/reset:      rejected as normal recovery
Attempt identity:          implemented offline
Selected mechanism:        additive Plan/Policy/Grant v2 binding
RequiresReconciler:        no
Infrastructure mutation:   none in implementation checkpoint
Next full-run attempt:      NOT GRANTED
```
