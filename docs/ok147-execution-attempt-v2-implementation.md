# OK-147 execution-attempt v2 implementation checkpoint

## Outcome

The R10 stop exposed a correct but incomplete boundary: the stage authority
durably rejected a second Stage-1 request whose deterministic request digest
had already been claimed by R9. This checkpoint implements the selected
additive recovery model without deleting or resetting any historical claim.

```text
historical plan v1 + consumed claim
        -> remains immutable and replay-protected

verified execution-attempt document
        -> ExecutionAttemptDigest
        -> staged plan v2 / new PlanDigest
        -> authority policy v2
        -> request + signed grant v2
        -> isolated single-use claim identity
```

No Kubernetes API was contacted and no infrastructure object was changed.

## Attempt identity

`ok147-execution-attempt/v1` is a strict, redaction-safe document that binds:

- an explicit attempt identifier;
- source FixtureDigest and source staged-plan semantic identity;
- an immutable runner image;
- the activation-package digest;
- the exact `create-converge-observe/v1` mode;
- predecessor-attempt and stopped-evidence digests together for recovery;
- a decision-window digest; and
- `maxAttempts: 1`.

The verifier accepts only independently supplied expected identities. It
canonicalizes the document and returns `ExecutionAttemptDigest`; the document
is not a grant and its receipt has `mutationAllowed: false`.

## Additive protocol formats

The implementation adds these formats while preserving every v1 format:

```text
ok147-staged-execution-plan/v2
ok147-verified-staged-execution-plan/v2
ok147-bounded-stage-authority-policy/v2
ok147-stage-authorization-request/v2
ok147-stage-authorization/v2
ok147-full-run-execution-manifest/v4
```

Their redaction-safe receipts also carry `executionAttemptDigest`. A v1 plan,
policy, request or full-run manifest rejects an attempt field. A v2 plan or v4
full-run manifest rejects a missing, malformed or foreign attempt identity.

The command-line stage and authority-policy boundaries accept the optional
`--execution-attempt-digest` expected input. It must be absent for plan v1 and
must exactly match plan v2.

## Proven behavior

Offline tests establish:

1. equivalent attempt documents produce the same digest;
2. a changed bound runner identity produces a different digest;
3. incomplete recovery lineage, mutable runner images and `maxAttempts != 1`
   fail closed;
4. a changed attempt produces a different PlanDigest, policy and request;
5. the signed grant carries the same attempt identity;
6. same-attempt replay remains HTTP 409;
7. a request from another attempt is rejected;
8. predecessor receipts remain PlanDigest-bound, preventing cross-attempt
   receipt splicing; and
9. historical plan-v1 and full-run-v3 fixtures remain accepted only with no
   attempt field.

## Classification

```text
Attempt recovery mechanism: implemented offline
Historical claims:          retained
Automatic retry:            absent
Claim reset/delete:         absent
RequiresReconciler:         no
Infrastructure mutation:    none
Next full-run attempt:      NOT GRANTED
```

The next live step requires a reviewed attempt document, plan v2, authority
policy v2, full-run manifest v4, a freshly published runner image and a new
explicit launch checkpoint.
