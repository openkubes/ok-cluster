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

The live activation installs exactly four objects on `ok-mgmt`, in this order:

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

## Closure record

The final redacted record must bind the source commit, image digest, activation
package digest, Plan, R/E/P, target identity, grants, stage receipts, source
observations, aggregate result and evidence-bundle digest. It must also state
whether the run completed, stopped before mutation or preserved partial/unknown
state.
