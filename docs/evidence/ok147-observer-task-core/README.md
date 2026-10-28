# OK-147: experimental one-shot observer task core

Status: **candidate code / NO-GO / not activated**. This is the first bounded
code slice toward the fixed platform-side issuer path. It does not connect the
CLI, runner, Console, Kubernetes, a signer, or a real source reader.

## Contract boundary

The new `bootstrapauthority.ObserverTask` accepts only trusted in-process
configuration for its `Authority`, independently established observer inputs,
source owner, source reader, result issuer and clock. Those adapters cannot be
selected through a user request. `Run` is single-use per instance and follows a
fixed order: authenticate the signed request; inspect the exact one-use slot;
read and validate the bound source; persist the claim; revalidate the request
and source; call the configured result adapter once; verify and persist the
authenticated result; then return only the public signed result.

It never executes a stage, redelegates authority, installs policy, retries a
potentially mutating call, returns source/key bytes in a receipt, or treats a
credential result as stage success. A recorded result remains
`RESULT_RECORDED_NOT_STAGE_AUTHORIZED`; convergence and durable runner evidence
remain separate requirements.

## Not ready for deployment

The adapters are interfaces, not implementations. Production integration still
needs an independently reviewed operation boundary that authenticates the
caller/tenant/environment and derives plan/predecessor evidence; a fixed
platform workload identity and image; a real source reader that proves fresh,
atomic UID/resourceVersion/owner and key correspondence; a signer that enforces
the approved profile before key use; and durable single-use storage with
anti-deletion/anti-rollback fencing. Process/Job lifetime and unknown write
outcomes must be terminal and must not cause task recreation or replay.

The local in-memory tests do not prove those deployment properties. No
Kubernetes Job, endpoint, public wire contract, CLI flow, resolver allowlist or
runner credential gate is changed. ADR-030 security acceptance item 9 remains
OPEN. OK-197/OK-198 remain out of scope.

## Verification scope

Targeted package tests use generated in-memory fixtures only. They prove the
core's ordering and failure behavior against its current interfaces, not a real
issuer, source, signer, store, cluster or successful provisioning. See the PR
checks for the exact commands and results. No live cluster contact, credential
read/issuance, mutation, publication, or user CLI installation is performed.
