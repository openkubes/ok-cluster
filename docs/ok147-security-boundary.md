# OK-147 bounded runner security boundary

## Trust model

The OK-147 runner is a short-lived, bounded executor. It verifies and consumes
externally issued decisions; it does not issue its own authorization, render a
second Contract-to-CAPI projection or become a lifecycle reconciler.

```text
contract and authoritative projection
        -> signed, request-bound grants
        -> single-use runner
        -> existing reconcilers
        -> bounded evaluator
        -> durable redacted evidence
```

Authority remains split:

- `ok-infra` owns only provider prerequisites;
- `ok-mgmt` is the sole CAPI lifecycle writer and hosts the durable ledger and
  ephemeral runner Job;
- the selected Enablement controller owns Helm/CNI desired-state convergence;
- Argo CD on `ok-shared` owns Platform convergence for external workload
  clusters only; and
- source controllers retain ownership of their own status and Conditions.

The runner may observe, correlate and report those sources. It may not repair
them outside the exact authorized stage operation.

## Authorization and replay protection

Every mutating stage uses a signed grant bound to its exact operation, request,
R, projection, audience, validity window and single-use declaration. The
durable Kubernetes ledger creates an immutable claim before mutation. An
existing claim, conflicting receipt or indeterminate prior attempt fails
closed; process replacement does not make a consumed grant reusable.

The runner never accepts generic commands, shell fragments, arbitrary Helm
arguments or unbounded manifests. A dry-run plan, signed decision or package
receipt alone grants no mutation authority.

## Credential boundary

The two activation Secrets contain exactly the allowlisted executor and
independent-evidence inputs for one run. Tokenless init containers verify their
individual hashes and copy
them from projected symlinks into a memory-backed `0700` workspace as regular
`0600` files. The executor sees only that workspace.

The Job:

- has no automounted ServiceAccount token;
- runs as a fixed non-root UID/GID with a read-only root filesystem;
- drops all Linux capabilities and forbids privilege escalation;
- has no retry and a fixed active deadline;
- uses only short-lived or stage-isolated credentials; and
- has deny-by-default egress with six exact IP/port exceptions.

The immutable activation Secrets retain credentials for their lifetime.
Therefore their lifecycle is part of the operational risk: they
must not be reused, copied to Git or treated as a durable credential store.
Cleanup requires separate authority.

## Installation boundary

The launcher can only perform exact-name `GET` operations for the required
Namespace, runtime ServiceAccount and four expected-absent activation objects,
then collection `POST` operations for two immutable Secrets, one NetworkPolicy
and one Job. All reads finish before the first write. It exposes no update,
patch, apply, delete, list, watch, retry, rollback or cleanup operation.

Kubernetes RBAC cannot prove create-body equality. The launcher therefore
verifies the complete package digest before opening the installer credential,
and admission plus response verification constrain the installed objects. A
failed or uncertain write is a terminal partial/unknown state for that run.

## Evidence boundary

Public receipts contain semantic identities and digests only. They must not
contain Secrets, tokens, Kubeconfigs, private keys, certificate payloads,
private endpoints, private filesystem paths, raw Kubernetes objects, UIDs or
resourceVersions. Raw evidence stays in the explicitly approved private
location and is never committed.

An operation is complete only when revision-correlated source evidence and the
aggregate evaluation have been persisted independently of the executor. Logs
and process exit status are diagnostic inputs, not the success oracle.

## Explicit non-goals and residual risks

This MVP does not provide:

- a public OpenKubes API;
- a broad or continuously running OpenKubes lifecycle operator;
- a persistent aggregate-status controller;
- automatic retry, rollback, cleanup or disaster recovery;
- transactional execution across Kubernetes authority domains; or
- protection against total loss of the DEV infrastructure.

The first deployment is intentionally DEV-only. It accepts non-atomic stage
boundaries, temporary availability loss and rebuild-on-loss, while preserving
fail-closed identity checks, single-use authorization and public-evidence
redaction. ADR-031 remains responsible for management-plane fencing and
disaster recovery.
