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

## PR #430 security follow-up

ADR-030 security acceptance item 9 remains **OPEN** pending independent review and
credential/negative-RBAC/expiry evidence. The retained local CAPI credential was
an administrator certificate, not bounded executor authority. Certificate mode
is denied before constructing clients. The default lifecycle-derived Stage 1–7 and downstream Stage 8–12
paths are rejected before Stage 1 pending a reviewed bounded credential bootstrap.

Network-profile recovery execution is disabled at bundle, authorization-request,
authority-policy derivation and core execution boundaries. The signer separately
rejects every Stage-7/target-access request, including externally supplied
policies, before claims/signatures. Old grants/signers require separate retirement
and fencing; this PR does not deploy revocation. Offline artifact verification
does not check authoritative source ledger state and does not grant execution
permission. No atomic gate, legacy migration or executor fencing is implemented
by this release. An empty-slot read alone would have a concurrency race.
See [the follow-up contract](ok147-security-review-contract.md) for the exact
enablement requirements and remaining evidence. Ordinary execution and the ledger
remain separate from lifecycle desired state; ADR-031 is unchanged.

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

Provider credentials consumed by an ongoing infrastructure controller have a
different lifetime responsibility from the executor's short-lived management
and ledger capabilities. Ending a runner does not end the provider's need to
authenticate. A finite provider token therefore bounds continued reconciliation,
not just the execution window. The current CLI does not own automatic renewal,
choose a longer lifetime or guarantee durable rotation. The lifecycle operator
owns continuing provider access; its renewal mechanism remains outside bounded
runner authority and is not implemented here.
See the operator runbook for current-health reporting and separately authorized
immutable-Secret recovery; neither a completed receipt chain nor an expired
replacement package grants repair or credential-renewal authority.

## Installation boundary

The launcher can only perform exact-name `GET` operations for the required
Namespace, runtime ServiceAccount, Ledger writer ServiceAccount/RBAC and
fail-closed Ledger admission policy/binding plus four expected-absent activation
objects. It then permits collection `POST` operations for two immutable
Secrets, one NetworkPolicy and one Job. All reads finish before the first
write. It exposes no update, patch, apply, delete, list, watch, retry, rollback
or cleanup operation.

Kubernetes RBAC cannot prove create-body equality. The launcher therefore
verifies the complete package digest before opening the installer credential,
and admission plus response verification constrain the installed objects. A
failed or uncertain write is a terminal partial/unknown state for that run.

## Stage-7 target admission: local core implemented, deployment not integrated

The fail-closed admission policy above protects only immutable ledger
ConfigMaps in `openkubes-execution-system`; it does **not** constrain the
sixteen Stage-7 target-access objects on a workload cluster. The local
`internal/targetadmission` package now contains the decision core and deployment
primitives, but no CLI/runner command installs or starts them. Stage-7 remains
subject to the existing signer and runner gates; do not treat the new package
as an active cluster control.

The local implementation provides:

- an Ed25519 signed policy envelope. `SignBundle` is for a separately
  controlled platform signer; the signing key must not be made available to
  `ok-cli` or the Stage-7 writer. Consumers must pin the verification key
  out-of-band, verify the signature, and recompile the exact sixteen-object
  content allowlist before use;
- a startup gate (`NewBoundTLSServer`) that will not return a serving HTTPS
  handler until the signature is valid and two read-only GETs to the same
  explicitly pinned target API endpoint succeed over its pinned CA: one reads
  the `kube-system` Namespace UID and compares it with the signed bundle; the
  other reads `/version` and requires a stable Kubernetes 1.30-or-later
  release (vendor build metadata is allowed; prerelease versions are rejected).
  The signed CAPI
  Cluster UID must also hash to the plan's `targetIdentityDigest`. Same-name
  target replacement and unsupported Kubernetes versions therefore fail
  closed. Its dedicated ServiceAccount requires only `get` on Namespace
  `kube-system` plus non-resource `get` on `/version`;
- a TLS 1.2+ handler requiring a certificate SAN for the exact Kubernetes
  Service DNS name and a valid chain to the same CA bundle intended for the
  API-server webhook configuration. The target-bound signed policy also
  carries a bounded, canonical API-server source-CIDR allowlist; only the
  actual TCP peer on the admission route is checked against it, and forwarded
  client-IP headers are ignored; and
- a generated `ValidatingWebhookConfiguration` with `failurePolicy: Fail`, no
  namespace/object selector, and CEL `matchConditions` that scope calls to the
  exact approved resource names, namespaces and CREATE operation. This narrow
  configuration requires stable Kubernetes 1.30 or later (stable CEL webhook match
  conditions); and
- an offline, digest-addressed two-phase activation plan which puts the
  six-resource service scaffold before the webhook configuration, records
  only a digest of signed target UIDs, and states that target/version checks
  remain unverified and the webhook inactive; and
- a separate read-only activation preflight which verifies that plan, performs
  exactly two pinned GETs (target `kube-system` UID and `/version`), and marks
  the evidence stale and unusable for any later write boundary.

This remains a **local building block**, not independent delivery by itself.
No signer implementation/key custody, Kubernetes Deployment/Service/RBAC
materializer, install command, or activation receipt is wired into the runner.
Before activation, a separately reviewed installer must verify authoritative
runtime evidence for the CAPI UID ↔ workload `kube-system` UID association,
sign with a separately held key, pin the public key, deliver certificate and
CA material safely, create the webhook/service/server resources, and retain
durable receipts for both the target bind and activation. The raw UIDs and
private bundle are sensitive local data and must not enter public receipts or
Git. No such installation, API request, or live cluster mutation was performed
by implementing these local primitives.

The handler checks the AdmissionReview's authenticated username as asserted by
the API server; the Kubernetes webhook protocol here provides server-side TLS,
not mutual TLS authentication of the API-server client. The serving adapter
additionally restricts admission requests to the actual TCP peer CIDRs in the
independently signed target policy; `X-Forwarded-For` is not trusted. Those
CIDRs must come from verified target-network evidence and must reflect the
source address actually observed at the pod. Network reachability should also
be limited by the platform's service/network design. The policy still never
grants authority: it only denies requests that do not exactly match the
separately installed allowlist.

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
