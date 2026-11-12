# OK-226 — Kubernetes Claim Store Candidate (disconnected)

**Status:** experimental HTTPS API adapter + synthetic TLS API tests. **No production authorization or writer activation.**

## Scope

`internal/desiredauthority/kubernetes_claim_store.go` implements the `ClaimStore` **shape** for a Kubernetes ConfigMap in the separately pinned desired-authority Domain. It reuses `PinnedDomainReaderConfig` and `VerifyDomain`, whose trust material and namespace/fence identities must be independently provisioned, not inferred from the target API.

- Explicit HTTPS endpoint and CA roots; explicit bearer token only; no current-context discovery, proxy, redirects or credential plugins.
- Domain checks read the `kube-system` identity, pinned Authority namespace UID and exact immutable Fence ConfigMap UID, resourceVersion and data.
- Claim object has a full 256-bit slot key in a DNS subdomain ConfigMap name, `immutable: true`, one canonical `claim.json` payload, bounded size and exact identity annotations.
- A single `POST` attempts atomic Kubernetes create-if-absent. A valid `201` response is checked for exact immutable recorded content and server UID/resourceVersion. `409 AlreadyExists` is returned as a conflict **only** for a specifically matching Kubernetes Status response.
- `InspectClaim` performs an exact-name GET and checks the record, canonical JSON, metadata and bound identity. **404 returns ErrClaimUnverifiable**, not an empty trustworthy slot.
- Lost connection, malformed response, identity drift, wrong content type and changed trust return an indeterminate error. The client never retries an ambiguous POST.

## Important limitations

This candidate **does not implement or prove the security requirements of the ClaimStore abstraction**. Kubernetes ConfigMap create-if-absent is an atomic API primitive, but does not by itself provide permanent non-reuse after delete/recreate, database restore or administrator policy removal. A pre/post DomainReader check can be bypassed by changes between reads or an independent API administrator. The Claim record and Fence ConfigMap are ordinary Kubernetes objects; `immutable: true` protects data updates but **not deletion**.

It also does not bind successful claim consumption atomically to desired-state CAS acceptance, signed Policy evaluation, resource ownership inventory or an external append-only evidence log. A newly created claim may never lead to Acceptance; readback is historical evidence of attempted slot consumption only. The adapter is intentionally **not connected to `ClaimOnce` for live use**, `ok up`, the OK-147 executor or any cluster install path. The current validated **deny-all** Authority admission policy remains unchanged and would reject every claim creation.

## Evidence / tests

Synthetic pinned TLS API tests cover successful create/inspection, exact replay as conflict, lost response after commit, absent record as indeterminate, malformed immutable data, deletion, wrong Domain identity and invalid trust. Tests exercise a fake server and do not prove admission or retention in live Kubernetes.

Before deployment:

1. Add separately controlled, audited admission/RBAC and protect Policy/Binding against removal. Confirm supported Kubernetes versions and actual negative Kind admission tests.
2. Prove retention and rollback-resistant consumed-slot history **outside the same administrator domain**. Restore, namespace-delete and ConfigMap delete/recreate must not reopen a slot.
3. Bind claim consumption, independently approved Policy, and CAS Acceptance through an independently verified atomic protocol or fail-closed transaction/recovery design.
4. Perform real Kind conformance (409, delete, namespace ABA, lost response, privilege escalation, policy removal), then independent security review.
5. No production `ok up` activation before the full conformance and ADR-034-SP-001 approval.
