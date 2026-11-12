# OK-226 Authority Domain Fencing — Phase 2: disconnected read-only identity contract

**Status: EXPERIMENTAL. Neither a deployable fence nor authorization to run `ok up`.**

## Scope and security boundary

- `internal/desiredauthority/domain_fence.go` introduces a `DomainBinding` with an **independently pinned** HTTPS API endpoint, CA trust digest, `kube-system` Namespace UID (host API cluster identity), authority Namespace UID, dedicated Fence ConfigMap UID and separately pinned resourceVersion.
- `DomainIdentity()` binds the stable incarnation to those values except resourceVersion (a metadata-only change must not silently open a new authority domain).
- `VerifyDomain()` checks the identity and pre-existing immutable, active Fence observation from a **read-only `DomainReader`**. It rejects missing, deleting, owned, changed, mismatched or unreachable namespace/fence observations.
- `VerifyStableRead()` brackets a **read-only** operation with identity checks. It cannot atomically fence a concurrent write or prove history retained across a delete/recreate.
- In-memory fake reader negative tests cover substituted host/authority/fence UIDs, namespace/fence deletion, changed resourceVersion, wrong trust/endpoint, changed fence domain, unavailability and mid-read drift.

**The identity pins must be provisioned out-of-band by a separately trusted platform authority**. Never construct them through trust-on-first-use inside the user CLI or by observing a missing ConfigMap and calling it a new authority.

## No integration yet

No existing `KubernetesStore.CompareAndSwap`, `Inspect`, runner, CLI, Policy signer, claim service or Job calls this guard. Existing experimental Kubernetes CAS adapter still rejects `404` as `ErrUnverifiable` and cannot safely initialize an absent cluster record.

## Activation blockers and next slices

1. Build a Kubernetes API **DomainReader** with pinned CA, endpoint identity, bounded HTTP, credential audience/expiry, exact-name PartialObjectMetadata namespace and verified ConfigMap reads; robust duplicate-key/case-alias rejection.
2. Design and deploy independently reviewed **admission plus RBAC** that prevents all unauthorized deletion/recreation of Fence, namespace and desired-state records. Immutable ConfigMaps alone cannot do this. Test namespace/fence ABA and restore/fork scenarios.
3. Prove a protected, durable authoritative initial-state registration and independent CAPI/M2b inventory/adoption checks. Only then define an allowed transition from genuine `ABSENT`.
4. Implement a server-side transactional or equivalent **write fence**, including retained transition history, atomic CAS, negative writer-isolation tests and lost-response inspection. A pre/post read around HTTP writes is **NOT atomic**, so do not wire `VerifyStableRead` into CAS as authorization.
5. Independently review Policy signer and single-use claim integration, executor credentials and Same-Plane conformance. Keep ADR-034-SP-001 Proposed until live evidence.

## Local isolated verification

Read-only implementation and its tests were executed in a separate temporary Go module with the repository module path using `go test -race -count=5 ./...` and `go vet ./...`: **PASS**. These checks are **not** the repository PR-head CI and do **not** verify Kubernetes API behavior or deployment security.
