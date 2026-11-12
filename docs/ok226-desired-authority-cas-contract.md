# OK-226 SP.2 — desired-state Authority CAS contract (offline prototype)

**Status:** Experimental, not deployed; no mutation capability exposed in `ok`.

This package models the **desired-state revision acceptance** semantics discussed in ADR-Platform-034 and ADR-034-SP-001. It is **not** the existing OK-147 authorization grant ledger, and it is **not** the experimental bootstrap-issuer store.

## Scope

- `Transition`: exact tenant, cluster, Authority Profile, transitionID, predecessor, target revision, operation, request digest, execution binding P and authorization digest.
- `Store`: read-only `Inspect` and **atomic full-tuple** `CompareAndSwap` contract.
- `ReconcileIndeterminate`: read-only exact-tuple inspection after a lost acceptance response. It never retries an uncertain mutation.
- Tests: one winner under 32 competing transitions, stale predecessor, exact replay, conflicting tuple with same target, inspection failure, invalid/unsupported operations, namespace-key rejection.

The in-memory store is **test-only** and uses a mutex to model linearizable atomicity. It provides no persistence, authorization, admission, RBAC, anti-deletion fencing, network allocation, audit signatures, or Kubernetes CAS adapter. **Passing these tests is not evidence of a production-safe Authority Store.**

## Non-goals and activation blockers

1. No caller in the CLI, Job or Executor uses this package to authorize, accept or run a real cluster operation.
2. No Policy signer is implemented. The `AuthorizationDigest` is a *declared identity field*, not independently verified evidence; a future trusted layer must prove it before calling the store.
3. No Kubernetes API-backed store yet. Required: server-enforced compare-and-swap and complete durable tuple correlation, including lost-response readback.
4. Kubernetes immutable ConfigMaps alone are not sufficient: prevent unauthorized deletion/recreation/rollback and identity/fence replay with independently verified RBAC/admission plus recovery rules.
5. `ABSENT` in a desired-state store is **not proof of absent CAPI/KubeVirt/M2b resources**. Adoption and ownership verification precede any real CreateCluster.
6. `DeleteCluster` appears only as a validation shape; it is **not executable** and `ok down` remains unsupported.

## Review / verification

Local isolated Go module using the same module path was tested with `go test -race -count=5 ./...` and `go vet ./...`. Repository CI and independent review are still required on the exact PR head. Existing `ok up`, `ok cluster provision` and `ok cluster destroy` remain unchanged.

**Next:** prove the store adapter against fake Kubernetes API behavior including error/409/timeout/lost response, then review a real API-backed durable CAS and admission/fencing design. Do **not** activate the profile or merge a generic memory store into production wiring.
