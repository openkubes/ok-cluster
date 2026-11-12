# OK-226 — Single-Use Authorization Claim contract (isolated)

**Status: experimental contract only. No live claim store, no executor claim, no Authority CAS permission.**

This slice adds `internal/desiredauthority/single_use_claim.go` and a fake-only test store. It reuses the existing **offline Ed25519** `VerifyAuthorization` preflight, but does not merge the OK-147 bootstrap issuer domain with OK-226 desired-state authority.

## Contract

- `ClaimSlotDigest`: SHA-256 identity of **Authority Domain + intended audience + key ID + nonce**. Changing the signed transition while reusing the same nonce cannot produce a new claim slot.
- `ClaimRecord`: correlates the immutable slot with exact signed statement digest, detached signature digest, complete `Transition` tuple, domain/audience/signer and claimed-at time.
- `ClaimStore`: two operations only — atomic `CreateIfAbsent` and read-only `InspectClaim`. **No update, delete, list or lease APIs.**
- `ClaimOnce`: independently checks the signed authorization before attempting a conditional create. Exactly one `CREATED` in the **test-only** linearizable mutex store. Even **identical replay** yields `ErrClaimConsumed`, not a second claim.
- `InspectClaimAttempt`: read-only exact-match inspection after an indeterminate write. A matching previously stored claim is **historical evidence of consumption**, not authority to attempt execution again. Missing or inconsistent record is `ErrClaimUnverifiable`. Never automatically retry uncertain writes.

## Negative test coverage (test-only store)

40 racing agents / one winner, identical replay rejected, conflicting transition identity using same nonce collides, domain/audience/key/nonce slot separation, tampered signature rejection before any write, lost response after creation, unknown write without commit, failed inspection and modified stored claim. These tests are **not** proof of Kubernetes persistence, admission safety, live grant issuance or durable history.

## Mandatory gates before wiring to CAS

1. A real server-side store must prove linearizable, permanent single-use registration with **anti-delete/recreate and anti-rollback protection**, including namespace/fence lifecycle, restore and disaster recovery. Merely creating an immutable ConfigMap or checking `404` is **not** enough.
2. **Do not assume `CREATED` plus a valid signed statement permits cluster execution.** The Claim is not yet integrated with protected desired-state CAS and cannot atomically bind consumption to Acceptance. Lost-response and crash semantics across two stores are still unresolved.
3. Define claims' precise identity in Policy issuance, including signer key rotation/revocation, nonces, intended request principal and trusted audience. A signature proves origin but not correct Policy evaluation.
4. Independently verify desired-state resource ownership and safe initial `ABSENT` across CAPI, KubeVirt, M2b and network allocations. Current desired-state `KubernetesStore` remains fail-closed on any missing record.
5. Design a durable, independently verifiable append-only acceptance evidence history, counter/epoch fencing, with no ABA after delete/recreate or backup restore.
6. Review admission and RBAC for a restricted claim writer with no power to modify Fence or admission controls; **the existing deny-by-default Admission freeze remains unchanged and must not be relaxed by this PR.**
7. Run negative real API conformance on an isolated Kind cluster (concurrent claim registration, 409, lost connection, tampered record, deletes, recreates, admission removal, revoke and rollback) before production activation.

No new CLI, executor, network, cluster or Kubernetes API changes. ADR-034-SP-001 stays **Proposed**. The operator-verified Kind freeze test is a separate, narrower security result and does not establish an authorized writer.
