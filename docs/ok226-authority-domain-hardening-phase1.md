# OK-226 — Authority Domain Hardening, Phase 1

**Status:** Experimental, disconnected store adapter. No production authority activation.

This change deliberately **removes** the old `GET 404 -> ABSENT` inference from the Kubernetes-backed `desiredauthority` adapter. A ConfigMap can disappear through deletion, namespace recreation or store reset; without a protected, independently verifiable domain identity, `404` is `ErrUnverifiable`, not an authorization to recreate a first desired revision. `CompareAndSwap` therefore returns `INDETERMINATE` and performs **zero writes** on unfenced first use.

## Changes

- Fail closed on unverified ConfigMap 404. No fake `ABSENT` returned.
- Reuse `internal/jsonstrict.Decode` for duplicate-key validation of raw Kubernetes object JSON and for exact authority `state` record validation. Decode normal Kubernetes metadata with additional fields while verifying protected `kind`, `apiVersion`, namespace, name, UID, resourceVersion and `state` identity.
- Negative fake-TLS-API tests cover missing record, concurrent initial attempts, duplicate protected JSON keys, realistic extra metadata, exact replay and authorization-denied reads.
- This first hardening slice does **not** claim positive first-create functionality; such a path intentionally remains blocked until independently established never-reused domain fencing, authoritative initial state and inventory/adoption proof exist.

## Unresolved requirements

1. Pin and check storage-cluster and namespace UID, immutable independent domain identity, and an anti-rollback/fork fence across all reads and writes. This must survive absent or recreated ConfigMaps and namespace recreation.
2. Verify that objects cannot be deleted/recreated or forged by any other principal. An immutable ConfigMap alone cannot provide this. Prove deployed RBAC, admission, retention/backups and disaster recovery.
3. Resolve an authoritative initial `ABSENT` state without ordinary 404; e.g. via a separately established, trusted and fenced initial state record with independent CAPI/KubeVirt/M2b inventory proof. Do not create it as a side effect of `ok up` on a missing object.
4. Harden the HTTP transport with exact API CA, short-lived scoped credentials, timeout, redirect, proxy/credential policies, bounded errors and point-of-use identity verification.
5. Prove a full Policy verifier and single-use grant claim distinct from desired-state CAS. No user-supplied `AuthorizationDigest` is by itself permission.
6. Add fake API tests for UID drift, 409 races on an already registered record, partial/unknown writes, response tampering, backup/restore and network partitions. Keep unknown outcomes fail-closed.
7. Correct behavior must be validated against real Kubernetes API response shapes and an isolated disposable Same-Plane installation before activating any live profile.

**No changes** to the CLI, OK-147 Executor, authoring Contract, current `ok up`, M2b Make/Python lifecycle or destructive operations.

This PR is specifically a **safety tightening**. It intentionally changes the old experimental test expectation that the first ordinary 404 could lead to a successful create. That expectation was unsafe without a proven domain fence.
