# ADR-CAPI-003: Minimal Management Ownership and Fencing Contract

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
CAPI controllers, BYOH agents and provider credentials may outlive the management cluster that originally acquired them. A shadow manager or resurrected old manager could cause split-brain.

## Decision
Use existing Kubernetes/CAPI, RBAC, secrets infrastructure, provider permissions and an external persistent backend. Define only a **minimal provider-neutral OpenKubes management ownership contract**; do not create an alternative cluster reconciler or generic distributed coordination framework.

For a management domain, there may be **at most one manager authorized to execute effective lifecycle writes**. The ownership record includes immutable domain and owner IDs, monotonically increasing epoch, operation ID, current phase, evidence references and expected prior epoch. Transfer is conditional on an atomic compare-and-swap operation or equivalent serialization.

An ownership registry entry is **not** proof of fencing. Enforcement must be implemented at actual write boundaries, e.g. effective credential revocation, denied infrastructure-provider writes and blocked management API operations. Kubernetes Leases coordinate only where all writers honor them; they do not fence isolated writers.

## Required Capabilities
- Identify the current owner and immutable affected cluster/domain identities.
- Freeze and drain destructive lifecycle operations.
- Revoke or otherwise make old write privileges ineffective.
- Independently verify source fencing and target write gating.
- Atomically record the authorized epoch transition.
- Activate target writes only after validation; retain evidence and audit history.

## Failure Handling
If a fence cannot be proved, the system fails closed. An old management plane returning online must remain unable to write. A stale epoch never regains authority. A period with **zero** active owners is acceptable; simultaneous active ownership is not.

## Alternatives Considered
- Git-only ownership: rejected because committing does not revoke credentials.
- Lease-only ownership: rejected for partitioned or resurrected managers.
- New all-purpose OpenKubes reconciler: rejected.

## Validation Requirements
Demonstrate old-owner resurrection, network partitions, stale registry state, dual-writer attempts, expired/rotated credentials, independently verified denial of writes and auditable recovery authorization. All mechanisms are architecture targets until proven by E2E tests.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
