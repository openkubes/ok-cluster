# ADR-CAPI-006: Domain-Scoped Blue/Green BYOH Management Handover

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
Centralized CAPI management must evolve independently of workload clusters. Replacing the manager is not the same as upgrading or migrating the workload Kubernetes clusters.

## Decision
Adopt **Variant A: one controlled, domain-scoped handover** from active BYOH management Blue to independently prepared BYOH management Green. The complete domain's CAPI lifecycle ownership changes as one **logical authorization decision**. Workload clusters, Nodes and Kubernetes versions remain in place.

Use `clusterctl move` only for the CAPI resources it supports; it is **not** an atomic transaction and not the entire handover protocol. Progressive per-workload-cluster transfers are out of scope for v1.

## Handover Contract
1. Prepare Green with compatible CAPI core, bootstrap, control-plane and infrastructure providers.
2. Evaluate Kubernetes, provider contracts, CRDs/conversion and all domain-managed workload version compatibility.
3. Quiesce active upgrades, replacements, remediation and destructive operations.
4. Gate target writes and independently fence source writes; refuse transfer if fencing is unproven.
5. Execute an inventoried, controlled CAPI object move; handle global/shared objects and Secrets explicitly.
6. Compare target objects, existing BYOH host identities, machine bindings and live infrastructure.
7. Authorize one new ownership epoch for the **whole domain**; only then allow Green to execute effective writes.
8. Retire Blue after recorded evidence and closure.

Since `clusterctl move` may unpause migrated resources and enable target reconciliation, **the target must have an independently effective write barrier throughout the move**, not merely an advisory pause flag.

## Failure and Rollback Rules
- Failed preparation or compatibility: Blue stays active; discard Green safely.
- Failed fencing: do not move.
- Partial move: prevent effective writes by either side; inspect persisted state and recover explicitly.
- After Green activation: **no automatic rollback**. Returning to Blue would require a new authorized migration.
- The term 'atomic' refers to domain ownership authorization, not atomic Kubernetes object migration.

## BYOH Safety
Stable host IDs and cluster/machine bindings must survive intact. Credential migration, API trust, agent reconnection and in-flight upgrade state require dedicated E2E evidence. Existing open BYOH security findings are not implicitly closed.

## Validation Requirements
Normal handover, partial move, failed compatibility, stale Blue restart, network partition, BYOH identity continuity, no workload reprovisioning and zero effective concurrent management writers.

## Status Boundary
Accepted architecture, **not** an implemented or production-validated Blue/Green feature.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
