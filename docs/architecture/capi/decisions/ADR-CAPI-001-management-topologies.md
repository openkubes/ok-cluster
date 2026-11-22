# ADR-CAPI-001: Management Topologies: Self-Managed and Centralized CAPI

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
OpenKubes must support small independent installations and larger multi-cluster estates without binding the runtime of workload clusters to the availability of their management plane. Cluster API (CAPI) owns lifecycle reconciliation, not application availability.

## Decision
Support two explicit management topologies:

1. **Self-managed CAPI:** bootstrap using a temporary management cluster, install compatible CAPI components in the target cluster, then perform a separately authorized `clusterctl move`. The resulting cluster manages its own CAPI resources.
2. **Centralized CAPI:** one dedicated management domain manages a declared inventory of workload clusters. A new independently prepared BYOH management cluster can eventually replace the active domain owner under ADR-CAPI-006.

Both use Kubernetes and CAPI contracts without requiring a specific Kubernetes distribution. BYOH is the OpenKubes reference implementation for management infrastructure.

A planning heuristic of roughly ten clusters is **not** a capacity or support limit; operational criticality, failure domains and provider compatibility determine the choice.

## Invariants
- Workload Kubernetes continues operating during management-plane unavailability, subject to its own infrastructure health.
- No implicit cluster reprovisioning because a manager is lost.
- Exactly one authorized lifecycle management owner per domain (see ADR-CAPI-003).
- Self-managed clusters can need external rescue when their Kubernetes API or etcd is unavailable.

## Trade-offs
Self-managed CAPI isolates failures and version changes per cluster but repeats controller operations and complicates self-recovery. Central management centralizes policy, inventory and upgrades but creates a shared lifecycle failure domain requiring fencing, backup and disaster recovery.

## Alternatives Considered
- One universal management topology: rejected because failure domains and operational scale differ.
- Workload clusters fully dependent on a permanent manager: rejected.

## Validation Requirements
Demonstrate bootstrap and pivot, each topology's controller ownership, independent workload operation when management stops, and compatible provider version matrices. Record commits, versions and E2E evidence before asserting production readiness.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
