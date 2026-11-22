# ADR-CAPI-007: Cold Management Disaster Recovery and Safe BYOH Reattachment

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
Complete loss of an active management Kubernetes API prevents normal `clusterctl move`. Workload clusters can continue running but CAPI-driven scaling, remediation and upgrades may be unavailable. A stale management state backup can conflict with current machines and BYOH hosts.

## Decision
Adopt **operator-authorized cold recovery**, not automatic management failover. Rebuild a compatible management environment from versioned Git/IaC configuration; use externally stored Velero backups to restore the required operational management state. Reattach existing clusters only after independently verified old-owner fencing, infrastructure discovery and explicit ownership authorization.

Never automatically recreate, upgrade or destroy managed workload infrastructure as a consequence of management loss.

## Required Phases
1. Detect the incident, record affected domain and block new lifecycle mutations.
2. Prove previous owner cannot execute effective writes; mere unreachability is insufficient.
3. Rebuild isolated new management bootstrap and install compatible Kubernetes/CAPI/Provider versions.
4. Restore data and credentials into a target whose infrastructure write access remains blocked.
5. Compare saved cluster/machine/provider IDs and host registrations with live infrastructure; resolve stale or orphaned objects.
6. Approve a new ownership epoch in an independent, atomic record only after the recovery gate succeeds.
7. Enable target management writes, verify safe reconciliation and preserve incident evidence.

## Required Consistency Checks
- Immutable Cluster/Machine/Host identities and provider IDs.
- Missing or newly created infrastructure since the backup.
- In-progress control-plane or worker upgrades.
- Secret/agent credential validity and rotation.
- New management API certificate/trust relationship and agent reconnection.
- CRD stored versions, conversion compatibility and ownership metadata.

## Safety Conditions
Restored objects have **no automatic authority** over existing infrastructure. A resurrected old manager must remain fenced, even during network partitions. A failed restore or unavailable object store must stop the procedure safely.

## Trade-offs
Cold recovery can take longer than automated failover and requires an external fencing capability and operational approvals. It significantly limits unintended split-brain and destructive recovery behavior.

## Validation Requirements
Total management loss, Git/IaC rebuild, verified Velero restore, stale backup, partial restore, object-storage outage, unexpected old-Blue return and safe BYOH credential/identity reattachment. Production-readiness must be supported by concrete reproducible evidence.

## Status Boundary
Accepted architecture target; complete E2E-safe reattachment remains subject to implementation and validation.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
