# OpenKubes CAPI Architecture

> **Management is replaceable. Workload clusters remain.**

This is the standalone architecture series for OpenKubes CAPI/BYOH lifecycle management. It does not depend on any earlier platform-specific architecture series.

## Architecture Blueprint

Read [Managing the Managers: A Resilient CAPI Architecture for OpenKubes](blueprint.md) for the full publication-oriented English architecture narrative, risks, lifecycle contracts and implementation-status boundaries.

## Accepted Architecture Decisions

| ADR | Decision |
| --- | --- |
| [ADR-CAPI-001](decisions/ADR-CAPI-001-management-topologies.md) | Self-managed and centralized CAPI topologies |
| [ADR-CAPI-002](decisions/ADR-CAPI-002-git-source-of-truth.md) | Git as declarative source of truth |
| [ADR-CAPI-003](decisions/ADR-CAPI-003-ownership-fencing.md) | Minimal ownership and fencing contract |
| [ADR-CAPI-004](decisions/ADR-CAPI-004-disposable-bootstrap.md) | Disposable VM / kind / CAPI / BYOH bootstrap |
| [ADR-CAPI-005](decisions/ADR-CAPI-005-git-velero-recovery.md) | Git-first configuration and Velero-assisted recovery |
| [ADR-CAPI-006](decisions/ADR-CAPI-006-blue-green-handover.md) | Domain-scoped Blue/Green management handover |
| [ADR-CAPI-007](decisions/ADR-CAPI-007-disaster-recovery.md) | Cold disaster recovery and safe BYOH reattachment |

All seven ADRs were accepted as **architecture decisions** on 2026-11-22. Accepted is **not** equivalent to implemented, E2E validated or production ready.

## Architecture Boundaries

- BYOH is the preferred reference implementation, not a mandatory provider coupling.
- A bootstrap VM running kind, CAPI and BYOH is suitable for disposable labs. High availability is not implied.
- Planned handover uses `clusterctl move` for supported CAPI objects but requires additional fencing and verification.
- A fully lost management plane is recovered through cold rebuild, Git, verified Velero backups and independent infrastructure discovery, **not** `clusterctl move`.
- Git owns declared desired state. Runtime state, physical reality and management authority have separate sources.
- Workload clusters are not blue/green swapped by management handover.

## Status and Evidence

Before publication or production claims, provide evidence for each workflow including tested version matrices, bootstrap and pivot E2E, BYOH identity continuity, old-owner fencing, partial-move behavior, complete disaster recovery and restore safety. Existing tests for adjacent components must not be presented as proof of all these properties.

## Publication Workflow

This directory is the authoritative ADR source. A public architecture article and editable SVG diagrams may be maintained alongside it or published from it, but must distinguish architecture targets from implemented capabilities.
