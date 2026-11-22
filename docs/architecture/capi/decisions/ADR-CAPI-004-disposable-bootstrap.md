# ADR-CAPI-004: Disposable VM Bootstrap with kind, CAPI and BYOH

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
The first permanent CAPI management domain does not yet exist, and OpenKubes should not assume a pre-existing bare-metal Kubernetes infrastructure.

## Decision
Use a lightweight bootstrap environment: a provisioned VM running kind, Cluster API and the BYOH provider. This environment can provision or prepare an independently managed BYOH Kubernetes management cluster. In self-managed mode, a controlled pivot moves supported CAPI objects into the target cluster; in centralized mode, management ownership remains in an explicitly designated domain until a separate authorized handover.

The reference lab may use an Ubuntu VM, WireGuard, HAProxy and isolated OpenTofu states. These are **reference deployment details**, not mandatory features of the provider-neutral architecture. A disposable lab workload stack must not be confused with the durable lifecycle of production workload clusters.

## Invariants
- Bootstrap, pivot, shadow handover and disaster recovery are separate procedures.
- No automatic `clusterctl move` as a side effect of infrastructure provisioning.
- Management-stack destroy must not cascade into workload-stack destroy.
- Store OpenTofu states separately; guard destructive operations with scope, drift and approved-plan checks.
- The BYOH provider itself remains cloud-neutral.

## Trade-offs
A single VM plus kind is economical and reproducible, but is not a highly available production management service. Operational recovery and remote access require explicit testing.

## Validation Requirements
Offline stack isolation and destroy-safety tests; live network and node-IP verification only after separate approval; bootstrap reproducibility; an independently controlled pivot E2E test; no claim of automatic production failover.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
