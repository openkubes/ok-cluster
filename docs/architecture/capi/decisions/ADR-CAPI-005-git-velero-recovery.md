# ADR-CAPI-005: Git-First Configuration and Velero-Assisted Recovery

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
Git describes desired cluster configuration but cannot fully reproduce CAPI objects, generated machine references, BYOH registrations or operational credentials.

## Decision
Use Git as the primary declarative configuration source, with Velero backups of required management API resources and CAPI/BYOH operational state stored outside the management failure domain in **S3-compatible object storage**. The Scaleway lab may use Scaleway Object Storage; MinIO or other supported S3-compatible targets remain options.

Velero complements rather than replaces Git or a separate ownership register. Backups are not an authorization to enable reconciliation.

## Backup Boundary
Inventory namespaced and cluster-scoped CAPI/Provider resources, CRDs and API conversions, required Secrets, ownership metadata pointers and BYOH registration state. Validate that every required resource and credential can actually be restored; never assume a default Velero scope includes everything.

Encryption at rest, access control, credential rotation, versioning/retention and restore permissions must be independently specified. Do not operate the only backup target on the management VM.

## Recovery Material
- Git: desired cluster declarations and infrastructure code.
- External IaC state: existing management provisioning records.
- S3/Velero: saved operational management objects.
- Protected secret management: current trust and access material.
- Independent ownership/audit store: authority and recovery evidence.
- Infrastructure discovery: real live hosts and machines.

## Trade-offs
Velero provides a reusable restore mechanism, but stale backups, CRD/API mismatches and credential drift require validation. Git-first is not Git-only.

## Validation Requirements
Demonstrate complete resource inventory, backup verification, restoration into a write-fenced environment, stale-secret and stale-machine reconciliation and successful recovery-gate evaluation. Define RPO/RTO per management domain; no universal numerical guarantee is implied.

## Scope
Full management disaster recovery and activation are governed separately by ADR-CAPI-007.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
