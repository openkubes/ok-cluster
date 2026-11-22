# ADR-CAPI-002: Git as the Declarative Source of Truth

- **Status:** Accepted (architecture decision; implementation not implied)
- **Date:** 2026-11-22
- **Scope:** OpenKubes CAPI/BYOH lifecycle architecture
- **Series:** Independent ADR-CAPI architecture decisions

> Management is replaceable. Workload clusters remain.

## Context
Operators can create clusters through the `ok` CLI or GitOps. Imperative operations may otherwise leave no reviewed and recoverable desired configuration.

## Decision
Git is the authoritative versioned source for **desired cluster configuration**, including declared versions, topology, references to provider configuration and management-domain intent. This does not make Git the database of observed CAPI runtime state.

The `ok up -f cluster.yaml` workflow may remain available, provided the effective configuration and provenance are captured and can be reconciled into Git. A cluster-side ConfigMap or Secret may hold a recovery copy, but cannot substitute for a committed Git definition.

Distinct authorities:
- **Desired state:** Git.
- **Observed and lifecycle runtime state:** Kubernetes/CAPI APIs.
- **Infrastructure reality:** actual cloud, bare-metal and BYOH resources.
- **Management authority:** an independently persisted ownership record plus enforceable fencing (ADR-CAPI-003).

## Security and Operational Constraints
- Never commit plaintext tokens, private keys, or sensitive state files.
- Git commits do not grant operational authority and cannot themselves activate a second reconciler.
- Record the applied Git revision, actor/initiator, cluster immutable identity and evidence references.
- Drift between Git and observed state must be surfaced before destructive action.
- Do not blindly reapply declarative objects during disaster recovery; restoration is gated by ADR-CAPI-007.

## Trade-offs
Git offers review, audit and reproducibility but cannot reconstruct generated CAPI identities, runtime status, ownership authority, or secrets by itself.

## Validation Requirements
Create via CLI without initial Git commit, recover the effective declaration, detect divergence, and prevent unauthorized reconciliation during a Git-first management rebuild.

## Publication and Evidence Policy
The decision's **Accepted** status is not a claim that its workflows are implemented, E2E-validated, or production ready. Publish separate implementation status and reproducible test evidence; label untested mechanisms as architecture targets. This ADR is independent of previous platform-specific ADR series.
