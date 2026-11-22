# Managing the Managers: A Resilient CAPI Architecture for OpenKubes

*Self-managed Kubernetes, BYOH shadow management, Git-first recovery, and explicit lifecycle ownership*

**Architecture Blueprint v1.0 — 22 November 2026**

> **Architecture status:** Seven architecture decisions accepted. This blueprint defines a target architecture, not a production-readiness claim. The complete Blue/Green management handover, independently enforced fencing and full-loss disaster recovery are **not yet demonstrated as integrated production E2E capabilities**. Individual bootstrap/BYOH test results must be evaluated separately and cited before publication as validation evidence.

> **Design principle:** Management is replaceable. Workload clusters remain.

## The management-plane problem

Kubernetes clusters are often created by an external controller environment that later becomes a hidden operational dependency. If the management environment is destroyed, upgraded, compromised or partitioned, what happens to the clusters it created? What does it mean to transfer lifecycle responsibility without transferring workloads, cloud machines or physical hosts?

Cluster API (CAPI) provides Kubernetes-native cluster lifecycle resources and reconciliation. It also provides `clusterctl move` to transfer supported management objects between management clusters. But object movement is not equivalent to an authorized, reversible, all-or-nothing management failover. Nor can a lost management cluster always be recovered through Git alone: runtime-generated identities, credentials and machine associations may matter as much as the original configuration.

The OpenKubes CAPI architecture makes these boundaries explicit. It uses existing ecosystem components and a minimal OpenKubes-specific ownership contract instead of inventing a new cluster lifecycle engine.

## A small set of non-negotiable invariants

1. **Workload independence.** Management outage does not, by itself, terminate running workload-cluster Kubernetes control planes or workloads. CAPI-managed scaling, remediation and upgrades may be unavailable during the outage; underlying workload availability still depends on its own infrastructure.
2. **At most one effective writer.** Each management domain has zero or one authorized active lifecycle owner, never two. Logical registry ownership without enforced write isolation is insufficient.
3. **No inferred destruction.** Management loss, stale state or a restore event must not automatically recreate or delete existing workload infrastructure.
4. **State is not authority.** Git, backed-up objects and even a successful `clusterctl move` do not automatically authorize lifecycle writes.
5. **Migration is not recovery.** Planned handover and full-loss disaster recovery have different preconditions and procedures.
6. **Compatibility is explicit.** Kubernetes, CAPI, infrastructure providers, API/CRD conversion and BYOH identity continuity are gated before any transfer.
7. **Evidence precedes claims.** Accepted architecture, implemented components, tested E2E behavior and production readiness are separate statements.

## Two management topologies, one set of lifecycle contracts

### Self-managed CAPI

A temporary bootstrap Kubernetes environment starts CAPI and provisions the target cluster. Once the target Kubernetes API is available, a compatible management stack is installed there. A controlled `clusterctl move` transfers supported CAPI resources into the target. From then on, the cluster's own CAPI installation manages its lifecycle.

The benefit is an isolated lifecycle failure domain: each cluster can have its own Kubernetes/CAPI upgrade cadence. The trade-off is that a failure of that same cluster's API or etcd can also take away its native lifecycle manager, requiring external recovery. Self-managed does not mean self-repair under total API loss.

A rough order of ten clusters can be a planning conversation starter, but it is **not** a Cluster API technical limit or OpenKubes support threshold. Operational criticality, provider versions, ownership domains and team capacity drive the selection.

### Centralized CAPI with BYOH shadow management

A dedicated management Kubernetes domain owns CAPI resources for multiple independent workload clusters. The reference management infrastructure uses **Bring Your Own Host (BYOH)**: management hosts can be provisioned and later replaced without assuming a pre-existing bare-metal Kubernetes cluster. The management Kubernetes distribution is not prescribed by this architecture.

For planned replacement, a second BYOH-based *Green* management cluster is prepared while *Blue* remains the active owner. The complete management domain is handed over as one logically authorized transfer. There is no initial per-workload-cluster progressive move. Workload clusters are **not blue/green replaced**; only the management plane changes.

The centralized model simplifies shared governance and compatibility policy while increasing the blast radius of a management-plane incident. It therefore requires a stronger fencing, backup, audit and recovery contract.

## Bootstrap without a permanent management dependency

The OpenKubes reference bootstrap path is deliberately lightweight:

```text
Operator / Git configuration
          |
          v
Disposable VM + kind
          |
          v
Cluster API + BYOH Provider
          |
          +----> Provision or prepare BYOH management Kubernetes
          |
          +----> Bootstrap workload Kubernetes (appropriate topology)
```

Our Scaleway disposable lab reference splits infrastructure into **Stack A**, a management VM with kind/CAPI/BYOH and network access, and **Stack B**, separately state-managed disposable workload test resources. The lab uses independent OpenTofu state, safety checks and a deliberate destroy order. These details describe a **test profile**, not a universal management deployment requirement. A single VM is not a highly available production manager.

Bootstrap, self-managed pivot, Blue/Green handover and disaster recovery are separate authorized workflows. Infrastructure provisioning must not trigger a surprise `clusterctl move`, and destroying a test workload stack must not implicitly destroy the management stack or vice versa. Production workload clusters are not disposable just because a lab profile is.

## Four distinct kinds of state

| Concern | Source / authority | Recovery implication |
| --- | --- | --- |
| Desired cluster configuration | Reviewed Git revisions | Reconstruct declarations and intended versions |
| Observed management runtime | CAPI/Kubernetes API, externally backed up | Recover objects, references, identities and secrets |
| Actual infrastructure | Existing cloud instances, bare-metal machines, BYOH agents, workload APIs | Discover and reconcile physical reality rather than assuming backup truth |
| Authorized lifecycle ownership | Independently persisted ownership record **plus effective fencing** | Verify exclusive writing before controllers resume |

Git is the **declarative source of truth**, not a substitute for every generated Kubernetes resource. The `ok` CLI can accept an imperative `ok up -f` workflow while retaining sufficient applied configuration and provenance for Git synchronization and recovery. A ConfigMap/Secret copy in the cluster may help forensics but must not become the only source.

The ownership record is not placed solely in the management cluster it protects; it must survive that cluster's complete loss. It is not a license to create another general-purpose reconciliation framework.

## Ownership and fencing: the safety boundary

A minimal versioned **Management Ownership Contract** records:

- Immutable management domain and owner identifiers;
- Expected ownership epoch and a monotonically increasing successor epoch;
- Operation identifier, phase, authorization and evidence references;
- Source and target fencing-verification results;
- Desired-state Git revision and a bounded migration scope.

The central invariant is:

`active_effective_writers(management_domain) <= 1`

An atomically committed registry change (for example, compare-and-swap) records the decision; it does **not** enforce it by itself. Kubernetes Leases are useful for cooperating processes but do not revoke a partitioned controller's cloud or BYOH credentials. A robust plan must demonstrate effective write denial for the old manager and a target-side write barrier until explicit activation.

A period with **no** active lifecycle manager is acceptable. A period with **two** effective managers is not. If fencing is uncertain, the handover or recovery must fail closed.

Existing CAPI reconciliation and provider APIs stay responsible for cluster lifecycle. The OpenKubes contract describes authorization, phase transitions, evidence and provider-specific fencing capabilities. It does not reimplement CAPI.

## Planned Blue/Green management handover

**Scope: the entire management domain, Variant A.** Blue and Green must not simultaneously own different subsets of this same domain as part of the first handover design.

1. **Prepare Green.** Build a separate BYOH management cluster and install compatible Kubernetes, CAPI and providers. It holds no active lifecycle write authority.
2. **Run compatibility gates.** Verify provider contracts, CRDs and stored API versions, Kubernetes skew, the domain's complete set of workload cluster versions, BYOH agents and credentials.
3. **Quiesce Blue.** Drain or safely finish upgrades, replacements, remediation and destructive lifecycle operations.
4. **Fence and verify.** Independently block Blue's effective writes and maintain a separate effective target write barrier.
5. **Move supported objects.** Execute an inventoried `clusterctl move`; handle shared/global objects, secrets, owner references and provider-specific resources explicitly. Treat partial completion as a recoverable incident, not as a retryable transaction.
6. **Verify.** Reconcile the moved object inventory against running infrastructure **without permitting productive mutations**, and validate BYOH host and machine bindings.
7. **Commit and activate.** Authorize the next ownership epoch for the entire domain, then enable Green's effective write path only after all requirements hold.
8. **Retire Blue.** Preserve evidence, revoke old credentials and decommission only when isolation has been independently confirmed.

**Critical caveat:** `clusterctl move` is an object migration mechanism, not a transaction manager, access-control gate, universal backup utility or automatic rollback primitive. Destination CAPI controllers may begin reconciliation as moved objects are unpaused; the target's *effective* write barrier must survive that behavior. The compatibility and isolation strategy must be tested with the actual providers and CAPI version.

After Green becomes active, switching back to Blue is a **new authorized migration**, not an automatic rollback. Failed or interrupted moves require a frozen state and an explicit inspect-and-recover procedure.

## BYOH host identity is not management identity

Existing BYOH hosts remain attached to their existing workload clusters when management changes. We must preserve and validate distinct identifiers and trust relationships:

| Identity / relationship | Required outcome |
| --- | --- |
| Immutable workload cluster identity | Unchanged |
| CAPI Machine/MachineSet and provider IDs | Reconstructed and matched to live infrastructure |
| Stable BYOH host identity | No duplicate identity or assignment |
| Host-to-cluster binding | Existing membership maintained |
| BYOH agent registration | Explicitly validated reattachment/reconnect |
| Management API and CA trust | Safe credential/trust migration or re-enrollment |
| In-flight Kubernetes upgrade | Blocks handover unless a specifically proven safe checkpoint exists |

A DNS alias alone does not preserve Kubernetes API trust. A newly created kind/API endpoint can have a different certificate authority, agent registration state and credentials. Do not claim transparent agent reconnect before provider-specific tests prove it.

## Git-first backups with Velero and S3-compatible storage

Git stores desired declarations and version history. Velero is the proposed complementary mechanism to back up required namespaced and cluster-scoped Kubernetes management resources, including relevant CAPI and BYOH custom resources and secrets, to **object storage outside the management failure domain**.

The Scaleway reference lab may use Scaleway Object Storage. MinIO and other suitable S3-compatible implementations remain deployment options. No MinIO process or object storage dependency should be placed exclusively on the management VM being backed up.

Production backup policy must address encryption, least-privilege access, retention, restore access, CRD/version compatibility, secret lifecycle, recovery points and backup verification. The operator must inventory required resources rather than assume a default backup configuration is complete.

Velero backups are operational recovery material, not the whole declarative truth and not evidence that restored controllers may safely start writing.

## Cold disaster recovery after total management loss

A completely lost Blue manager cannot serve as the source for normal `clusterctl move`. Disaster recovery instead follows an independently authorized **cold rebuild and reattachment**:

1. **Declare and freeze the incident.** Record the affected management domain, suppress automatic infrastructure mutations and establish a recovery operation ID.
2. **Prove effective old-owner fencing.** Mere loss of connectivity is insufficient: Blue might return online or remain able to reach hosts.
3. **Rebuild a fresh management environment.** Use Git and externally preserved infrastructure state; stage the compatible CAPI/BYOH stack in write-isolated mode.
4. **Restore management data.** Recover selected CAPI/BYOH resources and secrets from verified Velero/S3 backup material, with valid CRDs and conversion support.
5. **Compare reality and restored state.** Check existing instances, physical hosts, Machine/provider IDs, orphaned or newly created resources, changed credentials, in-flight upgrades and Agent/API trust.
6. **Authorize a new epoch.** Record the recovery decision in the independent ownership backend and retain the approvals and evidence.
7. **Resume and observe.** Only now allow productive CAPI and BYOH reconciliation, checking for unintended infrastructure mutations and ongoing workload health.

A stale backup can describe a Machine that no longer exists or omit a BYOH host registered after the last backup. **The restored object must not immediately be treated as an instruction to recreate or delete infrastructure.** A restore is an inspection and recovery stage until the reconciliation gate passes.

The target failure mode is a *temporarily unmanaged but still running* workload cluster—not two competing managers or automated re-creation.

Recovery-point and recovery-time objectives (RPO/RTO) belong to each management domain's service requirements. This architecture does not claim a universal zero-data-loss or zero-downtime guarantee.

## Compatibility gates as first-class contracts

A management replacement must prove compatible versions across management Kubernetes, CAPI core, bootstrap and control-plane providers, infrastructure providers, CRD schemas, conversion webhooks, persisted objects and each managed workload Kubernetes version. BYOH identity/agent and credential compatibility is equally material.

The gate should return **PASS**, **BLOCKED** or **REQUIRES_VALIDATION**. Unknown is not a permissive pass. Results must include the exact version matrix, affected clusters, required attestations and evidence IDs.

CAPI/Kubernetes version skew and provider contract rules change with releases: keep those facts in a maintained compatibility matrix sourced from the actually tested upstream releases rather than freezing a guessed universal version range into this blueprint.

## Governance without another control plane

OpenKubes uses GitOps (such as Flux or Argo CD, depending on deployment profile) for reviewed desired state, `ok` CLI for explicit lifecycle operations, existing CAPI for reconciliation, and a small ownership/fencing contract for safe control transfer. The contract can be implemented through existing access control, secret management, an independent state store and provider-specific fencing adapters.

A future Kubernautic integration may analyze compatibility, propose recovery actions, assemble evidence and request approval. It must not acquire uncontrolled CAPI or provider write authority merely by making a recommendation.

## Security and failure cases to test

Before claiming production readiness, an E2E matrix must establish:

- Bootstrap/pivot into a self-managed cluster, including controller/provider compatibility;
- A domain-wide Blue/Green transfer with no workload-cluster reprovisioning;
- Credential and API endpoint rotation without accidental BYOH host duplication;
- Network partition: stale Blue still reaches infrastructure but must be unable to mutate it;
- Old-Blue resurrection after Green activation;
- Partial `clusterctl move` and interrupted Kubernetes/BYOH upgrade;
- Total management/API loss, cold restore from Git/Velero and safe host reattachment;
- Missing objects, stale backups, CRD conversion mismatch and unavailable object storage;
- Independently audited activation and destructive-operation denial.

These are **acceptance scenarios**, not a claim that the current implementation passes them.

## What is implemented and what is not?

| Capability | Publication status as of blueprint drafting |
| --- | --- |
| Local kind/CAPI/BYOH bootstrap and portions of BYOH lifecycle | **Prior project test evidence reported; verify precise commits, versions and logs before claiming a reproducible E2E result publicly** |
| Scaleway disposable management/workload OpenTofu stacks | **Implementation in progress in a separate lab repository; no live rollout implied** |
| Self-managed CAPI pivot across chosen providers | **Architecture target pending explicit E2E evidence** |
| Whole-domain BYOH Blue/Green management handover | **Accepted architecture target; not claimed implemented** |
| Independent enforced ownership/fencing and Compatibility Gate | **Accepted architecture target; not claimed production validated** |
| Velero/S3 management backup and full-loss cold recovery | **Accepted architecture target; integrated restore/reattachment E2E not yet demonstrated** |

**Accepted** applies to the architecture decision, not to an implementation or service-level certification. We will replace status assertions with linked, reviewed test evidence as the work progresses.

## Architecture decisions

The source of truth for this blueprint is the standalone OpenKubes CAPI ADR series in `openkubes/ok-cluster`:

- [ADR-CAPI-001 — Management Topologies](decisions/ADR-CAPI-001-management-topologies.md)
- [ADR-CAPI-002 — Git as Declarative Source of Truth](decisions/ADR-CAPI-002-git-source-of-truth.md)
- [ADR-CAPI-003 — Ownership & Fencing](decisions/ADR-CAPI-003-ownership-fencing.md)
- [ADR-CAPI-004 — Disposable VM Bootstrap](decisions/ADR-CAPI-004-disposable-bootstrap.md)
- [ADR-CAPI-005 — Git-First & Velero-Assisted Recovery](decisions/ADR-CAPI-005-git-velero-recovery.md)
- [ADR-CAPI-006 — Domain-Scoped Blue/Green Handover](decisions/ADR-CAPI-006-blue-green-handover.md)
- [ADR-CAPI-007 — Cold Disaster Recovery](decisions/ADR-CAPI-007-disaster-recovery.md)

## Primary upstream references

- [Cluster API: `clusterctl move`](https://cluster-api.sigs.k8s.io/clusterctl/commands/move)
- [Cluster API documentation](https://cluster-api.sigs.k8s.io/)
- [Velero documentation](https://velero.io/docs/)
- [Kubernetes: Coordinated leader election / Leases](https://kubernetes.io/docs/concepts/architecture/leases/)

---

**Next documentation deliverables:** Four independently maintainable SVG diagrams (topologies, bootstrap/pivot, Blue/Green handover, cold recovery) followed by publishing integration with [openkubes.org/architecture/](https://openkubes.org/architecture/). The architecture overview should link to this dedicated blueprint rather than duplicate its normative ADR content.
