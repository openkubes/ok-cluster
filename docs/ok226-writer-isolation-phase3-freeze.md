# OK-226 Phase 3 — Authority Writer Isolation / Admission freeze candidate

**Status:** NOT INSTALLED, NOT A LIVE AUTHORITY, NO WRITER ALLOWED. This is an intentionally strict, disconnected admission policy candidate for design and conformance review.

## Exact behavior

`deploy/ok226-authority-freeze-candidate.yaml` includes two separately bound Kubernetes `ValidatingAdmissionPolicy` resources with `failurePolicy: Fail` and `validationActions: [Deny]`.

1. In namespace `openkubes-authority`, **all ConfigMap CREATE, UPDATE and DELETE** admission requests fail. This includes the desired-state Authority records and Fence ConfigMap. There is **no bypass for an Authority writer** and no claim that this grants a writable CAS path.
2. Independently, **UPDATE and DELETE** on the namespace object named `openkubes-authority` fail, since deleting a namespace can indirectly remove namespaced ConfigMaps without emitting individual ConfigMap DELETE admission events.
3. The YAML is never called by any CLI, build, runner or deployment installation path. Only the dedicated offline manifest test consumes it.

### Prerequisites / careful rollout

- This candidate deliberately locks down ConfigMaps and namespace after **out-of-band provisioning**. It cannot install, register or rotate the Fence itself and must not be applied to existing production clusters as-is.
- A missing namespace can still be created by a separately privileged actor and is **not** by itself proof of the correct incarnation; independent pinned cluster/namespace/fence UID and protected initialization remain necessary.
- Effective RBAC permission boundaries, aggregation, cross-namespace bindings, admission controller configuration, privileged principals and Kubernetes version-specific policy semantics must be reviewed and tested on a disposable cluster.
- Changes to the `ValidatingAdmissionPolicy` / Binding themselves can disable this protection. This policy is **not** a security boundary against a malicious cluster-admin or someone controlling the Kubernetes API server. For stronger guarantees, the root of trust and rollback-resistant evidence must be external to the relevant administrative domain.
- Do not accidentally grant a catch-all privileged controller ConfigMap writes in this namespace; **RBAC alone cannot deny** access granted by another role.
- CEL/Admission tests are not yet executed against a real Kubernetes API; YAML structural tests prove only declared manifests. Actual denial of DELETE/CREATE/UPDATE must be observed in a disposable environment before any installation proposal.

## Required next engineering gates

1. Negative API integration tests using isolated, disposable Kubernetes: executor, observer, random workload SA and read-only SA must not write, delete or recreate records. Namespace UPDATE/DELETE must fail; admission unavailability must not silently allow.
2. Independent platform-operator bootstrap, retained authoritative initial-state registration and protected namespace/fence identities. No in-band TOFU after 404.
3. Server-enforced **authorized write path**: update of an existing record using UID+resourceVersion, Policy-signed request, single-use executor claim and immutable append-only acceptance history. Explicit owner principal/identity and non-colluding admission control required.
4. Threat model for cluster-admin, admission policy removal, namespace recreation, restore/rollback, disaster recovery and cross-domain fencing. Conformance gates must remain fail-closed.
5. No routing to `ok up` until full Same-Plane conformance and architectural review are complete.

Existing `KubernetesStore`, `DomainReader`, `ok up`, OK-147 Executor, M2b scripts and production assets remain unchanged. ADR-034-SP-001 is still **Proposed**.
