# OK-147 bounded lifecycle credential contract (proposal)

Status: design proposal only. This document does not enable the runner, change a
manifest or credential policy, authorize a Job installation, or permit cluster
access. ADR-030 security acceptance item 9 remains OPEN.

## Goal

Allow one reviewed, single-use Bare-MVP run to use the existing lifecycle owners
without giving the executor a CAPI administrator identity. The contract must
work for the existing `ok up`/full-run interfaces and preserve the runner's
durable stage receipts, single-use grants, terminal STOP behavior and
independent convergence evidence.

## Existing boundaries

- Stage 1–7 authority is already split: provider prerequisites use the
  infrastructure API; Cluster lifecycle and its ledger use the management API;
  workload observations use the created workload API.
- The public full-run path currently expects distinct, short-lived
  infrastructure and management credentials, plus a workload kubeconfig
  derived from the exact lifecycle result. Credential-policy validation rejects
  the current lifecycle-derived workload materializer before Stage 1.
- A CAPI-generated `kubernetes-admin` / `system:masters` certificate is not an
  acceptable substitute, even if short-lived.
- The existing experimental `bootstrapauthority` protocol is for observer
  certificate requests/results. It does not define a lifecycle credential,
  enable a stage grant, or establish cluster success. It must not be silently
  repurposed.
- Its code makes that separation concrete: `bootstrapcheck` accepts only the
  `network-observer` role (bound to a Stage-4 receipt) and
  `runtime-observer` (bound to a Stage-5 predecessor); it fixes each
  certificate CN to a request-nonce/role value, permits only client-auth
  digital-signature certificates, and requires a trusted, independently
  supplied target CA. It has no installer, `system:masters`, lifecycle or
  general workload-client profile. Therefore it is not a reusable credential
  issuer for `ok up` and cannot be widened by changing only the caller or
  passing its certificate result into the full-run manifest.
- The role name also does not prove least privilege: the current Stage-5
  adapter uses `pods/exec`, and Stage 7 creates cluster-scoped RBAC objects.
  Until those operations have an accepted server-enforced authority boundary,
  issuing either certificate does not make the associated stage safe to
  activate. Keep the existing execution-open denial in place.
- A management super-admin kubeconfig, if used as a temporary installer
  credential under a separately approved test, is not mounted into the runner
  or issuer and does not itself authorize workload access.

## Proposed identity and issuance boundary

Use a short-lived, workload-scoped X.509 client credential for the exact
workload cluster, because the current execution interface consumes a
kubeconfig and explicitly rejects a generic bearer-token substitution. The
credential must be issued only after the authoritative lifecycle receipt
contains the target Cluster UID and a trusted workload CA source is available.
Issuance is a separate, one-shot platform operation; it is not performed by the
runner and is not an automatic replay or recovery path.

The issuer must:

1. Accept one canonical request bound to the exact Plan/attempt, target name
   and UID digest, successful lifecycle receipt digest, approved credential
   policy digest, audience/purpose, request nonce and bounded validity window.
2. Independently re-read the authoritative lifecycle object and CA source,
   checking UID/resourceVersion and certificate/key correspondence immediately
   before signing. Caller-supplied identity fields or a matching digest alone
   are insufficient.
3. Issue only the exact subject and groups in an independently reviewed
   allowlist; prohibit `system:masters`, administrator identities, extra
   groups, unknown extensions/usages, and validity outside the policy window.
4. Store an immutable claim before signing and an authenticated immutable result
   after issuance. Claim-without-result, uncertain writes, source drift,
   duplicate requests, or missing durable fencing are terminal STOP; never
   retry, release, or take over automatically.
5. Return private credential bytes only to the single-use local/job handoff.
   Durable/public receipts contain digests, identity labels, expiry and source
   evidence identifiers only—never key, certificate, token, kubeconfig,
   endpoint or raw Kubernetes UID/resourceVersion.

The issuer Job must be fixed-image, digest-pinned, non-retrying and
non-privileged; have no automounted ServiceAccount token unless that exact
capability is part of a separately reviewed issuer design; use a dedicated
ServiceAccount and narrowly scoped source-read/signing/storage permissions;
and have no generic proxy, shell, arbitrary signer, credential-renewal,
Cluster-write, or lifecycle-execution surface. Installer authority and issuer
authority are distinct. A one-shot Job is an invocation shape, not by itself a
security boundary.

## Authorization/RBAC is a prerequisite, not implied by issuance

The certificate's exact CN, complete O/group set, issuer CA, client-auth usage,
target binding and maximum lifetime must be fixed before code enables it. Any
stage-specific workload RBAC must be derived from actual API calls and verified
with positive and negative authorization tests. It must exclude lifecycle
writes, arbitrary Secret reads, arbitrary RBAC writes/escalation,
impersonation, node/proxy access and unrelated namespaces/resources.

### Code-derived Stage 5–7 authority impact

The current adapters show that a single broad workload identity cannot be
called “read-only” or assumed least-privilege:

| Stage | Workload API operations found in current code | Security consequence |
| --- | --- | --- |
| 5, network observation | Workload credential: GET `/api/v1/nodes`, exact Cilium DaemonSet/Deployment objects, list Cilium Pods in `kube-system`, GET the selected Pod identity, then open `pods/exec` against that Pod to run the fixed probe. Management-side HCP/HRP reads use a separate management credential. | Pod listing is selector-bounded in client code, but Kubernetes RBAC cannot enforce that client-side label selector as a role boundary. `pods/exec` is an execution capability, not an observation-only permission. The exact Pod UID is runtime-verified, but the Pod name is selected at runtime. |
| 6, runtime binding | Repeated GETs for `/api/v1/namespaces/kube-system` and `/apis/storage.k8s.io/v1/storageclasses/local-path`; no workload write in this adapter. | This stage can use a narrow read-only workload capability, but the current prefix reuses the same workload credential as other stages. |
| 7, target access | Exact-name GET preflights followed by collection POST creates from the verified renderer artifact; the fixed 16-object inventory includes Namespace, ServiceAccount, multiple ClusterRoles, ClusterRoleBinding, Roles and RoleBindings. | Cluster-scoped RBAC creation is a distinct mutation authority. Creating roles/bindings that grant permissions beyond the caller can hit Kubernetes privilege-escalation/bind checks; do not assume a non-admin identity can create them. A generic create permission is also not equivalent to the Plan's exact-object restriction. |

This inventory is derived from `internal/runner/kubernetes.go`,
`internal/runner/cilium_websocket.go`, `internal/runner/runtime_binding_source.go`,
`internal/runner/target_access_stage_operation.go` and
`internal/submission/target_access.go`. It is code evidence, not proof of
deployed RBAC or of every server-side authorization check.

Kubernetes RBAC has two relevant limits: top-level `create` cannot be narrowed
by `resourceNames`, and a `list` constrained by `resourceNames` must use a
matching `metadata.name` field selector (the current Pod selection uses a label
selector instead). See the official [RBAC authorization reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

**Preferred direction (selected for design, not activation):** use a bounded
management-plane platform controller for Stage-7 object installation, and
replace Stage-5 Pod `exec` with an independently validated, read-only health
evidence source. This fits the future Operator boundary and avoids handing
`ok up` a workload identity capable of both arbitrary Pod execution and
cluster-scoped RBAC creation. The controller is a coordination boundary, not
automatically a least-privilege boundary: a long-running controller holding a
workload-admin credential would merely move the same risk out of the CLI.
Its own target writer must be fixed-purpose, isolated, and server-constrained
to the exact request. This is a direction for the next reviewed contract, not
authority to change the current seven-stage contract or deploy a controller.

The Stage-7 controller contract should be a fixed operation, not a generic
Kubernetes apply endpoint. Its request must bind the Plan and attempt, exact
target Cluster namespace/name/UID, approved target-access artifact digest,
ordered object identities and canonical object-set digest. The controller
must independently resolve and verify the target UID and immutable artifact,
claim the attempt before mutation, install only the fixed approved inventory,
and persist an authenticated terminal outcome. Unknown create outcomes or
target/artifact drift are terminal STOP, never an automatic replay. The
terminal result must carry the exact per-object API verification already
represented by `submission.PlaneReceipt`: ordered identities, expected content
digests, observed object UIDs/states, mutation state, and partial/STOP detail.
The runner verifies this result against the staged 16-object set and exact
request binding before writing the Stage-7 outcome/receipt. A controller Job
completion or a name-only ClusterResourceSetBinding is not sufficient. The
full-run's separate convergence evaluator remains necessary and must still
observe revision-correlated success for the exact target Cluster UID; the
Stage-7 controller result alone never means cluster success.

For compatibility with the existing operation evidence, the request/result
mapping should preserve these identities without creating a second stage-grant
claim. A distinct immutable controller dispatch/result record may still be
required to recover a submitted operation; it records execution state, not a
second authorization or permission to replay:

| Controller handoff | Required binding |
| --- | --- |
| Request | Existing Plan digest, execution-attempt digest, `target-access` stage digest/order, `CreateTargetAccess` grant identity, Contract/Platform revisions, target namespace/name plus independently checked Cluster UID digest, target-access artifact digest, exact ordered 16-object identity list and canonical content digest. No kubeconfig, token, private key or raw UID in public status. |
| Durable outcome | Immutable terminal outcome tied to the one consumed grant/claim; exact request digest, target UID digest, artifact/object-set digests, mutation state, result category and completion time. An absent, conflicting or unreadable outcome after submission is STOP, not permission to submit again. |
| Stage receipt | Existing ledger finalization links the outcome digest and Stage-6 predecessor chain. Preserve current receipt-chain verification and single-use grant semantics; do not mint a parallel grant or infer success from a controller condition alone. |
| Runner verification | Validate the authenticated controller result against the exact request and all 16 staged object identities/digests; only then finalize the existing Stage-7 outcome/receipt. This is operation evidence, not whole-cluster convergence. |
| Full-run convergence | The later independent evaluator must still observe revision-correlated success for the exact target Cluster UID. Do not add an extra Stage-7 read credential unless the controller result cannot provide the existing `PlaneReceipt`-equivalent API evidence or the reviewed Contract requires independent pre-receipt reads. |

One open integration point is how the controller's immutable outcome connects
to the existing stage ledger. The stage-grant claim remains the single-use
authorization boundary. A controller request/result record, if needed, must be
derived from that exact claimed grant and support read-only recovery of its
terminal state without resubmitting the mutation. The runner then bridges the
verified controller result into the existing stage outcome and receipt chain.
Do not treat two independent claims as equivalent fencing. Claim-without-result
and uncertain writes must terminate in STOP.

### MVP transport recommendation (design only)

Prefer one create-only, namespaced management-plane request object containing
the bounded canonical target-access object bundle, its digest, the exact
request bindings above, and the signed existing stage authorization. This
avoids a payload ConfigMap plus a separate trigger object and their partial
creation boundary. The bundle is security-sensitive even though the current
fixed object schema contains no kubeconfig or key field: rendered labels and
annotations are still input values and must not be copied into public status or
logs. Keep the request namespace private and its reader/writer roles exact.

The controller must reject requests that are not the one fixed
`CreateTargetAccess` operation, verify the full artifact with the same strict
schema and digest rules as the runner, independently resolve the Cluster UID,
and consume the signed stage authorization exactly once before touching the
workload API. The request object's existence is not success. Persist a
separately authenticated, create-only terminal result bound to the request
digest; allow the runner only exact-name GET recovery. Never resubmit an
uncertain request or recreate its worker automatically.

This transport does not solve controller target-side authority. In particular,
do not silently reuse a privileged CAPI kubeconfig or copy the existing
`ok up` super-admin test credential into the controller. The controller's
workload identity and its ability to create the exact cluster-scoped RBAC set
must be reviewed as a separate trusted execution boundary. Post-create API
verification remains part of the controller's bounded result, while
independent whole-run convergence remains with the existing evaluator. The
rendered observer ServiceAccount and Role do not produce a credential; do not
assume they are needed for this Stage-7 handoff or silently mint an observer
token. If a future Contract requires an independent pre-receipt observer, that
credential and its exact read authority need a separate design.

The current artifact confirms that the authority being installed is
materially privileged in two separate ways. First, the `ok147-argocd-manager`
ClusterRole grants broad create/patch/update/delete on CRDs,
ClusterRoles/ClusterRoleBindings, and mutating/validating webhook
configurations, in addition to `bind`/`escalate` for five exact Platform
ClusterRole prerequisites. Second, the Stage-7 writer needs sufficient
authority to create that role and its binding. Do not conflate the resulting
Argo CD manager's intended platform authority with the controller's own
installation authority; the controller must not inherit the former just to
install it.

A controller cannot be described as a least-privilege CRUD writer merely
because its own code submits only the verified bundle. Kubernetes RBAC does
not restrict collection `create` by `resourceNames` or by request body; exact
role subjects, names, and rules need server-side enforcement, and the
target-side credential still needs the necessary escalation/bind capability.
The enforceable design must therefore choose and test either a purpose-built
admission/applier boundary that accepts only the signed exact request, or a
separately reviewed privileged controller boundary with equivalent fixed-code
and durable-request protections. Neither is present in this repository
today. Do not install a new target admission policy from the same untrusted
Stage-7 payload it is meant to constrain.

The repository search found the ledger ValidatingAdmissionPolicy only; the
`talos-kubevirt-mvp` recipe and Talos/KubeVirt CAPI templates do not currently
install a target-side policy for these 16 objects. The KubeVirt-specific Talos
template already uses Talos `inlineManifests`, so it has a plausible earlier
bootstrap delivery point, but the profile does not use it for target-access
admission today. The controller cannot bootstrap its own admission safety as
part of Stage 7. Any policy must arrive through a separately reviewed,
earlier bootstrap/profile contract and be independently verified before the
target-access request is eligible. This is a new prerequisite and
lifecycle-contract change, not a detail to hide in the request Job.

A built-in [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
can validate a matching API request with CEL and optional parameter objects,
making it a possible exact-object guard; it does not execute the controller
operation or persist its single-use claim and terminal result. So even a strict
fail-closed VAP would complement, not replace, the controller's authorization
and durable outcome protocol. A static policy could encode the fixed
profile's invariants, but the current rendered objects include a dynamic
cluster name and target/request binding; per-attempt parameter objects are one
possible design to assess, not an assumed solution. Any parameter object must
be created by an authority independent of the Stage-7 controller, immutably
bound to the target Cluster UID and exact attempt/object set, and protected
from controller modification or replay. Otherwise the controller could
authorize its own over-broad request by changing the parameters. CEL admission
does not verify the cryptographic stage authorization; the trusted controller
and existing single-use ledger protocol must do that. Do not assume a static
policy can validate an arbitrary signed grant.

Credential issuance alone cannot make the current Stage-5/7 operations safely
least-privileged. In particular, a fixed command in the runner is not enforced
by Kubernetes authorization once a `pods/exec` credential is issued, and exact
object bodies in the runner are not enforced by ordinary RBAC for collection
`POST` creates. The selected direction is to change Stage 5 to a reviewed
non-exec health evidence source and move Stage 7 behind the bounded controller
contract above. The runner must verify the controller's durable outcome and
independently observe convergence. This changes stage ownership and requires an
explicit versioned contract revision before implementation or activation; the
management super-admin installer credential cannot be reused as a workload
capability.

The direct-operation alternative—keeping Pod `exec` and runner-side Stage-7
creates behind separately reviewed server-side enforcement—is not the selected
working direction. It remains a possible fallback only if the controller
contract proves infeasible; it would still need per-stage credentials bound to
the exact grant, target UID and bounded window as defense in depth, not as a
substitute for server-side enforcement. No direction is implemented or
approved for production activation by this proposal.

### Stage 5 non-exec probe candidate

The current profile pins Cilium 1.19.6. Upstream Cilium documents separate
clusterwide health API operations: `GetStatus` returns connectivity from
interval-based probes; `PutStatusProbe` runs a synchronous probe. This makes a
read-only status query a plausible replacement for the current
`cilium-health status --probe` Pod exec, while retaining the existing evaluator
only if its response shape, freshness timestamps, per-node/path coverage and
failure meaning match exactly. See [Cilium's API restriction table](https://docs.cilium.io/en/stable/configuration/api-restrictions-table/)
and [network-health troubleshooting description](https://docs.cilium.io/en/stable/operations/troubleshooting/).

The pinned v1.19.6 generated model confirms the expected structural fields:
`HealthStatusResponse` includes `probeInterval`, `timestamp`, optional
`local`, and `nodes`; each `NodeStatus` includes `host` and
`health-endpoint`; primary paths include `http`/`icmp` with `status` and
`lastProbed`. These match the collector's expected field names closely. The
important remaining gap is semantic: the schema says `local` carries only the
local node name, so that field alone is not connectivity evidence. However,
the pinned v1.19.6 server's `/cluster/nodes` handler constructs `nodes` from
the Cilium node manager's full `GetNodes()` result without filtering local
nodes, and the health prober builds statuses from those node entries. A
same-named local entry can therefore have real host/health-endpoint path
statuses in `nodes`; the model comment and the client formatter unit test do
not establish whether the deployed Cilium node store always includes it. The
current normalizer/evaluator require four paths for every Kubernetes Node UID,
and the repository fixture synthesizes exactly that complete set. Before
calling `GetStatus` equivalent, prove against the pinned server behavior that
the local Node is represented with all required probe paths and bind each
Cilium node name to exactly one independently observed Kubernetes Node UID.
Otherwise propose a reviewed, versioned evidence-contract change. Do not
fabricate local paths or count `local.name` alone as connectivity evidence.
Also verify that interval probing provides the same freshness and failure
meaning as the current active probe evaluator. The exact model source is
[Cilium v1.19.6 HealthStatusResponse](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/api/v1/health/models/health_status_response.go),
[NodeStatus](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/api/v1/health/models/node_status.go),
and [PathStatus](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/api/v1/health/models/path_status.go); see also the pinned [node-manager REST handler](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/pkg/node/manager/rest_api.go), [health prober](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/pkg/health/server/prober.go), [health client formatter](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/pkg/health/client/client.go) and [formatter tests](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/pkg/health/client/client_test.go).

The API server must also be explicitly enabled and reached through a reviewed
authenticated or tightly isolated endpoint; enabling the API is not itself
proof of caller authentication. A client allowlist must permit only read-only
`GetStatus`, not `PutStatusProbe` or general Cilium APIs. The current workload
NetworkPolicy and manifest do not bind that endpoint. If equivalent per-node/
path evidence, freshness, or a suitably restricted endpoint cannot be proven,
do not substitute lesser health signals and call them the same Contract
result. The official API-restriction documentation describes `GetStatus` as
interval-based observations and `PutStatusProbe` as synchronous probing; the
latter is not acceptable as a read-only substitute.

The pinned v1.19.6 CLI source confirms that `cilium-health status --probe`
calls `PutStatusProbe`, while plain `status` calls `GetStatus`; `--output json`
prints the returned `HealthStatusResponse` directly. That is useful for a
future conformance fixture, but it does not justify calling `GetStatus` an
equivalent probe: its cache is interval-driven. Before adapter work, the
version-pinned test gate should cover (a) the exact 1.19.6 response schema,
(b) proof that complete Kubernetes-Node coverage includes the local Node with
all four paths, including missing/duplicate/foreign names, (c)
freshness and partial-path outcomes at threshold boundaries, and (d) transport allowlisting
that permits only GET `/status` and denies PUT `/status/probe` and all other
routes. See the [v1.19.6 Cilium status command](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/cilium-health/cmd/status.go)
and [health API handlers](https://raw.githubusercontent.com/cilium/cilium/v1.19.6/pkg/health/server/status.go).

### Existing CAPI component worth evaluating for Stage 7

Upstream CAPI `ClusterResourceSet` is a candidate to apply the verified
Stage-7 resource set using the existing management-plane controller rather
than giving the runner direct workload RBAC writes. CAPI describes it as
applying ConfigMap/Secret-backed resources to matching existing or newly
created Clusters; the resources and referenced objects must be in the same
namespace. The CAPI 1.13 docs specify the `addons.cluster.x-k8s.io/v1beta2`
API with `ApplyOnce` or `Reconcile` strategy and a `ClusterResourceSetBinding`
resource that records per-resource hashes/applied state. See the [CAPI 1.13
ClusterResourceSet documentation](https://release-1-13.cluster-api.sigs.k8s.io/tasks/cluster-resource-set)
and [API reference](https://release-1-13.cluster-api.sigs.k8s.io/reference/api/crd-api-reference).

The offline conversion shape is plausible: a digest-bound resource-set Secret
could contain the already-verified Stage-7 objects, and one ClusterResourceSet
could select only the intended Cluster. The runner would then observe the
ClusterResourceSetBinding/result and the target objects rather than receive a
workload certificate with ClusterRole/ClusterRoleBinding create rights. The
runner would need to verify CAPI's target binding/status and independently
observe the resulting target objects. This would replace the Stage-7 mutation
authority and its grant operation, so it is not a transparent implementation
detail.

This is a reuse candidate for controller mechanics, not the selected Stage-7
contract as-is: its selector binds
Cluster labels, not the target UID, so selection must be unique and protected
from name-reuse ambiguity; its input objects and desired object set need
immutable digest binding; its binding/status must be correlated to the actual
target UID and converted to durable stage evidence. `ApplyOnce` / `Reconcile`
semantics must be compared with the current exact GET/POST create-only and
STOP-on-uncertainty behavior; do not assume they preserve that behavior. The
upstream docs state that deleting the ClusterResourceSet does not delete the
resources it applied, so teardown and recovery semantics need separate
treatment. A bounded controller operation may reuse CRS internally only if it
supplies the missing UID fence, exact-object policy and immutable terminal
outcome; otherwise use a narrow controller-owned request/result API instead
of CRS.

The v1beta2 schema makes the evidence gap concrete: the binding's
`spec.clusterName` is name-only; each resource binding records a source
resource name/kind, hash and `applied` boolean; the ClusterResourceSet status
offers Conditions and `observedGeneration`. Those are useful controller
observations, but the schema does not itself carry the target Cluster UID, the
full canonical applied-object digests, or an immutable terminal attempt
receipt. A safe adapter would have to bind the binding owner/reference and
generation to a separately observed exact Cluster UID, verify every expected
target object from the immutable source bundle, and persist its own durable
attempt outcome. See the [CAPI 1.13 v1beta2 API schema](https://release-1-13.cluster-api.sigs.k8s.io/reference/api/crd-api-reference).

The repository's local management bootstrap template selects CAPI v1.13.3,
but that does not prove the live management cluster has the required
ClusterResourceSet CRD/controller or its configuration enabled. The current
workspace search found no ClusterResourceSet manifests or usage in the
renderer/deployment source. Confirming the live CRD/controller would require a
separately approved read-only cluster inspection; no such inspection is part of
this design work.

The static bootstrap-source check confirms `clusterctl init` pins the CAPI core
provider to v1.13.3. The versioned CAPI 1.13 documentation classifies
ClusterResourceSet as GA and documents its `addons.cluster.x-k8s.io/v1beta2`
API; it is not listed among that release's experimental feature gates. This
makes reuse technically plausible without introducing a new controller
dependency, but does not establish that the deployed management cluster has the
CRD/controller available or that a CRS execution would meet this runner's UID,
immutable-outcome, or recovery contract. See the official [CAPI 1.13
ClusterResourceSet documentation](https://release-1-13.cluster-api.sigs.k8s.io/tasks/cluster-resource-set)
and [experimental feature list](https://release-1-13.cluster-api.sigs.k8s.io/tasks/experimental-features/experimental-features).

The v1.13.3 controller contract rules CRS out as a drop-in executor for the
current Stage-7 semantics. Its documented behavior is best-effort: it continues
after unsupported resources, apply failures, or missing inputs, and
reconciliation can retry failed application with backoff. In `ApplyOnce` mode,
an already existing workload object is not overwritten and can nevertheless be
recorded as applied. Therefore a binding/`ResourcesApplied` condition alone
cannot prove exact object convergence, and controller retries violate the
runner's terminal STOP/no-replay boundary. Independent exact-object reads could
prove final convergence after the fact, but cannot undo or fence a background
retry or turn a partial application into an immutable one-shot outcome. See the
versioned [v1.13.3 controller API documentation](https://pkg.go.dev/sigs.k8s.io/cluster-api@v1.13.3/internal/controllers/clusterresourceset)
and the [ClusterResourceSet design contract](https://github.com/kubernetes-sigs/cluster-api/blob/main/docs/proposals/20200220-cluster-resource-set.md).

**Result of this feasibility check:** do not select stock CRS as the Stage-7
executor under the current contract. Reuse would require an explicit contract
change accepting reconciliation/best-effort semantics, or an additional
server-side one-shot fence that disables the controller's automatic retry
behavior for the operation. Neither is present or approved here.

### Minimum Stage-7 delegated-operation contract (proposal)

If Stage 7 is moved behind a platform-owned operation, its interface must be
stronger than “Job completed” or a generic `ResourcesApplied=True` condition.
The narrowest useful request/result pair is:

- Request identity: exact attempt ID, plan digest, target namespace/name/UID,
  lifecycle receipt digest, policy digest, unique nonce and bounded deadline.
- Exact desired set: immutable bundle digest plus a canonical sorted list of
  every expected API version, kind, namespace/name and object digest. The
  approved object set is produced by the trusted renderer; neither the caller
  nor the worker may add arbitrary objects or select a different bundle.
- Server-side admission: accept only one request for an unused attempt/nonce;
  re-read the target Cluster and compare its UID immediately before applying;
  reject drift, duplicates, changed policy/bundle, or expired windows before
  any workload write. Caller-supplied labels/selectors alone are not identity.
- Apply and verification: apply only the listed objects; read each back and
  compare its canonical digest, expected identity and observed UID. Do not
  claim completion from successful API calls alone.
- Durable result: record request digest, exact target UID digest, bundle and
  policy digests, per-object verified outcomes, terminal state and signer
  identity in an append-only or otherwise deletion/rollback-resistant ledger.
  The result must distinguish `COMPLETE`, `STOPPED` and `INDETERMINATE`; only
  `COMPLETE` with all object checks may satisfy the runner's Stage-7 evidence
  requirement.
- Recovery: no automatic replay after a claim, partial apply, uncertain write
  or missing result. A new operation needs a new explicitly authorized
  attempt; it must first account for any already-created exact objects and
  must never silently overwrite or adopt same-name drift.

The runner would verify the signed/durable result and independently GET the
target objects through its observation authority. It would not receive a
workload credential capable of collection POST, RBAC create, or `pods/exec`.
The platform executor's implementation could be an existing controller or a
single fixed-purpose Job, but that choice is downstream of this contract and
must provide equivalent server-enforced scope, durable fencing and recovery
semantics. This proposal does not authorize adding such a component or enabling
Stage 7.

### Existing runner acceptance boundary

The current Stage-7 implementation is already stricter than a generic job
condition. `TargetAccessMutator` is constructed from the verified target-access
projection, which contains exactly sixteen renderer-validated objects. A
successful `PlaneReceipt` must contain one ordered result per object, matching
its API identity and desired digest and carrying a non-empty runtime UID; each
state must be `CREATED` or `UNCHANGED`, with `MutationState` consistent across
the complete set. A fully unchanged set is not treated as a successful
create-stage outcome. See
[`target_access_stage.go`](../internal/execution/target_access_stage.go),
[`staged_submission.go`](../internal/execution/staged_submission.go), and
[`kubernetes.go`](../internal/submission/kubernetes.go).

There is now a concrete, inert delegation seam alongside the direct submitter:
it passes one typed `TargetAccessDispatch` containing the verified
`StageMutationRequest`, deterministic dispatch ID, artifact digest, target
identity digest, and immutable plane to a narrow interface, and still requires
the exact receipt shape above. This is an in-process interface, not yet a
versioned Job wire format. The ID is derived from the verified stage binding,
contract identity, execution-attempt digest, single-use grant ID, predecessor
receipt digest, signed authorization digest and key ID, target-access artifact
digest, and target identity. The mutation request carries the exact public
signed authorization envelope; the mutator verifies its digest, but a future
receiver now has a pure offline verifier which checks the exact fields,
predecessor boundary, usage limit and validity window against a separately
configured public key; it must not trust a key supplied by the request. That
verifier is tested but is not yet wired to a Job. Within the runner process,
the mutation request also carries an unexported verification marker set only
after `StagedOperation` has verified and claimed the grant; direct callers
cannot manufacture the request through the exported struct fields. The marker
is not a remote trust proof and is intentionally not serialized. The attempt digest is also
checked against the preconstructed mutator, despite already being
transitively bound by the plan digest, so a receiver can validate it
explicitly. The dispatch ID supports exact-request deduplication but is not a
nonce or permission to replay. This typed seam has no adapter. There is,
however, a separate existing Target Access launch path that packages the exact
input, credentials and fixed-purpose Job, then installs it through
`KubernetesTargetAccessStageLauncher`; the Job itself invokes the public
Target-Access stage command and therefore uses the existing signed-grant
verification and durable stage-claim path. Do not mistake the in-process
`TargetAccessDispatch` seam for that Job's wire format. The offline dispatch
verifier is not currently needed by the Job path and is not wired into it.
Neither a Job condition nor its process exit alone establishes stage or
cluster success; the exact durable stage receipt remains authoritative.

#### Wire-format and payload confidentiality stop line

`TargetAccessDispatch` is deliberately an in-process Go value. It must not be
JSON-marshaled as a Job request: `submission.Object.Raw` is intentionally
excluded from ordinary JSON, so that encoding would silently omit the exact
manifests, while a custom encoder would create a new security-sensitive
protocol. The current Target-Access schema validates allowed Kubernetes
object fields and object count, but metadata labels/annotations are values from
the renderer artifact; the dispatch layer does not classify arbitrary values
there as non-sensitive. Therefore the full plane must not be copied into Job
annotations, logs, public receipts, or a broadly readable ConfigMap as a
convenience.

Before a wire format is implemented, its review must specify (a) a bounded,
confidential request channel for exact manifest bytes and any operation
credentials, (b) a strict versioned decoder that rejects unknown or duplicate
fields and rechecks each object body against its digest, identity, ordered
allowlist and REST path, (c) independent trust configuration for the stage
signing key and exact expected plan/attempt/target, (d) a durable create-only
dispatch fence written before the first remote mutation, and (e) a durable,
redacted result that carries the existing `PlaneReceipt` evidence without
inventing a weaker success condition. Request transport, execution fence and
result transport must share one dispatch identity but remain separately
auditable. No current Kubernetes object or runner credential provides that
complete protocol, so there is intentionally no serializer, Job manifest, or
remote retry behavior in this change.

If the needed Stage 5–7 operations cannot be expressed with a defensible
least-privilege role under the current manifest/API contract, stop and propose
a versioned contract change; do not widen to cluster-admin or silently alter
the first-run contract. Stage grants remain independently required for every
mutating runner operation. The workload credential never creates or replaces
those grants.

#### Existing durable-claim primitive: reuse boundary

The repository already has a useful runner-side primitive: `ledger.KubernetesStore`
stores canonical immutable ConfigMaps using collection `POST` and exact-name
`GET`, and `ledger.Ledger` records a verified stage-grant claim before calling
the mutator. The installed writer Role has only `create` and `get`; its
ValidatingAdmissionPolicy restricts creates to the dedicated execution
namespace, exact service account, immutable receipt shape, and the existing
`claim`, `outcome`, and `stage-receipt` record types. Thus the runner already
fails closed if it crashes after the Stage claim and before durable completion.

The Target-Access launcher already provides a bounded Job-creation path:
`ok cluster stage run target-access launch prepare` is offline, while the
separate `launch execute --execute` uses an independently prepared package and
installer credential to create the exact six-object envelope, with the Job
created last. It preflights the exact object set, is single-use in process,
has no update/delete/retry path, and the Job uses `backoffLimit: 0`; the
worker's signed single-use stage-grant claim fences the actual mutation. The
ledger claim is not proof that Kubernetes accepted or completed the Job, so
the launch receipt means only `LAUNCHED`, never stage success. The repository
also has a separate full-run activation Job launcher.

The normal `ok up` live path currently opens `FullRunExecutionActivation`
locally; it does not route through the full-run activation Job launcher. More
importantly, both currently supported full-run manifest formats are rejected
by `VerifiedFullRunExecutionManifest.ExecutionConfig` while the bounded
client-certificate bootstrap remains disabled. Moving the same execution into
a Job would not remove that rejection. The Target-Access Job is a later
stage-only path and requires the already completed prefix, signed stage grant,
and separately bound ledger/workload credentials; it is not a bootstrap
shortcut for `ok up`.

The existing ledger's stage-grant claim remains the mutation single-use
boundary; do not add a second `dispatch` record merely to duplicate that
purpose. If a future requirement needs durable proof that a particular Job
object was accepted/completed, that is a separate evidence record and would
require coordinated schema, name-policy, admission, and activation changes.
The current ConfigMap design protects against the bounded service accounts,
not deletion by a cluster administrator or rollback of the backing cluster;
do not describe it as universally deletion-proof.

The implementation audit confirms that any separate durable Job-dispatch
record cannot be added by changing only `ledger.KubernetesStore`: the
category/name mapping is in
`internal/ledger/kubernetes.go`, the local filesystem backend has its own
category map in `internal/ledger/ledger.go`, and the installed policy is both
rendered in `deploy/contract-executor-ledger.yaml` and structurally checked by
runner activation in `internal/runner/full_run_activation_launcher.go`. The
activation installation plan also pins the existing policy objects. The
deployed writer ServiceAccount has only ConfigMap `create,get`; it has no Job
create authority. The existing CLI launcher instead uses a separately
prepared, bounded installer credential and fixed Job package. No broader
ledger role or arbitrary runner-supplied Job payload is needed for that path.

The next gate is to complete and review the bounded workload-credential
bootstrap so the exact Bare-MVP manifest can pass `ExecutionConfig` without
re-enabling privileged client certificates. Only then should the product
choose whether `ok up` uses local execution or the existing reviewed full-run
Job launcher, and add bounded wait/read behavior for its durable execution
result. Do not add a generic Job API, new authority, or duplicate dispatch
ledger category; either route must preserve the exact manifest, grant,
receipt and convergence bindings.

This is not currently a flag-only route: the expert full-run package builder
requires installer endpoint/token/CA, a pinned Job template and image, bounded
network endpoints/CIDRs, and independent evidence-authority material. The
product `ok up` live contract currently carries only the manifest digest,
evidence public key, terminal marker and local manifest path. Do not silently
invent defaults or infer private installer/evidence material from ambient
machine state. First decide which of those values belong in the reviewed
private run configuration and which remain explicit operator inputs; then
make `ok up --job` prepare and display their exact redacted package before any
credential is opened or Job object is submitted.

## Success and recovery semantics

Credential issuance is not runner success. The run is successful only after
the runner has persisted the complete required stage-receipt chain and the
independent evaluator has recorded revision-correlated convergence evidence
for the exact target UID. Process exit status, Job completion, a certificate,
or a CAPI `Provisioned` phase alone is insufficient.

Runner stage receipts and issuer claim/result records are separate durable
domains. An interrupted issuance is not repaired by replaying it. A completed
issuer result does not authorize re-running the runner. A stopped/indeterminate
runner attempt remains terminal; any new attempt or recovery requires its own
reviewed binding and explicit authorization. No automatic bootstrap-resume,
credential renewal, stage replay, teardown, or rollback is introduced here.

## Recommended implementation order (proposal)

Keep the controller choice small and testable. The next work should produce
reviewable artifacts in this order, without enabling live execution:

1. Freeze a versioned Stage-5/Stage-7 contract revision: identify Stage-5's
   replacement evidence source and the one exact Stage-7 operation/result.
   Preserve the current public `ok up` contract and current fail-closed gate
   until that revision is independently reviewed.
2. Specify the target-side enforcement prerequisite before designing the
   controller's writer credential. Prove that an over-broad or malformed
   request is rejected by the API server, including forged manager roles,
   subjects, webhook/CRD objects, target UID drift, and wrong object digests.
   Deliver and observe that enforcement through a reviewed earlier profile
   bootstrap, never through the Stage-7 request it constrains.
3. Define one versioned create-only request and immutable terminal-result
   schema, including private bundle transport, single-use grant verification,
   exact per-object receipt evidence, retention, and read-only recovery. Keep
   grant consumption in the existing ledger as the sole authorization fence.
4. Prove controller isolation and target writer permissions with positive and
   negative authorization/admission tests. The controller must have no shell,
   generic apply, arbitrary signer, lifecycle mutation, unbounded target
   credential, or automatic resubmission path.
5. Only after the contract is reviewed, add the runner adapter and verify that
   it bridges the authenticated terminal result to the existing Stage-7
   receipt chain. Add crash/unknown-write tests proving STOP and read-only
   result recovery, then run offline and isolated integration tests. Activation
   remains a separate decision after security review.

## Unresolved decisions before implementation

These are evidence/design gates, not implementation defaults:

1. Specify exact Stage 5–7 Kubernetes API operations and the narrowest viable
   controller/evidence authority boundary, including which objects are
   cluster-scoped; evaluate ClusterResourceSet only as an internal reuse
   candidate, not as an assumed security boundary.
2. Exact workload CA source, trusted ownership, signer isolation, key-handling
   mechanism, and how UID/resourceVersion drift is fenced during issuance.
3. Credential subject/groups, key algorithm, extensions, maximum TTL and
   expiry margin, justified by the run's bounded window rather than guessed.
4. Durable claim/result backend with deletion/rollback resistance and retention
   across Candidate namespace teardown; the current experimental adapter does
   not prove these deployment properties.
5. Versioned binding between issuer result and the existing full-run manifest
   without changing the first successful happy-run outcome or weakening grants.
6. Test and rollout evidence: signer/RBAC positive and negative tests, expiry,
   replay/crash/source-drift tests, race checks, offline CLI/runner tests, and
   independent security review before any activation.

Until all six are resolved and reviewed, the current fail-closed policy stays
unchanged. No live cluster mutation, credential refresh, Job installation,
publication or runner invocation is part of this proposal.
