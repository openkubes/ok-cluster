# OK-147 bounded Contract Executor MVP

The implementation started with a shared, side-effect-free core for local CLI
and in-cluster Job execution. The current boundary retains non-mutating
Contract planning and adds exactly two separately authorized Contract-to-CAPI
submission stages, a durable ledger, bounded observation components and an
offline ConfigMap/Job/NetworkPolicy packager. It is still an MVP rather than a
general lifecycle runner or controller.

```text
versioned contract + test schema
              |
              v
schema-driven normalization
              |
              v
semantic projection + canonical JSON
              |
              v
R = SHA-256(canonical contract)
              |
              v
non-mutating CreateCluster plan
```

The `cluster create` command is intentionally dry-run-only:

```bash
go run ./cmd/ok cluster create \
  --contract internal/contract/testdata/ok141-contract-v5.yaml \
  --schema internal/contract/testdata/ok141-contract-v3.schema.json \
  --dry-run
```

It performs no cluster discovery, credential read, API contact, submission, or
observation. A command without `--dry-run` fails closed. Mutating submission is
available only through the later, independently authorized staged execution
path described below; it cannot be activated through `cluster create`.

The emitted `ok147-create-plan/v1` document is an internal, test-only format.
It is deliberately not shaped as a Kubernetes API object and does not establish
a public OpenKubes API.

The fixtures are test-only copies of the Phase-R v5 OK-141 contract and schema.
They preserve the proven semantic revision
`sha256:166504ae61fd558d391daedde50986cbc7a28f5f4e9d57f4acbd0433b448aa0f`;
they are not a stable public OpenKubes API.

## Verified projection boundary

The CLI can consume an immutable projection already produced by the existing
authoritative renderer:

```bash
go run ./cmd/ok cluster create \
  --contract internal/contract/testdata/ok141-contract-v5.yaml \
  --schema internal/contract/testdata/ok141-contract-v3.schema.json \
  --projection-manifest /path/to/projection-manifest.json \
  --dry-run
```

The verifier checks `R`, contract identity, every referenced raw artifact,
authority-map identity, resource counts, and the split between `ok-infra`
provider prerequisites and the `ok-mgmt` single lifecycle writer. It rejects
path traversal and altered artifacts. It deliberately does not render CAPI
objects, so the Go code cannot become a second Contract-to-CAPI compiler.

This emits an internal `ok147-create-plan/v2` and a canonical
`ok147-create-request/v1` digest. The source projection remains
`authorizationState: NO-GO`; a projection is evidence, not authorization.

## Signed authorization boundary

An optional authorization document can bind exactly one request:

```text
format:                    ok147-create-authorization/v1
audience:                  ok-cluster-contract-executor
decision:                  ALLOW
operation:                 CreateCluster
requestDigest:             exact ok147-create-request/v1 digest
contractRevision:          exact R
projectionManifestDigest:  exact projection manifest
contractIdentity:          exact namespace/name
notBefore / notAfter:      RFC3339, maximum 30 minutes
maxUses:                   1
signature:                 Ed25519 over canonical payload JSON
```

The trusted key file contains standard Base64 of the raw 32-byte Ed25519 public
key. The CLI requires an explicit evaluation time to keep tests deterministic:

```bash
ok cluster create ... --dry-run \
  --projection-manifest /path/to/projection-manifest.json \
  --authorization /path/to/authorization.json \
  --authorization-key /path/to/trusted-ed25519-public-key.base64 \
  --evaluation-time 2026-08-16T10:00:00Z
```

Verification covers the signature, key fingerprint, request digest, operation,
contract identity and revision, projection digest, audience, validity window,
and the one-use declaration. The output receipt intentionally excludes the
signature and all source paths.

Even a verified decision still produces `mutationAllowed: false`. This
boundary proves content binding and trust verification only. It does not by
itself consume the grant or authorize Kubernetes submission.

## Single-use and crash boundary

The third checkpoint adds a filesystem-backed ledger for a future short-lived
executor. It is not wired to the dry-run CLI and still has no Kubernetes client.

Before any future external write, the executor must atomically create an
immutable `ok147-grant-claim/v1` using `O_CREATE|O_EXCL`:

```text
verified signed grant
        |
        v
atomic immutable claim
        |
        +-- process stops before outcome --> CLAIMED_INDETERMINATE_STOP
        |                                    no automatic retry
        v
future bounded operation
        |
        v
separate immutable ok147-operation-receipt/v1
```

The claim binds the authorization, key, operation, request, `R`, and projection
digests. A concurrent or later attempt using the same grant is rejected. A
completion receipt additionally binds the claim and evidence digest. Repeating
the exact completion write is idempotent; a conflicting completion fails
closed. A successful `CreateCluster` receipt cannot claim that no mutation was
attempted.

Ledger directories must be real private directories and records must remain
regular `0600` files. Non-canonical or modified records are rejected. Tests
prove that 24 concurrent claim attempts produce exactly one winner.

The filesystem backend proves the consumption algorithm for local execution.
It is not sufficient for a Job because an `emptyDir` cannot enforce single use
across Job recreation.

## Durable Kubernetes ledger boundary

The fourth checkpoint adds a `RecordStore` implementation that persists the
same canonical receipts as immutable ConfigMaps on `ok-mgmt`. It is a durable
execution-evidence store, not a second lifecycle source of truth:

```text
verified grant
      |
      v
POST immutable claim ConfigMap (create-if-absent)
      |
      +-- executor disappears --> replacement GETs the same exact name
      |                          --> CLAIMED_INDETERMINATE_STOP
      v
future bounded operation
      |
      v
POST immutable outcome ConfigMap
```

The client performs only exact-name `GET` requests and collection `POST`
creates. It never lists, watches, updates, patches, deletes, or follows an API
redirect. A `409 Conflict` consumes the grant fail-closed. Every object uses a
deterministic name derived from the full grant-key digest, is `immutable: true`,
and carries the full key plus the canonical receipt digest. Responses are
verified before they are trusted.

[`deploy/contract-executor-ledger.yaml`](../deploy/contract-executor-ledger.yaml)
is an offline deployment candidate containing a dedicated namespace, Service
Account, `get`/`create`-only Role, and a fail-closed
`ValidatingAdmissionPolicy`. Within the dedicated namespace, the admission
policy denies ConfigMap creation by every identity except the exact Service
Account and binds object-name shape, immutable flag, receipt-only data shape,
exact labels, and digest syntax. Kubernetes CEL has no SHA-256 primitive, so admission
cannot prove that `content-digest` equals `receipt.json`; the Go client performs
that equality check on every create response and read. Likewise, RBAC cannot
restrict `create` to one exact body. Signed request binding and strict receipt
validation remain required application-level controls.

The ledger identities deliberately have no mutation authority over CAPI,
provider, enablement, GitOps, or workload resources. The manifest is not
deployed and no cluster was contacted. Tests use an in-memory API transport and
prove that a replacement executor observes the original claim and cannot reuse
it. The read-only Job integration is described next.

## Read-only Job preflight envelope

The fifth checkpoint wires the same `ok` binary to a short-lived `ok-mgmt` Job
in read-only preflight mode. With an exact signed authorization already
verified, `--ledger-inspect` reads only the deterministic claim/outcome names
and emits `ok147-create-plan/v3` with the current restart decision:

```bash
ok cluster create --dry-run \
  --contract /var/run/openkubes/input/contract.yaml \
  --schema /var/run/openkubes/input/schema.json \
  --projection-manifest /var/run/openkubes/input/projection-manifest.json \
  --projection-root /var/run/openkubes/input \
  --authorization /var/run/openkubes/input/authorization.json \
  --authorization-key /var/run/openkubes/input/trusted-ed25519-public-key.base64 \
  --evaluation-time 2026-08-16T10:00:00Z \
  --ledger-inspect \
  --ledger-api-endpoint https://10.43.0.1:443 \
  --ledger-token-file /var/run/openkubes/kubernetes/token \
  --ledger-ca-file /var/run/openkubes/kubernetes/ca.crt
```

The TLS adapter accepts bounded projected token and CA files, requires an exact
HTTPS endpoint, disables proxies, compression and redirects, and does not
include credential paths or contents in returned errors. The preflight uses a
separate Service Account whose Role contains only `get` on ConfigMaps. It cannot
create a ledger claim even though the later execution identity has
`get`/`create`.

[`deploy/contract-executor-job.yaml.tpl`](../deploy/contract-executor-job.yaml.tpl)
defines one non-retrying Job and its NetworkPolicy. The Pod runs off the control
plane, has explicit requests/limits, uses a read-only root filesystem, drops all
capabilities, mounts a ten-minute projected token, and can egress only to one
exact Kubernetes API IP on TCP 443. The image must be SHA-256 digest-bound.
Typed Go materialization rejects mutable images, DNS API endpoints, broad CIDRs,
shell-like names, invalid timestamps and unknown placeholders.

This checkpoint still does **not** claim the grant, submit CAPI/provider
resources, observe cluster convergence, or publish an outcome. The template is
not applied and no image is built or published. It proves only that local mode
and the future Job can use the same binary and read-only ledger boundary.

## Reproducible container boundary

The sixth checkpoint defines the container supply-chain boundary for the same
`ok` binary. [`Containerfile.ok147`](../Containerfile.ok147) pins the Dockerfile
frontend, Go builder and distroless runtime by SHA-256 digest. The build context
is deny-by-default and admits only the Go module plus `cmd/ok` and `internal`;
kubeconfigs, credentials, evidence and unrelated worktree files cannot enter the
image context.

The binary is cross-compiled with `CGO_ENABLED=0`, `-trimpath`, an empty build
ID, and explicit version and full Git revision. The runtime contains no shell,
runs as UID/GID `65532`, and exposes only `/ok` as its entrypoint. The pinned
supply-chain identities and exact `linux/amd64` plus `linux/arm64` platform set
are recorded in
[`build/ok147-runner-image.json`](../build/ok147-runner-image.json).

Planning is non-executing and non-publishing:

```bash
make ok147-runner-image-plan \
  OK147_IMAGE_VERSION=0.1.0-dev \
  OK147_IMAGE_OUTPUT=/private/tmp/ok147-runner.oci.tar
```

An actual local build additionally requires a clean worktree, the exact checked
out 40-character revision, and `OK147_IMAGE_BUILD=yes`. It produces only a local
multi-platform OCI archive, BuildKit `mode=max` provenance attestations, one
Syft SPDX JSON SBOM per platform and an exclusive `0600` build record. The
record keeps both each raw SBOM digest and a deterministic semantic digest that
excludes only the generated SPDX document namespace and creation timestamp. The
verifier rejects a missing or extra platform, absent per-platform provenance, a
changed pinned base image, or a revision mismatch.

Repeated builds must reproduce the two platform image-manifest digests and the
semantic SBOM digests. The overall OCI index, provenance manifests and raw SBOM
files are run evidence and may differ because their envelopes contain build
timestamps or generated document identities; they are bound exactly per build,
not presented as reproducible payload identities.

This checkpoint deliberately has no registry destination and never uses
`--push`. It does not publish an image, deploy a Job, contact Kubernetes, consume
an authorization, or permit lifecycle mutation. A later checkpoint must bind a
verified registry digest before any in-cluster execution can be proposed.

## Bounded registry-publication candidate

The next checkpoint defines that publication boundary without executing it.
[`build/ok147-runner-publication.json`](../build/ok147-runner-publication.json)
binds the sole image name, exact platform set, protected GitHub Environment,
provenance mode, digest-pinned BuildKit SBOM generator, digest-only pullback and
90-day receipt retention. Its tag includes both the source-SHA prefix and the
unique workflow-run ID, so a second authorized publication cannot overwrite a
previous run tag.

The publisher is manual `workflow_dispatch` only, runs exclusively from an
exact reviewed `main` commit, and accepts the publication-contract digest as an
explicit input. Every referenced action is pinned by full commit SHA. It creates
only a non-authoritative `sha-<commit>-run-<run-id>` tag—never `latest` or a
release tag—and publishes with BuildKit SLSA provenance plus SPDX SBOM
attestations for both platforms. A separate GitHub artifact attestation binds
the resulting OCI index digest.

Pullback occurs only as `image@sha256:...`. The verifier hashes the returned OCI
index, enforces exactly `linux/amd64` and `linux/arm64`, resolves one attestation
manifest per platform, and requires each to contain exactly the SPDX Document
and SLSA Provenance v1 predicate classes. `gh attestation verify` must also
succeed before an exclusive redacted receipt is retained.

The workflow still cannot deploy a Job or contact a Kubernetes cluster. Merely
merging it does not publish anything: the protected
`ok-147-runner-publish` Environment and a separately reviewed dispatch binding
the exact merged SHA and publication-contract digest are required first.

## Bounded submission primitive

The next offline checkpoint implements, but does not activate, the exact-create
submission primitive needed by a future executor. It consumes only a projection
that already passed the authoritative renderer verifier. Immediately before
use it re-reads and digest-verifies both projection YAML artifacts and checks
every object, in order, against the authority map.

```text
verified projection
        |
        v
re-verify exact artifact bytes
        |
        v
hard-coded resource allow-list + exact REST paths
        |
        +-- ok-infra: exact GET, then at most one collection POST
        |
        `-- ok-mgmt:  exact GET, then at most one collection POST
                              |
                              v
                  SUBMITTED_OBSERVATION_PENDING
```

Only the eleven resources bound by the OK-141 projection are accepted:
Namespace, Role, RoleBinding, Cluster, KubevirtCluster,
KubevirtMachineTemplate, TalosControlPlane, TalosConfigTemplate and
MachineDeployment objects in their exact API versions. The implementation has
no list, watch, discovery, update, patch, apply, delete, retry, rollback or
arbitrary-resource path. Separate TLS clients and authority identities are
required for `ok-infra` and `ok-mgmt`, and infrastructure submission must
complete before management lifecycle submission starts.

An existing object is accepted only when it contains every exact projected
field; Kubernetes-added metadata and defaulted fields may be additional. A
missing object receives one create attempt. Conflict after an observed absence,
drift, redirect, malformed API response, partial submission or an authority
mismatch stops fail-closed and preserves the exact completed receipt prefix.

Successful submission is deliberately classified as
`SUBMITTED_OBSERVATION_PENDING`, never as lifecycle success. The primitive is
not wired to the CLI or Job because claim consumption and generation-correct
observation still need to be composed into one crash-safe execution path.
Therefore this checkpoint does not contact Kubernetes, consume a grant, deploy
the published image or authorize any mutation.

## Crash-safe execution composition

The following offline checkpoint composes the previously separate mechanisms
without activating them in the CLI or Job:

```text
reverify Contract, request, grant, projection and condition policy
        |
        v
atomically claim the one-use grant
        |
        v
exact-create submission v2
        |
        v
bind the CAPI Cluster UID from the API response
        |
        v
bounded aggregate observation for current R, E and P
        |
        v
immutable ledger outcome
```

Every check that can be completed without external writes occurs before the
claim. After the claim, an observer or persistence failure leaves
`CLAIMED_INDETERMINATE_STOP`; a replacement must not retry the operation.
Known submission failure is retained as `STOPPED`. Current authoritative
failure is retained as `FAILED`. `SUCCEEDED` is possible only when at least one
write was attempted and all required Conditions evaluate `True` for the exact
runtime policy after the claim.

The aggregate evaluator derives its required membership and `R`/`E`/`P`
identities from the normalized Contract. CAPI evidence must carry the exact
submitted Cluster UID and current `observedGeneration == generation`.
Network and Platform evidence must carry the same target UID and exact `E` or
`P`; they must not invent Kubernetes generation fields for sources that do not
expose them. Missing, stale, foreign, conflicting or revision-mismatched
evidence cannot produce `Ready=True`. `False` takes precedence over `Unknown`,
matching the OK-141 aggregate evaluation model.

The submission receipt is versioned as v2 because it now records per-object
UIDs plus whether a write was attempted. This runtime identity is required to
reject a same-name foreign Cluster during observation. The composition remains
an internal offline primitive: there is still no mutating CLI flag, observer
HTTP adapter, Job wiring, deployment or infrastructure contact in this
checkpoint.

## Bounded CAPI lifecycle observation

The first concrete source adapter observes only the management-plane CAPI
`Cluster` used by the verified projection. It performs one exact GET on the
bound namespace and name and emits normalized evidence only for:

```text
InfrastructureReady
ControlPlaneAvailable
```

The adapter binds the actual Cluster UID, resource version, object generation,
the `openkubes.io/intent-revision` carrier, and each Condition's
`observedGeneration` into a redacted evidence digest. Kubernetes-added fields
and Condition messages are not copied into the normalized evidence. A missing
revision carrier is represented as unproven correlation; a foreign UID or
stale generation therefore evaluates to `Unknown`, never `True`. Duplicate
authoritative Conditions, malformed runtime identity, invalid status, a
non-200 response, or an ambiguous object stop fail-closed.

The client has no discovery, list, watch, mutation, retry, repair, or status
publication path. Its projected TLS and token adapter independently verifies
that the credential authority matches the management authority from the
projection plan. Network and Platform evidence remain separate bounded source
domains; this CAPI adapter does not infer either one.

This checkpoint still does not wire the observer into the CLI or Job and does
not contact a cluster. The later single-pass composition described below
combines this exact CAPI evidence with separately verified Network and Platform
evidence before the aggregate evaluator can produce lifecycle success.

## Deterministic NetworkReady source evaluation

The next offline source boundary translates the NetworkReady semantics proven
by OK-141 into typed Go inputs. It does not reduce NetworkReady to Helm success
or DaemonSet availability. `NetworkReady=True` requires one current evaluation
that correlates all of the following to the exact target Cluster UID and `E`:

```text
current HCP + exactly one owned current HRP
        |
        v
exact reviewed HCP/HRP semantic digests
        |
        v
all expected Nodes Ready with CiliumIsUp
        |
        v
current Cilium, Envoy and operator rollouts at pinned image digests
        |
        v
one ready Cilium agent Pod per Node
        |
        v
complete host + health-endpoint HTTP/ICMP probe matrix
```

The functional status rule retains the Cilium v1.19.6 finding: an omitted or
empty path status is a success candidate, while any non-empty status fails.
Freshness uses the observed probe interval plus the bounded cache-exposure
window instead of the disproven fixed 120-second assumption. The evaluated
snapshot retains only normalized identities, counters, timestamps and status
categories; no Secret, kubeconfig, token, certificate, endpoint, IP address,
raw API object, log, or raw probe output is part of the type.

Revision or convergence gaps evaluate to `Unknown`. Current invariant
violations such as image mismatch, duplicate identity, incomplete functional
coverage, failed paths, or stale probe evidence evaluate to `False`. The
result is one `BoundedNetworkEvaluator` source statement carrying exact `E`
and a deterministic snapshot digest.

The following offline checkpoint adds the bounded source collector behind that
evaluator. Its interfaces permit at most two exact management reads (the bound
HCP and its label-selected HRP set), five workload reads (Nodes, the exact
Cilium and Envoy DaemonSets, the exact Cilium operator Deployment, and the
label-selected Cilium agent Pods), and one fixed functional probe. The probe
interface accepts only the selected Pod name and UID; it has no arbitrary
command or argument surface. The collector sorts runtime collections before
digesting them, rejects malformed or ambiguous list members, verifies exact
object/owner/target selection, and discards raw transport errors and probe
output after normalization.

At that checkpoint, fake clients exercised the complete collector and evaluator
path, while credential materialization, TLS/token HTTP adapters, Secret reads,
cluster contact, polling, CLI/Job wiring, and mutation remained out of scope.
The collector itself does not infer authority from reusable names or API
endpoints.

The next adapter checkpoint establishes that authority boundary without making
a live request. It materializes separate TLS-only, redirect-denying clients
from distinct projected management and workload tokens. The management client
accepts only the two HCP/HRP paths; the workload client accepts only the five
runtime paths above. Equal endpoints, equal token contents, a management-plane
identity mismatch, a runtime Cluster UID mismatch, and every non-allowlisted
path fail before source data can be accepted. Raw transport failures are never
returned to the evidence layer.

The functional probe is also bound at the type boundary to exactly:

```text
cilium-health status --probe --output json
```

It carries the selected Pod name and UID plus the fixed `kube-system` namespace
and `cilium-agent` container to a narrow Pod-exec transport. The concrete
transport now uses the official `client-go` v0.29.15 RemoteCommand WebSocket
executor and requests only protocol `v5.channel.k8s.io`; it has no SPDY
fallback. One exact Pod GET verifies the selected UID immediately before exec,
and a second exact GET verifies it again afterwards so a same-name replacement
cannot be accepted as evidence. Namespace, container and the five command
arguments come from one authoritative constructor and are validated again at
the transport boundary.

The operation is bounded to 30 seconds, 4 MiB of stdout and 64 KiB of stderr.
Any stderr, empty or oversized stdout, Pod-identity change, transport failure,
or protocol construction failure stops fail-closed without returning raw
remote details. A local TLS/WebSocket integration test proves the v5 handshake,
channel-1 stdout decoding, exact query shape, bearer-token use and the two UID
checks. Unit tests cover altered commands, an initial foreign UID, replacement
races and bounded output failures.

This checkpoint still introduces no shell, `kubectl`, arbitrary command
arguments, mutation, polling, retry, CLI/Job wiring, status publication, or live
cluster contact. The executor is constructed as part of the bounded Kubernetes
Network source collector and can be invoked only through the single-pass
composition described next; no production command activates that path yet.

## Single-pass aggregate source composition

The next offline checkpoint implements the exact `Observer` shape required by
the crash-safe execution operation. It composes three ownership domains without
introducing a controller or persistent status surface:

```text
CAPI Cluster source                → InfrastructureReady + ControlPlaneAvailable
bounded Network source + profile   → NetworkReady
bounded Platform source            → PlatformReady
                                      |
                                      v
                       deterministic aggregate evaluator
                                      |
                                      v
                         one verified observation result
```

Only domains named by the Contract-derived required-condition policy are
called. CAPI may emit only its two lifecycle statements, while the Network and
Platform sources may each emit only their own statement. Cross-domain evidence
is rejected before evaluation; duplicate CAPI authority is retained and becomes
`Unknown/ConflictingAuthority` rather than being silently selected. Source
failures are redacted and stop the already claimed execution path
indeterminately, while valid `False` or `Unknown` evidence remains an explicit
deterministic outcome.

The composer performs exactly one pass in CAPI, Network, Platform order and
then evaluates one ordered bundle at the injected clock time. It has no polling,
retry, watch, mutation, repair, durable status publication or default source.
The concrete Kubernetes adapters and immutable profile loaders are described
next. This composition is not yet wired to the CLI or Job and made no cluster
contact.

## Digest-bound Network profile loading

NetworkReady expectations are no longer available only as freely constructed
Go values. The runner can load exactly one maximum-64-KiB strict-JSON
`ok147-network-profile/v1` document and requires three independent bindings:

```text
expected canonical profile digest
expected Contract revision R
expected Enablement revision E
```

The expected values must come from already verified execution inputs. Unknown
fields, duplicate JSON keys, trailing values, malformed or mutable image
identities, invalid HCP/HRP spec digests, unsafe node counts, and unbounded
probe timing fail closed. The loader retains neither the source path nor raw
document. Canonical JSON gives semantically equivalent key ordering and
whitespace the same profile digest, while any semantic field change requires a
new binding.

NetworkReady evidence now hashes a versioned pair of the canonical profile
digest and normalized runtime-snapshot digest. Therefore an unchanged runtime
snapshot evaluated under different profile semantics cannot produce the same
source identity or evidence digest. This closes the evaluator-provenance gap
without making the profile a Kubernetes resource or introducing a reconciler.

The loader is not yet wired to the CLI or Job, contains no built-in OK-141
profile default, and performs no Kubernetes access or mutation.

## Bounded Argo PlatformReady adapter

The concrete Platform source now reads only the exact Argo CD Applications
named by an immutable `ok147-platform-profile/v1`. Its Kubernetes transport is
TLS-only, denies redirects, accepts no arbitrary path and derives an allowlist
containing one namespaced GET per required Application. It has no discovery,
list, watch, sync, mutation, retry, target-cluster or command-execution path.

Each Application observation binds its UID, resource version, R, P, execution
fixture, normalized semantic spec, immutable desired Git commit, applied
revision, sync state and health state. The normalized spec includes source,
project, destination and sync policy, while target registration is also checked
against the profile. Membership is exact and canonicalized as a set, so input
ordering does not create a different profile identity.

Argo `Synced` and `Healthy` is intentionally not sufficient for
`PlatformReady=True`. A separately verified, redaction-safe capability
assertion must bind the same target UID, R, P, execution fixture, capability
contract and executable identities; its self-independent evidence digest and
bounded age are checked by the evaluator. The Argo adapter cannot manufacture
that assertion or run its executable. Missing, stale or revision-mismatched
proof therefore remains `Unknown`, while current health, identity or
capability failures remain `False`.

Capability execution is additionally fail-closed behind a separately hashed
Application gate. The collector first reads and normalizes every exact
Application. It does not invoke the capability source unless all required
Applications have the expected spec identity, current R/P/fixture correlation,
the exact applied source revision, `Synced`, and `Healthy`. Pending, unhealthy,
foreign, missing, or stale Application state therefore produces bounded
`PlatformReady` evidence without starting capability code. The same gate also
protects direct full-snapshot collection, so callers cannot bypass it.

The runner-side opener binds the reader to one explicitly named GitOps
authority (for the OK-141 topology, `ok-shared`) and a short-lived projected
credential. The adapter is still not wired to the CLI or Job, no built-in
OK-141 profile is selected, and this offline checkpoint made no cluster
contact or infrastructure mutation.

## Digest-bound Platform input loading

The Platform adapter no longer depends on freely constructed profile and
capability values at its runner boundary. Two separate maximum-64-KiB,
strict-JSON loaders now materialize:

```text
Platform profile
  ↔ expected canonical profile digest + R + P + FixtureDigest
     + target identity scheme capi-cluster-uid/v1

Capability assertion
  ↔ expected evidence digest + R + P + FixtureDigest + target UID
     + capability contract digest + executable digest
```

Both inputs must be bounded regular files and reject duplicate keys, unknown
fields, trailing values, malformed identities and semantic changes. Required
Application membership is canonicalized as a set, so ordering alone does not
change the profile digest. Capability content is verified against its
self-independent digest before becoming an immutable in-memory
`PlatformCapabilitySource`; subsequent changes to or removal of the source file
cannot alter the loaded assertion.

These loaders execute no capability code and contact no Kubernetes API. The
independent expected values still have to come from verified execution inputs;
successful file parsing is neither provenance authority nor a GO decision.

The concrete target Cluster UID is deliberately absent from the Platform
profile and therefore from P: it does not exist until the exact CAPI Cluster
submission response is available. The profile binds the
`capi-cluster-uid/v1` resolution scheme and the Argo registration name. At
observation time, the Platform collector receives the post-submission UID from
the execution policy, rejects any different configured target before an Argo
request, and requires the capability assertion to carry that same UID. This
keeps pre-runtime Platform semantics separate from runtime correlation.

## Post-submission aggregate observer wiring

The runner now exposes one concrete `execution.Observer` boundary that lazily
composes the CAPI, Network and Platform adapters. Construction validates and
freezes the immutable Network and Platform profiles but reads no credential
file and contacts no API. `Observe` first requires the policy to carry the
concrete CAPI Cluster UID returned by the exact-create submission receipt and
to match R, E and P from both profiles.

Only then can two explicit runtime resolvers run:

```text
submitted CAPI Cluster UID
        |
        +--> workload-authority resolver --> Network source
        |
        +--> capability-evidence resolver -> Platform source
```

The workload resolver must return an authority identity exactly equal to the
runtime Cluster UID. The capability resolver receives the same bound policy
and an isolated copy of the immutable Platform profile. Resolver failures are
redacted, and a foreign workload identity, missing capability source or
profile/revision mismatch fails before the affected source is opened.

Domains absent from the Contract-derived required-condition policy are not
opened and their runtime resolvers are not invoked. Required domains still run
in the fixed CAPI, Network, Platform observation order and are immediately
evaluated by the bounded aggregate evaluator. The wiring adds no resolver
implementation that could silently reuse historical capability evidence: the
single-run workload binding and capability execution remain explicit later
runner boundaries.

This checkpoint is library wiring only. It remains disconnected from the CLI
and Job, performs no polling, retry, mutation or status publication, and made
no live cluster contact.

## Digest-bound resume observation inputs

Two concrete file resolvers now implement the lazy runtime boundaries without
pretending to produce first-run evidence.

The workload resolver reads one maximum-64-KiB, non-symlink, strict-JSON
private binding only after the observation policy carries the submitted CAPI
Cluster UID. Its
canonical digest binds R, the exact target UID, the
`capi-cluster-uid/v1` identity scheme, the HTTPS workload endpoint and the API
CA digest. The bearer token and CA paths remain separate execution inputs and
are never part of the semantic record. The resolver verifies the actual CA
bytes, and the Network adapter verifies them again when opening its client, so
a changed CA cannot retain the runtime authority binding. The private endpoint
means this binding is not public evidence.

The Platform resolver loads one already produced, strict capability assertion
only after runtime correlation. An independently supplied evidence digest is
required, and the existing loader then binds the assertion to the current
target UID, R, P, execution fixture, capability contract and executable. A
capability file from another cluster incarnation or executable fails closed.

Both constructors are side-effect free: files are read only when the required
domain is observed. They enable a later executor invocation to resume bounded
observation from durable correlation inputs. They deliberately do not create
the workload credential, run the capability test, poll convergence, contact a
cluster or mutate infrastructure. Producing those current single-run inputs
remains an explicit subsequent runner boundary.

## Digest-bound staged execution plan

The first live OK-141 run proved that cluster creation is not one undivided
submission followed by one observation. The desired state crosses explicit
authority and evidence boundaries:

```text
provider prerequisites (ok-infra)
  -> CAPI lifecycle (ok-mgmt)
  -> lifecycle observation
  -> Enablement submission (ok-mgmt)
  -> NetworkReady observation (workload)
  -> runtime binding
  -> target access + short-lived credential (workload)
  -> target registration + Applications (GitOps authority)
  -> PlatformReady observation
  -> aggregate evidence
```

The runner therefore verifies a strict twelve-stage
`ok147-staged-execution-plan/v1` document before any future orchestration can
use it. The plan binds `R`, `E`, `P`, `FixtureDigest`, the distinct
infrastructure, management and GitOps authorities, exact stage dependencies,
one immutable input set per stage and a separate operation name for every
mutating stage. Its canonical digest identifies the complete experiment.

The plan must remain `authorizationState: NO-GO`; it is never a grant. It
contains no manifest content, credentials, endpoints, commands or rendering
logic. Stage input digests can point only to artifacts produced by the
authoritative Contract projection, Enablement, registration and Platform
mechanisms. Consequently this boundary can detect a missing, reordered,
foreign-authority or silently changed stage without becoming another
Contract-to-CAPI/CAAPH/Argo compiler.

This checkpoint verifies only the orchestration shape. The current bounded
execution operation is still limited to its initial lifecycle submission and
must not be activated as a complete happy-run command until separately
authorized stage operations and receipts consume this plan.

## Content-bound authorization per mutating stage

Every mutating stage now has a distinct signed authorization envelope. A grant
binds the canonical staged-plan digest, Contract identity, `R`, `E`, `P`,
`FixtureDigest`, exact stage order and digest, operation name, authority role,
the exact immutable receipt digest of every required predecessor, single-use
declaration and a maximum 30-minute validity window. Verification accepts only
Ed25519 signatures from the explicitly supplied trust key. Even the first
stage must carry an explicit empty predecessor set rather than omit the field.

This means, for example, that `CreateCluster` authority cannot be reused for
`CreateEnablement`, `IssueTargetCredential`, target registration or Platform
Application submission. Read-only observation and evaluation stages reject
mutation grants altogether. Reordering a stage or changing any immutable input
changes its stage and plan identity and invalidates the signature.

Successful verification produces only a redaction-safe receipt and a typed
consumption binding. It does not consume the grant or execute the stage yet;
durable single-use claims and per-stage execution receipts remain the next
runner boundary.

## Durable single-use stage claims

Verified mutation grants can now be consumed through the same atomic ledger
namespace as the original CreateCluster grant. The ledger writes an immutable
claim before any future stage write and binds the authorization, staged plan,
stage, operation, authority and Contract revision. Concurrent claim attempts
produce exactly one winner. The claim also persists the canonical predecessor
set digest, so a stage cannot be resumed against different prior evidence.

If the process disappears after that claim, inspection returns
`CLAIMED_INDETERMINATE_STOP`; it never makes the stage available again. A
separate immutable outcome record binds the evidence digest and mutation state,
and exact completion replay is idempotent while conflicting completion fails
closed. A successful mutating stage must report `ATTEMPTED`.

This checkpoint still invokes no stage implementation. It provides the durable
crash boundary needed before separately bounded HCP, target-access,
TokenRequest, registration and Application submitters can be composed.

## Immutable stage receipt chain

Every one of the twelve stages now produces the same canonical
`ok147-stage-receipt/v1` evidence shape. A receipt binds the staged-plan and
Contract identities, exact stage metadata, completion state, evidence digest
and the receipt digest of each direct predecessor:

```text
verified successful predecessor receipt(s)
                  |
                  v
       current canonical stage receipt
                  |
                  v
      independently retained receipt digest
```

Mutating stages additionally bind whether mutation was attempted and the exact
operation-outcome digest. Read-only stages must declare
`mutationState: NOT_APPLICABLE` and cannot carry an operation outcome. Only a
`SUCCEEDED` receipt may open a dependent stage. Failed, stopped, foreign-plan,
wrong-order or wrong-stage receipts fail closed.

Loading a receipt during resume requires both its canonical bytes and an
independently supplied expected digest; otherwise a semantically valid rewrite
could silently acquire a new identity. A per-stage signed authorization must
likewise match verified successful receipts rather than caller-asserted
predecessor values. The receipt is immutable evidence, not authority: it does
not consume a grant, execute a stage, retry work or authorize a Kubernetes
write.

## Durable immutable stage-receipt slots

The receipt chain can now survive process or Job replacement through the same
create-only ledger boundary used for authorization claims. Each verified plan
and stage maps to exactly one deterministic receipt slot:

```text
SHA-256(canonical planDigest + stageId slot identity)
                         |
                         v
       immutable ok147-receipt-<key> ConfigMap
```

The local ledger uses a private `stage-receipts` directory with exclusive
`0600` files. The Kubernetes store uses exact-name `GET` and collection
`POST` only; admission binds the shortened object-name prefix to the distinct
`stage-receipt` label. Both stores treat an exact create replay as idempotent
and reject different content for an occupied plan/stage slot. This prevents a
failed or stopped result from being replaced later by a fabricated success.

Resume still requires the expected receipt digest from an independent binding
and the complete verified direct-predecessor set. Merely finding a ConfigMap is
not sufficient. This checkpoint only persists evidence: it does not execute a
stage, consume a grant, select a retry, contact a cluster during construction,
or activate the CLI/Job path.

## Durable mutating-stage outcome finalization

A completed mutating-stage ledger outcome can now be transformed into the
common stage receipt without re-running the operation. Finalization rechecks
the verified grant against the same staged plan, requires the ledger claim and
outcome to be complete, and requires the supplied predecessor-receipt set to
have the exact digest signed into that grant. It then binds the immutable
ledger outcome digest as `operationOutcomeDigest` and persists the resulting
stage receipt in its deterministic slot.

This split is intentionally crash-safe:

```text
claim -> one bounded mutation -> durable outcome
                                  |
                    process may disappear here
                                  |
                                  v
                   idempotent receipt finalization
```

An outcome cannot be finalized against a different predecessor chain, and a
claimed stage without a durable outcome remains indeterminate. Finalization is
evidence bookkeeping only; it cannot invoke a stage implementation, create an
authorization, retry a mutation or turn a failed/stopped receipt into success.

## Fail-closed stage resume cursor

The runner can now evaluate an explicit, gap-free prefix of verified receipts
and select exactly one result: the next stage, completed plan, or permanently
stopped plan. Every prefix item is reverified from its canonical bytes and
independently retained digest against the same plan and direct predecessor.
Receipt completion times must also be monotonic across the chain.

```text
no receipts                 -> NEXT provider-prerequisites
successful prefix           -> NEXT exact following stage
all twelve successful       -> COMPLETED
FAILED or STOPPED receipt   -> STOPPED, no next stage
gap / reorder / foreign R   -> verification error
```

For a `NEXT` result the cursor exposes only the exact stage identity,
authority, operation, authorization requirement and direct predecessor receipt
set. It contains no dispatcher, implementation registry, credential, endpoint
or retry policy. Therefore it can guide a later local or Job runner without
becoming a second desired-state source or allowing a terminal plan to resume.

The same cursor is now available through a generic, local-only inspection
entrypoint:

```text
ok cluster stage resume
  + exact plan identity
  + explicit canonical receipt prefix
      -> NEXT | COMPLETED | STOPPED
```

Unlike the earlier submission-specific `stage inspect`, this command does not
require a grant or projection and can therefore select read-only stages such
as `lifecycle-observation`. It verifies every receipt and its direct
predecessor again before returning a decision. It has no credential, endpoint,
ledger, stage implementation, write or cluster-contact input. An explicit
empty prefix selects only the first stage; changed, missing, reordered or
foreign receipts fail closed.

This is the resume decision boundary, not observation execution. A later
typed stage adapter must still prove its own authoritative evidence and append
one canonical receipt. The command cannot turn `NEXT` into authorization or
execute the selected stage.

## Crash-safe lifecycle-observation stage

The first read-only stage can now be executed through a typed operation rather
than a generic dispatcher. Its constructor accepts only a verified cursor that
selects `lifecycle-observation`, and derives the durable target identity from
the successful `cluster-lifecycle` predecessor receipt:

```text
cluster-lifecycle receipt
  targetClusterUidDigest
            |
            v
exact CAPI Cluster GET on ok-mgmt
  SHA-256(observed metadata.uid) == retained digest?
            |
      no -> fail closed
      yes
            v
bind runtime policy to observed raw UID
            |
bounded InfrastructureReady + ControlPlaneAvailable polling
            |
immutable lifecycle-observation receipt
```

The raw Cluster UID exists only inside the runtime policy and normalized
source evidence; redaction-safe stage output carries only evidence and receipt
digests. A Cluster recreated under the same namespace, name and intent
revision therefore cannot be mistaken for the originally submitted target.
The observer has one exact GET path and no discovery, list, watch, mutation,
authorization or retry of operational errors. Only verified `Unknown`
readiness is polled until the bounded deadline; `True` succeeds, `False` fails
and deadline expiry stops the stage.

Before contacting its observer, the operation inspects the ledger's
deterministic immutable stage-receipt slot. If a fully verified receipt already
exists for the same plan and predecessor chain, it returns that receipt and
does not observe again. This closes the process-termination window after
receipt persistence but before caller acknowledgement without turning a
read-only stage into a controller loop.

This remains library-only composition. No CLI or Job activates the observer,
and this checkpoint performs no Kubernetes request or infrastructure change.

The next composition boundary retains the reverified plan and cursor in a
private lifecycle-observation bundle. It rejects any prefix that selects a
different stage or whose lifecycle predecessor lacks the durable target UID
digest. Opening the bundle reads the ledger and management-observer credential
files exactly once, requires distinct token values and binds the observer's
namespace, name and authority to the plan rather than caller input. Opening
constructs TLS clients but performs no Kubernetes request.

The resulting value exposes only one bounded `Run` method. Callers cannot
replace its plan, cursor, predecessor, source implementation or credential
after verification. An unverified zero value cannot expose a decision, open
credentials or run. This provides the environment-neutral boundary needed by
a local CLI or short-lived Job.

The local CLI now activates exactly this one read-only source-observation
stage:

```text
ok cluster stage observe lifecycle --execute
  + exact plan identities
  + explicit canonical receipt prefix
  + distinct bounded ledger and management-observer credentials
  + poll interval and maximum duration
      -> exact CAPI GET polling
      -> immutable lifecycle-observation receipt
```

It accepts no grant, projection, renderer, authority map or implementation
selector. `--execute` is still mandatory because the command contacts the
management API and persists evidence in the ledger. The context is bounded to
the caller's poll timeout plus one minute of fixed completion overhead. Invalid
timing or incomplete runtime input fails before credential opening; terminal
`FAILED` and `STOPPED` receipts are still emitted while the process returns an
error. The execution command does not implicitly package, launch or deploy an
observation Job, and its tests make no Kubernetes request.

## Lifecycle-observation Job package

The same command is now represented by a separate offline Job envelope. Its
input ConfigMap contains exactly four public files: the staged plan, canonical
receipt-prefix manifest, provider receipt and lifecycle receipt. It contains no
grant, trusted key, projection, authority map, credential or rendered resource.

```text
ok cluster stage observe lifecycle package
      -> immutable public input ConfigMap
      -> single-endpoint egress NetworkPolicy
      -> backoffLimit: 0 lifecycle-observation Job
```

The Job mounts distinct externally materialized ledger-writer and read-only
management-observer Secrets. Both capabilities are bound to the same exact
management API IP and port, but token object names must differ. The Pod has no
automounted ServiceAccount token, runs non-root with a read-only filesystem,
drops all capabilities and cannot schedule on a control-plane node. Its active
deadline is derived deterministically from the verified polling timeout plus
one minute of receipt-completion overhead.

The packager reverifies the complete plan/receipt chain before and after source
capture, binds the template and each emitted component by SHA-256, writes only
a new `0600` local file and reports `authorizationState: NOT_REQUIRED` with
`mutationAllowed: false`. Packaging is not installation or execution. No Job,
ConfigMap, NetworkPolicy or credential Secret is created by this checkpoint,
and all tests remain offline.

## Lifecycle-observation launch boundary

The lifecycle-observation package has a separate sealed launch path. Its
preparation command rebuilds and correlates the verified package with exactly
two distinct immutable credential Secrets, the shared tokenless runtime
ServiceAccount and one expiry-bound management installer candidate:

```text
ok cluster stage observe lifecycle launch prepare
      -> redacted package/material receipt
      -> redacted candidate receipt
      -> mutationAllowed: false
```

Both Job credentials must be short-lived TokenRequest-derived JWTs for the
management authority, but they remain separate capabilities: one writes the
durable ledger and the other performs only the bounded CAPI observation. Their
token values and object names must differ. Candidate validity ends 15 minutes
before either Job credential expires. Preparation reads bounded local sources
and performs no Kubernetes request.

Live installation is exposed only through the matching execute command:

```text
ok cluster stage observe lifecycle launch execute
  + every exact preparation input
  + --execute
  + --expected-candidate-digest sha256:...
  + --installer-token-file PATH
  + --installer-ca-file PATH
```

The command rebuilds the same private material, requires the recomputed
candidate to equal the separately supplied digest and only then opens the
installer credential. A five-minute outer deadline bounds the complete
operation. Before the first write, the launcher performs an exact global
preflight for the ServiceAccount, both Secrets, ConfigMap, NetworkPolicy and
Job. It accepts only all absent, the exact runtime ServiceAccount alone, or all
six objects already present and exact. Mixed or uncertain state stops
zero-write.

For an absent set, creation order is fixed:

```text
ServiceAccount -> ledger Secret -> observer Secret
               -> ConfigMap -> NetworkPolicy -> Job
```

A complete exact duplicate returns `ALREADY_LAUNCHED` without mutation. A
failed or ambiguous create stops with a redaction-safe
`STOPPED_PARTIAL_OR_UNKNOWN` receipt and never retries or cleans up. The
launcher exposes no update, patch, apply, delete, list, watch, discovery,
adoption, retry or rollback path. This makes live invocation a narrow critical
boundary while keeping package construction and candidate preparation
non-authorizing.

## Cursor-to-grant binding

Selecting a next stage is not claim authority. Before a later runner may claim
a mutating ledger slot, the verified single-use grant can now be rebound to the
cursor's exact plan digest, stage identity and digest, operation, authority,
Contract revision and verified direct-predecessor receipt digest. A read-only
stage can never accept such a grant, and a grant verified for another stage or
another predecessor outcome fails closed.

The ledger still owns the final claim-time validity-window and single-use
checks. This checkpoint adds no stage implementation, dispatcher, mutation,
credential handling, cluster contact or CLI/Job activation.

## One bounded mutating-stage operation

The offline runner core can now compose the cursor and grant boundaries into
one typed mutating-stage operation:

```text
verified cursor + exact verified grant + preconstructed typed mutator
        -> immutable single-use claim
        -> at most one mutator call
        -> immutable outcome
        -> immutable common stage receipt
```

The mutator is prebound to the exact plan, stage, operation, authority and
Contract revision. It receives only verified identities; implementation input
and credentials remain inside that preconstructed capability. It cannot choose
another operation dynamically. A completed ledger outcome is finalized without
calling the mutator again, while a claim without an outcome remains
`CLAIMED_INDETERMINATE_STOP` and cannot be retried.

Non-success results are persisted and close the receipt chain fail-closed. Raw
mutator errors never enter the redaction-safe orchestration result. This core is
tested with fake mutators only: no concrete Kubernetes stage implementation,
credential resolver, dispatcher, cluster contact or CLI/Job activation exists
at this checkpoint.

## Externally rendered Enablement projection

The next submission stage begins with a separate offline verifier for exactly
one `addons.cluster.x-k8s.io/v1alpha1` `HelmChartProxy`. The object remains an
output of an authoritative external profile/renderer; the runner does not
construct Helm values, choose a chart or translate Contract intent.

The verifier binds the raw artifact digest from `stage.enablement`, the exact
management authority and object identity, R, E, the execution fixture, the OCI
manifest digest, chart-content digest and values digest. It also requires
explicit Contract name/namespace carriers, an OCI repository, a fixed chart
version, `Continuous` reconciliation and the bounded atomic/wait Helm options.
YAML aliases, multiple objects, status, runtime metadata, mutable chart
versions and non-OCI sources fail closed.

The resulting `ok147-bounded-enablement-plan/v1` contains one exact canonical
create candidate for the management plane and reports
`mutationAllowed: false`. It does not submit the object, install CAAPH, contact
Kubernetes or write a `HelmReleaseProxy`; the latter remains exclusively owned
by CAAPH. Cursor/grant composition and live exact-create execution are later
boundaries.

That projection can now be composed with the verified three-receipt prefix,
the `enablement` resume cursor and one signed `CreateEnablement` grant. The
bundle requires `stage.enablement` to bind exactly the raw renderer artifact;
neither a caller nor the operation can replace the HCP after verification.

Opening the bundle binds the management exact-create client and durable ledger
with two distinct credentials but performs no API request. The resulting typed
mutator can submit only the one HCP already retained by the bundle. It rejects
a foreign R, E, fixture, authority, stage input, object kind or mutation
request. A partial or ambiguous API result produces redacted stopped evidence;
an exact no-write result cannot claim stage success. Grant claim and completion
remain crash-safe in the existing staged ledger.

This checkpoint is library composition exercised with in-memory submission
transports. It adds no CLI command, Job envelope, credential materialization,
live Kubernetes contact, retry, rollback or cleanup.

The complete public preclaim chain can also be snapshotted into one immutable
`ok147-enablement-stage-input/v1` ConfigMap. It contains only the staged plan,
canonical three-receipt prefix, three receipt files, signed grant, public key
and exact HCP artifact. It deliberately excludes tokens, CA bundles,
kubeconfigs and the unrelated Contract-to-CAPI projection artifacts.

Materialization verifies the bundle both before and after every bounded source
read, rejects symlinks and non-text input, and emits only artifact and ConfigMap
digests. It remains an offline input package: no NetworkPolicy, Job, credential
Secret or live launch exists at this checkpoint.

The local binary can now activate the same typed boundary directly:

```text
ok cluster stage run enablement --execute
  + exact plan and three-receipt prefix
  + signed CreateEnablement grant and public key
  + exact HCP artifact and independently expected name
  + distinct short-lived ledger and management-writer credentials
      -> durable single-use claim
      -> at most one exact HCP create
      -> immutable outcome and stage receipt
```

The command has a fixed ten-minute outer deadline. It derives the namespace,
R, E, fixture and management authority from independently supplied plan
expectations; the caller can choose neither another API kind nor a
`HelmReleaseProxy`. Missing `--execute`, incomplete receipt or credential
inputs, a malformed evaluation time or positional input fail before bundle
execution. This CLI does not package or launch a Job and adds no retry,
rollback or cleanup.

The separate `ok147-enablement-stage-package/v1` composer can materialize the
same boundary as a deterministic three-object stream:

```text
immutable eight-key ConfigMap
        -> single-endpoint deny-all NetworkPolicy
        -> backoffLimit: 0 Enablement Job
```

The Job is tokenless and non-root, mounts the public input and the ledger and
management-writer credentials from three distinct objects, and has a fixed
660-second deadline around the command's ten-minute context. Both credentials
must address the same exact management API IP and port; the NetworkPolicy has
only that one egress rule. The Job submits the bound `HelmChartProxy` and never
renders Helm or writes a `HelmReleaseProxy`. Package construction remains
offline: no Secret, ServiceAccount, ConfigMap, NetworkPolicy or Job is created.
`ok cluster stage run enablement package` exposes that composer as a local
fail-closed command. It reads a digest-bound Job template, writes one new 0600
package file without overwrite, and emits only the redaction-safe package
receipt on stdout. It has no `--execute` flag and accepts no credential
contents.

## Typed Contract-to-CAPI submission stages

The existing bounded exact-create submission primitive now has a typed adapter
for the first two mutating stages only: `provider-prerequisites` selects the
verified infrastructure plane and `cluster-lifecycle` selects the verified
management plane. Construction binds one copied plane to its exact staged-plan
identity and authority; the runtime request cannot switch plane or operation.
Enablement and later writes are deliberately rejected by this adapter.

A complete, validated submission receipt becomes redaction-safe stage evidence.
A partial submission becomes durable `STOPPED` evidence, and an all-unchanged
pass cannot claim first-run stage success because it attempted no mutation.
Malformed or foreign receipts stop indeterminately rather than manufacturing a
stage outcome. Tests use a fake plane submitter: Kubernetes credentials and the
live client are not yet composed into the staged runner path.

The successful `cluster-lifecycle` stage additionally hashes the exact CAPI
Cluster UID returned by the create response. That digest is carried through
the immutable operation outcome and common stage receipt, so it survives
executor termination and ledger recreation. The raw Kubernetes UID is not
retained in redaction-safe output. A later lifecycle observer must hash the UID
from its exact GET and match this durable value before it can correlate current
Conditions. Successful lifecycle submission without that runtime identity, or
a target-identity digest on any other stage, fails closed.

## Runtime composition for one submission stage

The runner package can now construct one staged submission operation from an
explicit ledger credential, one explicit write-authority credential, the
verified staged plan and the already verified projection plan. The selected
stage determines exactly one expected authority: infrastructure for provider
prerequisites or management for Cluster lifecycle. Ledger and writer tokens
must be distinct even when both APIs are served by `ok-mgmt`.

Construction reads bounded token and CA files and creates redirect-denying TLS
clients, but makes no API request. The returned `execution.StagedOperation` is
environment-neutral: the same value can be invoked by a later local CLI path or
ephemeral Job path. Invocation, artifact loading, cursor/grant loading and CLI
activation remain outside this checkpoint.

## Bounded stage-authorization loading

A signed per-stage grant and its trusted Ed25519 public key can now be loaded
through one shared file boundary before verification. Both inputs must be
non-empty regular non-symlink files within separate size limits; source paths
are neither retained nor disclosed by loader errors. The resulting grant is
identical to in-memory `VerifyStage` output and remains bound to the exact plan,
cursor stage, predecessor receipts and evaluation time.

This loader reads and verifies only. It does not consume the grant, construct a
writer, inspect the ledger, contact Kubernetes or activate a CLI command.

## Verified staged submission bundle

The first two Contract-to-CAPI stages can now be assembled from one complete
preclaim artifact chain shared by a future local CLI and ephemeral Job:

```text
verified staged plan + explicit canonical receipt prefix
        -> verified NEXT cursor
        -> exact projection artifact digest bound to the selected stage input
        -> exact signed single-stage grant
        -> one verified submission-stage bundle
```

An explicit empty receipt list is required for the first stage. A successful
provider receipt advances the same loader to `cluster-lifecycle`; omitted,
reordered, foreign or changed receipts fail closed. The selected plan input
must carry the verified raw digest of `ok-infra-prerequisites.yaml` or
`ok-mgmt-lifecycle.yaml`, so a valid plan and a valid projection cannot be
combined when they describe different submission content.

Opening the bundle reads independently supplied ledger and one-authority
credentials, requires the two token contents to differ, and preconstructs the
same typed operation for every environment. Opening performs no API request;
only an explicit later `Run` can inspect or claim the ledger and invoke the
single bound mutator. No CLI command, Job entry point, retry or live cluster
access is introduced by this checkpoint.

## Inspect-only staged CLI

`ok cluster stage inspect` is the first production entry point for the shared
bundle loader. Callers must provide every expected R/E/P/fixture and authority
identity, the bounded plan, an explicitly ordered zero-or-more receipt prefix,
the projection manifest, the signed stage grant and one explicit RFC3339
evaluation time. Receipt arguments bind a source file to an independently
supplied canonical digest; malformed or positional input fails before loading.

The command emits only the redaction-safe verified cursor decision plus
`AuthorizationState=VERIFIED` and `MutationAllowed=false`. It does not accept
ledger or Kubernetes credentials and cannot open or run the bound operation.
Consequently it provides an executable local preclaim inspection path without
introducing submission, claim, mutation, retry, discovery or cluster contact.
The future Job can use the same bundle loader rather than a second artifact
interpretation path.

The receipt prefix can additionally be supplied as one independently
digest-bound `ok147-stage-receipt-prefix/v1` document. It contains an explicit
ordered array, including an explicit empty array for the first stage, and only
plain sibling file names plus canonical receipt digests. The loader rejects
symlinked, oversized, traversing, duplicate, unknown-field or implicitly empty
prefix documents. Every referenced receipt is still reloaded and verified by
the normal stage-receipt chain; the manifest cannot turn a file name into
evidence. Direct repeated `--receipt` flags and a prefix document are mutually
exclusive. This fixed single-file argument is the input shape required by a
later non-shell Job template.

## Explicit local staged execution

`ok cluster stage run` composes the same verified bundle with exactly one
ledger credential and one selected write-authority credential. The command
requires the additional literal `--execute` gate; merely supplying credentials
or a valid grant cannot activate it. The selected cursor stage derives either
the independently expected infrastructure or management identity, and the
runtime still rejects equal ledger and writer token contents.

Execution uses the real claim-time clock and one fixed ten-minute cancellable
context. SIGINT and SIGTERM cancel that context. The command emits the
redaction-safe staged-operation receipt even for a durable non-success result,
but never retries, chooses a different stage, or exposes a generic Kubernetes
operation. Only `provider-prerequisites` and `cluster-lifecycle` are supported;
all later stages remain unavailable through this path.

This checkpoint tests CLI composition with an injected operation and the
concrete artifact/runtime path with local TLS material only. It does not run
the command against a cluster, create credentials, install the CLI, activate a
Job, or change live infrastructure.

## Bounded submission-stage Job envelope

The separate `contract-executor-stage-job.yaml.tpl` now materializes the same
`ok cluster stage run --execute` path for either `provider-prerequisites` or
`cluster-lifecycle`. The expected stage is independently bound in the Job and
rechecked against the verified cursor before credentials can be opened. The
cluster-lifecycle variant adds exactly one code-owned provider-receipt mount;
callers cannot inject an arbitrary YAML or argument fragment.

Every input ConfigMap key is mounted as an individual read-only `subPath` file.
This deliberately presents regular files to the bounded loaders instead of the
symlink layout of a whole projected ConfigMap volume. The ConfigMap item set is
allowlisted; unrelated keys are not mounted. Ledger and write credentials use
two distinct Secret names and four separate token/CA `subPath` mounts, with no
automounted Pod token. Equal token contents are still rejected when the runtime
opens. Supplying and expiring those short-lived Secrets remains an external
prerequisite, not authority granted by the Job template.

The non-retrying, single-completion Job runs as non-root with a read-only root
filesystem, dropped capabilities, explicit resources and an eleven-minute Pod
deadline around the runner's ten-minute context. Its deny-all NetworkPolicy has
exactly two egress entries: the literal ledger API IP/port and the literal
selected-authority API IP/port. DNS names, implicit ports and broad CIDRs fail
materialization. Provider submission requires an authority endpoint distinct
from the management ledger, while Cluster lifecycle requires the same
management endpoint with a distinct credential Secret. The image remains
SHA-256-bound.

This is an offline rendering checkpoint. It creates neither the immutable
input ConfigMap nor credential Secrets, ServiceAccount/RBAC, Job or
NetworkPolicy, and it made no Kubernetes request.

## Immutable submission-stage inputs

`BuildSubmissionStageInput` now materializes the Job's immutable input
ConfigMap from exactly one fully verified submission-stage bundle. The
materializer first verifies the staged plan, explicit receipt prefix, cursor,
projection, stage grant and public signing key. It then copies only the fixed
public input set expected by the Job and repeats full bundle verification after
capturing the source files. A provider stage contains an explicit empty receipt
prefix; a cluster-lifecycle stage contains exactly the verified provider
receipt under the code-owned `provider-receipt.json` identity.

The resulting ConfigMap is fixed to `openkubes-execution-system`, must use an
`ok147-` DNS-label name and has `immutable: true`. Every source must be a
bounded regular non-symlink UTF-8 file without NUL bytes, and the complete JSON
object must remain below the fail-closed 900 KiB limit. The materialization
receipt binds the ConfigMap digest, receipt-prefix digest, selected stage and
sorted data-key inventory without exposing source paths or content.

Tokens, CA files, kubeconfigs, private signing keys and Secret material have no
input slot and cannot be packaged by this API. Credential Secrets,
ServiceAccount/RBAC, ConfigMap creation, Job creation and any Kubernetes
request remain external prerequisites. The Job independently reverifies all
mounted artifacts before it opens credentials, so source races or changed
inputs stop execution rather than authorizing them.

## Coherent submission-stage package

`BuildSubmissionStagePackage` now composes the immutable input ConfigMap with
the bounded Job and NetworkPolicy as one deterministic three-object stream.
Its fixed create order is ConfigMap, NetworkPolicy, then Job, so the executable
Pod is always the final object and cannot intentionally precede its egress
boundary.
The caller supplies only runtime object names, a digest-pinned image, a
separately SHA-256-bound Job template and exact API endpoint/CIDR identities.
Stage ID, Contract identities, evaluation time, input ConfigMap identity and
receipt-prefix digest are derived from the same verified bundle and
materialization receipt, so they cannot drift across the two artifacts.

The package receipt independently binds the complete stream, ConfigMap and
Job/NetworkPolicy envelope digests plus the exact object-kind inventory. It is
explicitly non-mutating (`mutationAllowed: false`): package construction does
not read credential content, contact Kubernetes, create the externally named
credential Secrets or apply any of its objects. Reusing a credential Secret
name as the input ConfigMap identity is rejected in addition to the Job's
existing distinct-credential and endpoint boundaries.

`ok cluster stage package` exposes this composition as an offline CLI. It
accepts no credential file and has no execute flag. The command reads the
bounded regular non-symlink template, refuses to overwrite its requested local
output, writes the package with mode `0600`, and emits only the redaction-safe
package receipt on stdout. The Job-template digest is required explicitly and
is retained in that receipt.

## Exact-create installation plan

`PlanSubmissionStageInstallation` converts only an in-memory verified package
into a redaction-safe, non-mutating create plan. It rechecks the package and
component digests, exact three-object membership, namespace, names, immutable
ConfigMap, NetworkPolicy selector, tokenless ServiceAccount reference and
ConfigMap volume binding. The output fixes this sequence:

```text
1. exact GET ConfigMap       → collection POST only when absent
2. exact GET NetworkPolicy   → collection POST only when absent
3. exact GET Job             → collection POST only when absent
```

Every entry records the exact object and collection paths plus a canonical
object digest. The plan has `mutationAllowed: false`; it contains no Secret,
credential, generic path, update, patch, apply, delete, retry or API client.
The bounded installer consumes only that in-memory verified package. It first
performs all three exact object GETs; any existing object or unexpected API
result stops before the first write. Only after the complete absence preflight
does it POST ConfigMap, NetworkPolicy and Job in that order. Created responses
must contain every exact desired field plus a UID and resourceVersion. Its
redaction-safe receipt retains digests of those runtime identities and the
verified created prefix, never their raw values.

The installer is single-use and exposes no caller-selected manifest, object
name or API path. It has no update, patch, apply, delete, list, watch,
discovery, adoption, retry or rollback operation. A failure after a POST stops
with `STOPPED_PARTIAL_OR_UNKNOWN`; cleanup is deliberately outside this
boundary. The separately opened installer credential must identify the
package's verified management authority, use an exact IP-literal HTTPS
endpoint and carry a CA bundle matching its bound digest. It is distinct from
the ledger and selected-authority credential Secrets mounted by the future
Job. This checkpoint verifies the mutation behavior against an in-memory API
transport only; it does not authorize or perform a live installation.

## Short-lived credential Secret package

`BuildSubmissionStageCredentialPackage` creates the two credential objects
referenced by a verified stage package entirely in memory: one ledger Secret
for the management authority and one writer Secret for the stage-selected
authority. The provider stage selects the infrastructure authority; the
lifecycle stage selects management. Both Secrets are fixed to
`openkubes-execution-system`, immutable, distinct, and contain exactly
`token` and `ca.crt`. The package validates that the Job mounts those exact
names and keys before reading any credential source.

Each source must be a bounded regular non-symlink file and match independently
supplied token, CA and TokenRequest-evidence digests. The TokenRequest JWT is
checked structurally for an accepted asymmetric algorithm, encoded signature,
exact issuer, ServiceAccount subject, audience set, `iat`, `nbf` and `exp`.
The token must retain at least 15 minutes at materialization time and may have
no more than a one-hour total lifetime. The CA bundle must contain only
currently valid CA certificates. JWT signature authenticity is not established
by local parsing; it remains a claim of the separately verified TokenRequest
evidence and ultimately of API-server acceptance.

Secret bytes have no public accessor. The redaction-safe receipt binds the
source stage package, exact immutable Secret object digests, CA identities,
TokenRequest evidence, authorities, audiences and expirations without
retaining tokens, CAs, subjects or source paths. Building this package is
non-mutating. Secret installation, TokenRequest issuance and live execution
remain separate boundaries.

The matching `KubernetesSubmissionStageCredentialInstaller` consumes only
that private verified package. Before contacting Kubernetes it rechecks the
credential-package digest, management installation authority, exact Secret
semantics and at least 15 minutes of remaining token lifetime. Its own bounded
management writer credential must be different from both Job credentials.
It then performs both exact Secret absence GETs before the first write and, if
both are absent, creates the ledger Secret followed by the selected-authority
Secret. The GETs request `PartialObjectMetadata`; lack of server support stops
zero-write instead of falling back to a full Secret response. Existing state
is never adopted or returned.

The installer is single-use and has no caller-selected Secret, path or body.
It exposes no update, patch, apply, delete, list, watch, discovery, retry,
rollback or cleanup operation. A redaction-safe receipt contains only the
verified created prefix and digested runtime identities. This implementation
is exercised only through an in-memory API transport in this checkpoint; it
does not issue TokenRequests or authorize a live Secret installation.

## Tokenless submission runtime identity

[`deploy/contract-executor-stage-runtime.yaml`](../deploy/contract-executor-stage-runtime.yaml)
defines the sole in-cluster identity referenced by the bounded submission Job:
`ServiceAccount/ok147-contract-executor-runtime` in the existing execution
namespace. It has `automountServiceAccountToken: false` and deliberately has no
Role, RoleBinding, ClusterRole or ClusterRoleBinding.

The Job therefore receives no implicit local API credential or Kubernetes
permission from its Pod identity. Its ledger and selected-authority access can
only come from the two separately named, externally materialized short-lived
Secret mounts already bound by the Job envelope.

`BuildSubmissionStageRuntimePrerequisite` binds this exact one-object manifest
and its canonical ServiceAccount representation to a verified stage package.
The matching single-use installer performs one exact GET and creates the
ServiceAccount only when absent. Existing state is accepted only when its
token setting, exact two labels and absence of annotations, image-pull Secrets
or other runtime semantics match the prerequisite. Server-generated identity
and managed-fields metadata are allowed and retained only as digests in the
receipt. There is no update, patch, apply, delete, list, watch, discovery or
retry operation.

This prerequisite installer is tested only against an in-memory API transport
in this checkpoint. Creating the ServiceAccount, credential Secrets or stage
package remains a separately authorized live operation.

## Coherent six-object launch plan

`PlanSubmissionStageLaunch` correlates the verified runtime prerequisite,
private credential package and three-object stage package before any of their
installers can be composed into a live launch. It requires one exact stage ID,
stage-package digest and management installation authority across all three
inputs. The returned plan is redaction-safe and contains no object bodies,
token, CA or Secret content.

The plan places all six object checks behind one global barrier:

```text
GET ServiceAccount (verify exact or absent)
GET ledger Secret (verify exact or absent)
GET authority Secret (verify exact or absent)
GET ConfigMap (verify exact or absent)
GET NetworkPolicy (verify exact or absent)
GET Job (verify exact or absent)
        |
        +-- all exact --> ALREADY_LAUNCHED, zero writes
        +-- any mixed, changed or uncertain state --> STOP, zero writes
        v
fixed create sequence:
ServiceAccount -> ledger Secret -> authority Secret
               -> ConfigMap -> NetworkPolicy -> Job
```

This is a non-mutating plan (`mutationAllowed: false`), not an executor. It
does not contact Kubernetes, open a credential, invoke a child installer or
authorize a launch. The global barrier and fixed order are executable contract
evidence for the next composition boundary; tests still use only in-memory
objects and transports.

`KubernetesSubmissionStageLauncher` implements that next composition boundary
as one single-use operation. It opens one separately supplied short-lived
management installer credential, rechecks that this credential is distinct
from both Job credentials, and rejects launch when either Job credential has
less than 15 minutes remaining. All six exact GETs then run before the first
POST. Full Secret bodies are required only to compare them with the already
held private package; they never enter a receipt or error. No object lookup
falls back to list, watch or discovery.

Exactly three global outcomes are accepted: all six objects absent; only the
exact tokenless ServiceAccount present; or all six objects present and exact.
The last outcome returns `ALREADY_LAUNCHED` with six redaction-safe
`EXISTING_VERIFIED` results and performs no POST. Every mixed state, including
an exact partial prefix, stops zero-write. For an absent set, the launcher
creates the ServiceAccount, both immutable Secrets and the ConfigMap,
NetworkPolicy and Job in fixed order. Every create response must contain the
exact desired fields and bounded runtime identity. Failure stops without retry,
rollback or cleanup and retains only a redaction-safe verified prefix;
transport-ambiguous results remain explicitly unknown.

The launcher has no update, patch, apply, delete, list, watch, discovery,
adoption or retry API. This checkpoint exercises it only with an in-memory
Kubernetes transport. Opening live credentials or invoking it against a
cluster remains a separate, critical execution decision.

That decision is now represented by a separate
`ok147-submission-stage-launch-candidate/v1`. Candidate preparation binds the
launch-plan digest, all three package identities, the hashed exact API
destination, CA digest, installer TokenRequest-evidence digest and a private
installer-token identity. The receipt exposes only a double-bound credential
identity, never the endpoint, token digest, token path or token. Its validity
ends 15 minutes before the earliest Job credential expires.

The public launcher opener requires the exact candidate digest, recomputes the
launch plan, verifies the destination and CA, and reads the installer token
only after all public candidate checks pass. The opened token must match the
candidate's retained private identity. An expired candidate stops locally
before any API request. Preparing this candidate remains non-mutating and is
not itself permission to launch; it provides the exact digest to which a later
critical execution approval can be bound.

`BuildSubmissionStageLaunchMaterial` closes the remaining local composition
gap. One call now rebuilds and verifies the stage package, reads the two
bounded Job credential sources into the private immutable Secret package,
binds the tokenless runtime manifest, and prepares the exact launch candidate.
The returned `ok147-submission-stage-launch-material/v1` receipt contains only
the correlated digests, stage, authority and validity limit.

The verified material keeps all four private components in memory and exposes
no bytes accessor. Its `Open` method requires the caller to repeat the exact
candidate digest and supplies the retained candidate to the public launcher;
the caller cannot substitute a package or candidate after composition. Local
composition still performs no Kubernetes request. The installer credential is
opened only by `Open`, and mutation remains possible only after a separate call
to the single-use launch operation.

The local CLI exposes only this preparation boundary:

```text
ok cluster stage launch prepare
  + verified stage-bundle flags
  + package/template identities
  + two bounded Job credential-source identities
  + tokenless runtime manifest identity
  + installer endpoint, CA, token and TokenRequest-evidence digests
  + exact materialization/preparation times
```

It emits `ok147-submission-stage-launch-preparation/v1`, containing the
redaction-safe material and candidate receipts. Credential files, endpoint,
token digest, manifest bodies and local source paths are not emitted. Every
input is explicit; audiences use an exact comma-separated set and bounded
template/runtime files must be regular non-symlink files.

There is deliberately no execute flag on this command. `--execute` is rejected
as an unknown option, no installer token file is opened, and no Kubernetes
client is constructed. A future execution command must rebuild the same
material, require the exact emitted candidate digest and retain a separate
critical live-authorization boundary.

That separate boundary is exposed as:

```text
ok cluster stage launch execute
  + every exact preparation input
  + --execute
  + --expected-candidate-digest sha256:...
  + --installer-token-file PATH
  + --installer-ca-file PATH
```

The command rejects missing or malformed candidate identity before rebuilding
the launch material. It then rebuilds the complete private material, requires
the recomputed candidate to equal the separately supplied digest, and only
after that opens the bounded installer credential. Execution has a five-minute
outer deadline and delegates to the single-use launcher: all six exact GET
preflights complete before the first create, followed by at most six fixed-order
create requests. A complete exact duplicate instead returns
`ALREADY_LAUNCHED` with zero writes. There is no update, patch, apply, delete,
list, watch, retry or rollback path.

The command emits the redaction-safe launch receipt whenever the launcher
returns one, including `STOPPED_ZERO_WRITE` or
`STOPPED_PARTIAL_OR_UNKNOWN`. A stopped receipt is evidence of the observed
boundary, never permission for an automatic retry.

## Typed first-run Platform capability boundary

First-run capability production now has a separate lazy resolver from the
resume file loader. Resolution binds only the post-submission target Cluster
UID, R, P, execution fixture, capability contract digest and executable
digest. It performs no probe. The resulting source is single-use and invokes
the typed probe only when the Platform collector has already opened its
capability gate.

The probe request deliberately contains no command, argv, environment, file
path, endpoint, credential, raw payload or arbitrary extension field. A probe
returns only `Passed`; the runner supplies the observation time, constructs
the complete capability assertion and computes its semantic evidence digest.
Probe errors are redacted and consume the source, so neither caller code nor a
transient failure can create an implicit retry. This boundary does not yet
implement the concrete Kubernetes observability capability test, polling or
target mutation.

## Fixed observability capability orchestration

The typed first-run probe now has a closed orchestration layer for the five
Observability Capability Contract guarantees. It accepts exactly these
semantic operations: prepare the synthetic metrics fixture; verify metrics,
dashboards, logs, alert delivery and autonomy; and clean up only the owned
synthetic resources. There is no generic request, manifest, command, exec,
HTTP, Kubernetes or extension method on this boundary.

Each run receives a deterministic `ok147-...` identity derived from the exact
runtime-bound probe request. The configured namespace, contract digest and
executable digest must match before any transport method is called. The checks
run once in fixed order under one bounded timeout and stop at the first false
guarantee or operational error. Synthetic cleanup is attempted after every
prepare attempt, including partial preparation, false capability and cancelled
execution, under its own bounded timeout. Cleanup failure fails the probe
closed and transport details are never returned.

This is still an offline semantic checkpoint. The concrete Kubernetes
transport, fixed synthetic objects, bounded service access and credential
materialization remain separate follow-ups. In particular, the existing Bash
contract test is not embedded or executed by the runner.

## Deterministic observability synthetic fixture

The first concrete Kubernetes-facing input is now generated internally from
the bound capability run. It contains exactly four namespaced objects in fixed
order: a Pushgateway Deployment, its Service, a ServiceMonitor and a one-shot
log-emitter Pod. Callers cannot supply raw manifests, API versions, kinds,
names, labels, commands or REST paths. The only external content inputs are the
two container images, and both must be complete OCI references pinned by a
SHA-256 digest.

Every object carries R, P, execution-fixture, capability-contract and
capability-executable annotations plus the deterministic run label. Object
JSON, object digests, exact collection/object paths and membership are folded
into a separate synthetic-fixture digest. The Pod executes only
`/bin/echo <derived-marker>`; neither fixture contains a shell or service
account token. Pod/container security contexts, resource bounds and the
Prometheus release selector are fixed by the implementation.

This checkpoint still performs no Kubernetes request. Exact absence/create,
UID/resourceVersion observation, service-proxy checks and guarded cleanup will
consume this generated fixture in later transport checkpoints.

## Exact synthetic fixture create and cleanup client

The generated fixture now feeds a dedicated workload-cluster client frozen to
one runtime Cluster UID. The client accepts no manifests, names or paths at
execution time. Before its first mutation it performs exact object GETs for
the complete four-object fixture; any existing object or uncertain response
stops with zero writes. Only after all four are absent does it issue the four
fixed collection POSTs in fixture order. A redacted receipt preserves the
exact successfully created prefix if a later create fails.

Synthetic cleanup accepts only a receipt for the same fixture digest and
created prefix. It processes that prefix in reverse order, re-reads each exact
object, verifies the original UID and complete desired subset, and uses the
current resourceVersion plus UID as Kubernetes DeleteOptions preconditions.
Deletion is Foreground and any first error stops without retry. Redirects are
denied, responses are bounded JSON, credentials are never included in errors,
and no list, watch, discovery, apply, update, patch or force-delete path exists.

The implementation has so far been exercised only against an in-memory HTTP
transport. Opening credentials and invoking it against a live workload cluster
remain later integration steps.

## Workload-bound observability transport

The fixture client is now composed with the fixed five-check interface behind
one workload-bound transport. Its opener reads the bounded token and CA files,
verifies the actual CA digest against the runtime authority binding and rejects
any authority identity other than the submitted CAPI Cluster UID. Opening the
transport performs no API request.

Preparation retains its complete private create receipt, including a known
partial prefix. Each capability check receives an isolated clone of the same
fixture and can run only in the contract-defined order. Direct out-of-order
calls fail before reaching the check adapter. Cleanup cannot accept caller
identities: it uses only the internally retained receipt. A known created
prefix is cleaned through the guarded client, zero-write preflight failure is a
no-op, and an unknown POST outcome fails closed instead of guessing which
object to delete.

The concrete service checks are still injected typed implementations in this
checkpoint; no live Kubernetes request or capability mutation was performed.

## Bounded convergence observation polling

The aggregate observer can now be wrapped by a bounded polling observer before
it is supplied to `execution.Operation`. This closes the immediate-observation
gap: CAPI, Network and Platform sources may remain `Unknown` while their
existing owners converge after submission without causing the executor to
pretend the run is complete.

Only `Ready=Unknown` permits another read-oriented observation. `Ready=True`
and `Ready=False` return immediately. An operational source error, invalid or
unverified result, cancellation or wait failure also stops immediately and is
never retried. Interval and total duration have hard constructor bounds; the
final delay is shortened to the exact deadline. If the deadline is reached
while state remains Unknown, the latest verified fail-closed result is returned
so the execution outcome remains STOPPED rather than fabricated success.

This wrapper never repeats submission or another mutation. Because the
Platform collector's separately hashed Application gate invokes capability
code only after Argo is current, ordinary pre-convergence polling also does not
consume the single-use first-run capability source.

## Staged authority observation gates

Each polling pass now opens source authorities in dependency order rather than
materializing every runtime credential up front:

```text
CAPI lifecycle current
        ↓
resolve workload authority and evaluate NetworkReady
        ↓
resolve GitOps capability and evaluate PlatformReady
```

If a required CAPI condition is `False`, `Unknown`, missing, stale, foreign or
conflicting, the workload resolver and Platform source remain unopened. If
NetworkReady is not `True`, the Platform resolver remains unopened. The partial
authoritative bundle is still evaluated normally, so `False` remains terminal
and unresolved downstream conditions remain `Unknown`; no success is inferred.
Malformed source evidence remains an operational error.

This staging is required for a real first create: the workload authority cannot
exist before CAPI has produced the target, and capability execution must not
start before NetworkReady. The gate adds no retry, credential creation,
mutation, repair or persistent state.

## Bounded Kubernetes execution composition

The runtime package now composes the durable ledger, the two exact-create
authorities, the runtime-bound aggregate observer and bounded polling into the
single `execution.Operation` boundary. Construction reads bounded credential
files for the ledger and submission authorities but performs no Kubernetes
request. Observer credentials remain lazy. Infrastructure and management must
have different endpoints, identities and actual bearer-token values; the
management observer must use exactly the same authority binding as management
submission, and the GitOps observer must name its authority explicitly.

The same injected clock drives source evidence, polling and durable execution
completion. The resulting operation still has no renderer, policy decision,
retry, rollback, status writer or controller loop. This is library wiring only:
the dry-run CLI and Job do not activate it, and this checkpoint made no cluster
contact or mutation.

## OK-141 compatibility evidence

The verifier was run offline against the preserved Phase-R v5 projection. It
accepted all six bound artifacts and produced:

```text
R:                         sha256:166504ae61fd558d391daedde50986cbc7a28f5f4e9d57f4acbd0433b448aa0f
projectionManifestDigest:  sha256:37b65b7ff1f7f46e5809000d8a469f423943c6b7f4f043a7bc6123d033ee765b
authorityMapDigest:        sha256:c872b0378dfb58b845adc709aad864f07fa416f529698e050cebe80c407e927a
requestDigest:             sha256:0c64e26a3697c7f19c25783c8c26b044413a07a5dc0c3e131a8647c1bba9db26
ok-infra resources:        3
ok-mgmt resources:         8
```

This is compatibility evidence for the preserved OK-141 fixture, not a new
authorization and not permission to recreate the disposable cluster.
