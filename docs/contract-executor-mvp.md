# OK-147 bounded Contract Executor MVP

The implementation establishes a shared, side-effect-free core for local CLI
and future in-cluster Job execution. The second checkpoint adds verified
projection and authorization boundaries without adding Kubernetes access.

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

The command is intentionally dry-run-only:

```bash
go run ./cmd/ok cluster create \
  --contract internal/contract/testdata/ok141-contract-v5.yaml \
  --schema internal/contract/testdata/ok141-contract-v3.schema.json \
  --dry-run
```

It performs no cluster discovery, credential read, API contact, submission, or
observation. A command without `--dry-run` fails closed. Submission will be
added only after the authorization, projection, idempotency, and evidence
interfaces have executable tests.

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
