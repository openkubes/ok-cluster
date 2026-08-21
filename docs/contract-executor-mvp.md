# OK-147 bounded Contract Executor MVP

The implementation started with a shared, side-effect-free core for local CLI
and in-cluster Job execution. The current boundary retains non-mutating
Contract planning and now models the complete twelve-stage bounded execution
path, including separately authorized mutations, a durable ledger, bounded
observation and evaluation components and offline Kubernetes workload
packaging. The stages are now composed into a typed in-process Stage 1-7 prefix,
a Stage 8-12 suffix and a receipt-bound, single-use full-run execution seam. The
Stage 1-7 prefix and Stage 8-12 suffix both have concrete single-use execution
adapters; only the post-runtime suffix currently has a bounded ephemeral Job
activation path.
That Job path is fully exercised offline and against fake APIs, but has not yet
been run on the DEV management plane. The full-run library is not yet exposed
as one local or Job-based CreateCluster activation. A strict private full-run
manifest now verifies the complete fresh-run input boundary offline, but does
not yet open that execution. It is still an MVP rather than a general lifecycle
runner or controller.

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

## Explicit terminal-receipt retry boundary

Lifecycle and Network observation plus runtime binding now expose one
deliberate retry boundary. A caller must supply the exact digest of an
immutable `FAILED` observation receipt or `FAILED`/`STOPPED` binding receipt.
The runner reloads and reverifies that receipt against the same Plan and direct
predecessor chain before invoking the bounded operation again. A missing,
successful, foreign or malformed receipt stops before source access.

The original deterministic receipt is never replaced. A different result is
stored in its digest-addressed attempt slot, so both failure and recovery remain
auditable. The CLI routes this boundary only through explicit
`--retry-after-failed-receipt-digest` or
`--retry-after-terminal-receipt-digest` flags. It never chooses a latest
attempt, infers retry authority from elapsed time or retries a mutating stage.

For process handoff, `ok cluster stage receipt materialize --execute` can load
one independently digest-bound successful receipt from the durable ledger and
write its canonical bytes create-only to an absent private path. The command
does not run a stage or convert a terminal receipt into success.

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

`ok147-enablement-stage-credential-package/v1` adds the private credential
boundary without contacting Kubernetes. It accepts two independently obtained,
digest-bound and short-lived TokenRequest results for the ledger and management
writer. Both must prove the verified `ok-mgmt` authority, use different Secret
names and different token bytes, carry exact issuer/subject/audience/time
claims, retain at least fifteen minutes, and expire within one hour. The two
immutable Secret objects remain private inside the verified package; its public
receipt contains only authority, expiry, CA/evidence/object digests and object
names. Changing the previously verified Enablement package identity fails
closed. No credential or Job is installed by this checkpoint.

`ok147-enablement-stage-runtime-prerequisite/v1` independently binds the exact
shared `ok147-contract-executor-runtime` ServiceAccount manifest to the same
Enablement package. The accepted manifest contains one tokenless ServiceAccount
only: no Role, binding, Secret or implicit Pod credential. Its canonical object
digest, source-manifest digest, `ok-mgmt` authority and package digest are
retained in a redaction-safe receipt. This step is also entirely offline.

`ok147-enablement-stage-installation-plan/v1` parses the sealed three-object
package again and derives the exact create order `ConfigMap -> NetworkPolicy ->
Job`. Every item carries an exact-name GET preflight path, collection-only POST
path and canonical object digest. The planner verifies immutable input,
NetworkPolicy/Job run identity, tokenless ServiceAccount, `ok-mgmt` authority
and the two exact credential Secret names. It deliberately excludes the Secret
objects themselves and grants no mutation authority.

`ok147-enablement-stage-launch-plan/v1` then correlates the verified package,
private credential package and tokenless runtime prerequisite into six exact
objects: runtime ServiceAccount, input ConfigMap, NetworkPolicy, ledger Secret,
writer Secret and finally the Job. Every GET must establish the single global
state `ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT` before any POST may start. The
runtime alone may already exist if it matches exactly; every other object is
create-only after global absence. The redaction-safe plan contains no object
body or credential content and still grants no mutation authority.

`ok147-enablement-stage-launch-candidate/v1` binds that plan to one normalized
IP-literal HTTPS management endpoint, exact CA digest and independently
evidenced installer-token identity. Its validity ends fifteen minutes before
the earliest Job credential expires; a preparation time before credential
materialization or after that boundary fails closed. The public receipt exposes
only digests and times, not the endpoint or installer token, and remains
non-mutating.

`ok147-enablement-stage-launch-material/v1` rebuilds and seals the package,
private credentials, tokenless runtime and expiry-bound candidate as one
coherent private value. Its public receipt contains only the correlated
package, credential, runtime, launch-plan and candidate digests plus validity.
Post-verification changes to any retained component fail closed. At this
checkpoint the material exposes no private bytes. Its `Open` boundary requires
the exact candidate digest and reuses only retained verified components;
opening validates the bounded local installer credential without API contact.
The offline CLI boundary is:

```text
ok cluster stage run enablement launch prepare
```

It requires the complete package, private two-credential, tokenless-runtime
and installer-candidate inputs and emits only the material and candidate
receipts. The separately gated execution boundary is:

```text
ok cluster stage run enablement launch execute --execute
```

It rebuilds the same material and additionally requires the exact prepared
candidate digest and bounded installer token/CA files. Missing `--execute`, a
foreign digest or incomplete installer input stops before opening a launcher.

`ok147-enablement-stage-launch-receipt/v1` is produced by a single-use bounded
launcher that completes all six exact-name GETs before its first POST. It
accepts only global absence, the already verified runtime alone, or all six
objects matching exactly; every other partial state stops with zero writes.
Creation is fixed to runtime, ConfigMap, NetworkPolicy, ledger Secret, writer
Secret and Job. A failed create preserves the verified prefix and stops without
retry. The launcher is currently exercised only through a fake Kubernetes API
in tests; no live Enablement launch is performed by the repository suite.

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

## Receipt-correlated network-observation stage

The `network-observation` stage now has a narrow typed adapter around the
existing NetworkReady source and evaluator. It does not introduce another
network evaluator or an OpenKubes reconciliation loop. The adapter verifies
the full four-receipt prefix through `enablement` and correlates the private
workload Cluster UID to the digest retained by `cluster-lifecycle`:

```text
verified receipt prefix
  cluster-lifecycle.targetClusterUidDigest
                    |
 SHA-256(private workload Cluster UID)
                    |
              exact equality
                    v
 existing bounded NetworkReady source + immutable E profile
                    v
 deterministic one-condition evaluation and bounded Unknown polling
                    v
 SUCCEEDED | FAILED | STOPPED stage result
```

This deliberately reaches past the direct `enablement` predecessor for
identity correlation without weakening the direct receipt chain. A same-name
replacement, missing historical UID digest, foreign profile, reordered prefix
or prefix selecting another stage fails before observation. Only verified
`Unknown` evidence is polled; terminal `True` and `False` return immediately,
and operational source details are redacted.

This checkpoint is the stage observer only. It adds no Kubernetes bundle, CLI,
Job, credential opening, cluster request or infrastructure mutation. Those
activation boundaries remain separate reviewable steps.

The subsequent private bundle now supplies that environment-neutral
composition boundary. It retains the complete reverified prefix, loads the
strict workload-authority binding and immutable Network profile, and proves
that the binding's raw Cluster UID hashes to the historical lifecycle digest.
It then opens three distinct bounded capabilities: ledger writer, management
network reader and workload network reader/probe. Management and workload
endpoints must differ, all three bearer-token values must remain separate, and
the HCP identity is derived from the Contract identity rather than caller
input. Opening reads bounded local files and constructs TLS clients but makes
no API request; only the resulting private `Run` method can invoke the existing
crash-safe observation-stage operation.

The local CLI can now activate exactly this bundle:

```text
ok cluster stage observe network --execute
  + exact plan identity and four-receipt prefix
  + distinct ledger, management and workload credentials
  + digest-bound private workload binding and Network profile
  + bounded poll interval and timeout
      -> existing NetworkReady source and evaluator
      -> immutable network-observation receipt
```

It accepts no grant, renderer, arbitrary target UID, HCP name, command or
mutation input. `--execute` is mandatory because the command performs bounded
reads and persists the stage receipt. The outer context is limited to the poll
timeout plus one minute of completion overhead, and terminal `FAILED` or
`STOPPED` receipts remain visible even though the command returns an error.
This checkpoint adds no Job, credential issuance, infrastructure mutation,
repair or controller loop; command tests inject the execution boundary and
make no Kubernetes request.

The first packaging boundary now emits one immutable public input ConfigMap.
It contains exactly the staged plan, the four canonical receipts, their
digest-bound prefix manifest and the immutable Network profile. It is built
only after the bundle and profile have been verified both before and after
file capture. The private workload-authority binding, API endpoint, token and
CA are intentionally absent and remain inputs to a later Secret/runtime
boundary. This step creates no Kubernetes object and performs no API request.

The matching offline Job template now binds the remaining runtime geometry.
It mounts the public ConfigMap plus three different external Secrets for the
ledger, management reader and workload reader. Only the workload Secret may
carry the private binding alongside its token and CA. Its NetworkPolicy permits
exactly two single-address API destinations: the shared management/ledger API
and the distinct workload API. The tokenless runtime ServiceAccount,
`backoffLimit: 0`, `restartPolicy: Never`, fixed resource bounds, non-root
security context and digest-pinned image prevent an implicit retry or broad
ambient authority. Rendering is strict literal substitution and performs no
cluster request or object creation.

The complete offline package now combines that envelope with the immutable
public ConfigMap. Before rendering, it reads the private workload binding only
long enough to prove its digest, R, target-UID correlation and exact workload
API endpoint. Binding bytes are not copied into the package or receipt. The
redaction-safe package receipt retains only the binding digest plus the public
input, prefix, profile, template, envelope and complete package digests. This
is package coherence, not credential materialization or launch authority.

The package is now exposed through an offline CLI boundary:

```text
ok cluster stage observe network package
  + exact plan and four-receipt prefix
  + immutable Network profile and private workload-binding digests
  + reviewed Job-template digest and two exact API destinations
  + three distinct external credential Secret names
      -> new 0600 ConfigMap/NetworkPolicy/Job package
      -> redaction-safe package receipt
```

The command accepts no `--execute`, credential bytes or grant, refuses an
existing output path and validates all semantic digests and polling bounds
before invoking the packager. Its tests inject package construction, so no
private runtime file or Kubernetes API is read.

The package now also produces a tokenless offline installation plan for its
three public objects. It re-decodes the sealed package, verifies component and
per-object digests, enforces ConfigMap → NetworkPolicy → Job order, checks the
shared run identity, tokenless runtime ServiceAccount, management-authority
argument and exact three-Secret volume geometry (including `binding.json`
only on the workload credential). The plan exposes only GET/POST paths and
object digests and grants no mutation or credential access.

The next offline boundary materializes three pairwise-distinct, immutable
credential Secrets from independently bound short-lived TokenRequest results:
one ledger writer and one management reader from the management authority,
plus one workload reader from the digest-bound workload authority. Only the
workload Secret contains the canonical private workload binding alongside its
token and CA. Its CA, R, endpoint and target-UID digest must still equal the
verified observation package. The public receipt exposes only expiry,
audiences, authority/digest identities and exact Secret-object digests; it
contains no token, CA, endpoint, raw target UID, subject or source path. This
primitive performs no TokenRequest, Secret installation or Kubernetes call.

The tokenless runtime prerequisite and seven-object launch plan now close the
offline launch geometry. One global preflight barrier covers the reusable
runtime ServiceAccount, immutable input, NetworkPolicy, all three private
Secrets and finally the Job. Only the runtime may already exist if its exact
digest matches; every stage-specific object must be globally all absent or all
exact before a later launcher may create anything. The Job is always last.
The launch plan carries only package, credential and runtime digests plus exact
GET/POST metadata and remains `MutationAllowed=false`.

A time-bounded launch candidate now seals that plan to one IP-literal HTTPS
management endpoint, one CA digest and one independently evidenced installer
credential identity. Its validity ends fifteen minutes before the earliest of
the three stage credentials expires. Endpoint and installer-token values stay
private; the public candidate exposes only their digests and remains
`MutationAllowed=false`. Candidate preparation reads no credential and makes
no API request.

The complete launch material now reconstructs and re-verifies the package,
three private credentials, tokenless runtime and time-bounded candidate from
their independently bound local sources. The resulting value retains all
private bytes internally but exposes only a redaction-safe receipt and the
candidate receipt. Any changed package, credential, runtime, candidate or
cross-component digest invalidates the material. Construction remains offline
and grants no launch authority.

Before HTTP execution, a private installation-material boundary re-decodes the
three public YAML objects and all three Secret objects and proves that their
canonical bodies still match the launch-plan digests. It additionally enforces
that only the workload credential contains `binding.json` and rechecks that
binding's semantic digest, target-UID digest and CA identity. Callers receive
defensive copies only. No API is contacted and no installer credential is
opened at this boundary.

The bounded launcher now consumes only that sealed material. It is single-use,
checks candidate lifetime and all three credential lifetimes locally, then
performs all seven exact GET preflights before any mutation. It accepts only
global absence, the exact reusable runtime alone, or an exact complete prior
launch. A fresh launch uses create-only POSTs in the planned order and holds
the Job until the runtime, public prerequisites and all three Secrets have
been verified as created. Any response or partial-state ambiguity stops with
no retry, rollback or cleanup path, and public results retain only UID and
resourceVersion digests.

The same boundary is now exposed through two explicit CLI commands. Preparation
reconstructs every private component, emits only redaction-safe material and
candidate receipts and performs no Kubernetes request:

```text
ok cluster stage observe network launch prepare
      -> verified seven-object material receipt
      -> expiry-bound candidate receipt
      -> mutationAllowed: false
```

Execution accepts the complete identical input set and additionally requires
`--execute`, the separately copied candidate digest and bounded installer token
and CA files:

```text
ok cluster stage observe network launch execute
  + --execute
  + --expected-candidate-digest sha256:...
  + --installer-token-file PATH
  + --installer-ca-file PATH
```

The command rebuilds the material before opening the installer authority and
applies a five-minute outer deadline. Missing execution intent, a changed or
malformed candidate, incomplete credential sources or missing installer files
stop before the launcher is invoked. A stopped live launch still emits its
redaction-safe receipt so partial or uncertain state remains visible without
creating an implicit retry path.

## Crash-safe runtime-binding operation

The stage immediately after successful NetworkReady observation now has a
dedicated non-mutating execution primitive. `BindingStageOperation` accepts
only a verified cursor selecting `runtime-binding` with runner authority and a
preconstructed binder whose plan, stage, authority and R identities match that
decision exactly:

```text
successful network-observation receipt
                 |
                 v
       exact runtime-binding cursor
                 |
                 v
     one prebound local binder call
                 |
                 v
 immutable runtime-binding stage receipt
```

The binder's future private artifact, credentials and source reads remain
encapsulated behind its single `Bind` method. Public orchestration retains only
the result state, evidence digest, completion time and final receipt digest.
Raw operational errors are never returned. A failed or stopped result is
persisted as terminal evidence and cannot be replaced by success.

Before invoking the binder, the operation inspects the deterministic receipt
slot. A verified existing receipt is returned without rebinding, closing the
process-termination window after receipt persistence. Observation, submission,
credential and evaluation cursors are rejected before the binder is called.
This checkpoint supplies only the execution composition: it does not yet read
the workload-kubeconfig Secret, contact a cluster, create the private runtime
binding file, activate a CLI/Job path or grant target access.

The first concrete runtime-binding materializer now defines what that binder
must retain. It accepts only the exact successful five-receipt prefix, the
previously verified private workload-authority binding, the matching CA file
and explicit results of the two bounded workload reads:

```text
cluster-lifecycle target UID digest
        + NetworkReady receipt
        + workload authority binding
        + matching workload API CA
        + kube-system UID
        + local-path StorageClass UID/provisioner
                         |
                         v
        canonical private runtime-binding material
                         +
        redaction-safe public material receipt
```

The private material binds the exact CAPI Cluster UID, target identity scheme,
workload API endpoint, CA payload and digest, `kube-system` UID, `local-path`
StorageClass UID and provisioner, R/E/P/Fixture and the lifecycle/network
evidence digests. The public receipt replaces the endpoint, CA payload and raw
UIDs with digests. A same-name replacement target, changed CA, incomplete
prefix, missing namespace identity or unexpected provisioner fails closed.

Materialization is deterministic and returns defensive copies. It performs no
Kubernetes request and no file write.

The bounded workload source and private writer now implement those two side
effects independently. The source proves that endpoint, target Cluster UID and
CA digest still match the verified workload-authority binding before it opens
one short-lived token. It then permits exactly these ordered requests:

```text
GET /api/v1/namespaces/kube-system
GET /apis/storage.k8s.io/v1/storageclasses/local-path
```

There is no arbitrary path, list, watch, discovery or mutation. Responses are
size bounded, duplicate-key rejecting and reduced to the Namespace UID plus
StorageClass UID and exact `rancher.io/local-path` provisioner. Redirects,
non-JSON responses, replacement identities and any request error stop without
retry and expose no endpoint, token or raw response in the returned error.

The writer accepts only verified private material and one absent absolute path
inside an existing private, non-symlink directory. It creates exactly one
`0600` file with `O_EXCL`, syncs, closes and digest-verifies the stored bytes.
There is no overwrite, rename, retry, cleanup or delete path. A write-side
failure remains `STOPPED_PARTIAL_OR_UNKNOWN`; the public persistence receipt
contains only the material digest, size and mode and explicitly denies
Kubernetes mutation.

The verified stage bundle now composes that source, materializer and writer
with `BindingStageOperation`. Opening the bundle re-verifies the five-receipt
prefix, lifecycle target, private workload binding, distinct management-ledger
and workload credentials, distinct API endpoints and safe output path without
contacting either API. Running it performs the two workload GETs, creates and
verifies the private file, then stores one immutable runner-owned stage receipt
in the ledger. A source or persistence failure becomes a redaction-safe,
terminal `STOPPED` receipt; a restart returns an existing receipt without
re-reading or rewriting the workload binding.

The first product activation is deliberately local and explicit:

```text
ok cluster stage bind runtime --execute ...
```

The command requires the exact five-receipt prefix, immutable plan identities,
separate short-lived ledger and workload credentials, the digest-bound private
workload-authority binding and one clean absolute output path. It has a fixed
two-minute context and accepts no grant, projection, arbitrary API path, retry,
overwrite or cleanup option. Output combines the immutable stage receipt with
the redaction-safe binding evidence; endpoint, CA payload, tokens, local paths
and raw runtime UIDs stay private.

Ephemeral Job packaging and launch remain separate checkpoints. Target access
is still unreachable: this command only captures the exact private authority
material that a later target-access stage must consume.

### Immutable Kubernetes runtime-binding store

The first Job-suitable persistence candidate stores the same verified private
runtime-binding material in one exact immutable `Secret` on `ok-mgmt`. This
avoids both an `emptyDir`, which would lose the binding when the Job is
recreated, and a new PVC/storage lifecycle owned by the runner.

The store is bound before execution to the verified management authority,
namespace `openkubes-execution-system` and one DNS-safe name prefixed with
`ok147-runtime-binding-`. It permits only this sequence:

```text
POST exact Secret collection
        |
        +-- 201 -> verify exact immutable object and server identity
        |
        `-- 409 -> one exact GET-by-name
                    `-- accept only byte-equivalent existing object
```

The Secret is `immutable: true`, contains exactly one data key and carries
only the fixed runner labels plus content and plan digests. A conflicting
object, uncertain response or altered metadata stops fail-closed. The client
has no update, patch, delete, list, watch, discovery, redirect or retry path,
and its public receipt contains only digests and categorical state—not the
Secret identity, endpoint, token, CA, runtime UIDs or private material.

This checkpoint is deliberately only a typed store capability. It is tested
against a local fake TLS API and is not yet composed with the runtime-binding
stage, packaged in a Job or invoked against a live cluster. The existing local
exclusive-file path remains unchanged. A later composition checkpoint must
select exactly one persistence implementation and bind a separately scoped
management credential; adding this store does not create an OpenKubes
reconciler or grant lifecycle mutation authority.

The following composition checkpoint now provides that exact selection in the
runner library. The existing `Open` method remains file-only; a distinct
`OpenKubernetes` method selects only the immutable Secret path. Its Secret name
is derived from the verified plan digest rather than accepted from a caller.
The Secret store must use the same exact management API and namespace as the
ledger, while ledger writer, persistence writer and workload observer tokens
must all differ. Opening reads those bounded credentials but performs no API
request.

The Kubernetes-persisted stage emits evidence format
`ok147-runtime-binding-stage-evidence/v2`. It truthfully records that the exact
persistence mutation was allowed while separately denying lifecycle mutation;
the local file path retains the historical v1 evidence semantics. After a
successful or byte-equivalent Secret result, the same crash-safe stage
operation stores the immutable ledger receipt. A later process can therefore
verify an equivalent pre-existing Secret if it stopped between those two
writes, without gaining an update or generic retry path.

The CLI now exposes the composition through an explicit, mutually exclusive
mode:

```text
ok cluster stage bind runtime --execute
  --persistence-mode local-file
  --output /private/absolute/path

ok cluster stage bind runtime --execute
  --persistence-mode immutable-secret
  --persistence-token-file /bounded/persistence/token
  --persistence-ca-file /bounded/persistence/ca.crt
```

`local-file` remains the compatibility default and rejects Kubernetes
persistence credentials. `immutable-secret` rejects `--output`, reuses the
exact ledger API destination, derives the management authority from the
verified plan and emits outer execution format v2. Both modes retain the fixed
two-minute context and explicit `--execute` requirement.

The activation has been tested only through injected local execution paths and
fake TLS APIs. It has not been invoked against a live Kubernetes API, and no
Job package selects it yet.

The first offline Job-packaging component now materializes one immutable
`ok147-runtime-binding-stage-input/v1` ConfigMap. Its data is closed to the
verified staged plan, an ordered five-receipt prefix manifest and the exact
provider, lifecycle, lifecycle-observation, enablement and network-observation
receipts. The ConfigMap is rebuilt against the verified bundle after reading
all files, so a changed input fails before package output is accepted.

The input deliberately has no slot for the private workload-authority binding,
endpoint, CA, credential, runtime UID or resulting runtime-binding material.
Those values must arrive only through separately scoped Secret mounts in the
future Job envelope. This checkpoint does not yet render that Job or its
NetworkPolicy and performs no Kubernetes request.

The matching offline envelope now renders exactly one `NetworkPolicy` and one
non-retrying `Job`. The tokenless Pod mounts the immutable input ConfigMap plus
three distinct externally materialized Secrets: ledger writer, runtime-binding
Secret writer and workload observer. The workload Secret alone also carries
the previously verified private workload-authority binding. No implicit
ServiceAccount token is mounted.

The NetworkPolicy permits egress only to the exact management API address used
by both ledger and persistence, and to the distinct exact workload API
address. The Job invokes only `bind runtime --execute --persistence-mode
immutable-secret`, has a three-minute hard deadline, fixed resources, a
read-only root filesystem and no retry. It accepts neither a local output path
nor grant, projection, renderer or generic Kubernetes input.

This remains template rendering tested offline. The ConfigMap, NetworkPolicy,
Job, runtime identity and credential Secrets are not yet assembled as one
verified package, installed or launched, and no Kubernetes API was contacted.

The public input and envelope are now also composed as one verified
`ok147-runtime-binding-stage-package/v1`. Before emitting bytes, the builder
reopens the private workload-authority binding and proves that its R, raw CAPI
Cluster UID digest and API endpoint match the durable lifecycle receipt and
the Job's exact workload destination. The private binding itself is never
copied into package output.

The package receipt binds the ConfigMap, receipt prefix, private binding
identity, template, rendered envelope and final three-object byte stream. It
remains `mutationAllowed: false`: package construction neither creates its
objects nor authorizes a launcher. Runtime identity, credential packaging,
installation planning and launch remain later checkpoints.

The shared tokenless runtime ServiceAccount is now bound offline to this exact
package as `ok147-runtime-binding-stage-runtime-prerequisite/v1`. The verifier
accepts only the existing `openkubes-execution-system/ok147-contract-executor-runtime`
ServiceAccount shape: automount disabled, fixed labels, no annotations, image
pull Secrets, owner references or embedded RBAC. The receipt binds both the
source manifest and normalized object digest to the runtime-binding package.

This prerequisite remains non-mutating. It neither creates the ServiceAccount
nor issues or mounts a token.

The three private runtime-binding credentials are now composed offline as one
verified `ok147-runtime-binding-stage-credential-package/v1`. The package
requires independently issued, short-lived and pairwise-distinct credentials
for the management-side ledger writer, the management-side immutable Secret
writer and the workload-side observer. Each token and CA must match its bound
TokenRequest evidence and authority; the workload CA and raw CAPI Cluster UID
must additionally match the private workload-authority binding already bound
by the stage package.

Only the workload observer Secret carries `binding.json`. The public receipt
contains roles, authority identities, expiry, audiences and digests, but never
tokens, CA bytes, subjects, API endpoints or source paths. The exact immutable
Secret bytes remain private for a later installer boundary. Construction is
still non-mutating: it neither requests a token nor contacts Kubernetes.

The public side of that boundary now also has a verified
`ok147-runtime-binding-stage-installation-plan/v1`. It reparses the package,
rechecks the ConfigMap and Job-envelope digests, verifies the tokenless runtime
identity, exact input mount, management authority and all three credential
Secret references, then fixes the create order to ConfigMap, NetworkPolicy and
Job. The plan contains only object identities, paths and digests; it contains
neither credentials nor object bodies and grants no mutation authority.

The complete tokenless prerequisite set is now correlated by
`ok147-runtime-binding-stage-launch-plan/v1`: shared ServiceAccount, immutable
input ConfigMap, NetworkPolicy, three immutable credential Secrets and the Job.
All seven exact GET preflights belong to one global barrier. The shared runtime
may already exist only when its exact digest matches; every other object must
be either globally absent or part of a completely exact already-existing set.
No create can be considered after a mixed or foreign preflight result.

The launch plan contains only paths, identities and digests and remains
`mutationAllowed: false`.

The corresponding private material boundary now reparses the three public
objects and recovers the three retained immutable Secret bodies. It rechecks
every planned object digest, Secret label, authority annotation, expiry, CA
digest and data-key inventory. The two management-side Secrets must not carry
a workload binding; the workload Secret must carry the exact binding and CA
already correlated by the stage package. Any changed byte fails closed before
material can reach an installer.

No public API exposes these recovered bytes.

The redaction-safe `ok147-runtime-binding-stage-launch-candidate/v1` now binds
the seven-object launch plan to one normalized management API destination, CA
identity and independently evidenced installer-token identity. It never reads
the installer token. Its validity ends fifteen minutes before the first of the
three Job credentials expires, so a later launcher cannot begin without the
minimum credential lifetime still available.

The candidate contains endpoint, CA, plan, package, credential and runtime
digests plus exact preparation and expiry times, but no endpoint, token,
credential subject or object body. It remains `mutationAllowed: false`.

`ok147-runtime-binding-stage-launch-material/v1` now reconstructs the complete
private launch input from bounded local sources: stage package, three
credentials, tokenless runtime and launch candidate. It re-verifies their
shared identities and retains their private bytes internally while exposing
only package, plan, candidate and validity digests. Changed private material or
a mismatched candidate invalidates the whole aggregate.

The material has no method that performs an API request and remains
`mutationAllowed: false`.

The first private open boundary now validates one exact candidate digest,
management authority, normalized API endpoint, CA and installer-token digest.
It also rejects an installer token reused as any of the three Job credentials,
rechecks all public and private install material and fixes redirect and timeout
behavior on the retained client. Its public
`ok147-runtime-binding-stage-launch-open-receipt/v1` exposes only stage,
authority, candidate and validity identities.

Opening performs no HTTP request and still grants no mutation authority. The
opened material now exposes only one single-use `Launch` operation. It performs
all seven exact-name GETs before the first possible POST. A completely exact
existing set returns `ALREADY_LAUNCHED`; the shared exact runtime alone may
preexist; every other mixed, foreign or unexpected response stops with zero
writes.

After a globally absent preflight, the create-only order is ServiceAccount,
ConfigMap, NetworkPolicy, the three immutable Secrets and finally Job. Every
response must contain the exact submitted fields and a bounded UID and resource
version. A failure after the first POST returns
`STOPPED_PARTIAL_OR_UNKNOWN`, preserves the successful prefix and offers no
retry, update, patch, delete or cleanup path. Candidate expiry and credential
remaining lifetime are checked locally before the first API request.

This execution has been tested only against injected local fake Kubernetes
clients. No DEV cluster was contacted. The public CLI preserves the same split
boundary: `ok cluster stage bind runtime launch prepare` reconstructs the
material and emits redacted receipts without API contact, while the matching
`launch execute` command alone can open the installer credential and invoke
the launcher after receiving the exact candidate digest and explicit
`--execute`.

## Target-access verified projection

The first `target-access` boundary is again side-effect free. One externally
rendered artifact is accepted only when its digest and exact eight-object
identity list are independently supplied by the staged experiment. The plan
binds `R`, `P`, `FixtureDigest` and the immutable workload target identity to a
single workload authority plane.

The allowlist fixes this order: Namespace, manager ServiceAccount,
ClusterRole/ClusterRoleBinding, one namespaced Role/RoleBinding pair for the
Platform namespace and one Role/RoleBinding pair for `kube-system`. Every
binding must refer to the exact manager ServiceAccount and corresponding role.
Wildcard permissions, non-resource URLs, user/group subjects, runtime metadata,
status, aliases, symlinks, additional or reordered objects fail closed. The
verified output is `ok147-bounded-target-access-plan/v1` with
`mutationAllowed: false`.

This verifier does not render RBAC, consume `CreateTargetAccess` authorization,
read a credential or contact the workload API. Those remain later boundaries.

The runner now composes this projection into one verified preclaim bundle. It
requires the complete six-receipt chain through successful runtime binding,
reuses the raw-UID-free target digest carried by the lifecycle receipt, checks
that the staged plan binds exactly one `stage.target-access` artifact and
verifies an Ed25519 `CreateTargetAccess` grant against the runtime-binding
predecessor. Its redacted `ok147-target-access-stage-bundle/v1` receipt exposes
only plan, authorization, artifact, target and object digests and remains
`mutationAllowed: false`.

Bundle loading still does not claim the grant, open the durable ledger, read a
workload credential or submit any of the eight objects.

## Target-access Job launch boundary

The verified Target Access bundle can now be materialized as one immutable
ConfigMap plus a deny-all NetworkPolicy and non-retrying Job. The package binds
the exact six-receipt predecessor chain, signed `CreateTargetAccess` grant,
eight-object workload artifact, private runtime-binding digest, immutable
target identity, runner image and the distinct ledger/workload API endpoints.
The private runtime binding, CA bundles and credentials are never embedded in
the ConfigMap or exposed by its receipt.

Two independently evidenced, short-lived Job credentials are reconstructed as
immutable Secrets. The management-side ledger writer carries only token and CA
data. The workload writer additionally carries the exact private workload
binding, whose target UID digest, endpoint and CA must still match the package.
The two tokens must be distinct from each other and from the installer token.
Only redaction-safe object, authority, expiry and package digests are public.

The shared tokenless ServiceAccount, public ConfigMap and NetworkPolicy, both
private Secrets and final Job form one six-object launch plan. All six exact
GETs complete before the first POST. The exact shared runtime alone may
preexist, or the complete exact set may be returned as `ALREADY_LAUNCHED`.
Every other existing or mixed state stops with zero writes. After global
absence, the create order is ServiceAccount, ConfigMap, NetworkPolicy, ledger
Secret, workload Secret and Job. A failed create preserves the resulting
partial prefix and exposes no retry, update, patch, apply, delete or cleanup
path.

An expiry-bound candidate binds that plan to one exact `ok-shared` API
endpoint, CA and independently evidenced installer-token digest. The sealed
launch material retains all private bytes but exposes only correlated receipts.
Opening requires the separately copied candidate digest and validates the
bounded installer files without API contact. The opened launcher is
single-use.

The CLI preserves all three boundaries:

```text
ok cluster stage run target-access package
        -> new local 0600 package only

ok cluster stage run target-access launch prepare
        -> redacted material and candidate receipts only

ok cluster stage run target-access launch execute --execute
        -> exact candidate + bounded installer files + single-use launch
```

The implementation is covered by offline, fake-API and race tests. This
checkpoint did not contact a DEV cluster or launch a Target Access Job.

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

## Staged runner library closure

The reusable Go implementation now models the complete bounded create path as
twelve ordered stages. Every stage consumes an immutable input digest and the
durable receipt of its direct predecessor:

```text
 1  provider-prerequisites   Submission   ok-infra
 2  cluster-lifecycle       Submission   ok-mgmt
 3  lifecycle-observation   Observation  ok-mgmt
 4  enablement              Submission   ok-mgmt
 5  network-observation     Observation  workload
 6  runtime-binding         Binding      runner
 7  target-access           Submission   workload
 8  target-credential       Credential   workload
 9  target-registration     Submission   ok-shared
10  platform-applications   Submission   ok-shared
11  platform-observation    Observation  ok-shared
12  aggregate-evidence      Evaluation   runner
```

Mutating stages require a signed, stage-specific, predecessor-bound grant.
Observation, binding and final evaluation stages cannot carry a mutation
operation or authorization grant. Durable stage receipts distinguish
`ATTEMPTED` mutation from `NOT_APPLICABLE`, bind the exact plan and predecessor
and prevent a replacement process from repeating a completed action.

The final Stage-12 profile fixes the required condition order to
`InfrastructureReady`, `ControlPlaneAvailable`, `NetworkReady` and
`PlatformReady`. Its runtime policy adds the private CAPI Cluster UID only
after lifecycle submission. One bounded source pass reads CAPI, Network and
Platform authorities and evaluates `Ready=True|False|Unknown`; the resulting
stage outcome is respectively `SUCCEEDED`, `FAILED` or fail-closed `STOPPED`.
No normalized status is written back to Kubernetes.

Local TLS integration tests prove the final operation performs exactly one
CAPI read, one Network source pass, three exact Argo Application reads and one
capability read. Once the Stage-12 receipt is durable, replay performs no
additional authoritative-source access.

Network source correlation also normalizes CAAPH's semantic default for
`spec.options.enableClientCache`: an omitted field and an API-defaulted
`false` are equivalent. Other option differences remain revision-significant.
This prevents API defaulting from manufacturing a false E mismatch without
weakening the exact HelmChartProxy/HelmReleaseProxy identity checks.

Stage 12 also has an explicit local launch surface:

```text
ok cluster stage run aggregate-evidence launch prepare
ok cluster stage run aggregate-evidence launch execute --execute ...
```

`prepare` is local and non-mutating. It binds the verified Stage-12 package,
the durable runtime binding, four pairwise-distinct short-lived credentials and
their earliest safe expiry into one launch candidate. `execute` accepts only
the exact candidate digest, performs all ten exact-name absence checks before
the first write and then creates exactly nine fixed-order Kubernetes objects.
The durable runtime-binding Secret must already exist and is never created or
replaced by this launcher. Existing mixed state and any failed create stop
without update, patch, apply, delete, retry or rollback.

The launched Job now has the matching direct executable boundary:

```text
ok cluster stage evaluate aggregate --execute ...
```

It requires the exact eleven-receipt prefix, all three immutable source
profiles, the verified private runtime binding and the separately digest-bound
Platform capability assertion. The workload identity and endpoint come from
the runtime binding rather than an independent CLI identity. The mounted Argo
CA is re-hashed before any API contact. The command performs no submission or
status write and emits only the durable Stage-12 evaluation receipt.

## Target credential and GitOps stages

The target credential stage verifies an exact, short-lived TokenRequest policy
and keeps token material in memory only. The following target-registration
stage binds the Argo registration Secret and AppProject to the immutable CAPI
target identity and the selected project boundary. The registration launcher
uses exact-name preflights and create-only submission; unexpected existing or
partial state stops without retry.

The staged plan binds pre-runtime templates for target registration and the
three Platform Applications. Those templates must carry the literal
`RUNTIME-TARGET-IDENTITY-DIGEST-REQUIRED` placeholder; a prefilled digest is
rejected. After lifecycle submission, the loader takes the target digest only
from the verified `cluster-lifecycle` receipt, substitutes that one carrier in
memory and records the resulting concrete object digests. This avoids a
causality cycle in which the plan would otherwise have to hash the
Kubernetes-assigned CAPI Cluster UID before Stage 1. It also prevents a caller
from predicting or selecting a different runtime target identity.

Platform application submission verifies exactly three externally rendered
Applications and their immutable profile membership. Argo CD remains the sole
owner of Platform convergence. The runner neither renders an alternative
Platform graph nor invokes repair logic. Platform observation performs exact
Application reads plus the separately bounded capability assertion and emits
only normalized, revision-correlated evidence.

The memory-only target credential intentionally creates a narrow process-crash
boundary between successful credential issuance and durable registration. The
runner does not solve that boundary by persisting the bearer token. It normally
executes both steps within one bounded process lifetime. If that process stops
after the immutable successful Stage-8 receipt, the recovery path first binds a
redaction-safe recovery request to that exact receipt and the original Stage-8
authorization. An external authority must return a new signed Stage-8 grant
with a different authorization digest and GrantID. The existing durable ledger
claims that grant before one new TokenRequest and records its outcome, while
the authoritative Stage-8 receipt is neither finalized again nor overwritten.
Only a successful recovery recreates the one-use in-memory handoff for Stage 9.

The registration-side refresh primitive is narrower than a general adoption
or update path. It first requires the existing AppProject to have the exact
bound spec, labels and annotations. It then accepts only the exact bound Argo
cluster Secret: the target name, server, namespaces, project, cluster-resource
mode, CA configuration and all non-expiration annotations must match. The old
bearer token must be structurally present and different from the newly issued
one. A single `PUT` carries the observed UID and resourceVersion and changes
only the new credential configuration plus its bound expiration; the response
is reverified byte-for-byte at the data boundary. Drift stops before mutation,
and an unknown `PUT` outcome is preserved without retry. The recovery
coordinator now places a separate redaction-safe Stage-9 authorization request
and durable ledger claim around this package-private primitive. That request
binds the immutable successful Stage-9 receipt, the Stage-8 credential-recovery
request and the new credential evidence. It accepts only a fresh signed
Stage-9 grant, claims it before the first registration read and records a
durable `SUCCEEDED` or `STOPPED` outcome without finalizing or rewriting the
historical Stage-9 receipt. A consumed recovery grant cannot reach a second
`PUT`.

The in-process pre-runtime orchestrator fixes the Stage 1-7 call order:

```text
provider prerequisites -> Cluster lifecycle -> lifecycle observation
       -> Enablement -> network observation -> runtime binding
       -> target access
```

Each callback receives only the redaction-safe receipt of its direct
predecessor. The orchestrator verifies the receipt format, successful terminal
state, expected stage, Plan identity and receipt digest at every transition.
A malformed or foreign receipt, a stage error or context cancellation stops
the prefix before any later callback. It exposes no retry, rollback or cleanup
method and contains no dynamic renderer or Kubernetes writer. Concrete stage
construction, authorization and activation remain outside this composition
boundary.

The in-process post-runtime orchestrator fixes the Stage 8-12 call order
and passes the one-use credential handoff only from Stage 8 to Stage 9. It
validates every redaction-safe run receipt against one Plan digest, stops at
the first error or malformed receipt, invokes no later stage and discards an
unconsumed credential. It deliberately exposes no retry, rollback or cleanup
method. The later activation checkpoints provide its concrete CLI and Job
adapters without changing this orchestrator's ownership.

The full-run orchestrator joins those two segments without weakening the
receipt boundary:

```text
Stage 1-7 completed receipt identities
                  |
                  v
exact Plan + seven-digest continuation binding
                  |
             exact match only
                  v
concrete single-use PostRuntimeExecution (Stage 8-12)
```

The already-opened `PostRuntimeExecution` exposes the exact verified seven-
receipt prefix it will consume. The full runner compares every stage ID, state
and digest with the prefix it just completed before invoking Stage 8. A foreign
Plan, changed/missing receipt, malformed suffix or cancelled context stops
without running a later stage. The combined redaction-safe receipt contains
only the twelve ordered stage identities. A second invocation is rejected.
This is an in-process composition seam only: it adds no renderer, dynamic
writer, retry, rollback, cleanup, CLI command or Job mutation surface.

The concrete full-run execution adapter now opens Stage 1-7 first and defers
opening Stage 8-12 until all seven receipts are successful and durable. It
loads the private prefix from the completed adapter, checks every private
digest against the redaction-safe checkpoints and injects only that exact
prefix into a fresh PostRuntimeExecution. A suffix carrying historical
receipts, a prebound Stage-8 grant or either recovery mode is rejected before
the prefix opens. Stage-8 authorization is instead resolved through the same
external authority boundary after the completed seven-receipt prefix. The
existing full-run binding then independently compares the PostRuntimeExecution
continuation identity before Stage 8 can run. The adapter is single-use and
still has no manifest, CLI or Job activation surface.

The accompanying receipt bridge can reload only the independently
digest-bound, already durable public receipt selected by the current cursor.
It writes canonical receipt bytes create-only as `0600` below an existing
private directory, re-verifies the stored digest and returns the exact
`StageReceiptSource` for the next bundle. Private credentials, endpoints and
runtime identity never enter this bridge.

The concrete pre-runtime execution adapter now wires that bridge to the
existing typed Stage 1-7 bundles. It resolves authorization dynamically only
for provider prerequisites, Cluster lifecycle, Enablement and target access,
and only after the exact direct predecessor receipt is durable. Observation
and runtime-binding stages never receive a mutation grant. After every
successful stage, the adapter reloads the authoritative ledger receipt and
persists canonical bytes create-only as a private `0600` receipt source before
the next stage can open. If this bridge fails after the operation succeeded,
the successful stage checkpoint is preserved and the single-use adapter stops
without replaying that stage. Only a fully successful seven-stage execution
exposes the defensive private prefix required by the full-run seam. This adds
no renderer, policy authority, retry, rollback, cleanup, CLI command or Job
mutation surface.

The same adapter now defers its workload-authority binding until the exact
four-receipt prefix through Enablement is durable. A caller may bind only three
future private destinations while opening the execution; it cannot preselect
the workload-authority binding digest. One injected resolver must return those
exact destinations plus the lifecycle-derived binding digest before Stage 5
opens.
That one result is reused unchanged by Network observation, runtime binding,
target access and the Stage-8 credential suffix. A missing resolver result,
changed path or prebound identity stops before Network observation and exposes
no completed workload handoff. The resolver seam performs no implicit retry or
fallback and is not itself an authority materializer.

The private full-run execution manifest closes the fresh-run input contract
without inventing runtime truth. It binds one empty Stage-1 Plan cursor, the
verified Contract projection, all R/E/P profiles and renderer artifacts, one
coherent ledger and the three isolated authority planes, bounded observation
settings, private future handoff destinations and the eleven private
create-only stage-receipt destinations across the twelve-stage chain.
Loading is offline and grants no mutation.

The manifest deliberately cannot carry a selected target identity. After
Stage 2 succeeds, the concrete execution adapter reloads the exact lifecycle
receipt and injects its CAPI-UID digest into the Stage 8-12 registration and
Application expectations. Workload endpoint, CA and the client-certificate
kubeconfig are also future lifecycle-derived files, Stage-8 authorization
remains predecessor-bound, and capability evidence is produced in memory at
observation time.
Pre-existing handoff or receipt files, mismatched authorities or ledgers,
foreign profile/artifact digests, duplicate destinations and a non-empty
resume cursor stop verification. The redaction-safe manifest receipt contains
only semantic identities and execution modes.

The local manifest-to-executor activation now converts that verified document
into the existing concrete Stage 1-12 adapters. It binds the lifecycle-owned
client-certificate kubeconfig materializer to the exact three future private
destinations, opens the predecessor-bound authorization resolver and maps all
profiles, artifacts, authorities, polling limits and receipt destinations
without an API request. The process-local Platform capability factory receives
only namespace, timeout, R, P, fixture, contract and executable identities; it
receives no credential, endpoint, target UID, command or arbitrary payload.
Its lazy result executes at most once after the Application gate opens and is
then reused unchanged by aggregate evaluation. A failed capability is cached
as failure and is never retried by this seam. The direct
`OpenFullRunExecutionManifest` entry point remains inert until `Run`.

The shared full-run activation boundary now wraps that exact operation for
both a local adapter and a future ephemeral Job adapter. Opening produces one
redaction-safe `PREPARED` receipt and performs no stage action. `Run` consumes
the activation before delegating exactly once to the concrete Stage 1-12
executor, preserves a stopped orchestration receipt unchanged and exposes no
retry, rollback or cleanup method. The Platform capability factory remains an
explicit process-local dependency; this boundary does not invent a production
observability transport or widen the private execution manifest.

The first concrete local adapter exposes only the offline half of that
boundary:

```text
ok cluster stage run full prepare --manifest /private/full-run.json
```

It loads the complete private manifest, emits only the redaction-safe
activation receipt and never opens a credential or runtime dependency. There
is deliberately no `full execute` command yet: registering one before the
binary has a fixed production Observability capability adapter would create an
incomplete mutation surface.

The capability fixture transport now accepts either one bounded bearer token
or the strict client-certificate kubeconfig produced by the lifecycle handoff,
never both. The latter reuses the already verified endpoint and CA binding,
adds no synthetic bearer header and performs no request while opening. This
closes the credential-mode mismatch between the full-run lifecycle authority
and the existing fixed synthetic fixture client; the five concrete
observability checks remain the next separate adapter boundary.

The first part of that adapter boundary is now a closed, deterministic
`ok-observability-standard` check profile. It freezes the four Service names,
ports and schemes; the credential Secret and exact key names; the platform
dashboard ConfigMap and UID; the Prometheus datasource, synthetic alert and
log-index identities; and the requirement that alert *delivery* is proven
rather than treating alert firing as equivalent. Callers may select this
profile only for `ok-observability`; none of these targets or assertions is an
execution-time parameter. A canonical profile digest makes any future change
to this list explicit. This checkpoint defines identities only and still
performs no Secret read, service-proxy request or cluster mutation.

The five semantic checks now have one production evaluator over typed backend
observations. Every observation must repeat the exact run ID, target Cluster
UID, synthetic-fixture digest and check-profile digest before its result can
count. Metrics require both target discovery and the exact synthetic sample;
dashboards require reachability, the fixed provisioned dashboard and the
synthetic sample through the named datasource; logs require the exact marker;
alerts require both firing and delivery; autonomy requires all local services
ready and zero cross-cluster dependencies. A wrong identity or tampered
fixture is an error, while a correctly correlated unmet guarantee is `false`.
The evaluator never repairs an observed mechanism. The Kubernetes backend that
collects these typed observations remains the next adapter checkpoint.

The post-runtime authorization resolver closes the next authority boundary.
After a predecessor receipt is durable, it derives one canonical,
redaction-safe request from the verified cursor, including the exact Plan,
stage, operation, authority and predecessor receipt digest. An external
authority resolves that request to one signed grant source; the runner reloads
and verifies the grant before exposing it to the selected stage bundle. The
request digest changes with its predecessor, so Stage 9 and Stage 10 grants
cannot be safely precomputed from an earlier receipt prefix. The resolver does
not sign, persist or widen a grant and performs no ledger or Kubernetes
request. This keeps the future in-process adapter from becoming its own policy
authority.

The concrete HTTP resolver posts that canonical request exactly once to the
bound TLS authority endpoint, rejects redirects and unexpected media types,
and stores the signed response create-only as a private `0600` file. The
existing verifier then binds that grant independently to the current cursor
and pinned public key. A failed request, invalid response or invalid grant is
preserved as a stopped single-use attempt; the resolver exposes no automatic
retry or overwrite path. This client is not the policy authority or grant
issuer: deployment and operation of that external authority remain outside
this checkpoint. Credential and registration crash recovery use the same
bounded endpoint but distinct canonical request media types, so the authority
cannot confuse a normal stage grant with either recovery decision.

The concrete post-runtime execution adapter now composes those boundaries into
one single-use Stage 8-12 library path. It normally starts from the exact
seven-receipt cursor, reuses one verified runtime binding, resolves the fresh
Stage 8 grant only after that exact prefix is durable, executes the memory-only
credential handoff, then resolves Stage 9 and Stage 10 authorization only
after each current direct predecessor receipt is durable. The three resolved
authorization receipts are ordered with those stages. An explicit
recovery configuration may instead supply the exact successful Stage-8 receipt
and the separate recovery authority described above; after the new grant is
durably consumed, execution continues at Stage 9 using that unchanged receipt
as the authoritative predecessor. If Stage 9 had also completed before the
process stopped, a second explicit recovery configuration must provide its
exact successful receipt and an independent Stage-9 recovery authority. The
adapter then refreshes only the bound registration credential, retains both
historical Stage-8 and Stage-9 receipts unchanged, and resumes at Stage 10.
Canonical receipts produced by the normal path are persisted create-only as
private `0600` files for the next cursor. A missing grant,
consumed recovery grant, failed stage, malformed receipt, unsafe destination or
cancelled context stops the suffix without automatic retry, rollback or
cleanup. The adapter itself does not own a CLI or Job activation surface; the
activation layer composes it without widening this library boundary.

The private post-runtime execution manifest now provides the local activation
boundary for that adapter. The baseline v1 form binds the verified
Plan and seven-receipt prefix, Stage-8 grant and policy, predecessor-bound TLS
authority, runtime binding, exact registration and Application projections,
Network/Platform/Aggregate profiles, one shared capability assertion, isolated
runtime credentials and private receipt destinations. Loading derives target
identity from durable lifecycle evidence and rejects identity, profile,
artifact or capability divergence before opening the execution suffix. Its
redaction-safe receipt exposes only semantic digests and explicitly grants no
mutation. Loading remains verification-only; every activation surface must
bind that verified identity separately.

The additive v2 form activates crash recovery without changing historical
evidence. It requires the exact successful Stage-8 receipt and may additionally
bind the exact successful Stage-9 receipt. Both paths and digests are strict,
private inputs. Stage 8 selects credential recovery; Stage 8 plus Stage 9
selects registration refresh and continuation at Stage 10. A v1 manifest that
carries recovery state, a v2 manifest without Stage 8, a relative path, a
changed digest or a failed historical receipt stops before authority or
Kubernetes contact.

The local post-runtime CLI now keeps verification and mutation as two explicit
operations. `post-runtime prepare` opens and verifies the private manifest and
emits its redaction-safe semantic digest without executing any stage.
`post-runtime execute` reopens the manifest, requires that exact prepared
digest plus an explicit `--execute` flag, and runs the Stage 8-12 suffix once
inside a fixed three-hour context. A stopped execution still emits its bounded
composite receipt before the command returns the failure. Neither operation
adds automatic retry, rollback or cleanup. This closes the local activation
surface; the following checkpoints bind the same operation to an ephemeral
Kubernetes Job.

The first ephemeral post-runtime Job envelope binds that same command to one
immutable activation Secret, one canonical bundle-index digest and one
semantic manifest digest. Because Kubernetes projected Secret entries are
symlinks while the runner deliberately accepts only regular private files, a
non-networked init invocation copies exactly 34 baseline inputs, plus the one
or two recovery receipts selected by the v2 manifest, into one new `0700`
memory-backed workspace as individually hashed `0600` files. The bundle index,
Secret projection and rewritten manifest all bind the same recovery mode. The
initializer also creates the private create-only authorization and receipt
directories. The executor container can see only that workspace, not the
original Secret projection.

The Job has no automounted ServiceAccount token, no retry and a deadline around
the CLI's three-hour bound. Its deny-all NetworkPolicy permits only four exact
IP/port destinations: management/ledger, workload, Argo and the external
authorization authority. The materializer, NetworkPolicy and Job envelope are
rendered and tested offline. The following package and launcher checkpoints
construct and install the immutable activation Secret and launch the resulting
Job.

The private activation package builder now closes the first of those two
checkpoints. It reopens the complete local post-runtime manifest, requires one
coherent Ledger source and one coherent GitOps source, verifies the Workload,
GitOps and management credential/CA bindings, and rewrites every accepted path
to the fixed in-Pod workspace. The seven predecessor receipts receive fixed
names and a newly bound prefix digest; the rewritten semantic manifest
therefore receives its own digest without changing R, E, P or the execution
fixture.

The builder emits exactly one immutable opaque Secret followed by the already
verified NetworkPolicy and Job. Its 34 baseline files and any selected
historical recovery receipts are individually digest-bound by a canonical
index. The CLI writes this credential-bearing package create-only as `0600`
and emits only a redaction-safe package receipt containing component digests
and the recovery mode. Source and rewritten manifest identities are both
retained. Package construction remains offline and grants no installation or
launch authority.

The final activation boundary derives an exact credential-free installation
plan from that private package. It permits only this order:

```text
GET Secret, NetworkPolicy, Job by exact name
        ↓ all three absent
POST Secret
POST NetworkPolicy
POST Job
```

All three GETs complete before the first write. Any existing object or failed
preflight stops with zero writes. After the first POST, a failed or uncertain
result is preserved as `STOPPED_PARTIAL_OR_UNKNOWN`; the launcher is consumed
and exposes no retry, update, patch, apply, delete, rollback or cleanup path.
Created UIDs and resourceVersions are represented only by digests in its
public receipt.

The CLI keeps preparation and mutation separate:

```text
ok cluster stage run post-runtime launch prepare ...
ok cluster stage run post-runtime launch execute --execute ...
```

`prepare` rebuilds and verifies the complete private package and emits only
its redaction-safe receipt and exact installation plan. `execute` rebuilds the
same package, requires its separately copied package digest, binds the
installer to the package's `ok-mgmt` authority and checks that identity before
opening the installer credential. It then invokes the single-use three-create
launcher in a bounded context. This completes the offline and fake-API
activation implementation; it does not itself prove a live DEV Job run.

The concrete Stage 6 to Stage 8 private handoff is now closed as well. Stage 6
creates the canonical runtime material first, then the Stage 1-7 adapter reads
the material receipt directly from that exact opened binding operation,
re-verifies it against the canonical private bytes and current Plan, and writes
the receipt create-only as a distinct `0600` file. Only after both private
files exist does the adapter persist the public Stage-6 ledger receipt and
open Stage 7. The full-run composition requires the Stage 8-12 material and
receipt paths to equal those exact Stage 1-7 destinations. A missing,
pre-existing, non-canonical, changed or foreign handoff stops at Stage 6; it
cannot open target access or the post-runtime suffix. Neither private file is
part of public evidence.

## Current OK-147 implementation boundary

The twelve-stage Go library and its durable replay semantics are complete and
covered by unit, negative, local TLS integration and race tests. Stage 1-7 and
Stage 8-12 each have an exact, fail-closed in-process orchestration order and a
concrete single-use execution adapter. The Stage 1-7 adapter dynamically binds
its four mutation grants, persists the private runtime material and matching
receipt, and persists all seven ledger-backed receipts before exposing its
exact prefix. The concrete full-run execution injects that prefix into a fresh
Stage 8-12 adapter, and the full-run seam independently binds it through the
exact Plan, private runtime handoff paths and seven predecessor receipt
digests. A shared single-use activation type now provides the common inert-open
and exact-run entry for future local and Job adapters without selecting a
concrete capability transport. The Stage 8-12 suffix additionally has a local
prepare/execute command, a bounded ephemeral Job, a deterministic private
activation package, an exact installation plan and a single-use CLI launcher.
Successful Stage-8 and Stage-9 crash boundaries can be reactivated through the
same manifest, authority, package, Job and CLI chain without rewriting their
durable receipts. This is not yet the OK-147 Definition of Done:

- the legacy `ok cluster create` command remains dry-run-only;
- the joined concrete Stage 1-7 and Stage 8-12 adapters have a shared
  activation boundary and offline local preparation command, but no concrete
  local execute command or ephemeral Job adapter selects its production
  capability transport yet;
- the standalone Stage-12 launcher has not yet been executed as part of the
  complete predecessor-bound stage chain;
- the current staged-library source is published as the immutable multi-platform
  image recorded by the verified
  [publication receipt](ok147-runner-publication-receipt.json), including SLSA
  provenance, SPDX SBOMs and digest pullback;
- no ephemeral `ok-mgmt` Job has executed the complete current implementation;
- the disposable-cluster create conformance and executor-termination failure
  conformance have not yet been repeated through this MVP;
- the final [operator runbook](ok147-operator-runbook.md),
  [security boundary summary](ok147-security-boundary.md) and
  [ADR-030 amendment proposal](ok147-adr-030-amendment-proposal.md) are defined
  and remain to be reviewed with the live evidence.

The concrete lifecycle-authority materializer now reads exactly the runtime
CAPI Cluster and its CAPI-owned `<name>-kubeconfig` Secret after Stage 4. It
verifies the lifecycle UID correlation, endpoint, CA and client-certificate
kubeconfig, then writes the kubeconfig, CA and semantic binding create-only as
private `0600` files with the binding last. It has no list, watch, discovery,
Kubernetes mutation, retry or cleanup surface. The verified full-run manifest
now opens that materializer, all concrete Stage 1-12 adapters and the shared
single-execution Platform capability session without contacting a cluster.
The remaining implementation work is the shared local/Job activation surface
for this concrete composition; this is not a new controller or reconciliation
mechanism. After that, live closure must
publish the current image, construct fresh short-lived private inputs, run the
exact bounded activation on `ok-mgmt`, preserve a stopped partial state without
automatic retry, and separately repeat disposable-cluster and
executor-termination conformance.

These remaining items may compose the verified packages, but must not add a
second Contract-to-CAPI compiler, persistent aggregate-status controller,
long-running lifecycle reconciler, automatic retry after partial mutation or
credential persistence.
