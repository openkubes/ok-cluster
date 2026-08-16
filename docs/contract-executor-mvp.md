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
multi-platform OCI archive, BuildKit `mode=max` provenance attestations, a Syft
SPDX JSON SBOM and an exclusive `0600` build record. The verifier rejects a
missing or extra platform, absent per-platform provenance, a changed pinned base
image, or a revision mismatch.

This checkpoint deliberately has no registry destination and never uses
`--push`. It does not publish an image, deploy a Job, contact Kubernetes, consume
an authorization, or permit lifecycle mutation. A later checkpoint must bind a
verified registry digest before any in-cluster execution can be proposed.

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
