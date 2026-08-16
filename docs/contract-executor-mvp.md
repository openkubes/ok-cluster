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
checkpoint proves content binding and trust verification only. It does not yet
provide grant consumption, idempotency, credentials, Kubernetes submission,
retry, rollback, or evidence publication.

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
