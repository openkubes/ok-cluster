# OK-147 bounded Contract Executor MVP

The first implementation checkpoint establishes the shared, side-effect-free
core for local CLI and future in-cluster Job execution.

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
