# Guided up: explain credential-policy STOP without changing execution

Baseline: `origin/main@ccc5d018a640d22c0ad289ef345a64f28b75b84a`.
Implementation/test source: `ab71825142e6bd54a08d741f0a9ecd0a7a01666c`.
Subsequent evidence-only commits do not change executable/test source.

## User-visible change

The existing guided YAML `ok up --file cluster.yaml` path adds a human-readable
explanation when its existing workflow returns the exact (possibly wrapped)
`runner.ErrClientCertificateDisabled` sentinel:

- cluster creation is blocked by the current runner credential policy;
- automatic workload-access setup is not enabled yet and requires a reviewed
  platform integration;
- supplying an administrator kubeconfig, deleting retained preparation or
  retrying the run is not a supported workaround.

The explanation is applied **after** the existing workflow stops, on its error
return only. It neither reads files nor writes state, invokes a capability,
changes a stage outcome or claims no earlier API/stage activity from the error
category alone. The original error chain remains available through `%w` and
`errors.Is`. Nil, unrelated errors and same-text sentinel lookalikes are returned
unchanged. No success classification is introduced.

Explicit expert modes and JSON preparation output are untouched. No flags,
schemas, JSON fields, exit-code behavior, authorization/readiness semantics,
approval prompts, receipt formats or automatic retries are added or changed.
This is parallel UX work, not activation of #452 or #455-#457, not a replacement
for #458, and not security acceptance. ADR-030 item 9 remains OPEN.

## Checks

Local environment: Go 1.26.7 / macOS amd64, Python 3.13.7, PyYAML 6.0.3.
Owning offline renderer: `ok-linux@a1687263d46c48e47c14f5bf202c9a652d7c1a71`.
CLI build: `CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false`.

| Check | Result |
| --- | --- |
| `go test -mod=readonly ./... -count=1` | PASS, all packages |
| `go test -race -mod=readonly ./cmd/ok -run 'TestGuidedUp\|TestAutomaticUp' -count=10` | PASS |
| `go vet -mod=readonly ./...` | PASS |
| `tests/ok147_cluster_intent_test.py` against actual CLI/PTY and owning renderer | PASS, 27/27 |
| Offline CLI smoke: help/requirements/template/version | PASS, 14 calls |
| `git diff --check` | PASS |

The actual-CLI guided denial regression now asserts the human explanation as
well as non-zero exit, empty stdout, retained original policy diagnostic and no
confirmation prompt. Its existing assertions retain the no-start/no-terminal,
no-handoff-success, empty runtime/receipts/authorization directories, forbidden
tool marker and unchanged evidence on repeated invocation. No fake dispatch or
relaxed production security gate is used to make that denial reachable.

No final-source failures in the checks above. Linux/Go 1.21 PR CI is separate
and must not be inferred from local Go 1.26 results. Full-repository race on
this UX branch is NOT RUN; the changed guided/automatic CLI tests were raced
ten times. Live cluster contact/mutation, credential issuance/renewal, runner
execution and bootstrap/probe activation are NOT RUN and not authorized here.
The user's installed CLI is unchanged. No automatic merge.
