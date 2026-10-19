# OK-147: post-merge internal execution denial follow-up

## Source and review scope

- Baseline: `origin/main@ccc5d018a640d22c0ad289ef345a64f28b75b84a`.
- Implementation: `a82278ca0ee697a85081a9d3bb5f055cdeada8c4`.
- Independent finding: [Suchit's OK-147 comment 15038](https://kubernauts.atlassian.net/browse/OK-147?focusedCommentId=15038), checked against the actual comment and baseline source.
- This follow-up does not supersede the accepted PR #437 milestone. Independent security re-review of this new implementation is still required.

## Contract impact

The workload-resolver allowlist is deliberately **empty**. Every non-nil
resolver is rejected at pre-runtime and full-run execution open, including
wrappers, embedded implementations, method/function adapters and typed nils.
A missing resolver is not an approved resolver: the production pre-runtime
constructor still rejects it as incomplete. No bootstrap package is implicitly
approved by its existence or by successful local tests.

Unsupported `KubeconfigFile` authorities for provider prerequisites, cluster
lifecycle, lifecycle observation, network observation and enablement are
rejected before stage factories, grant resolution, or credential/file loading.
The three workload destinations remain guarded as well. Lifecycle/network
source adapters also reject unsupported kubeconfig inputs instead of ignoring
them, and the identified stage wrappers preserve error identity with `%w`.
`ProviderAccessKubeconfigFile` is not an executor authority and is not redefined
by this change.

Public manifest v3/v4 and CLI/YAML denials are unchanged. No stage, credential,
grant, recovery, convergence or receipt contract is enabled or broadened. No
automatic replay, retry, local operator mode or Make fallback was introduced.
Command completion is still not provisioning-success evidence. ADR-030
security acceptance item 9 remains **OPEN**.

## Bootstrap overlap

#455's offline observer validation, #456's local candidate issuer authorization
and #457's candidate Kubernetes issuer store remain unmodified and disconnected
from the runner/CLI. `go list -deps ./cmd/ok` contains neither
`internal/bootstrapcheck` nor `internal/bootstrapauthority`. Their immutable
claims/results, indeterminate STOP states, namespace/fence checks and explicit
trust inputs are not resolver approval, a signer integration or production
security acceptance.

No changed file overlaps the active #452 bootstrap/Cilium design branch at
`16cbe9e1e54760b7ab3e9c746f549e564961512d`. The observed Cilium/template-writer
boundary and anti-delete/fencing work remain separate. OK-197/OK-198 are not
implemented here.

## Regression approach

- Fifteen independently configured denial cases exercise internal and public
  pre-runtime/full-run openers. Authority cases use a nil resolver so the
  resolver denial cannot mask a missing authority guard. Exact sentinel checks
  prevent incomplete-config failures from passing as credential-policy denial.
- Stage and grant recorders, a per-case fake TLS API/TCP counter, and a resolver
  invocation counter must all remain zero. Only loopback test servers are used.
- Separate lower-adapter wrapper tests require `errors.Is` to preserve
  `ErrClientCertificateDisabled` through submission/lifecycle/network wrappers.
- Target-drift tests change each referenced kubeconfig while leaving the YAML
  and normalized digest unchanged; the exact drift error must precede an absent
  manifest. No production dispatch or credential gate is mocked or weakened.
- The polling call-site test constructs an intentionally unloadable private
  in-package manifest format to reach `ExecutionConfig` after its v3/v4 gate.
  Only a test value changes; no accepted format or production gate changes.
- Existing orchestration tests construct synthetic executors in `_test.go`
  using fake stage factories. Pure structural validation remains covered without
  creating a production resolver-approval escape hatch. These tests prove
  ordering and durable receipt handling, not permission to execute a live run.
- CLI API/mutation/grant/TCP counters reset for every denial subtest. The
  existing positive TLS-denial control and all sixteen real-loader CLI denial
  cases remain present.

## Validation environment and limits

Local environment: macOS amd64, Go 1.26.7, Python 3.13, PyYAML 6.0.3.
Offline renderer owner: `ok-linux@a1687263d46c48e47c14f5bf202c9a652d7c1a71`.
The tested binary is built with `CGO_ENABLED=0`, `-mod=readonly`, `-trimpath`,
and `-buildvcs=false`. It has not replaced the user's installed CLI.

Final-source results (implementation commit above; subsequent evidence-only
commits do not change executable/test source):

| Check | Result |
| --- | --- |
| `go test -mod=readonly ./... -count=1` | PASS, all packages |
| `go vet -mod=readonly ./...` | PASS |
| `go test -race -mod=readonly ./internal/runner ./cmd/ok ./internal/bootstrapauthority ./internal/bootstrapcheck -count=1` | PASS, all four packages; final-source runner 112.172s |
| Focused policy/sentinel/target-drift/polling regression tests, `-count=10` | PASS |
| Offline build and CLI smoke (14 help/requirements/template/version calls) | PASS |
| `tests/ok147_cluster_intent_test.py` (real owner renderer, synthetic inputs) | PASS, 27/27 |
| `tests/ok_cli_config_interactive_test.py` | PASS, 8/8 |
| `tests/ok_cli_network_suggest_test.py` (fake APIs only) | PASS, 23/23 |
| `git diff --check` | PASS |

The local smoke/intent binary SHA-256 is
`a594e211ab9b7c7457c18803fc18d24e9a0e0d745db6f79700986f0c7481b48a`.
No final-source failures remain in the completed checks. A new lower-adapter
sentinel regression initially failed and was corrected by the explicit
lifecycle/network kubeconfig guards; that intermediate failure is not reported
as a passing run.

Linux/Go 1.21 checks are delegated to the existing PR CI and must be reported
separately from local Go 1.26.7 results. CI pending is not PASS. No local
Go 1.21 or live Stage 5-7 acceptance result is claimed.

Live cluster mutation, credential renewal/issuance, runner execution, Stage 5-7
activation and recovery/fencing acceptance are **NOT RUN**, deliberately outside
this follow-up's authorization and security scope. No live cluster API was
contacted during this follow-up. The preceding separately authorized read-only
`ok-cli-mvp-3` snapshot is a different operation and not execution evidence here.
