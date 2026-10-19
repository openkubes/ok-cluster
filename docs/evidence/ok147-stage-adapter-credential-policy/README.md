# OK-147: token-only stage-adapter open boundary

Focused follow-up to Suchit's independent review of #458, items 2 and 3.
Base: `origin/main@b2e0c60cceb20289ba1ae68eb5100d0e8d7e541b`.
This change is independent of the unmerged #458 and #460 implementations.

## Contract impact

The execution adapters below now apply one I/O-free credential-mode check as
their first action. Any non-empty `KubeconfigFile`, including whitespace or a
nonexistent path, returns `ErrClientCertificateDisabled`; a simultaneous token
does not select a token fallback. Neither credential returns an explicit missing
transport error. Token-only mode continues through all existing plan, authority,
CA/token binding, package, lifetime and single-use checks unchanged.

Covered entry points: submission package/credential/runtime installers;
submission, lifecycle-observation, enablement, network-observation, target-access,
aggregate-evidence, target-registration, platform-applications, observability
collector, post-runtime and full-run activation launchers; runtime-binding launch
material Open; lifecycle stage observer; enablement stage operation; and the
shared bounded authority transport. The repeated constructor changes are only
three-line calls to the shared check, not new credential loaders or lifecycle
logic. Certificate parsing/materialization remains disabled.

Before: some direct stage adapters read only `TokenFile` and silently ignored a
set `KubeconfigFile`; kubeconfig-only input could fail later with a generic
configuration/file error. After: unsupported mode fails before package/candidate
verification, ledger/source opening or credential-file loading. Mixed mode is
also rejected with the security sentinel by the shared transport. Lifecycle and
enablement contextual errors preserve their underlying cause using `%w`.

No public flags, YAML/JSON schemas, Candidate manifests, receipts, stage sequence,
convergence criteria, issuer policy, grants, bootstrap/recovery gates or successful
token-only behavior change. There is no Candidate before/after diff: no Candidate
was read or changed. Existing historical happy-run evidence is untouched. This
does not claim to restore the disabled certificate-based full-run happy path.

## Regression evidence

- 18 open-boundary cases, each with kubeconfig-only, mixed and absent credentials
  (54 negative subtests). Each has fresh local TLS API request/TCP counters,
  absent synthetic paths, exact sentinel/missing-mode assertions and no usable
  returned adapter/operation/transport. Counters remain zero and errors do not
  disclose paths. Empty package/candidate values intentionally test rejection
  precedence, not package validation or later stage execution.
- An otherwise-valid submission runtime prerequisite and synthetic token/CA
  positively open in token-only mode. The same valid inputs with either mixed
  or kubeconfig-only mode are denied with the sentinel.
- Three genuine lower-open failures (lifecycle source, enablement ledger and
  enablement authority) retain an unwrap-able cause. These exercise the actual
  lower error branches rather than only the earlier mode guard.
- 24 targeted mutants were rejected: remove the shared kubeconfig check;
  independently remove each of the 15 constructor guards, the shared transport
  call-site and the two operation/observer guards; replace `%w` with `%v` in each
  of the three lower error branches; disable the missing-token rejection; inject
  a TCP connection before the runtime-installer guard. The TCP injection fails
  all three mode subtests with `connections=1, requests=0`, proving that HTTP
  counters alone are not the assertion. Every mutated test failed; source was
  restored after each run. These tests are part of `ok-cli-offline-smoke`.

The open tests do not call Run/Launch/Ensure, grant issuers or a durable ledger.
Zero returned capability plus the early sentinel is the relevant assertion;
zero fake-API counters alone is not proof about later execution paths.

## Verification and limitations

Local environment: Go 1.26.7, darwin/amd64. Renderer checkout:
`ok-linux@a1687263d46c48e47c14f5bf202c9a652d7c1a71`.

Local results on the restored source:

| Check | Result |
| --- | --- |
| `go test -mod=readonly ./... -count=1` | PASS |
| `go vet -mod=readonly ./...` | PASS |
| New adapter/positive-control/error-cause tests with `-race -count=10` | PASS |
| `go test -race -mod=readonly ./internal/runner ./cmd/ok -count=1` | PASS |
| `make ok-cli-offline-smoke OK_LINUX_PATH=<pinned renderer>` | PASS after the environment correction below |
| `git diff --check` | PASS |

The complete smoke includes the existing Go/CLI checks, projection rendering,
26 destroy, 27 cluster-intent, 23 fake-network and 8 interactive-config tests,
plus the contract-executor dry-run and new adapter regressions.

Real-cluster integration, credential renewal, real grant/issuer/store enforcement, Cilium exec,
bootstrap installation and live provisioning are NOT RUN / NOT AUTHORIZED. No
cluster mutations were performed. No local user CLI installation was changed.

The first offline smoke attempt failed because the Python projection test requires
a sibling `ok-linux` checkout even when Make's `OK_LINUX_PATH` is set. A symlink to
the existing pinned renderer was added only in this new temporary worktree's
parent; no production or test source was changed to bypass the requirement.

ADR-030 security acceptance item 9 remains OPEN. This is adapter preparation,
not issuer activation, approval of certificate mode or complete security
acceptance. Authenticated platform operation/plan/predecessor provenance,
durable issuer-store enforcement/continuity, mediated fixed Cilium discovery/probe
and exact-body Stage-7 installation remain separate integration requirements.
