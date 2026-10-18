# OK-147: isolated Kubernetes issuer-record adapter

This follow-up to merged PR #456 adds an explicitly configured Kubernetes
`Store` adapter for the experimental `bootstrapauthority` claim/result protocol.
It is not linked into the CLI or runner and does not install or activate an
issuer. There is no new user-facing setup step, public manifest revision,
signer, key reader, credential renewal, Job or operator in this change.

## Contract impact

The platform must independently supply the exact HTTPS API endpoint, public CA
bundle, existing bearer credential, dedicated storage namespace UID, existing
immutable fence UID/resourceVersion and expected storage-domain digest. The
constructor validates locally without HTTP. It discovers no kubeconfig, system
trust, proxy, auth plugin or credentials and never refreshes them.

The domain digest binds API endpoint/trust and namespace/fence incarnations.
Fence resourceVersion is separately pinned, not part of the slot identity:
refreshing metadata must not open a new issuance slot. Recreating/rebinding the
namespace or fence is not a supported recovery/reset mechanism. Storage must
outlive Candidate teardown; Candidate namespaces and the execution ledger are
not used as issuer storage.

Only these requests are implemented:

- GET the pinned namespace as PartialObjectMetadata, without a full-object
  fallback, and GET the exact existing fence ConfigMap.
- GET exact claim/result ConfigMap names, preserving the entire 256-bit slot
  digest, or POST a new immutable ConfigMap into the dedicated namespace.

There is no LIST, WATCH, PATCH, PUT or DELETE, Secret access, namespace/fence
creation, redirect following or mutating retry. TLS uses only explicit roots;
responses are bounded and errors omit server bodies and credentials. Protected
JSON identity fields reject duplicate/case-alias keys. Record schema/slot checks
do not replace the Authority's signature, evidence and time checks.

Namespace/fence identity is checked before and after each operation. Known,
well-formed exact-name 404/409 responses mean absence/conflict; unknown or
malformed responses mean STOP. A lost POST response, or drift detected after a
committed POST, also means STOP without retry, rollback or a success claim.
Separate historical inspection does not authorize another issuance.

## Persistence is not production fencing

Kubernetes immutable ConfigMaps prevent data updates, **not deletion and
recreation** ([Kubernetes documentation](https://kubernetes.io/docs/concepts/configuration/configmap/#configmap-immutable)).
Metadata-only namespace reads use the documented
[PartialObjectMetadata negotiation](https://kubernetes.io/docs/reference/using-api/api-concepts/#metadata-only-fetches).
The fake TLS API exercises this adapter's behavior; it does not prove production
RBAC, durability, admission or linearizability of a deployed platform.

The pre/post checks are not an atomic server-side transaction with namespace
lifecycle. Dedicated writer isolation, anti-deletion/anti-rollback admission,
retention, protection against domain forks and a reviewed platform trust/config
provisioning contract remain activation blockers. An attacker able to delete and
recreate a record inside an unchanged domain cannot be stopped by immutable data
or client checks alone. This adapter must not be treated as production-safe
single-use issuance merely because unit tests pass.

All other blockers in `../ok147-bootstrap-authority-local/README.md` remain:
authoritative predecessor/source checks, CA/key correspondence inside the
privileged task, trust provisioning, authorization-window policy, fixed
image/spec/ServiceAccount and installer/probe authority boundaries. #437 gates
remain closed; Stage-7 signing/recovery is not enabled. Existing stage ledger,
teardown, OK-197 and OK-198 are unchanged.

## Exact Candidate comparison

Before: the existing Candidate files and historical outcomes on merged main.
After: byte-for-byte unchanged; **no Candidate-file diff**. No active manifest,
profile, lifecycle implementation, stage receipt, convergence requirement or
first successful happy-run contract changes. Command execution alone is still
not provisioning success evidence.

## Verification (2026-10-18)

- PASS: `go test ./...` and `go vet ./...` with local Go 1.26.7.
- PASS: `go test -race -cover ./internal/bootstrapauthority ./internal/bootstrapcheck`;
  statement coverage 92.2% and 98.6%, respectively.
- PASS: fake TLS API round trip, separate authority reconstruction, concurrent
  single-winner create, namespace/fence replacement, pre/post-write drift,
  known conflict versus unknown committed-write response, unsafe local config,
  TLS trust rejection, redirect refusal, cancellation and malformed/foreign
  records. All credentials and records in these tests are synthetic fixtures.
- PASS: concurrent create and lost-write-response tests repeated ten times under
  race detection; `git diff --check`.
- PASS: Linux/amd64 test-binary cross-compilation with Go 1.21.13 (compilation,
  not runtime evidence). Native Go 1.21 execution on this Mac is NOT RUN here:
  the known dyld `missing LC_UUID` environment failure from #456 remains.
- PASS: dependency inspection confirms both experimental bootstrap packages
  remain outside `go list -deps ./cmd/ok`.
- PASS: freshly built CLI help/version smoke checks; interactive config suite
  (8 tests), network proposals against synthetic inventories/fake APIs (23),
  and offline intent/automatic preparation/handoff suite (27). Renderer owner
  checkout: `ok-linux@a1687263d46c48e47c14f5bf202c9a652d7c1a71`.
- NOT RUN: real Kubernetes persistence/admission/RBAC, installation, source-key
  access, certificate signing, credential refresh, publication and live runner.
  No live cluster requests or mutations were performed.

Linux Go 1.21 CI and its existing offline CLI/config/network/automatic-handoff
suites must be checked on the PR head. Their result is reported in the PR, not
inferred from cross-compilation. Existing OK-178 Darwin/tool-version limitations
are not relabeled as passing results.
