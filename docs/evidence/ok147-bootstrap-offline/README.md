# OK-147: first offline bootstrap validation checkpoint

This implements only the first checkpoint of the design in draft PR #452,
following operator approval of the bounded bootstrap direction. It does not
approve a production certificate profile or install/execute the proposed issuer.

## Contract impact

`internal/bootstrapcheck` is an isolated, internal experimental candidate model.
There is no public schema, command, config option, handoff integration or runtime
import. Existing v3/v4 manifests, requirements output, CLI behavior and the #437
certificate/recovery/Stage-7 signing gates remain unchanged. The successful
historical happy-run evidence is retained, not replayed or retroactively treated
as approval of a credential policy.

The checker takes independently established expected binding and explicit
subject, CA certificate, lifetime and clock-skew constraints. It validates:

- Exact plan, attempt, target UID/API, policy, Stage-4 receipt prefix and CA-source
  namespace/name/UID/resourceVersion/Cluster owner UID binding.
- Signed CSR, exact CN-only subject with no certificate groups, no SANs or other
  CSR extensions/attributes, and an explicit pinned public CA certificate.
- Result/request digest consistency, matching CSR public key, direct CA signature
  and X.509 trust verification, clientAuth-only/digitalSignature-only leaf, no
  groups/SANs/CA capability, total validity cap, initial backdating limit and
  current validity at first handoff.
- A proposed coordination-slot digest keyed by plan/attempt/target/observer role,
  not CSR, policy revision or source RV. Changing those inputs changes the request
  digest, not the slot, and must be rejected against independent expectations.
- Supplied CA-source `PartialObjectMetadata` against the independently expected
  namespace/name/UID/resourceVersion and exact Cluster controller owner
  name/API version/UID. Deleting sources, absent/ambiguous owners, full Secret
  responses, duplicate JSON keys, case-alias identity shadowing and trailing
  JSON are rejected. No live source is fetched or approved by this checker.

Only network-observer and runtime-observer candidate roles are modeled. Fixed
probe and privileged target-access installation are intentionally rejected here;
their admission/exec/escalation boundaries need separate implementation review.

All identities, times and CA signing in unit tests are synthetic, ephemeral and
in memory. The fixture's ten-minute cap and one-minute backdating allowance are
**test values, not production defaults or policy approval**. Clock skew here
limits backdating at initial handoff; it does not permit future NotBefore or
expired certificates and is not a general certificate-reuse check.

## What this does not prove or implement

The request digest is a consistency binding, **not request authentication or a
signed issuer receipt**. The caller must supply trusted expectations; deriving
them from the request defeats the check. Exact subject selection is not proof
that the subject is operation-specific or that its live RBAC is least-privilege.
The later operator-approved observer profile below supplies fixed local
subject/lifetime checks. No deployed issuer policy or accepted public wire
protocol has been introduced.

There is no CA-key reader, private-key generator, signer, Job launcher, file or
network I/O, credential renewal, live source inspection, RBAC/admission installer,
runner enablement or provisioning-success receipt in production code here.
Slot hashing is not durable claiming: it does not solve concurrent issuance,
crash-after-claim, authenticated provenance, result persistence or replay fencing.
Those remain explicit activation blockers; no timeout takeover or automatic
retry is authorized. Evidence of command completion never substitutes for
existing convergence requirements. Teardown and OK-197/OK-198 are unchanged.

The metadata checker is separate from request/result validation and does not
make caller-supplied expectations trustworthy. A future source adapter must use
[Kubernetes metadata-only negotiation](https://kubernetes.io/docs/reference/using-api/api-concepts/#metadata-only-fetches)
without falling back to a full Secret. Client-side output filtering of a full
Secret is not metadata-only access. Even metadata annotations can contain
sensitive material; they must not be dumped into logs or evidence. This change
contains no fetch adapter and grants no Secret access. UID/owner consistency
does not establish the actual CA certificate/key relationship or authenticate
the API response; those remain outside this offline checkpoint.

## Verification

Results are recorded after executing the relevant local checks. Live issuance,
deployment, CA-source inspection and runner execution are NOT RUN: deliberately
outside this checkpoint, not failed environmental tests.

Local results (2026-10-18):

- PASS: `go test ./...`.
- PASS: `go test -race ./internal/bootstrapcheck ./cmd/ok ./internal/runner`.
- PASS: final checker tests with race detection and 98.2% statement coverage,
  including the added source metadata checks.
- PASS: `go vet ./...` and `git diff --check`.
- PASS: `go list -deps ./cmd/ok` confirms the checker is not in CLI dependencies.
- PASS: `make ok-cli-offline-smoke`, including 26 destroy, 27 YAML, 23 network
  proposal and 8 config Python checks, plus its Go safety checks.
- PASS: 64 OK-186 lifecycle checks (offline fixtures).
- PASS: 31 split-provider teardown checks (offline fixtures).
- FAIL (environment prerequisites): additional
  `make ok178-workload-user-namespaces-test` on Darwin. Its exact `talosctl
  v1.9.5` assertion fails with the installed client `v1.13.5`; its real Talos
  patch validation then aborts because Python has no Linux `os.memfd_create`.
  Earlier printed render/schema checks passed, but the complete target did not.
  Remaining Talos-backed assertions are NOT RUN. This patch changes neither the
  renderer nor that test; no compatibility claim is inferred from partial output
  and the required tool/version/platform checks have not been relaxed.

No Candidate manifest is modified: before/after manifests are identical because
the change adds only this documentation and the isolated checker/test package.
No live cluster mutation or real credential operation was performed during this
implementation. GitHub CI status must be evaluated separately from local results.

Source-metadata follow-up: all Go tests, checker race/coverage, `go vet ./...`,
diff check and CLI dependency isolation were rerun and passed. The earlier
CLI smoke/lifecycle results above are from the initial checkpoint; those suites
were not rerun for this isolated follow-up, which changes no existing runtime,
CLI, lifecycle, renderer or tests outside `bootstrapcheck`.

## Operator-approved local observer profile checkpoint

Following explicit approval of the observer proposal in draft #452, the isolated
checker now also enforces, without runtime activation:

- Exact CN `ok147:<nonce>:<role>` for network-observer or runtime-observer; the
  independently expected nonce is 32 lowercase hexadecimal characters generated
  before rendering/plan hashing. No groups, SANs, CA capability or extra EKU.
- A 45-minute total validity cap and at most 60 seconds backdating, measured
  against independently authenticated issuance time, not stage-entry time.
- At most five minutes from issuance to stage entry; a positive observation
  window of at most 30 minutes and an explicit positive wrapper-overhead budget.
- At entry, remaining certificate validity must strictly exceed polling plus
  wrapper overhead. No arithmetic overflow, expiry-at-completion equality,
  observation shortening, renewal or replay fallback is accepted.
- Explicit role-specific predecessor expectations: Stage 4 for network
  observation and Stage 5 for runtime binding. The caller must verify those
  outcomes independently; digest syntax is not authoritative receipt verification.

The generic initial-result freshness check remains unchanged. The observer entry
check verifies at both issuance and stage-entry time, so legitimate scheduling
delay is not incorrectly counted as extra certificate backdating. Issuance time
is NOT extracted from a certificate or inferred from a local response timestamp;
authenticated issuer-result provenance remains required before integration.

This implements the certificate/budget portion only. It does not implement or
approve the platform-mediated Pod-discovery/probe protocol, raw Pod LIST/exec,
RBAC/admission, a signing task, key-source access, request authentication, durable
claims/results, or the explicit next manifest/adapter revision. In particular,
passing local checks cannot authorize Stage 1 or reopen #437 gates. The issuer
image/spec and coordination backend still require review; no platform was changed.

Profile follow-up local verification: PASS all Go tests, checker race tests
(98.5% statement coverage), `go vet ./...`, diff check and CLI dependency
isolation. Existing CLI smoke/lifecycle tests are not rerun for this unlinked
package-only change. Earlier OK-178 environment failures remain as recorded;
live issuance, installation and runner execution remain NOT RUN.
