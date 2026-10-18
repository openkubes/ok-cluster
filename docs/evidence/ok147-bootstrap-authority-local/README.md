# OK-147: local issuer authority and coordination checkpoint

This is the separately approved local implementation following PR #455. It is
not a deployed issuer, production storage adapter or accepted public protocol.
It deliberately remains outside the CLI/runner dependency graph.

## Boundaries

`internal/bootstrapauthority` introduces distinct candidate request and result
signature domains/audiences, not stage grants. It verifies Ed25519 signatures
against explicit pinned public keys. Request-delegation and result-attestation
keys must differ from one another and from declared Stage-Authority and
independent-evidence keys; an Ed25519 workload CA cannot serve as either key.
No private-key reader, generator, signer, callback or certificate issuer exists
in production code. All signing and key generation is synthetic, ephemeral and
in-memory in tests.

A signed request binds the exact observer request (including CSR and source
identity), policy, operation nonce, role-specific predecessor digest, validity
window, polling/wrapper budgets and dedicated storage-domain digest. Independent
expected inputs are checked through `bootstrapcheck`; they are not inferred from
the signed request. Trust configuration requires an explicit maximum request
lifetime, with no default. The five-minute request lifetime in tests is fixture
configuration, not an approved production authorization-window policy. It is
distinct from the approved certificate/handoff limits.

A signed result binds its public leaf certificate, request digest, authorization
digest, slot and claim digests, issuer key identity and issuance timestamp. The
observer certificate and remaining-stage-window checks run before recording it.
CSR private keys and CA private keys never enter requests, claims, results or
logs. No authentication or storage record is converted into a runner grant or
cluster-success receipt.

## Issuer-only record contract

The injected `Store` capability requires a stable independently pinned domain,
linearizable exact-name reads and atomic immutable create-if-absent for separate
claim/result records. It has no update, delete, lease, release or takeover method.
Only a mutex-backed in-memory **test** backend is included. Existing ledger
formats/categories, their adapters, Stage-Authority and teardown are unchanged.

| Observed state | Meaning |
| --- | --- |
| Neither record exists | `EMPTY_NOT_AUTHORIZED`; not permission to sign. A currently valid verified request still needs a successful atomic claim. |
| Claim exists, result absent | `CLAIMED_INDETERMINATE_STOP`; no restart or lease-expiry reissuance. |
| Matching claim and authenticated result exist | `RESULT_RECORDED_NOT_STAGE_AUTHORIZED`; read-only historical retrieval, not current certificate usability or cluster success. |
| Orphan result, drift, malformed/noncanonical record or read error | STOP; no fallback, replacement or repair. |

The slot is keyed by plan/attempt/target/role, not CSR, signing key or predecessor
changes. Changing a CSR or presenting a newly signed predecessor does not create
another slot. Claim consumption rechecks the authorization time window. Zero
values and verified objects from another authority configuration cannot be used.
Mutable input slices are frozen after verification.

Unknown write outcomes return STOP without retry. A known result-create conflict
may only retrieve and compare an identical authenticated result; a different
result cannot replace the original. Inspection may retrieve a historical result
after request expiry but never returns a new claim or reauthorizes stage entry.
The injected `now` is a trusted adapter/test clock, never a client-supplied claim.

## Still required before production integration

- Independently authenticated authoritative lifecycle/predecessor verification,
  actual CA/source UID/RV/fingerprint checks immediately before signing, and
  certificate/key correspondence checked inside the privileged platform task.
- Concrete request/result trust provisioning, production request-window policy,
  fixed issuer image/spec/ServiceAccount, and platform-mediated Pod/probe and
  exact-body installer/admission contracts.
- A reviewed durable, single-authoritative-domain adapter. Its identity must bind
  the real management trust boundary and storage incarnation, not an arbitrary
  caller label. A backend that lies about its domain, forks, loses records, serves
  stale reads or permits deletion violates this contract. The in-memory tests
  do not prove those deployment properties or survive a process loss themselves.
- Dedicated writer isolation, anti-deletion fencing and reviewed retention. No
  existing ledger is widened and OK-197/OK-198 are not implemented here.
- An explicit future manifest/adapter revision and separate deployment/live
  approval. #437 certificate/recovery/Stage-7 signing gates stay in force.

## Verification

Local results and limitations are listed below. No live cluster request,
credential refresh, key-source read, installation, publication or runner call
was performed during this implementation. Candidate manifests are unchanged
(exact before/after: no Candidate-file diff); historical happy-run outcomes and
all prior terminal evidence remain untouched.

Local verification (2026-10-18):

- PASS: `go test ./...` and `go vet ./...`.
- PASS: race tests for `bootstrapauthority`, `bootstrapcheck`, existing
  `authorization` and existing `ledger` packages.
- PASS: issuer authority statement coverage 93.3%; observer checker 98.5%.
- PASS: the 24-contender single-winner/crash-STOP test repeated 50 times under
  race detection with the test backend.
- PASS: positive request/claim/result paths for both observer roles; request and
  result signature/key/audience separation; predecessor/CSR/domain drift;
  immutable-result conflict; orphan/corrupt records; lost-write responses;
  historical retrieval versus expired authorization; nil/foreign opaque values.
- PASS: `git diff --check`; `go list -deps ./cmd/ok` confirms neither experimental
  bootstrap package is linked into the CLI.
- NOT RUN for this isolated follow-up: CLI Python smoke/lifecycle suites. Earlier
  results and the existing OK-178 Darwin/tool-version limitation are recorded in
  `../ok147-bootstrap-offline/README.md`; they are not relabeled as new results.
- NOT RUN by design: any real persistence backend, Job, HTTP issuer endpoint,
  key provisioning, CA signing, installation, credential renewal or live run.

This follow-up is stacked on PR #455 for a focused review diff. CI for its own
head must be checked separately; no automatic merge or deployment is requested.
