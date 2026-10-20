# OK-147: offline source/coordination contract rehearsal

Status: **TEST ONLY / NO PRODUCTION TASK / NO-GO**. Stacked on the current #460
source/key helper (`7c594b496647d43ed19436153411e70a2e50006a`), whose review and
merge remain separate. This branch adds only a `_test.go` file and this evidence
document. It does not modify #458/#461, the issuer packages' production APIs,
manifest formats, runner/CLI imports, credential gates or authority allowlists.

## Purpose and evidence scope

Rehearse the proposed ordering with the existing #455 observer checks, #456
request/result authentication and coordination, and #460 source/key checks:
authenticate the candidate request against synthetic independent expectations;
validate supplied source metadata/CA/key correspondence; claim the one-use slot;
check the source before hypothetical use; create a synthetic test result; verify
and record it; inspect it without turning it into stage authorization.

The composition function exists **only in tests**. No production method enforces
this complete ordering yet. Passing these tests is not proof that a deployed
issuer checks its source, reads fresh/atomic snapshots, persists a claim before
signing or withholds output until persistence. Those remain requirements for the
future reviewed task, not enabled capabilities or security acceptance here.

All keys, metadata, certificates, signatures and records are generated in memory.
The existing fixture signer is test-only. The memory store models immutable
atomic creates; replacing an Authority against that same memory store models a
process replacement, **not** machine-crash durability or a real storage fence.

## Scenarios

- Network observer after a synthetic Stage-4 predecessor, runtime observer after
  a synthetic Stage-5 predecessor. Both use their own role-correct CSR subject,
  the same explicit observer limits, and separate request/result/CA keys.
- Signed target/role/predecessor drift, expired request, invalid signature,
  source UID/RV/owner drift, full-Secret responses, wrong CA bytes and wrong
  private key fail the test-only composition before it attempts a claim.
- A valid result records exactly one claim and one result and survives Authority
  replacement as `RESULT_RECORDED_NOT_STAGE_AUTHORIZED`. The existing observer
  stage-entry checker accepts the synthetic result, but no stage/grant/execution
  is invoked. Historical retrieval does not reactivate an expired request.
- Source RV drift after a durable fake claim is detected before the test signs
  anything. The claim remains `CLAIMED_INDETERMINATE_STOP`. A restarted Authority
  cannot reclaim it. Even a newly signed request with matching updated RV cannot
  reset that same plan/attempt/target/role slot or replace its original claim.
- Unknown result-write outcomes, both uncommitted and committed-with-response-lost,
  return STOP. Inspection distinguishes claim-only STOP from a recorded public
  result; neither permits another claim/issuance. This is not automatic replay or
  automatic result delivery after an unknown operation outcome.
- A valid source and authenticated result envelope cannot admit a leaf signed by
  another CA. The leaf keeps the correct CSR key, subject and lifetime so the
  test reaches issuer/trust rejection rather than an earlier key/subject check.

Before/after Candidate comparison: **no diff**. No Candidate, private runtime
input, live receipt or terminal marker is read or changed. Public contracts and
the historical happy-run/convergence requirements are preserved; the disabled
certificate-based full-run happy path is not restored by a test rehearsal.

## Unproven deployment boundaries

There is still no platform source loader, approved signer task/image/identity,
production orchestration or CLI/Console task endpoint. In particular:

- Real caller/tenant/environment delegation and authoritative plan/predecessor
  evidence must be established independently at the operation boundary.
- Source identity/key reading and signing-time policy must be checked inside the
  privileged task. Revalidating the same supplied bytes is not fresh API evidence.
- The real store needs isolation, admission/anti-deletion and continuity/fencing
  acceptance. These tests do not prove a durable STOP after a claim write that
  itself returns an unknown outcome without a stored record. The future operation
  owner must retain that terminal outcome; an apparently empty store is not
  permission to retry, recreate a namespace or rebind a domain after uncertainty.
- Mediated fixed Cilium discovery/probing, exact-body Stage-7 installation and a
  reviewed explicit runner/profile revision remain required before activation.

ADR-030 security acceptance item 9 remains **OPEN**. No OK-197/OK-198 work, generic
issuer, CRD/operator, automatic refresh/recovery or privileged CAPI-client mode is
introduced. No cluster contact/mutations, real credential access/issuance, runner
publication or user CLI installation is performed.

## Verification

Local environment: Go 1.26.7, darwin/amd64; renderer
`ok-linux@a1687263d46c48e47c14f5bf202c9a652d7c1a71` via a symlink only in the new
temporary worktree parent. Linux/Go 1.21 CI and independent review are distinct
evidence, not inferred from local results.

| Local check | Result |
| --- | --- |
| `go test -mod=readonly ./... -count=1` | PASS |
| `go vet -mod=readonly ./...` | PASS |
| `go test -race -mod=readonly ./internal/bootstrapauthority ./internal/issuersourcecheck -count=10` | PASS |
| Final new contract tests with `-race -count=10` | PASS |
| Full `make ok-cli-offline-smoke` with the pinned renderer | PASS |
| Production dependency graph for CLI/runner | No bootstrap or source-check dependency |
| Production dependency graph for bootstrapauthority | No source-check dependency |
| Test dependency graph for bootstrapauthority | Source-check dependency present only with tests |
| Production `.go` diff against #460 head | Empty; all experimental mutations restored |
| `git diff --check` | PASS |

All six targeted primitive mutations fail the **new** contract tests: bypass
source metadata validation; bypass private/public-key correspondence; add source
RV to the one-use slot identity; return success for unknown result writes; bypass
observer-request binding; bypass observer-certificate trust checks. Each mutation
compiled, failed a test assertion, and was restored. This checks the tests'
sensitivity to the existing primitives, not the presence of a production task.
The wrong-CA leaf test also asserts the specific issuer-check error so an earlier
CSR-key/subject rejection cannot shadow that path.

The full offline smoke includes existing Go/CLI checks, projection rendering,
26 destroy, 27 cluster-intent, 23 fake-network and 8 interactive-config tests,
plus the contract-executor dry-run. It verifies unchanged product behavior; the
new contract tests run separately in the Go suite, not through a live CLI path.

NOT RUN / NOT AUTHORIZED: actual source/Secret reads, production issuer signing,
platform delegation/enforcement validation, real coordination-store durability,
cluster provisioning, Cilium exec, teardown or Console mutation integration.
