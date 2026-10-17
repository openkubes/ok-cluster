# PR #437 re-review regression evidence

These are new local runs for the B1/S2 corrections. They do not revise Suchit's
corrected record in Jira 14978: his earlier complete non-root race transcript
was not retained. Effective UID **501** is non-root. Each transcript records its
own Go version, command, complete combined stdout/stderr and exit status.

- `tests.txt`: all packages, ordinary tests with cache bypassed.
- `race.txt`: all packages with the race detector and cache bypassed.
- `vet.txt`: static checks.
- `smoke.txt`: offline CLI smoke, including the real CLI denial regression,
  rendering and contract-executor dry-run.
- `boundaries.txt`: verbose CLI, signer, materializer, activation and requirements
  compatibility regressions, including explicit zero-activity assertions.

The source digest binds sorted tracked and untracked non-ignored Go sources,
`go.mod`, `go.sum`, and `Makefile`: for each path, hash path bytes, NUL, file
contents, NUL using SHA-256. All runs should carry the same source digest.
Documentation and evidence outputs are excluded from this digest. No source
changes are made between these retained runs and the accompanying commit.

The only transcript normalization replaces the local workspace prefix with
`<worktree>`; no output lines are omitted. Raw combined output was retained
locally as `/tmp/ok147-pr437-<name>.raw.txt`. A successful command has an explicit
`Exit status: 0` footer. These offline results do not prove live RBAC, revoke
previously issued grants, fence legacy executors, or satisfy ADR-030 acceptance.

The CLI cases run a built binary with synthetic private manifests, isolate every
API endpoint to a local fake server, and require the explicit credential denial.
Zero API/grant requests and absent terminal markers are checked. The signer cases
supply external v1/v2 full and legacy recovery-shaped policies directly; 16
concurrent/repeated requests per case must return 403 with no signatures/claims.

Certificate subject/group/lifetime cases remain **blanket-mode denial tests**,
not evidence of individual CN, group or TTL validators. Bounded bootstrap and
atomic reservation/fencing remain unimplemented integration dependencies.
