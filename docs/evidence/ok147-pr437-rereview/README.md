# PR #437 re-review regression evidence

## Follow-up to review 5561419466 (2026-10-18)

The original transcripts below are historical. In particular their HTTP-handler
counters **did not prove absence of network contact**: the fixture did not trust
the local fake TLS server, so a connection could fail before reaching a handler.
Do not use those counters as evidence of zero connections.

The follow-up counts `ConnState(StateNew)` independently of HTTP handlers, and a
positive control deliberately fails TLS while proving that the connection was
counted. The 16 built-CLI denial cases require zero connections as well as zero
HTTP/mutation/grant requests and no terminal marker. Build VCS stamping is
disabled for reproducible execution inside worktrees. The new
`followup-boundaries.txt` records these cases and the constructor/zero-value,
sentinel-propagation, static plane/manifest and polling-window regressions.

Current-main #450 real-loader YAML integration tests now require explicit
credential-policy denial, not a successful handoff. Automatic, guided-terminal
and existing-prepared YAML paths cannot emit a successful handoff or start
marker; concurrent/repeated handoffs retain failure without replay. Static
Contract/plan/target selection tests remain, as do fake-adapter tests that
exercise future sequencing without claiming present execution readiness.

The merge of `main@e56835d` is integration only, not a merge of this PR into main.
No policy gate is relaxed, bounded issuer is invented, or live action performed.

## Historical B1/S2 transcripts

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
