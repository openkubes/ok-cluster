# OK-147 R25 network-observation diagnostic

## Outcome

R25 completed provider prerequisites, cluster lifecycle, lifecycle observation,
and enablement, then stopped fail closed at `network-observation`. The
deterministic network-observation Ledger slot was absent, so runtime binding and
all later stages were not attempted. No retry, cleanup, rollback, or diagnostic
mutation was performed.

## Read-only correlation

The retained environment converged without runner repair:

- both expected Nodes became available;
- both Cilium agent Pods were Running and Ready;
- the Cilium, Envoy, and operator workloads were fully available;
- the bound HCP and its single HRP were Ready; and
- the fixed, bounded Cilium health probe succeeded.

The final HCP/HRP readiness transitions occurred 36 seconds after the executor
stopped. Reconstructing the CAAPH Conditions visible before that transition and
replaying them against the published collector produced a verified `Unknown`
result, proving that this schema-valid partial representation is already
pollable.

## Correction

The remaining failure window is a later transient source failure after an
initial verified convergence result. The generic polling primitive now has an
opt-in boundary that permits such an error to remain bounded only when a prior
verified result already established the source and authority path. The network
observer enables that boundary; other observers do not.

An error on the first read still stops immediately. Terminal success still
stops immediately, invalid or unverified results still stop, and the existing
poll deadline still returns the last verified fail-closed result. This adds no
mutation, repair, credential reuse, arbitrary query, or unbounded retry path.

## Verification

- focused bounded-poller and network-stage tests: PASS
- focused network collector tests, including the reconstructed R25 CAAPH
  partial state: PASS
- the three known synthetic client-certificate fixture failures remain under
  the workstation Go toolchain and are independent of this change

