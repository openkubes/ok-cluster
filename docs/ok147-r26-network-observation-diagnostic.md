# OK-147 R26 network-observation diagnostic

## Outcome

R26 completed provider prerequisites, cluster lifecycle, lifecycle observation,
and enablement, then stopped fail closed at `network-observation`. No
network-observation Ledger record was persisted, and no later stage ran.

## Read-only correlation

The retained environment subsequently reached the intended network baseline
without runner repair:

- both expected Nodes were present;
- both Cilium agent Pods were Running and Ready;
- the Cilium, Envoy, and operator workloads were available;
- the bound HCP and its single HRP were Ready; and
- the fixed bounded Cilium health probe succeeded.

The diagnostic performed no mutation or retry. Its redacted summary digest is
`sha256:5c1c60a610ddddec4b33eb964f135ac680c1aa0cf4e1511dc70606f0edfd1de5`.

## Cause and correction

R26 already contained the bounded transient-read handling proven after R25.
The execution manifest nevertheless gave lifecycle observation 45 minutes and
the later network observation only 30 minutes. Normal CAAPH and Cilium
convergence therefore exhausted the shorter network deadline before reaching
the healthy state seen by the correlation diagnostic.

The full-run manifest boundary now rejects a network polling timeout shorter
than its lifecycle polling timeout. This keeps polling bounded and fail closed,
does not reinterpret negative evidence, and grants no repair or mutation path.
For the next run the existing 45-minute lifecycle window therefore implies a
network window of at least 45 minutes.
