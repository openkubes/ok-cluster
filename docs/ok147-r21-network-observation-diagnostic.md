# OK-147 R21 network-observation diagnostic

## Scope

This checkpoint records only redacted, read-only evidence from the stopped
R21 full run. It contains no Kubernetes object payloads, endpoints, UIDs,
resource versions, credentials, tokens, kubeconfigs, Pod names, Node names,
IP addresses, or raw probe output.

## Bound execution

- Launch candidate: `sha256:be4aa70e9beed31d68b3deaee43b09c9802d1a0c4b4e4d7cc91923b5464e065f`
- Package: `sha256:6c52f7f4fa4f540da14724c08b0450dc27363324a69daee097fd82b67bb4e840`
- Bundle: `sha256:044c72829cea22421477644dfa55a74587903abe699718340e0682ae6a0e2b80`
- Plan: `sha256:495baaeb13357c95d95533c582c42c8fb802603f24e16772f51d9ec34434f00e`
- Execution attempt: `sha256:fa1b9444a184a1758d99fe73228f1eb6f6dcb226710dae9589f5b870310db11d`
- Runner: `ghcr.io/openkubes/ok-cluster-runner@sha256:1c14031972bec08db5ff0da7ff3728eade028a44a4b66670b0e5a867f06743ae`
- Canonical launch receipt: `sha256:7d4ade2d0201060e2e25e531574ad2bfe57c821219c0c61dc7886062970d5da9`

The create-only launch activated successfully. Provider prerequisites,
cluster lifecycle, lifecycle observation, and enablement completed
successfully. The executor then stopped fail closed at
`network-observation`. No retry, cleanup, rollback, or further mutation was
performed.

## Read-only findings

The deterministic immutable ledger slot for the R21 network-observation
receipt was absent. Therefore the stage did not end in a bounded
`NetworkReady=False` or `NetworkReady=Unknown` result; source collection
failed before a verified observation receipt could be persisted.

A later bounded diagnostic repeated the exact two management reads, five
workload reads, and fixed Cilium functional probe:

- both management reads succeeded and exactly one release object existed;
- all five workload reads succeeded;
- the workload contained two Nodes and two Cilium agent Pods;
- the UID-bound fixed probe exited successfully and returned valid JSON;
- the probe contained two Nodes and eight unique paths;
- all eight paths used the proven success representation in which `status`
  is absent.

The executor had stopped roughly three minutes after Pod start, while CAAPH
and Cilium status were still converging. The collector required initialized
status arrays and attempted the functional probe during this transient
window. Those normal convergence gaps were returned as an operational source
error, which the bounded poller correctly does not retry.

## Corrective boundary

The collector now:

1. normalizes absent, not-yet-initialized CAAPH and Cilium status collections
   into a redaction-safe partial snapshot;
2. lets the evaluator classify that snapshot as `Unknown`;
3. avoids workload collection until the bound add-on source is ready;
4. avoids the fixed Cilium probe until Nodes, Cilium components, and agent
   Pods are ready; and
5. continues to reject malformed fields, foreign identities, duplicate or
   incomplete initialized Conditions, transport failures, and probe errors.

This changes convergence handling only. It adds no mutation, discovery,
arbitrary query, retry of operational errors, repair, or second-owner path.

## Verification

- `go test ./internal/observation`: PASS
- direct network-stage and network-observation runner tests: PASS
- new regression cases cover uninitialized HCP status, absent HRP, empty Node
  Conditions, absent Cilium Pods, malformed HCP selection, and malformed Pod
  container status.

The full local suite additionally exposes three pre-existing synthetic
certificate-test failures under the developer workstation's Go 1.26.7
toolchain. The published runner remains built with pinned Go 1.24.6; those
certificate fixtures are independent of this network-observation change.
