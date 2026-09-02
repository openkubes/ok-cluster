# OK-147 R23 network-observation diagnostic

## Scope

This checkpoint records only redacted, read-only evidence from the stopped
R23 full run. It contains no Kubernetes object payloads, endpoints, UIDs,
resource versions, credentials, tokens, kubeconfigs, Pod or Node names, IP
addresses, or raw probe output.

## Bound execution

- Launch candidate: `sha256:ffafffe62f75f5a2f2eb7d9627feedb4c1bae11f113e2c48b2f8d9fb407f7345`
- Package: `sha256:3071b02569ad0548cd529c2dfd8ddad8d3e0e79ac60d909d0ee4a87e67f98cb0`
- Bundle: `sha256:e7404697d37e39e2f3d11d62d31eea9a21b3a8766b955662025239244beade06`
- Plan: `sha256:1ba659a672b343745352c74dbe95ec2a900852bc211b0ee4b11832b731a1ef57`
- Execution attempt: `sha256:e2c33db7466f4ae078dd87ce0733b4100aca887f4d8c490d205a9290a1db744c`
- Runner: `ghcr.io/openkubes/ok-cluster-runner@sha256:a29132fb09db8dff3fff4db300e2ed16c8965647277c4f116e15270b3a186fe9`

The create-only launch activated successfully. Provider prerequisites,
cluster lifecycle, lifecycle observation, and enablement completed
successfully. The executor then stopped fail closed at
`network-observation`. Runtime binding and every later stage were not
attempted.

## Read-only findings

The deterministic network-observation receipt was absent, proving that
source collection stopped before evaluation and immutable receipt
persistence. The executor log retained only the redacted stage boundary and
did not expose a raw source error.

The retained environment subsequently converged without runner repair:

- both expected Nodes were Ready;
- both Cilium agent Pods were Running and Ready;
- the agent, Envoy, and operator workloads were fully available;
- the single bound Helm release proxy was current and deployed; and
- the UID-bound functional Cilium probe succeeded without an explicit failed
  path.

The latest required HCP and HRP readiness transitions occurred 31 seconds
after the executor stopped. This excludes a persistent add-on or functional
network failure and classifies the stop as a transient CAAPH pre-ready source
shape that escaped the existing convergence normalization.

## Corrective boundary

The remaining schema-valid pre-ready representation not covered by the
collector was an explicitly `null` optional Conditions collection. The
collector now treats only an absent or explicitly null optional object
collection as empty. The evaluator therefore returns `Unknown`, the bounded
observer keeps polling, and no functional probe runs prematurely.

Non-null values of the wrong type, oversized collections, non-object members,
duplicate Conditions, foreign identities, transport failures, and failed
functional probes remain fail closed. The change adds no mutation, repair,
discovery, arbitrary query, or second-owner path.

## Verification

- `go test ./internal/observation`: PASS
- network and bounded-polling runner tests: PASS
- regression coverage includes explicit null HCP and HRP Conditions
- a non-array HCP Conditions value remains rejected

The full suite reaches only the three previously documented synthetic
client-certificate fixture failures under the developer workstation's Go
1.26.7 toolchain. All other packages pass, and the publisher continues to use
its pinned toolchain.
