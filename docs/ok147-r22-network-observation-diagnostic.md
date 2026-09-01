# OK-147 R22 network-observation diagnostic

## Scope

This checkpoint records only redacted, read-only evidence from the stopped
R22 full run. It contains no Kubernetes object payloads, endpoints, UIDs,
resource versions, credentials, tokens, kubeconfigs, Pod or Node names, IP
addresses, or raw probe output.

## Bound execution

- Launch candidate: `sha256:b4cdbbe3e6bcc862deae6512ec5608325376ef8fce032efc90b3d3d3fcfea66c`
- Package: `sha256:b722b2f85cc3db048d14faa82875a245b3d24dae25240931b19071fc684c9315`
- Bundle: `sha256:401f5633e0fe6c261f10f5f6c042ed407632bf18efc39ea77304742ffac33908`
- Plan: `sha256:aee818c3699f6657a214ee5fd216bd0ad50c223ff1502328df61f665b61114b4`
- Execution attempt: `sha256:027922ac87de8e37f0f087f51267193ba6c05bc94e0352a3b300f0b010f14adb`
- Runner: `ghcr.io/openkubes/ok-cluster-runner@sha256:8b8a5555f6ab2f2c2efc13c330cba2174931dd2703efc2cd7ccf4807265d667e`

The create-only launch activated successfully. Provider prerequisites,
cluster lifecycle, lifecycle observation, and enablement completed
successfully. The executor then stopped fail closed at
`network-observation`. Runtime binding, target access, target credentials,
target registration, platform applications, platform observation, and
aggregate evidence were not attempted.

## Read-only findings

The executor stopped less than three minutes after Job start, during the
transition from lifecycle convergence to Cilium readiness. The add-on source
became ready shortly afterwards and the CAPI Cluster then reported all bound
availability Conditions as true.

A bounded diagnostic of the retained disposable Cluster found:

- two of two Nodes Ready;
- two of two Cilium agent Pods Running and Ready, with no restarts;
- the agent, Envoy, and operator rollouts fully available at their exact
  digest-pinned images;
- exactly one deployed and Ready Helm release proxy; and
- one UID-bound functional Cilium probe with two Nodes, eight fresh paths,
  and successful latency-bearing results for every path.

This excludes a persistent Cilium, image, rollout, Node-readiness, and
functional-connectivity failure. The stop occurred while Kubernetes was
publishing the two Node network Conditions independently. The collector
already treated an entirely absent Condition set as convergence, but treated
an intermediate one-of-two set as an operational source error. The bounded
poller therefore stopped instead of waiting for the second Condition.

## Corrective boundary

The collector now preserves whichever of `Ready` or `NetworkUnavailable` is
already present and normalizes only the missing half to an empty value. The
existing readiness gate keeps the functional probe closed and the evaluator
returns `Unknown` until both Conditions prove the expected state.

This does not weaken a terminal invariant: duplicate Conditions, foreign
identities, invalid field types, transport failures, probe failures, image
mismatches, and failed functional paths remain fail closed. It adds no
mutation, repair, discovery, arbitrary query, or second-owner path.

## Verification

- `go test ./internal/observation`: PASS
- direct Network-/Polling-runner tests: PASS
- regression coverage includes both publication orders for the two Node
  network Conditions and confirms that no functional probe runs early
- duplicate Node Conditions remain a hard source error

The broad runner suite still exposes the three previously documented
synthetic client-certificate fixture failures under the developer
workstation's Go 1.26.7 toolchain. The affected Network-/Polling tests pass;
the published runner remains built by the pinned publisher toolchain.
