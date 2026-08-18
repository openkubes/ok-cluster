# OK-147 evidence-based ADR-030 amendment proposal

This document proposes review changes to the still-`Proposed` ADR-030. It does
not edit or accept that ADR. The proposal is based on the OK-141 execution
evidence and the OK-147 bounded-runner implementation.

## Evidence conclusion

The spike has not proven a need for a broad OpenKubes-owned lifecycle
reconciler. The smallest supported model is:

```text
Contracts / Profiles
        -> external policy and authorization
        -> bounded, replaceable Contract Executor
        -> CAPI/CAPK and existing controllers
        -> selected Enablement controller
        -> selected GitOps controller
        -> generation- and revision-aware bounded evaluator
        -> durable evidence
```

The executor may run locally or as an ephemeral Job. Its termination does not
stop controller reconciliation, and its exit status is not readiness.

## Proposed changes before ADR acceptance

### 1. Specify an aggregate-result invariant, not a mandatory component

Replace the mandatory continuously running **OpenKubes Status Aggregator** with
a requirement for one deterministic, profile-aware aggregate result. A bounded
read-only evaluator is sufficient while the known consumers are CLI status,
wait, execution completion, evidence collection and troubleshooting.

If a future real consumer requires continuously updated Kubernetes Watch,
transition history or a durable normalized status API, a small single-writer
status adapter may be introduced through separate evidence and review. It must
only observe, correlate, normalize and publish; it must not repair source
resources.

For any persisted normalized status surface, the ADR's single-writer rule
continues to apply. Without such a surface there is no aggregate-status writer,
but every source Condition still has exactly one authoritative owner.

### 2. Describe Enablement as a responsibility, not a preselected controller

Replace wording that requires a new **Cluster Enablement Controller** with a
requirement that one selected existing mechanism own E convergence and expose
current, revision-correlated evidence. The spike's CAAPH/Helm path demonstrates
that existing controllers can own desired package convergence while Cilium and
Kubernetes provide runtime NetworkReady observations.

OpenKubes deterministically constructs E and evaluates its proof. It does not
need to duplicate Helm/CNI correction in a new package reconciler.

### 3. Make the bounded executor the implementation-neutral requirement

ADR-030 should require the executor properties rather than one deployment
shape: typed operations, external authorization, single-use consumption,
least privilege, durable evidence, stop-on-partial behavior and no independent
lifecycle truth. A CLI, CI process or ephemeral Job may implement those
properties. A continuously running OpenKubes operator is not required by the
current evidence.

### 4. Align Condition naming with authoritative sources

Use current CAPI `ControlPlaneAvailable` semantics rather than freezing the
historical `ControlPlaneReady` name. Normalized results must preserve source
reason/message detail and reject stale, missing, conflicting or wrong-revision
evidence. `Ready` remains derived and must never be asserted independently.

### 5. Preserve ownership and recovery boundaries

The amendment must retain these constraints:

- CAPI/CAPK own infrastructure and cluster lifecycle convergence;
- the selected Enablement mechanism owns E convergence;
- GitOps owns P convergence, drift detection, retry, prune and self-heal;
- the evaluator never remediates those sources;
- at most one management plane holds lifecycle write authority; and
- ADR-031 separately owns fencing, restore, promotion and orphan recovery.

Any proposal in which OpenKubes repairs CAPI, Helm/CNI or GitOps state in
parallel with its existing owner is a duplicated-writer architecture and must
be rejected.

## Acceptance impact

ADR-030 must not move to `Accepted` merely because the bounded runner compiles
or one happy path succeeds. Acceptance still requires reviewed evidence for:

- exact R/E/P and authority correlation through the complete forcing workflow;
- current-generation lifecycle, NetworkReady and PlatformReady results;
- executor termination/restart without loss of convergence or evidence;
- stale, missing, wrong-revision and conflicting-authority negative controls;
- controlled deletion with independently retained terminal evidence;
- security/RBAC and credential-lifetime conformance; and
- the management-plane-outage scenario, while ADR-031's fencing proof remains
  separate.

The status-aggregator and dedicated-enablement-controller acceptance clauses
should therefore become evidence invariants rather than mandatory component
checks. This keeps ADR-030 about contracts and ownership while allowing the
implementation spike to determine the minimum required components.
