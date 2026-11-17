# M3-UX-001 — CLI command routing, authority and M2b interoperability

**Status:** Proposed — requires architecture review (not effective as a behavioral change)  
**Date:** 2026-11-12  
**Issue:** [OK-226](https://kubernauts.atlassian.net/browse/OK-226)  
**Extends:** [ADR-Platform-034](https://github.com/openkubes/openkubes/blob/main/architecture/decisions/ADR-Platform-034-ok-up.md) (Proposed)  
**Related:** [OK-148](https://kubernauts.atlassian.net/browse/OK-148), [OK-147](https://kubernauts.atlassian.net/browse/OK-147), [OK-76](https://kubernauts.atlassian.net/browse/OK-76), [PR #475](https://github.com/openkubes/ok-cluster/pull/475)

## Context and evidence

The existing `ok` binary has **three distinct user-visible input/execution families**, not one interchangeable `Cluster` API:

1. `ok up`: `cmd/ok/command_aliases.go` rewrites the leading command prefix to `ok cluster create`. The `cluster create` dispatcher selects legacy technical manifest paths or the product `--file` workflow; the latter can prepare locally and stop while waiting for platform authorization. Existing route/security tests live in `cmd/ok/command_aliases_test.go`.
2. `ok cluster plan` / `ok cluster provision` / `ok cluster destroy`: the M2b **operator** path, validated for an existing compatible Talos/KubeVirt **Same-Plane** management/provider cluster. It accepts `cli.openkubes.io/v1alpha1` **`ClusterRequest`** with profile `talos-kubevirt-reference` and has a reviewed Make/Python lifecycle plus UID-bound schema-3 teardown evidence. The operator's explicit confirmation is **not** a policy authorization for the Contract Executor.
3. `ok preview`: an **offline-only** M3 prototype merged by PR #475. It invokes the existing `readClusterIntent` parser for `cli.openkubes.io/v1alpha1` **`Cluster`** with profile `talos-kubevirt-mvp`, not the M2b `ClusterRequest`. It reports `LOCAL_VALIDATION_ONLY` with a *local intent digest*, **not** a canonical OpenKubes Contract revision, approved plan, allocation, authority inspection, mutation, or readiness.

ADR-Platform-034 reserves the `./openkubes.yaml` authoring workflow and an authorized desired-state transition model, but explicitly **does not** finalize the public schema, `apiVersion`, `kind`, providers, or defaults. Therefore identical filenames do **not** make the three schemas interchangeable.

## Proposed decision

1. **`ok up` is the future product convergence UX**, under ADR-Platform-034. A planned `CreateCluster` transition requires canonical contract identity, comparison with **authoritative desired state**, an exact authorized transition, durable claim, atomic compare-and-swap acceptance, bounded execution, and independent outcome evidence. `NoOp` and unsupported transitions are distinct outcomes. A human confirmation cannot replace an independently verified Policy decision.
2. **Preserve deployed CLI routing while the product API is unsettled.** Do not change `canonicalProductArguments` or silently reinterpret `ok up --file` as Make-backed M2b provisioning. Publish explicit migration behavior and compatibility tests **before** any intentional reassignment.
3. **The M2b Same-Plane path stays an expert/operator path:** `ok cluster plan`, `ok cluster provision`, `ok cluster destroy`. It can be an eventual implementation/provider profile *only after* a reviewed adapter proves the same Contract/authorization/acceptance/evidence invariants. Do not promote M2b local evidence into authoritative desired-state acceptance by assertion.
4. **The M3 local preview is non-authorizing** and remains explicitly experimental. `ok preview` is suitable for safe CLI UX testing; its digest must not be named `contractRevision`, `transitionID`, `authorizationDigest` or an authoritative `planDigest`. It must not infer credentials or topology, invoke Make, or contact a cluster.
5. **Deletion is not a command alias.** Future product `ok down` means an accepted `DeleteCluster` transition to `DESIRED_ABSENT` followed by independently proven `CONFIRMED_ABSENT`. It must not map directly to `ok cluster destroy` before the separate delete contract and recovery model are accepted. The M2b teardown retains its independent original-UID, ledger and evidence gates.
6. **Same-Plane is a verified topology, not an automatic fallback.** Its management and provider APIs must resolve to the same *verified* infrastructure identity, while target workload APIs are independent. No implicit use of the current kubectl context, changed kubeconfig, or unrelated cluster. A separate management cluster (`ok-mgmt`) is *not required* for the already prepared Same-Plane M2b operator flow, but no general claim that arbitrary Kubernetes clusters are supported.
7. **Keep M4 separate:** a temporary `kind` bootstrap and subsequent CAPI pivot is not part of the M3 release or this ADR.

## Command compatibility matrix

| Command | Behavior on merged main (verified from source) | M3 product direction | Authority and mutation boundary |
| --- | --- | --- | --- |
| `ok preview [--file|-f]` | Experimental local `Cluster` intent parser; exact default `./openkubes.yaml` | May be superseded by an agreed public authoring schema | Offline, never mutates |
| `ok up ...` | Prefix-rewritten to `ok cluster create ...` | ADR-034 convergence command | **No unreviewed change**; future live acceptance requires independent authorization |
| `ok cluster create ...` | Product/technical bounded Runner paths | Internal/expert compatibility retained pending migration | Existing gates unchanged |
| `ok cluster plan -f ...` | M2b `ClusterRequest` read-only plan | Expert Same-Plane plan | Local validation only, not Policy authorization |
| `ok cluster provision ...` | M2b trusted Make-backed Same-Plane execution | Expert operator invocation | Existing confirmations, pinned identity and toolchain; no automatic fallback |
| `ok cluster destroy ...` | M2b evidence-bound teardown | Expert operator invocation | Original UID, schema-3 evidence and explicit approval |
| `ok validate` / `ok plan` | Not established as ADR-034 public commands by this decision | Reserved: validate canonical Contract / compare authoritative revision | Read-only; `ok plan` cannot invent Authority state |
| `ok status` | No ADR-034 product-status claim here | Reserved: desired state, execution, outcome, health separated | Read-only; health must not overwrite historical outcome |
| `ok down` | Not implemented as ADR-034 `DeleteCluster` | Reserved for authorized deletion | No direct teardown alias |
| `ok local up` | Dedicated local kind/demo lifecycle | Separate local developer flow | Must not be represented as production infra bootstrap |

## Input and authority contracts — explicit gaps

- **Input schema gap:** M2b `ClusterRequest/talos-kubevirt-reference` vs. legacy preview `Cluster/talos-kubevirt-mvp` vs. ADR-034 as-yet-unaccepted public Contract schema. *No automatic conversion* until a versioned schema/normalization decision and executable conformance tests exist.
- **Authority gap:** The M2b operator flow has a trusted lifecycle and teardown ledger, but this does not itself supply ADR-034 authoritative desired-state revision, approved `transitionID`, consumed grant, or atomic acceptance.
- **Adoption gap:** Existing M2b-provisioned clusters must not be interpreted as `ABSENT` merely because a new Authority Profile has no registered revision. A separate **Adopt/Import** operation or explicitly reviewed out-of-band registration may be required. Until specified, **reject** such ambiguity; never issue duplicate `CreateCluster`.
- **Confirmation gap:** Reducing two M2b interactive gates to one requires the pre-confirmation reviewed plan and all post-confirmation values to be immutable and reverified at point of use, or the existing extra gate must remain. This is a **future proof obligation**, not a cosmetic UI change.
- **Provider/identity gap:** Establish explicit supported runtime profiles and target identity proof before any profile-independent `ok up` promise.
- **Recovery gap:** Do not automatically retry, roll back or clean up an accepted/indeterminate transition. Recovery must inspect authoritative acceptance and durable evidence, per ADR-034.

## First implementation and conformance order

1. **Now (M3.1):** keep existing routing regression tests green; retain explicit `ok preview` as offline experiment; write and review this proposal. A draft PR is documentation, **not architecture acceptance**.
2. **Next:** freeze a versioned `openkubes.yaml` authoring schema and its deterministic canonicalization test vectors. Define whether/how it converts into existing profile-specific `ClusterRequest` or an accepted OpenKubes Contract. Never fork canonicalization logic.
3. **Then:** implement read-only `ok validate` and authority-aware `ok plan` only with an agreed Authority Profile contract. No fabricated revision when Authority is unavailable.
4. **With OK-147/OK-148:** prove authorized `CreateCluster` / `NoOp` end-to-end, including stale predecessor, unknown prior ownership, independent executor authorization, exactly-once claim and CAS acceptance, evidence correlation and interrupted execution.
5. **Later:** independently specify `DeleteCluster` /`ok down` as a desired-state transition, not a wrapper around destructive M2b scripts; run explicit failure/retention tests.
6. **Release gates:** independent security review, verified artifact/signing/install path and human acceptance, plus disposition of the five supplementary QEMU teardown investigations, remain required.

## Acceptance tests for any future routing change

- Alias prefix and flags remain byte-for-byte stable unless intentionally versioned; existing `command_aliases_test.go` continues to pass.
- Missing `./openkubes.yaml` never triggers parent traversal or a different default file; duplicate `--file/-f`, malformed YAML and symlinks fail without opening authority or Make.
- A locally computed digest is never labeled as approved Contract revision or authorization.
- Missing Policy Authority does **not** fall back to `ok cluster provision`.
- M2b operator confirmations remain enforced; one `ok up` terminal confirmation never bypasses Policy/CAS.
- Stale plans, changed kubeconfig identities and unknown preexisting clusters fail closed.
- Product deletion never bypasses durable `DESIRED_ABSENT`, cleanup checks, or preserved evidence.
- The CLI does not create a second Kubernetes reconciler, Contract-to-CAPI compiler or desired-state writer.

## Consequences

**Positive:** one eventual human-friendly command vocabulary with clear trust boundaries, preservation of the accepted M2b operator proof, compatibility with the ADR-034 convergence design, and no premature public-schema commitment.

**Trade-offs:** M3 cannot honestly promise a live one-command `ok up` for arbitrary infrastructure until the Policy Authority and canonical Contract integration have proven conformance. This is deliberate, testable scope control.

**Decision request:** Review this proposal jointly with OK-147 and OK-148 owners. Upon acceptance, update the owning ADR-034 with the approved compatibility and adoption boundaries. Do **not** change the runtime command routing by accepting this document alone.
