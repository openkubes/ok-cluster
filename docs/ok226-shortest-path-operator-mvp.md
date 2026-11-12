# OK-226 / OK-148 — shortest safe path to useful cluster automation

**Decision proposal for review (2026-11-12).** This document does not change CLI routing, grant new permissions or claim ADR-034 acceptance.

## What the code actually does today

| Command | Input | Current ownership and behavior | Decision |
| --- | --- | --- | --- |
| `ok cluster plan -f <request.yaml>` | `cli.openkubes.io/v1alpha1` `ClusterRequest` | Read-only Talos/KubeVirt reference profile preview; does **not** validate live infrastructure availability or grant authorization | Reuse now |
| `ok cluster provision -f <request.yaml> --topology same-plane --workload-kubeconfig <private-path>` | Same `ClusterRequest` | M2b trusted-operator lifecycle; checks reviewed local dependencies and cluster absence; prints plan; requires exact `provision <name>` confirmation, executes reviewed `make new`; validates scaffold/identities; requires exact `bootstrap <name>` confirmation, executes reviewed `make bootstrap`; preserves evidence and stops on failure | **First operator MVP: use as-is**, improve documentation and setup UX only |
| `ok cluster create -f <manifest.yaml>` | Existing distinct Cluster intent / Runner workflow | Authority/Runner preparation and guided platform handoff, not interchangeable with M2b `ClusterRequest` | Preserve without redirect |
| `ok up` (ADR-034 target) | `./openkubes.yaml` proposed | Authoritative desired-state `CreateCluster`/`NoOp` convergence with independently verified Policy, CAS, claim, execution and evidence; currently not an M2b alias | **Do not silently alias** to provision |
| `ok cluster destroy` | Explicit operator teardown | Independent safety and absence-evidence contract | Keep independent from proposed `ok down` |

The current M2b CLI already automates **both Make stages and most safety checks**. It needs operator-provided, reviewed sources, configuration and credentials; it is intentionally not a zero-config or autonomous operation. Its `ClusterRequest` is not ADR-034 `openkubes.yaml`.

## Shortest path, in order

1. **Use the existing CLI now.** Provide one short operator quickstart: reviewed `make ok-cli-build`, a minimal `ClusterRequest` for `talos-kubevirt-reference`, `ok cluster plan -f ...`, and the explicit `ok cluster provision` command above. Explain local sources, trust, preflight failures, the two confirmations, private workload kubeconfig destination and cleanup rules. No new provisioning backend.
2. **One UX slice only after a focused gap test.** Audit a clean macOS/Linux operator setup with a prepared `ok-infra`, then implement only failures that prevent completion or require redundant manual entry. Favor non-mutating diagnostics and precise actionable error messages, not bypasses, hidden credential selection or replay.
3. **Keep ADR-034 `ok up` separate.** Implement proposed exact `./openkubes.yaml` validation/plan first with `mutationAllowed=false`. Real `ok up` execution under OK-148/OK-147 requires reviewed policy/authority/claim/CAS integration and no second lifecycle path.
4. **Hold the broader OK-226 Authority prototypes.** No new anti-rollback/retention/CAS-writer PR until a separate architecture review decides whether and where an independent trust boundary is needed for the convergence product.

## Operator quickstart (prepared environment only)

Prerequisites: reviewed `ok-cluster` and `ok-linux` sources, required pinned tooling/chart, dedicated `ok-infra` management kubeconfig and a private, unused destination for the workload kubeconfig. Do not infer access from the default `kubectl` context.

```bash
# From the reviewed ok-cluster checkout:
make ok-cli-build

# Validate the request offline (no Kubernetes mutation):
.tools/bin/ok cluster plan -f /path/to/cluster-request.yaml

# Run the existing trusted-operator lifecycle; two deliberate confirmations:
.tools/bin/ok cluster provision \
  -f /path/to/cluster-request.yaml \
  --topology same-plane \
  --workload-kubeconfig /private/path/<cluster>.yaml
```

The request is `apiVersion: cli.openkubes.io/v1alpha1`, `kind: ClusterRequest` with `metadata.name` and `spec.profile: talos-kubevirt-reference`. A valid offline plan is **not** a readiness or authorization certificate; live provisioning may still refuse to proceed.

**Preserve safety behavior:** no automatic retry after partially completed `make new` or bootstrap; no inferred target or credentials, no forced adoption, no unreviewed full-admin context, and no unverified `ok down`/destroy alias.

## Scope / acceptance for an operator usability release

- On prepared Same-Plane Talos/KubeVirt infrastructure, one supported `ok cluster provision` invocation drives the existing `make new` and `make bootstrap` path with all current checks and approvals.
- Failure before confirmation causes **zero** Make stages; after a partial failure evidence/scaffold is retained and no implicit retry or cleanup is performed.
- Existing CLI tests and independent live cluster readiness/absence checks continue to pass.
- Documentation explicitly states that `ok cluster provision` is trusted operator automation, **not** autonomously authorized `ok up` convergence.
- Beta packaging/signing, outstanding QEMU teardown failures and independent release-artifact validation remain separate release blockers; this documentation is not a beta release approval.

**Related:** OK-76 M2b, OK-147 bounded Executor, OK-148 first `ok up` Convergence, OK-226 M3.1 routing review, ADR-Platform-034 (Proposed).
