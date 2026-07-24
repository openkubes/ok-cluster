# OK-106 Proof A — structural factorization (reviewable draft)

**Scope:** provider selection only, `openkubes/ok-cluster`. No provisioning, no XRD/runner/`capi-platform-v4.2` change, no API decision. `endpointIP` and Kubeadm→Talos remain marked Proof-B TODOs.

**Base commit (openkubes/ok-cluster@main):** `b991898808e3d4d00fe13f3da42e6f2c4849e843`

## What changed

1. **`templates/talos-mgmt/bootstrap-mgmt.sh.tpl`** — factored. Step 4 `clusterctl init` now uses `--infrastructure ${INFRA_PROVIDER}` (rendered kubevirt|openstack). Provider-neutral waits (`capi`, `cacppt`) stay in the main script. The provider-specific controller wait + infrastructure preparation moved to a sourced fragment (Step 5: `source "$(dirname "$0")/provider-infra.sh"`).
2. **`templates/talos-mgmt/providers/kubevirt/provider-infra.sh.tpl`** — new. Contains the original CAPK wait + `external-infra-kubeconfig` secret block, behaviour unchanged.
3. **`templates/talos-mgmt/providers/openstack/provider-infra.sh.tpl`** — new. Waits for `capo-system`; asserts an OpenStack credentials Secret (clouds.yaml / application credentials) as a prerequisite — no new credential API. Carries the two Proof-B TODO markers.
4. **`render.py`** — minimal: adds `INFRA_PROVIDER` to the render context (`cfg.provider`, default `kubevirt`) and selects the provider fragment dir the same way `type` already selects its dir. Unknown provider -> hard error.

The provider profile representation reuses the existing "template dir per selector" mechanism (`templates/talos-mgmt/providers/<provider>/`) — no new repo-wide structure, and because only the selected provider's fragment is rendered, provider-specific blocks never leak into the other provider's output.

## Static validation — 17/17 PASS

| # | Assertion | Result |
|---|-----------|--------|
| 1-4 | `bash -n` on all four rendered scripts (CAPK + CAPO x main/fragment) | PASS |
| 5-8 | No unresolved `${CLUSTER_NAME}` / `${INFRA_PROVIDER}` placeholders | PASS |
| 9 | CAPO main contains `--infrastructure openstack` | PASS |
| 10 | CAPO rendering contains no `capk-system` | PASS |
| 11 | CAPO rendering contains no `external-infra-kubeconfig` | PASS |
| 12 | CAPO rendering contains no `--infrastructure kubevirt` | PASS |
| 13 | CAPO fragment waits for `capo-controller-manager` | PASS |
| 14 | CAPK main contains `--infrastructure kubevirt` | PASS |
| 15 | CAPK fragment retains `external-infra-kubeconfig` | PASS |
| 16 | CAPK fragment retains CAPK rollout restart | PASS |
| 17 | No provisioning verb (`clusterctl generate`) introduced | PASS |

## Deliberate, transparent deviations (for review)

- **CAPK is functionally identical, not byte-identical.** The CAPK path now `source`s `provider-infra.sh` instead of inlining Step 5; the same commands run in the same shell (`set -euo` and `log/ok/fail` inherited). Relative order of two independent readiness waits changed (`capk` now waited in the fragment, after `cacppt`) — no behavioural effect.
- **Done-banner text:** the final "Next steps" example line was generalized from `Submit a KubeVirtClusterClaim ...` to `Submit a cluster claim ...` (echo-only; removes an incidental provider string from the banner). The XRD/claim kind itself is untouched — its KubeVirt-specific naming remains a Proof-B decision.
- **`--control-plane talos` kept as-is.** The Kubeadm->Talos coupling lives in the `capi-platform-v4.2` runner, not in this bootstrap; not touched here.

## Explicitly NOT done (Proof B)

- No change to the XRD, Composition, or `capi-platform-v4.2` runner.
- `endpointIP` (MetalLB vs Octavia/floating IP) — TODO marker only.
- Control-plane provider (KubeadmControlPlane vs Talos) — TODO marker only.
- No provisioning, no real OpenStack environment touched.

## Files in this delivery

- `diff-tracked-vs-b991898808e3.patch` — diff of the two tracked files vs base.
- `source-changes/` — the factored template, two new provider fragments, patched `render.py`.
- `rendered/capk/` and `rendered/capo/` — the two rendered bootstrap outputs (statically validated).
