# v1.0.1 + compatibility patch (`compat/v1.0.1-scaleway`)

**Status:** prepared for review only. Not merged to main, not released and not deployed. Every run that uses it
must be reported as **"v1.0.1 + compatibility patch"**, never as an unmodified v1.0.1 run.

## Why

The v1.0.1 Talos/KubeVirt reference profile pins two lab-specific values:
- **The node name.** VMs of the scheduling profile `ok-infra` must run on a Kubernetes node named `ok-infra`.
- **The endpoint pool.** Workload API endpoints are allocated from `192.168.100.200-254`, which is the production
  vSwitch range.

The Scaleway lab has the nodes `scw1`/`scw2`, which must not be renamed, and must not reuse the production range.

## What changes

There are two optional operator variables. **When both are unset, behaviour is identical to v1.0.1.** The tests
prove that rendered Talos and Ubuntu manifests are byte-identical, and that the Go and Python suites produce
identical results.

| Variable | Effect |
|---|---|
| `OK_COMPAT_PHYSICAL_NODE=<node>` | VMs of the logical profile `ok-infra` are placed on `<node>` (`kubernetes.io/hostname`). The Talos lifecycle checks look up that node: scheduling/capacity, VM nodeSelectors, Longhorn eligibility and VMI placement. PVC selected-node annotations use it as well. |
| `OK_COMPAT_ENDPOINT_POOL=<first>-<last>` | Replaces the endpoint pool constants. The pool may hold at most 256 IPv4 unicast addresses and must lie outside the workload Pod/Service CIDR pools `10.32.0.0/11` and `10.96.0.0/12`. |

**Unchanged:**
- the logical profile name and `nodeSelector` in `cluster-config.yaml`;
- the provider identity digest and the CLI's fixed-reference scaffold check;
- the storage contract (`ok-storage-block`, 2 replicas, snapshot class);
- the ok-linux pin, the Golden Image identity, the Cilium chart digest, the two typed confirmations and all other
  CLI checks.

**Where it is implemented:**
- `profile_resolvers/compat.py`: the only interpreter of the variables, with strict validation.
- `render.py`: the endpoint pool and the template placement value.
- `scripts/talos_golden_lifecycle.py`: four physical-node comparisons.
- `Makefile`: the `annotate-pvcs` node.
- `cmd/ok/compat_scaleway.go`: passes the variables through the child-environment allowlist only when they are
  valid; an invalid value refuses before anything runs; a `COMPATIBILITY MODE` banner appears in the provisioning
  plan.

**Not covered:**
- **Flatcar:** `scripts/flatcar_lifecycle.py` keeps its v1.0.1 `ok-infra` checks, so a Flatcar run with
  `OK_COMPAT_PHYSICAL_NODE` fails closed.
- **Talos-mgmt and the `ok-gpu` profiles** are not remapped.

## Use (Scaleway lab)

```bash
export OK_COMPAT_PHYSICAL_NODE=scw2 OK_COMPAT_ENDPOINT_POOL=10.250.0.10-10.250.0.20
ok up -f <cluster.yaml> --management <private-kubeconfig> --workload-kubeconfig <private-dir>/<cluster>.yaml
```

Build the CLI from this branch with `make ok-cli-build`, so that it runs from the exact checkout it was built from.

## Tests

`tests/compat_scaleway_test.py` (set `COMPAT_REFERENCE_JSON` to a render produced by the unpatched v1.0.1 tree
for the byte-identity check) and `cmd/ok/compat_scaleway_test.go`.
