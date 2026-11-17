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

## Backward compatibility

Both overrides are opt-in and additive:
- **Unset (the default):** v1.0.1 behaviour, unchanged for every cluster type (Talos, Talos-mgmt, Ubuntu, Flatcar).
  Rendered Talos and Ubuntu manifests are byte-identical to v1.0.1; the Go and Python suites give identical results.
- **Set but invalid:** the CLI refuses before anything runs; the Python entry points raise `CompatError`. An invalid
  value never silently falls back to the v1.0.1 constants.
- **Each override is independent:** the physical-node override does not change the endpoint pool, and the
  endpoint-pool override does not change node placement.
- **No new required input:** no variable, flag, file or configuration key becomes mandatory. The logical profile name
  `ok-infra` remains the contract in `cluster-config.yaml`.

## Support matrix with the overrides

| Cluster type | Overrides unset | `OK_COMPAT_PHYSICAL_NODE` and/or `OK_COMPAT_ENDPOINT_POOL` set |
|---|---|---|
| Talos (`ok up`, Make) | v1.0.1, unchanged | supported by this patch; target of the Scaleway E2E run (not yet run) |
| Ubuntu (Make) | v1.0.1, unchanged | rendered by this patch; not yet validated end to end |
| **Flatcar (Make)** | **v1.0.1, unchanged and still supported** | **not supported yet** |
| Talos-mgmt, `ok-gpu` profiles | v1.0.1, unchanged | not remapped; not supported |

**Flatcar is not supported with the overrides yet.** Flatcar Make workflows are unchanged when the overrides are unset:
this patch does not remove, disable or alter Flatcar support. Only the combination "Flatcar + override" is
unsupported, because `scripts/flatcar_lifecycle.py` keeps its v1.0.1 checks against a node named `ok-infra` and has
not been validated with a different endpoint pool. A Flatcar run with `OK_COMPAT_PHYSICAL_NODE` set fails closed in
those checks; a Flatcar run with only `OK_COMPAT_ENDPOINT_POOL` set is untested and must not be used. Extending the
Flatcar lifecycle is a separate, later change.

## Use (Scaleway lab)

```bash
export OK_COMPAT_PHYSICAL_NODE=scw2 OK_COMPAT_ENDPOINT_POOL=10.250.0.10-10.250.0.20
ok up -f <cluster.yaml> --management <private-kubeconfig> --workload-kubeconfig <private-dir>/<cluster>.yaml
```

Build the CLI from this branch with `make ok-cli-build`, so that it runs from the exact checkout it was built from.

## Tests

`tests/compat_scaleway_test.py` (set `COMPAT_REFERENCE_JSON` to a render produced by the unpatched v1.0.1 tree
for the byte-identity check) and `cmd/ok/compat_scaleway_test.go`.

## Talos image re-pin (ok-linux `compat/talos-v1.9.6-repin-scaleway`)

Image Factory no longer serves the byte-identical Talos v1.9.6
`openstack-amd64.qcow2` pinned by ok-linux `a1687263` (sha256 `461d72d30750…`).
For the Scaleway compatibility build the CLI pins the ok-linux re-pin commit
`0e9ecdcd6317bcfc27fa623295f464972697d4a5`, which changes only the boot
artifact digest and what derives from it:

| | v1.0.1 (unchanged) | compatibility build |
|---|---|---|
| qcow2 sha256 | `461d72d30750b9e18cf0656239e0274764b1e391bde5bbc41084a887b8a55ed5` | `11d7cbe34417199e6bad2fe455b79eb4e6c5e51d455be561aa686d317bf2b364` |
| OS identity | `sha256:7f5dd4276432f522727a50e604538b6befc0cac51ee2b90d4b1ccbfcac774a2d` | `sha256:bd10742249caf9437168b59f119f42834cb313597dc10a4310629be78723a1e7` |
| Golden PVC | `ok-images/talos-v1-9-6-ce4c980550dd-461d72d30750-amd64` | `ok-images/talos-v1-9-6-ce4c980550dd-11d7cbe34417-amd64` |

Talos version, schematic, URL and size are unchanged. Runs with this build are
reported as "OK CLI v1.0.1 + Scaleway compatibility patch with Talos image
re-pin". Historical fixtures and evidence keep the v1.0.1 values.
