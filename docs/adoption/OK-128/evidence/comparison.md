# OK-128 observed provisioning comparison

> Two sequential, controlled single runs. Observations only; no SLO claim.

| Milestone | Flatcar (s) | Talos (s) |
|---|---:|---:|
| `command_started` | 0 | 0 |
| `capi_cluster_created` | 7 | 3 |
| `api_reachable_control_plane_registered` | 96 | 212 |
| `first_node_ready` | 129 | 255 |
| `all_nodes_ready` | 180 | 264 |
| `cilium_daemonset_available` | 185 | 259 |
| `cilium_operator_available` | 119 | 250 |
| `capi_cluster_available` | 181 | 265 |
| `command_completed` | 189 | 265 |
| operator `real` | 188.22 | 264.04 |

## Management-cluster load

| Measurement | Flatcar before/after | Talos before/after |
|---|---:|---:|
| scheduled pods | 66/68 | 66/68 |
| running VMIs | 22/24 | 22/24 |

Order: flatcar then talos.
