# Standalone kagent deployment (OK-129)

Cluster-specific lifecycle for kagent on the disposable `ok-kagent` lab.

```bash
export OLLAMA_URL='<private endpoint>'

make preflight        # local tools, access config, openkubes assets
make access-summary   # what would the current profile grant?
make install          # kagent + the access profile
make verify-access    # prove the boundary against the API server
make status
make dashboard
make uninstall
```

`OLLAMA_URL` is substituted into `.values.local.yaml`, which is mode `0600` and
Git-ignored. Never place the private endpoint or credentials in the committed
template.

Helm is the recommended reproducible path. The kagent CLI install was exercised
once for OK-129 but is not the source of truth: its generated configuration is
less reviewable than versioned Helm values, `--profile minimal` still installs
Grafana-MCP and Querydoc, and `kagent uninstall` leaves the namespace behind.

## Permissions live in `access-config.yaml`

One file decides what the deployment may do. `make install` renders RBAC, the
scoped write tool server and the write Agent from it — nothing is configured by
hand, so nothing can drift out of sync with the documentation.

| Knob | Values | Effect |
|---|---|---|
| `mode` | `read-only` \| `read-write` | whether a write identity exists at all |
| `write.scope` | `namespaces` | cluster scope is refused by this installer |
| `write.namespaces` | `[kagent-lab]` | the only evidenced write target |
| `write.resources` | `[configmaps]` | the only evidenced mutable kind |
| `write.requireApproval` | `true` | Approve/Reject gate per write tool |

Switch a profile:

```bash
# diagnosis only
sed -i'' -e 's/^mode: .*/mode: read-only/' access-config.yaml
make install          # removes the write identity, Role, tool server and Agent

# approval-gated ConfigMap writes in the lab namespace
$EDITOR access-config.yaml   # mode: read-write; keep the constrained write block
make install
make verify-access
```

The cluster installer adds a fail-closed OK-129 guard before the generic
renderer. It refuses cluster scope, ungated writes, resources other than
ConfigMaps, and targets other than `kagent-lab`. The generic renderer's broader
schema therefore cannot silently widen this evidenced lab profile.

Full reference: `openkubes/platform/ai/kagent-standalone/access/README.md`.

## Where the boundary really is

Kubernetes calls are executed by the **tool server's ServiceAccount**, not by the
Agent pod. `toolNames`, `requireApproval` and the system prompt shape intent; RBAC
decides what is possible. `make verify-access` therefore asserts against the API
server rather than reading manifests:

- read identity: reads yes, writes no, Secrets no, wildcard no;
- write identity: every verb found in the rendered ConfigMap Role is tested in
  `kagent-lab`, denied outside it, and mutations of a representative
  non-configured workload resource remain denied;
- read-only mode: no label-owned write Agent, `RemoteMCPServer`, RBAC object, or
  write-tools namespace may exist.

The executable verification matrix is generated from the rendered Role, not
from a second permission list in the Makefile. A renderer or chart change that
quietly widens RBAC fails the target.

`make status` and every successful `make verify-access` write
`.access.local/evidence.json`. It records the `ok-cluster` commit, the coupled
`openkubes` asset commit, the access-config SHA-256 digest, both pinned chart
versions, dirty-worktree flags, and the observation result.

## Layout and prerequisites

Generic manifests and the renderer live in `openkubes`; only cluster-specific
values live here. The installer expects both repositories as siblings, or an
explicit path:

```bash
make install OPENKUBES_DIR=/path/to/openkubes
```

Local tools: `kubectl`, `helm`, `python3` with PyYAML. `make preflight` checks
them. The targets use POSIX tools plus python3 only — no ripgrep, no `envsubst`,
no BSD-only `stat` flags — so they behave the same on macOS and Linux.

Git-ignored, generated, never committed: `.values.local.yaml` (private endpoint)
and `.access.local/` (rendered access profile).
