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
| `write.resources` | resource-to-verb mapping | exact namespaced API verbs kagent may use |
| `write.requireApproval` | `true` | Approve/Reject gate per write tool |

Switch a profile:

```bash
# diagnosis only
sed -i'' -e 's/^mode: .*/mode: read-only/' access-config.yaml
make install          # removes the write identity, Role, tool server and Agent

# approval-gated writes for selected kinds in the lab namespace
$EDITOR access-config.yaml   # mode: read-write; set write.resources per kind/verb
make install
make verify-access
```

The cluster installer adds an independent fail-closed OK-129 guard before the
shared renderer. Both layers refuse cluster scope, ungated writes, unsupported
or sensitive resources, and targets other than `kagent-lab`. Supported kinds
are ConfigMaps, Pods, Services, Deployments, StatefulSets, DaemonSets,
ReplicaSets, Jobs, CronJobs and Ingresses; each selected kind receives only the
verbs explicitly configured for it.

Full reference: `openkubes/research/kagent-standalone/access/README.md`.

## Where the boundary really is

Kubernetes calls are executed by the **tool server's ServiceAccount**, not by the
Agent pod. `toolNames`, `requireApproval` and the system prompt shape intent; RBAC
decides what is possible. `make verify-access` therefore asserts against the API
server rather than reading manifests:

- read identity: reads yes, writes no, Secrets no, wildcard no;
- write identity: every verb found in the rendered Role is tested in
  `kagent-lab`, denied outside it, and mutations of a representative
  non-configured workload resource remain denied;
- read-only mode: no write Agent, `RemoteMCPServer`, RBAC object, write-tools
  namespace or `kagent-tools` release may exist.

The executable verification matrix is generated from the rendered Role, not
from a second permission list in the Makefile. A renderer or chart change that
quietly widens RBAC fails the target.

## Removing a write profile

`make install` on a read-only profile removes the previous write path, and does
not trust the profile that replaced it. Managed objects are found by ownership
label and deleted by the names the API returns, so a previous profile with a
different release, namespace or Agent name is still removed.

An automatically removable tool-server namespace must be grounded in one of two
ownership paths:

1. the `openkubes.io/purpose=kagent-write-tools` label;
2. the exact ServiceAccount namespace and name in a discovered OK-129
   RoleBinding or ClusterRoleBinding.

A cluster-wide Helm chart-name match is deliberately **not** a third ownership
path. `kagent-tools-*` releases outside those two paths are printed as unowned
candidates for manual confirmation and are not uninstalled; their namespaces
are never deleted. This avoids treating another team's use of the same upstream
chart as an OK-129 leftover.

Objects from before the `managed-by` label are also found by their older
`part-of` + ticket labels. The read-only `cluster-inspector` shares those labels,
so legacy Agent discovery additionally requires a write-server reference or an
approval-gated tool reference.

Release removal and namespace deletion are separate decisions. Every
ownership-proven write-tools release is uninstalled, including a historical
release that ran directly in `kagent-lab`; only a positively identified,
unprotected tool-server namespace is deleted. The install namespace and write
targets are derived from the discovered objects and never deleted, as are
`default` and `kube-*`.

Afterwards the former ServiceAccount identity is re-tested for every mutating
permission it used to hold. `kubectl auth can-i` reports a denial as exit
status 1, which is the answer this check wants — the installer reads the printed
answer and only treats other exit codes as a failure.

`profile.env` is generated and then sourced by the Makefile, so both the config
and the generated file are constrained: names must be plain DNS labels, and
`make render-access` refuses a `profile.env` line that is anything other than a
quoted or bare assignment.

`make status` and every successful `make verify-access` write
`.access.local/evidence.json`. It records the `ok-cluster` commit, the coupled
`openkubes` asset commit, the access-config SHA-256 digest, both pinned chart
versions, dirty-worktree flags, and the observation result.

## Layout and prerequisites

Generic manifests and the renderer live in `openkubes` under
`research/kagent-standalone`; only cluster-specific values live here. The
installer expects both repositories as siblings, or an explicit path:

```bash
make install OPENKUBES_DIR=/path/to/openkubes
```

Local tools: `kubectl`, `helm`, `python3` with PyYAML. `make preflight` checks
them. The targets use POSIX tools plus python3 only — no ripgrep, no `envsubst`,
no BSD-only `stat` flags — so they behave the same on macOS and Linux.

Git-ignored, generated, never committed: `.values.local.yaml` (private endpoint)
and `.access.local/` (rendered access profile).
