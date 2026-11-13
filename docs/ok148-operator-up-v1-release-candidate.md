# OpenKubes CLI v1.0 candidate — operator-mode `ok up`

**Candidate only:** this change does not constitute a v1.0.0 release or independent cluster conformance evidence.

## Supported first-slice workflow

```bash
make ok-cli-build
.tools/bin/ok up -f ~/clusters/preview-one.yaml --management <management-kubeconfig>
# or: export TALOS_INFRA_KUBECONFIG=<management-kubeconfig>; .tools/bin/ok up
```

`ok up` with a `kind: ClusterRequest` file (or without arguments in a terminal,
using `<ok config>/requests/`) is a thin UX layer over the same provisioning
engine. `<ok config>` is `$XDG_CONFIG_HOME/ok`, else `~/.config/ok`, on every OS
(paths passed to Make must be shell-safe, so macOS "Application Support" is not
used). Defaults: workload kubeconfig `<ok config>/kubeconfigs/<name>.yaml`; Make
output goes to a private 0600 log in `<ok config>/logs/`, created only after the
first typed confirmation. The log is raw Make output and may contain sensitive
information; nothing is masked. Directories are created with mode 0700 only when
`ok up` runs; existing permissions are never changed. The management kubeconfig
must name exactly one explicit current context.
The management cluster must be chosen explicitly (`--management` or
`TALOS_INFRA_KUBECONFIG`); `KUBECONFIG` and the current context are never used.
Output is concise by default; `-v` shows technical details and streams Make output live instead of writing a log.
Legacy `kind: Cluster` manifests keep the Runner route. The explicit form below
is unchanged:

```bash
.tools/bin/ok up --mode operator --topology same-plane \
  -f /private/path/cluster.yaml \
  --workload-kubeconfig /private/path/<cluster>.yaml
```

Input must be the existing `cli.openkubes.io/v1alpha1` **ClusterRequest**, with `spec.profile: talos-kubevirt-reference`, **not** the proposed ADR-034 `./openkubes.yaml` Contract. The supported topology is explicit `same-plane`; the output kubeconfig path must be private and unused.

The command invokes the **existing** `runClusterPlan` once (non-mutating offline preview), then the **existing** `runClusterProvision` once (real preflight, two exact operator confirmations and controlled Make new/bootstrap). No shelling out to `ok` CLI and no second contract renderer. All authority, target, dependency, private path and cancellation checks remain implemented in the existing provision function, **not** duplicated in the wrapper.

The preview is not a mutation grant, a signed policy authorization or proof that network allocation/cluster resources are available. The provisioning function must re-read the original request and re-validate its trusted runtime inputs before mutation; concurrent changes must stop rather than using the preview as authorization.

**Operator mode is not ADR-034 convergence.** There is no automatic NoOp if a cluster already exists, no CAS desired-state acceptance, no signed Policy/Single-Use Claim, and no autonomous retries. The separate `ok cluster create` guided Runner path and `ok cluster destroy` remain unchanged. There is no `ok down` alias.

## Release v1.0.0 gate — Do not tag before evidence

1. New CLI wrapper unit/negative tests pass in PR CI; existing repository-wide tests, vet, build and CLI help smoke checks pass.
2. Independent operator tests on reviewed macOS/Linux CLI environment, with the actual release candidate CLI binary, correct pinned sources and tools.
3. On prepared disposable `ok-infra` Same-Plane infrastructure: operator executes `ok up --mode operator` once, both confirmations happen, independently verified cluster readiness, failure/cancellation evidence and teardown proof are retained.
4. Review disposition of existing QEMU teardown-check failures and outstanding M2b/OK-147/ADR compatibility risk. No silent conversion of a human operator confirmation into independent Policy/CAS authority.
5. Versioned installer, binary provenance/signing, release asset integrity and platform compatibility verified. Explicit human release approval only after the checks.

v1.0.0 may deliberately describe a **narrow stable operator workflow**, not promised general cluster convergence, autonomous AI operations, Scale/Upgrade/Delete or multi-provider support. The published release notes and help must accurately state this restricted API/feature scope.

Related: OK-76, OK-148, OK-226 and ADR-Platform-034 (Proposed).
