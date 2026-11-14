# OpenKubes CLI v1.0 — Same-Plane installation and first cluster (Community Preview)

> **Scope and status (November 2026):** This is the **Same-Plane Talos/KubeVirt operator** workflow, not a general-purpose, one-command Kubernetes installation and not the separate OK-147 Runner/Bare-MVP path. The installed-bundle workflow (`ok up` → independently verify Kubernetes readiness → `ok destroy <name>` → independently verify absence) **passed a live acceptance run** on macOS ARM64 against the existing RKE2 management cluster (OK-228, cluster `ok-v101-a2`, build `2a9b805`). This is evidence for that narrow operator workflow, not general production support, arbitrary providers or signed release provenance.
>
> **v1.0.1 first run:** `install-ok.sh` installs a verified bundle without root, and `ok config init` finds and verifies that bundle and saves your management kubeconfig path. These are new in v1.0.1 and are being accepted as a new release candidate; until then, treat them as preview.

## What this workflow does

The CLI provisions a new Talos Kubernetes workload cluster as KubeVirt VMs **on an existing management/infra Kubernetes cluster** (Same-Plane). You must supply an authorized kubeconfig for that management cluster. This is **not** the kubeconfig of the cluster being created.

The management cluster needs a previously validated Talos/KubeVirt provider profile, Cluster API controllers, KubeVirt, storage with the appropriate Longhorn/CSI integration, Golden image and clone prerequisites, and required network services. A fresh generic Kubernetes cluster is **not** automatically prepared by these commands. Consult the infrastructure/operator runbooks before running against shared infrastructure.

## Prerequisites

- macOS ARM64 or Linux AMD64. Runtime tools: Git, Make, Python 3 with PyYAML, kubectl, clusterctl and Helm, plus standard shell tools. **Go is only needed to build from source.** `ok config init` lists any tool that is missing; it never installs anything.
- A release bundle and its SHA-256 from a trusted channel, or (developers) two sibling checkouts at the **reviewed, pinned revisions**: `ok-cluster` and `ok-linux`.
- A prepared Same-Plane provider/management cluster with an explicitly selected and authorized kubeconfig; do not use the current kubectl context or rely on `KUBECONFIG`.
- A unique, currently unused workload-cluster name, coordinated exclusive access to the shared network-allocation pool. This profile requires **automatic** endpoint and CIDR allocation; review its live inventory and the allocated values during provisioning.

**Shared infrastructure safety:** Read-only-check the API endpoint assignment, network allocations and other clusters before confirming provisioning. Never remove, overwrite or forcibly clean up existing namespaces, storage, evidence, or worktrees to make the preflight pass. A separate clean worktree can help, but must still match the CLI's embedded source revision and pinned dependencies.

## 1. Install the CLI from a release bundle

You need the archive `ok-<version>-<os>-<arch>.tar.gz` and its expected SHA-256 from a trusted channel (not only the `.sha256` file shipped next to the archive). Run everything as the user who will run `ok`; no root is needed.

```bash
EXPECTED=<sha256 from the trusted channel>
ARCHIVE=ok-<version>-<os>-<arch>.tar.gz
# The installer ships inside the archive. Verify the archive first, then use the installer from it:
shasum -a 256 "$ARCHIVE"          # Linux: sha256sum "$ARCHIVE"; must print $EXPECTED
tar -xzOf "$ARCHIVE" "${ARCHIVE%.tar.gz}/ok-cluster/scripts/install-ok.sh" > install-ok.sh
sh install-ok.sh --archive "$ARCHIVE" --sha256 "$EXPECTED" --link
ok version
```

`install-ok.sh` checks the SHA-256 again before it reads the archive, and refuses links, special files, absolute or `..` paths, privileged modes and archives for another OS/architecture. It extracts into a private staging directory and verifies the bundle there: `release.txt` against the binary and the Cilium chart, `ok version`, and both Git copies at their commits and clean. Only then does it move the bundle to `~/.local/share/ok/<bundle>`.

- **It never overwrites anything.** An existing installation of the same version is refused. `--link` creates `~/.local/bin/ok` only if nothing is there; without `--link` it prints the `ln -s` command. It never edits your shell profile; if `~/.local/bin` is not on `PATH`, it prints the line to add.
- **Other locations:** `--prefix DIR` and `--bin-dir DIR` (absolute paths of letters, digits, `.`, `_`, `/`, `-`).
- **macOS:** a browser download is quarantined, and macOS blocks the unsigned binary. Download with `curl`, or remove the flag only after the checksum matched: `xattr -d com.apple.quarantine "$ARCHIVE"`.
- **Integrity is not provenance.** The checksum shows you have the file whose value you trust; it does not establish who built it. The bundle is neither signed nor notarized.
- **Upgrades.** Install the new version next to the old one (`--link` leaves an existing link alone; repoint it yourself). **Destroying a cluster with a different version than the one that created it is not yet tested and not promised.** Keep the creating bundle until its clusters are destroyed, and destroy with that version: call its `ok-cluster/.tools/bin/ok` by full path.

### Developers: build from source

```bash
git clone https://github.com/openkubes/ok-cluster.git
git clone https://github.com/openkubes/ok-linux.git   # check out the commit pinned in cmd/ok/cluster_provision.go
cd ok-cluster && make ok-cli-build && .tools/bin/ok version
```

`make ok-cli-build` embeds the exact revision; an ad-hoc `go build` reports `unknown` and fails the source checks. Maintainers build bundles with `make ok-release-bundle GOOS=<os> GOARCH=<arch> OUT=dist` from a clean commit. The bundle layout:

```text
ok-<version>-<os>-<arch>/
  ok-cluster/          minimal Git copy of the release commit
    .tools/bin/ok      built from that commit (its embedded revision)
    .tools/cilium-1.19.6.tgz   pinned chart, SHA-256 verified
    scripts/install-ok.sh
  ok-linux/            minimal Git copy of the ok-linux commit pinned in bin/ok
  release.txt          version, both commits, SHA-256 of bin/ok and the chart
```

An official version such as `v1.0.1` is accepted only when the tag `v1.0.1` points at the packaged commit; any other build keeps a distinct preview version.

## 2. First run: `ok config init`

```bash
ok config init --management "$HOME/.kube/management-operator.yaml"
```

Replace the path with **your** management-cluster kubeconfig (for the internal OpenKubes acceptance environment `~/.kube/ok-infra-operator.yaml`, **not** a path to copy blindly). Without `--management`, init asks for it on a terminal; Enter skips, and `ok up` then asks each time.

`ok config init`:

- finds the bundle from where `ok` really is (through the `~/.local/bin/ok` link) and verifies it like `ok up`: `ok-cluster` at this binary's commit and clean, `ok-linux` at the pinned commit and clean, the pinned Cilium chart, and `release.txt`. It never searches for other checkouts;
- lists missing runtime tools (nothing is installed);
- saves only the **path** of the management kubeconfig: the file must be a private (0600) regular file; its contents are not read and no cluster is contacted. **No provider kubeconfig is needed for Same-Plane;**
- shows everything and, on a terminal, asks `ok`/`no` before writing a private, create-only file. Without a terminal it saves nothing unless you pass `--yes` (scripts: `ok config init --management <file> --yes`); `--yes` skips only the prompts, never the verification. It never overwrites an existing file.

The management cluster is chosen in this order: `--management`, then `TALOS_INFRA_KUBECONFIG`, then the saved path. `KUBECONFIG` and the current kubectl context are never used. The saved path only selects the file: `ok up` and `ok destroy` still verify the API server, CA and kube-system UID, and still require their typed confirmations. Check the target first:

```bash
kubectl --kubeconfig "$HOME/.kube/management-operator.yaml" config current-context
kubectl --kubeconfig "$HOME/.kube/management-operator.yaml" get clusters.cluster.x-k8s.io -A
```

In Same-Plane mode this management cluster also hosts the KubeVirt workload VMs. The created workload cluster gets a **different** kubeconfig.

Split-plane and legacy workflows (`ok cluster destroy`, Runner paths) keep the five-path setup: `ok config init --topology split-plane` or the explicit path flags; see `ok config init --help`.

## 3. Write an intent file

Bare `ok up` can write this file for you (option `n`, see step 4). To write it yourself, create `my-cluster.yaml` with the **operator-mode `ClusterRequest`** contract. **Do not copy `examples/ok-cli-cluster.yaml`**: that file uses `kind: Cluster` and `talos-kubevirt-mvp` for the separate Runner intent, and is rejected by `ok cluster plan`.

```yaml
apiVersion: cli.openkubes.io/v1alpha1
kind: ClusterRequest
metadata:
  name: my-cluster
spec:
  profile: talos-kubevirt-reference
  network:
    endpoint: auto
    podCIDR: auto
    serviceCIDR: auto
```

The Make reference profile allows network fields to be omitted or set to `auto` **only**. It rejects explicit IPs and CIDRs in the request. The existing Make scaffold selects values later; `ok cluster plan` does **not** allocate or reserve them. Before authorizing live provisioning, coordinate exclusive access to the shared MetalLB/network allocation pool, inspect existing allocations, and independently validate the chosen endpoint/CIDRs. The request is not the generated `cluster-config.yaml` from a previous cluster.

## 4. Plan, provision and verify

```bash
ok cluster plan -f my-cluster.yaml
ok up -f my-cluster.yaml
```

Or run `ok up` without arguments in an interactive terminal:

```text
$ ok up
Cluster requests in ~/.config/ok/requests:
  1) my-cluster.yaml
  n) new cluster request
  p) path to another ClusterRequest file
Choose [1]:
```

- **Enter** picks the first listed request, or `n` when there is none.
- **`n`** asks for a cluster name and writes `~/.config/ok/requests/<name>.yaml` (mode 0600) from the validated template above, then continues.
- **`p`** takes any other ClusterRequest path.

The OS profile comes only from `spec.profile` inside the file, never from its name. The management prompt appears only when neither `--management`, `TALOS_INFRA_KUBECONFIG` nor a path saved by `ok config init` selects the cluster; the banner shows which one was used. Cancelling or ending input (Ctrl-C, Ctrl-D) at any prompt starts nothing. Both paths then run the same plan, preflight and typed confirmations.

Read the plan and the target-cluster identity before authorizing either step. In interactive operator mode, the CLI requests **two separate typed confirmations**:

```text
provision my-cluster
bootstrap my-cluster
```

Bootstrap completion **does not** establish Kubernetes readiness. Read the actual workload kubeconfig generated by `ok up`:

```bash
kubectl --kubeconfig "$HOME/.config/ok/kubeconfigs/my-cluster.yaml" get nodes
kubectl --kubeconfig "$HOME/.config/ok/kubeconfigs/my-cluster.yaml" -n kube-system get pods
kubectl --kubeconfig "$HOME/.kube/management-operator.yaml" -n my-cluster get cluster,machines,vm,vmi,pvc
```

Verify Ready nodes, expected CAPI/KubeVirt resources and system components; investigate failures before declaring the cluster ready. Default workload kubeconfig path is shown above; override it with `--workload-kubeconfig` if necessary.

## 5. Destroy a cluster provisioned by this CLI

**Destructive operation:** Check the selected management cluster and exact target. The following operation will remove the cluster, its namespace, KubeVirt compute and any specifically identified retained storage volumes. Never try this command against another team's cluster.

```bash
ok destroy my-cluster
```

It uses the same management selection as `ok up` (`--management`, `TALOS_INFRA_KUBECONFIG`, then the saved path) and names its source in the banner.

This path is specifically for clusters created with the operator-mode `ok up`. It requires the original local preparation and provisioned UID evidence: in `~/.local/state/ok/clusters/<name>/` (or `$XDG_STATE_HOME/ok/clusters/<name>/`) for clusters created by v1.0.1, or in `<checkout>/<name>/` for clusters created earlier. If both exist, `ok destroy` refuses and deletes nothing. The same Python Same-Plane teardown engine independently validates management API identity, object UIDs, ownership, Golden-image state and storage bindings. It presents a live deletion inventory and requires **typing the exact cluster name**. It reports five progress stages and only reports success after the engine's final absence checks and durable teardown-ledger completion.

The historic form `ok cluster destroy <name>` (and its `ok destroy cluster <name>` alias) retains its distinct Runner/legacy routing; `ok local down` is for local kind environments. These are **not** interchangeable.

The current schema-3 teardown ledger preserves audit/evidence history and **prevents reusing a destroyed cluster name**. Choose a new test name for repeated runs; do not delete or edit ledger evidence to bypass this rule. Safe name reuse across independently identified lifecycle generations is a future improvement.

### Read-only teardown verification

```bash
kubectl --kubeconfig "$HOME/.kube/management-operator.yaml" get namespace my-cluster
kubectl --kubeconfig "$HOME/.kube/management-operator.yaml" get clusters.cluster.x-k8s.io -A
kubectl --kubeconfig "$HOME/.kube/management-operator.yaml" -n ok-cluster-teardown \
  get configmap ok-cluster-teardown-my-cluster
```

The deleted namespace should be `NotFound`; the teardown evidence ConfigMap should still exist. For retained PVs and Longhorn volumes, independently inspect **only the exact IDs captured in the teardown inventory**, not arbitrary cluster-wide storage. Verify other shared clusters remain unaffected.

On failures or interruption, **do not force-delete finalizers, namespaces, PVs or Longhorn volumes**. Preserve the original evidence and the ledger, inspect the error, then use the documented guarded recovery process. The CLI does not automatically retry.

## Where configuration and state live

| What | Where | Written by |
|---|---|---|
| Settings (bundle paths, management kubeconfig **path**) | macOS `~/Library/Application Support/ok/config.json`; Linux `$XDG_CONFIG_HOME/ok/config.json` or `~/.config/ok/config.json`; or `--config <file>` | `ok config init` (create-only) |
| Requests, workload kubeconfigs, Make logs | `$XDG_CONFIG_HOME/ok` or `~/.config/ok` (also on macOS) | `ok up` |
| Cluster lifecycle state and evidence | `$XDG_STATE_HOME/ok/clusters` or `~/.local/state/ok/clusters` | `ok up`, `ok destroy` |
| Installed bundles | `~/.local/share/ok/<bundle>` (or `--prefix`) | `install-ok.sh` |

Settings can be recreated; lifecycle state cannot: never delete it to work around an error. An explicit `--config` must exist and is never replaced by another file. `ok config show` prints the saved settings and verifies the **running** `ok`'s bundle live, with the same checks as `ok up`. It does not re-verify the saved source paths: `ok up` and `ok destroy` never use them, they always use the sources of the `ok` you run, and `ok config show` notes when the saved paths belong to another bundle (for example after an upgrade).

### Lifecycle state

From v1.0.1, `ok up` writes each cluster's lifecycle evidence (scaffold, preparation and provisioned-UID records) to `~/.local/state/ok/clusters/<name>/`, or `$XDG_STATE_HOME/ok/clusters/<name>/` when that is set. The source checkout stays clean, so one installation can create several clusters. Nothing is migrated: clusters created earlier keep their evidence in `<checkout>/<name>/` and remain destroyable from there. `ok up` refuses a name that already exists in either place.

Network allocation considers the committed clusters in the checkout, earlier checkout-layout clusters, the state directory and the management cluster's live LoadBalancer inventory. While `ok up` allocates and writes a scaffold, it holds a local lock (`~/.local/state/ok/clusters/.allocate.lock`). A second `ok up` on the same machine and user fails at once instead of choosing the same endpoint or CIDRs. **The lock does not coordinate independent machines or operators:** a cluster scaffolded elsewhere but not yet bootstrapped is invisible here, and pod/service CIDRs come only from local files. Coordinate shared-pool use between operators as before.

## Current limitations and next version

- Requires a prepared management infrastructure, a verified bundle (or reviewed source checkout with pinned `ok-linux`), the local toolchain and an explicitly selected management kubeconfig.
- Source-integrity checks may reject modified or unrelated untracked files; do not erase evidence to satisfy them. A checkout that still holds an earlier `<checkout>/<name>/` cluster can destroy it, but new `ok up` runs need a clean checkout.
- Cluster-name reuse is not supported by the current durable teardown ledger.
- Bundles are not signed, notarized or attested; the checksum is only as trustworthy as the channel it came from.

For legacy/Runner Bare-MVP behavior, see the separate sections and [security contract](ok147-security-review-contract.md) rather than assuming those paths are enabled by this quickstart.
