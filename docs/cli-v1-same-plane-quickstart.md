# OpenKubes CLI v1.0.1 — Same-Plane Quickstart

**Status:** [v1.0.1 Community Release](https://github.com/openkubes/ok-cluster/releases/tag/v1.0.1) (15 November 2026). Not production-certified.

The `ok` CLI creates and removes **Talos/KubeVirt workload clusters on an already prepared Kubernetes management cluster**. It does **not** install the management cluster or its CAPI/CAPK, KubeVirt, storage, networking, Talos controllers, or Golden Images. The separate Runner/Bare-MVP workflow is not enabled by this guide.

## 1. Download

Choose the bundle for the computer **running the CLI** (not the Kubernetes nodes):

| Your computer | Bundle |
| --- | --- |
| Apple Silicon Mac | [macOS ARM64](https://github.com/openkubes/ok-cluster/releases/download/v1.0.1/ok-v1.0.1-darwin-arm64.tar.gz) |
| Intel Mac | [macOS AMD64](https://github.com/openkubes/ok-cluster/releases/download/v1.0.1/ok-v1.0.1-darwin-amd64.tar.gz) |
| Linux/WSL2 AMD64 | [Linux AMD64](https://github.com/openkubes/ok-cluster/releases/download/v1.0.1/ok-v1.0.1-linux-amd64.tar.gz) |

[All v1.0.1 release assets, installer and official checksums](https://github.com/openkubes/ok-cluster/releases/tag/v1.0.1)

The bundles include the CLI, pinned `ok-cluster` and `ok-linux` sources, and Cilium. No Go compiler or separate source checkout is needed.

## 2. Verify and install (no sudo)

From the directory containing your downloaded archive, select the matching two values:

| Platform | `ARCHIVE` | `EXPECTED` (official SHA-256) |
| --- | --- | --- |
| Apple Silicon | `ok-v1.0.1-darwin-arm64.tar.gz` | `28e412ea9fa6c116d85caf4650c6449030d17d8b50de9d964c6ed2ee39795d11` |
| Intel Mac | `ok-v1.0.1-darwin-amd64.tar.gz` | `3b69891825e641e1f1dc09c7102b9f8fc82205577d08713341394bb3b1cb5369` |
| Linux AMD64 | `ok-v1.0.1-linux-amd64.tar.gz` | `722c09f3307d70bb5e05a76d93dd685c9fa9918ac2c2ce69a316d3afaee7e694` |

Example for **Apple Silicon** (change `ARCHIVE` and `EXPECTED` for another platform):

```bash
ARCHIVE=ok-v1.0.1-darwin-arm64.tar.gz
EXPECTED=28e412ea9fa6c116d85caf4650c6449030d17d8b50de9d964c6ed2ee39795d11

# Check before extracting anything; on Linux use sha256sum -c - instead.
printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | shasum -a 256 -c - || exit 1

# Extract only the bundled installer (not an unverified web script).
tar -xzOf "$ARCHIVE" "${ARCHIVE%.tar.gz}/ok-cluster/scripts/install-ok.sh" > install-ok.sh
sh install-ok.sh --archive "$ARCHIVE" --sha256 "$EXPECTED" --link

~/.local/bin/ok version
```

On Linux, replace `shasum -a 256 -c -` with `sha256sum -c -`. The installer validates the archive again and installs under `~/.local/share/ok/` without root. Add `~/.local/bin` to `PATH` if needed; the installer does not edit your shell configuration. It refuses to overwrite an existing installation or `ok` link.

**Security:** Compare the expected checksum with the official release notes through a trusted channel. v1.0.1 bundles are not signed, notarized or attested. macOS may quarantine browser downloads; use `curl -fLO` with the release URL, or remove the quarantine attribute only after verification.

## 3. Configure your management cluster

**Before `ok up`**, you need an authorized **management** kubeconfig (not a workload-cluster kubeconfig), with a valid current context, and a prepared Same-Plane Talos/KubeVirt provider profile. The kubeconfig must be a private regular file (mode 0600).

Required runtime tools: Git, Make, Python 3 with PyYAML, kubectl, clusterctl and Helm. `ok config init` reports missing tools but does not install them.

```bash
# Replace with your own management kubeconfig.
MGMT="$HOME/.kube/management-operator.yaml"
kubectl --kubeconfig "$MGMT" config current-context
kubectl --kubeconfig "$MGMT" get nodes

~/.local/bin/ok config init --management "$MGMT"
~/.local/bin/ok config show
```

`ok config init` saves the **path**, not kubeconfig contents. It does not create a cluster or contact Kubernetes. `ok up` separately verifies the management API identity before making changes. It does not silently use `KUBECONFIG` or your active kubectl context.

## 4. Create and verify a workload cluster

```bash
ok up
```

In the interactive prompt, choose **new cluster request** and enter a unique cluster name. Review the plan, selected management cluster, endpoint and auto-allocated CIDRs. Provisioning and bootstrap each require their own exact typed confirmation. `ok up` finishing is **not** proof that Kubernetes is Ready.

Alternatively, save this request as `my-cluster.yaml`:

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

Then run `ok cluster plan -f my-cluster.yaml` followed by `ok up -f my-cluster.yaml`.

**Verify independently** (replace `my-cluster` and the management kubeconfig path):

```bash
kubectl --kubeconfig "$HOME/.config/ok/kubeconfigs/my-cluster.yaml" get nodes
kubectl --kubeconfig "$HOME/.config/ok/kubeconfigs/my-cluster.yaml" -n kube-system get pods
kubectl --kubeconfig "$MGMT" -n my-cluster get cluster,machines,vm,vmi,pvc
```

Check the expected Ready nodes, CNI and CAPI/KubeVirt resources. Coordinate endpoint and CIDR allocation with other operators: the local allocation lock does **not** prevent collisions between computers. CLI workload ARM64 is not supported in v1.0.1 even when the CLI runs on Apple Silicon.

## 5. Destroy when finished

```bash
ok destroy my-cluster
```

Review the management identity and UID-bound deletion inventory before typing the exact cluster name. Verify that the workload namespace and cluster objects are gone. **Destruction with a different CLI version is not supported**: keep and use the version that created the cluster. A destroyed cluster name cannot currently be reused because its teardown evidence is retained. Never delete state, finalizers, namespaces or storage manually to bypass a refusal.

## Reference

- [Release notes and SHA-256 values](https://github.com/openkubes/ok-cluster/releases/tag/v1.0.1)
- [OK-Cluster documentation](./)
- [Runner/Bare-MVP security boundary](ok147-security-review-contract.md)

Configuration is stored in `~/Library/Application Support/ok/config.json` on macOS or `~/.config/ok/config.json` on Linux; requests and workload kubeconfigs in `~/.config/ok/`; lifecycle evidence in `~/.local/state/ok/clusters/` (respecting relevant XDG overrides). Never delete lifecycle evidence to repair a failed operation.
