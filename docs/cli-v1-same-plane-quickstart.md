# OpenKubes CLI v1.0 — Same-Plane installation and first cluster (Community Preview)

> **Scope and status (November 2026):** This is the source-checkout-based **Same-Plane Talos/KubeVirt operator** workflow, not a general-purpose, one-command Kubernetes installation and not the separate OK-147 Runner/Bare-MVP path. The complete `ok up` → independently verify Kubernetes readiness → `ok destroy <name>` → independently verify absence workflow **passed a live acceptance run** for `ok-v1-test-2` on the existing RKE2 management cluster, using CLI build `4cb6f12d0dff9a166e41212bd5ec8290b6e557de`. This is evidence for that narrow operator workflow, not general production support, arbitrary providers, or release-asset verification.
>
> **v1.0.1 UX direction:** We plan to simplify installation, dependency setup and the CLI experience. These improvements are not implemented in v1.0; no release date or particular installer is promised.

## What this workflow does

The CLI provisions a new Talos Kubernetes workload cluster as KubeVirt VMs **on an existing management/infra Kubernetes cluster** (Same-Plane). You must supply an authorized kubeconfig for that management cluster. This is **not** the kubeconfig of the cluster being created.

The management cluster needs a previously validated Talos/KubeVirt provider profile, Cluster API controllers, KubeVirt, storage with the appropriate Longhorn/CSI integration, Golden image and clone prerequisites, and required network services. A fresh generic Kubernetes cluster is **not** automatically prepared by these commands. Consult the infrastructure/operator runbooks before running against shared infrastructure.

## Prerequisites

- macOS or Linux; Git, Go, Python 3, Make, kubectl and the exact tooling required by the CLI preflight (including clusterctl and Helm). Tool versions must meet the repository's tested requirements.
- Two sibling checkouts at the **reviewed, pinned revisions**: `ok-cluster` and `ok-linux`. A random HEAD of `ok-linux` is not sufficient. Use the revision required by your checked-out `ok-cluster` and validate it using the CLI preflight. The source-integrity checks require reviewed/clean source, and may reject unrelated untracked files.
- A prepared Same-Plane provider/management cluster with an explicitly selected and authorized kubeconfig; do not use the current kubectl context or rely on `KUBECONFIG`.
- A unique, currently unused workload-cluster name, coordinated exclusive access to the shared network-allocation pool. This profile requires **automatic** endpoint and CIDR allocation; review its live inventory and the allocated values during provisioning.

**Shared infrastructure safety:** Read-only-check the API endpoint assignment, network allocations and other clusters before confirming provisioning. Never remove, overwrite or forcibly clean up existing namespaces, storage, evidence, or worktrees to make the preflight pass. A separate clean worktree can help, but must still match the CLI's embedded source revision and pinned dependencies.

## 1. Get and build the CLI

```bash
git clone https://github.com/openkubes/ok-cluster.git
git clone https://github.com/openkubes/ok-linux.git
cd ok-cluster

# Select the reviewed v1.0 source revision and the matching pinned
# ok-linux revision according to the release/maintainer instructions.
# Do not assume the latest main branch is a stable v1.0 release.

make ok-cli-build
.tools/bin/ok version
.tools/bin/ok up --help
.tools/bin/ok destroy --help
```

`make ok-cli-build` is the supported Make target (not `make ok-cli`). The resulting CLI is `.tools/bin/ok`; running an ad-hoc `go build` without the Makefile's version/revision linker flags can produce `unknown` revision and fail source-integrity verification.

> **Current installation limitation:** Unlike a standalone distributable binary, these operator commands depend on the matching reviewed source checkout and local lifecycle tools. Installation is not complete merely by placing `ok` on `PATH`.

## 2. Select the management Kubernetes cluster

```bash
export TALOS_INFRA_KUBECONFIG="$HOME/.kube/management-operator.yaml"
kubectl --kubeconfig "$TALOS_INFRA_KUBECONFIG" config current-context
kubectl --kubeconfig "$TALOS_INFRA_KUBECONFIG" get clusters.cluster.x-k8s.io -A
```

Replace the path with **your** management-cluster kubeconfig. For the internal OpenKubes acceptance environment it is `~/.kube/ok-infra-operator.yaml` (RKE2 `ok-infra`), **not** a path users should copy blindly. In Same-Plane mode this management cluster also hosts the KubeVirt workload VMs. The created workload cluster gets a **different** kubeconfig.

The simple CLI ignores `KUBECONFIG` and the current kubectl context for management selection. It uses `--management`, otherwise `TALOS_INFRA_KUBECONFIG`, otherwise it asks you for the path. The choice is not stored.

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
.tools/bin/ok cluster plan -f my-cluster.yaml

.tools/bin/ok up \
  -f my-cluster.yaml \
  --management "$TALOS_INFRA_KUBECONFIG"
```

Or run `ok up` without arguments in an interactive terminal:

```text
$ .tools/bin/ok up
Cluster requests in ~/.config/ok/requests:
  1) my-cluster.yaml
  n) new cluster request
  p) path to another ClusterRequest file
Choose [1]:
Management cluster kubeconfig (path; KUBECONFIG is never used): ~/.kube/management-operator.yaml
```

- **Enter** picks the first listed request, or `n` when there is none.
- **`n`** asks for a cluster name and writes `~/.config/ok/requests/<name>.yaml` (mode 0600) from the validated template above, then continues.
- **`p`** takes any other ClusterRequest path.

The OS profile comes only from `spec.profile` inside the file, never from its name. The management prompt appears only when neither `--management` nor `TALOS_INFRA_KUBECONFIG` is set. Cancelling or ending input (Ctrl-C, Ctrl-D) at any prompt starts nothing. Both paths then run the same plan, preflight and typed confirmations.

Read the plan and the target-cluster identity before authorizing either step. In interactive operator mode, the CLI requests **two separate typed confirmations**:

```text
provision my-cluster
bootstrap my-cluster
```

Bootstrap completion **does not** establish Kubernetes readiness. Read the actual workload kubeconfig generated by `ok up`:

```bash
kubectl --kubeconfig "$HOME/.config/ok/kubeconfigs/my-cluster.yaml" get nodes
kubectl --kubeconfig "$HOME/.config/ok/kubeconfigs/my-cluster.yaml" -n kube-system get pods
kubectl --kubeconfig "$TALOS_INFRA_KUBECONFIG" -n my-cluster get cluster,machines,vm,vmi,pvc
```

Verify Ready nodes, expected CAPI/KubeVirt resources and system components; investigate failures before declaring the cluster ready. Default workload kubeconfig path is shown above; override it with `--workload-kubeconfig` if necessary.

## 5. Destroy a cluster provisioned by this CLI

**Destructive operation:** Check the selected management cluster and exact target. The following operation will remove the cluster, its namespace, KubeVirt compute and any specifically identified retained storage volumes. Never try this command against another team's cluster.

```bash
.tools/bin/ok destroy my-cluster \
  --management "$TALOS_INFRA_KUBECONFIG"
```

This path is specifically for clusters created with the operator-mode `ok up`. It requires the original local preparation and provisioned UID evidence: in `~/.local/state/ok/clusters/<name>/` (or `$XDG_STATE_HOME/ok/clusters/<name>/`) for clusters created by v1.0.1, or in `<checkout>/<name>/` for clusters created earlier. If both exist, `ok destroy` refuses and deletes nothing. The same Python Same-Plane teardown engine independently validates management API identity, object UIDs, ownership, Golden-image state and storage bindings. It presents a live deletion inventory and requires **typing the exact cluster name**. It reports five progress stages and only reports success after the engine's final absence checks and durable teardown-ledger completion.

The historic form `ok cluster destroy <name>` (and its `ok destroy cluster <name>` alias) retains its distinct Runner/legacy routing; `ok local down` is for local kind environments. These are **not** interchangeable.

The current schema-3 teardown ledger preserves audit/evidence history and **prevents reusing a destroyed cluster name**. Choose a new test name for repeated runs; do not delete or edit ledger evidence to bypass this rule. Safe name reuse across independently identified lifecycle generations is a future improvement.

### Read-only teardown verification

```bash
kubectl --kubeconfig "$TALOS_INFRA_KUBECONFIG" get namespace my-cluster
kubectl --kubeconfig "$TALOS_INFRA_KUBECONFIG" get clusters.cluster.x-k8s.io -A
kubectl --kubeconfig "$TALOS_INFRA_KUBECONFIG" -n ok-cluster-teardown \
  get configmap ok-cluster-teardown-my-cluster
```

The deleted namespace should be `NotFound`; the teardown evidence ConfigMap should still exist. For retained PVs and Longhorn volumes, independently inspect **only the exact IDs captured in the teardown inventory**, not arbitrary cluster-wide storage. Verify other shared clusters remain unaffected.

On failures or interruption, **do not force-delete finalizers, namespaces, PVs or Longhorn volumes**. Preserve the original evidence and the ledger, inspect the error, then use the documented guarded recovery process. The CLI does not automatically retry.

## Where lifecycle state lives

From v1.0.1, `ok up` writes each cluster's lifecycle evidence (scaffold, preparation and provisioned-UID records) to `~/.local/state/ok/clusters/<name>/`, or `$XDG_STATE_HOME/ok/clusters/<name>/` when that is set. The source checkout stays clean, so one installation can create several clusters. Nothing is migrated: clusters created earlier keep their evidence in `<checkout>/<name>/` and remain destroyable from there. `ok up` refuses a name that already exists in either place.

Network allocation considers the committed clusters in the checkout, earlier checkout-layout clusters, the state directory and the management cluster's live LoadBalancer inventory. While `ok up` allocates and writes a scaffold, it holds a local lock (`~/.local/state/ok/clusters/.allocate.lock`). A second `ok up` on the same machine and user fails at once instead of choosing the same endpoint or CIDRs. **The lock does not coordinate independent machines or operators:** a cluster scaffolded elsewhere but not yet bootstrapped is invisible here, and pod/service CIDRs come only from local files. Coordinate shared-pool use between operators as before.

## Current limitations and next version

- v1.0 requires a prepared management infrastructure, reviewed source checkout, pinned `ok-linux`, local toolchain and explicit kubeconfig.
- Source-integrity checks may reject modified or unrelated untracked files; do not erase evidence to satisfy them. A checkout that still holds an earlier `<checkout>/<name>/` cluster can destroy it, but new `ok up` runs need a clean checkout.
- Cluster-name reuse is not supported by the current durable teardown ledger.
- v1.0.1 is intended to improve **UX and installation simplicity**, while keeping identity checks, human approval and independently verifiable operations. The exact UX and release timing remain to be defined.

For legacy/Runner Bare-MVP behavior, see the separate sections and [security contract](ok147-security-review-contract.md) rather than assuming those paths are enabled by this quickstart.
