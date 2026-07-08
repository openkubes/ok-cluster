# OK-Cluster

**The OpenKubes Cluster Lifecycle Engine**

OK-Cluster is the cluster lifecycle engine for [OpenKubes](https://github.com/openkubes/openkubes) — declarative creation, operation and upgrade of Kubernetes clusters across KubeVirt, bare metal, edge and cloud.

Powered by [Cluster API (CAPI)](https://cluster-api.sigs.k8s.io/), [CAPK (KubeVirt)](https://github.com/kubernetes-sigs/cluster-api-provider-kubevirt), [Talos Linux](https://www.talos.dev/) and [Ubuntu/kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/).

---

## ✨ Features

- **HA Kubernetes in ~3 minutes** — 3 control planes + N workers, fully declarative
- **Two cluster types** — Talos (immutable, API-driven) and Ubuntu (kubeadm, flexible)
- **OS layer owned by [ok-linux](https://github.com/openkubes/ok-linux)** — Talos version and schematic ID are read from ok-linux profiles, not hardcoded here
- **Auto IP/CIDR allocation** — MetalLB IPs and pod/service CIDRs allocated automatically
- **Blue/Green upgrades** — rolling Kubernetes version upgrades with workload migration
- **GitOps-ready** — all cluster state is declarative YAML, rendered from templates
- **Single Makefile UX** — `make new`, `make install`, `make status`, `make upgrade`

---

## Prerequisites

- A Kubernetes host cluster with:
  - [KubeVirt](https://kubevirt.io/) — VM runtime
  - [CDI](https://github.com/kubevirt/containerized-data-importer) — disk image importer
  - [MetalLB](https://metallb.universe.tf/) — LoadBalancer IP pool
  - [local-path-provisioner](https://github.com/rancher/local-path-provisioner) — PVC storage
  - [CAPI](https://cluster-api.sigs.k8s.io/) + [CAPK](https://github.com/kubernetes-sigs/cluster-api-provider-kubevirt) — cluster lifecycle
  - Talos Bootstrap Provider (`cacppt`) — for Talos clusters
- Tools: `clusterctl`, `helm`, `talosctl`, `kubectl`, `python3`, `make`
- Kubeconfig at `~/.kube/<host-cluster>.yaml`
- **For Talos clusters:** a sibling checkout of [ok-linux](https://github.com/openkubes/ok-linux) (see [OS Layer Integration](#os-layer-integration) below)

> See [OpenKubes Infrastructure](https://github.com/openkubes/openkubes/tree/main/platform/infrastructure) for host cluster setup.

---

## Quick Start

### Talos Cluster (recommended)

```bash
# Scaffold a new HA Talos cluster
# Talos version and schematic ID are read from ../ok-linux automatically
make new CLUSTER=my-cluster TYPE=talos WORKERS=2

# Deploy (applies CAPI manifests, annotates PVCs, bootstraps Talos)
make bootstrap CLUSTER=my-cluster

# Get kubeconfig once nodes are Running
make kubeconfig CLUSTER=my-cluster

# Check status
make status CLUSTER=my-cluster
```

### Ubuntu Cluster

```bash
# Scaffold a new HA Ubuntu cluster
make new CLUSTER=my-cluster TYPE=ubuntu HA=true WORKERS=2

# Deploy (applies manifests, waits for control plane, installs Cilium)
make install CLUSTER=my-cluster

# Get kubeconfig
make kubeconfig CLUSTER=my-cluster
```

---

## OS Layer Integration

ok-cluster does not own Talos version numbers or schematic IDs. **[ok-linux](https://github.com/openkubes/ok-linux) is the source of truth.**

```
ok-linux/profiles/kubevirt/profile.yaml
        ↓  (talos.version, talos.schematic_id — verified via make build/verify in ok-linux)
ok-cluster/render.py  reads this file from a sibling checkout
        ↓
cluster-config.yaml   os.profile: kubevirt, os.schematic_id: <resolved>
        ↓
cluster-v2.yaml        openkubes.io/talos-schematic annotation
        ↓
Running cluster
```

**Expected directory layout:**

```
~/your-workspace/
├── ok-linux/      ← github.com/openkubes/ok-linux
└── ok-cluster/    ← this repo
```

If `ok-linux` is checked out elsewhere, set `OK_LINUX_PATH`:

```bash
export OK_LINUX_PATH=/path/to/ok-linux
make render CLUSTER=my-cluster
```

If `ok-linux` cannot be found at all, `render.py` falls back to hardcoded defaults and prints a `WARNING` — this is a signal to fix the path, not normal operation.

To change which OS profile a cluster uses, set `OS_PROFILE` when scaffolding:

```bash
OS_PROFILE=baremetal make new CLUSTER=my-cluster TYPE=talos
```

---

## All Makefile Targets

```
make new           CLUSTER=<name> [TYPE=ubuntu|talos] [HA=true] [WORKERS=2] [NODE_SELECTOR=<node>]
make render        CLUSTER=<name>                    # re-render manifests from config
make install       CLUSTER=<name>                    # ubuntu: apply + wait + cilium
make bootstrap     CLUSTER=<name>                    # talos: apply + annotate PVCs
make kubeconfig    CLUSTER=<name>                    # save kubeconfig to ~/.kube/<name>.yaml
make install-cni   CLUSTER=<name>                    # install Cilium (manual)
make annotate-pvcs CLUSTER=<name>                    # annotate PVCs for node binding
make upgrade       CLUSTER=<name> K8S_VERSION=v1.x.y [TALOS_VERSION=v1.x.y]
make status        CLUSTER=<name>                    # show cluster, machines, VMs
make clean         CLUSTER=<name>                    # delete ubuntu cluster + local files
make teardown      CLUSTER=<name>                    # delete talos cluster + local files
make list                                            # list all defined clusters
```

---

## Cluster Types

### Talos (immutable, API-driven)

Uses [Talos Linux](https://www.talos.dev/) via the OpenStack-compatible qcow2 image from [Talos Image Factory](https://factory.talos.dev/). No SSH, no package manager — fully declarative and immutable. Talos version and schematic ID come from [ok-linux](https://github.com/openkubes/ok-linux) — see [OS Layer Integration](#os-layer-integration).

```bash
make new CLUSTER=ok1-talos TYPE=talos WORKERS=2
make bootstrap CLUSTER=ok1-talos
```

### Ubuntu (kubeadm, flexible)

Uses [CAPK container disk images](https://quay.io/repository/capk/ubuntu-2404-container-disk) — nodes are ready in ~2 minutes.

```bash
make new CLUSTER=ok1 TYPE=ubuntu HA=true WORKERS=2
make install CLUSTER=ok1
```

---

## Templating System

```
cluster-config.yaml  →  render.py  →  CAPI manifests  →  make install/bootstrap
```

`render.py` reads `cluster-config.yaml`, resolves `auto` values for IPs and CIDRs, resolves OS defaults from ok-linux (Talos clusters only), and renders the CAPI manifest templates. All resolved values are written back to `cluster-config.yaml` for reproducibility.

### cluster-config.yaml

```yaml
name: my-cluster
type: talos          # or ubuntu

controlPlane:
  replicas: 3        # 1 = single, 3 = HA
  cores: 2
  memory: 4Gi

workers:
  replicas: 2
  cores: 2
  memory: 4Gi
  disk: 15Gi

# OS layer — resolved from ok-linux, talos only.
# Set explicitly here, or let render.py resolve it from ../ok-linux.
os:
  distribution: ok-linux
  profile: kubevirt
  schematic_id: ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515

versions:
  kubernetes: v1.36.2
  talos: v1.9.5      # talos only — resolved from ok-linux if omitted

network:
  endpoint: auto     # auto-allocates next free LoadBalancer IP
  podCIDR: auto      # auto-allocates next free /16
  serviceCIDR: auto  # auto-allocates next free /20

nodeSelector: ""     # pin VMs to a specific host node (required for Talos PVC binding)

upgrade:
  strategy: blue-green
  workloadMigration:
    stateless: gitops
    stateful: app-native
```

### Auto-Allocation Pools

| Resource     | Pool                  | Size per Cluster |
|--------------|-----------------------|-----------------|
| MetalLB IP   | Configurable          | 1 IP            |
| Pod CIDR     | `10.32.0.0/11`        | /16             |
| Service CIDR | `10.96.0.0/12`        | /20             |

> Pool ranges are configured in `render.py` — adapt to your MetalLB setup.

---

## Repository Structure

```
ok-cluster/
├── Makefile                  # all lifecycle targets
├── render.py                 # template engine, auto IP/CIDR allocation, ok-linux integration
├── new-cluster.sh            # cluster scaffolding
├── upgrade-cluster.sh        # blue/green upgrade
├── templates/
│   ├── talos/
│   │   ├── cluster-base.yaml.tpl    # CAPI + CAPK + Talos manifests
│   │   ├── cluster-v2.yaml.tpl
│   │   ├── bootstrap.sh.tpl
│   │   └── generate-manifest.sh.tpl
│   └── ubuntu/
│       ├── cluster-v2.yaml.tpl      # CAPI + CAPK + kubeadm manifests
│       └── generate-manifest.sh.tpl
└── cluster-config.yaml.example      # example cluster config
```

> Rendered cluster directories (`my-cluster/`) are git-ignored — they contain environment-specific IPs and are generated locally.

---

## Part of OpenKubes

OK-Cluster is the cluster lifecycle layer of the OpenKubes platform. It owns *how* a cluster is created, scaled, and upgraded — never *which* OS image runs on its nodes:

```
OpenKubes
├── ok-local      — Local development (Multipass)
├── ok-cluster    — Cluster Lifecycle Engine  ← you are here
├── ok-linux      — OS profiles, Image Factory, MachineConfig (source of truth for Talos)
├── ok-storage    — Persistent Storage Contract (Longhorn v1)
├── ok-gitops     — GitOps bootstrap (ArgoCD)
└── ok-apps       — Platform applications
```

> ok-cluster expresses intent. ok-linux is the source of truth.
> See [ok-linux's architecture docs](https://github.com/openkubes/ok-linux/blob/main/docs/spec.md) for the full contract.

- [OpenKubes](https://github.com/openkubes/openkubes)
- [OK-Linux](https://github.com/openkubes/ok-linux)
- [OK-Storage](https://github.com/openkubes/ok-storage)
- [OK-Local](https://github.com/openkubes/ok-local)

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
