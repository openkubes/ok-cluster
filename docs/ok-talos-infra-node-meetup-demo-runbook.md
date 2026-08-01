# Talos on `ok-infra`: meetup demo runbook

This runbook creates, verifies, demonstrates, and removes the disposable
`ok-talos-infra-node-meetup-demo` workload cluster. It uses the reviewed Talos
Golden-Image path on the KubeVirt infrastructure cluster:

- scheduling node: `ok-infra`
- Golden Image: immutable, digest-pinned PVC in `ok-images`
- boot volumes: local CDI clones on Longhorn `ok-storage-block`
- control plane: 2 vCPU, 4 GiB memory, 20 GiB disk
- worker: 4 vCPU, 8 GiB memory, 30 GiB disk
- topology: one control plane and one worker
- Cilium: pinned chart `1.19.6`, verified before installation

This is the normal `ok-infra` path. It does not use the separate
`gpu-single-replica` demonstration profile or
`ok-storage-block-gpu-test`.

## Safety and lifecycle

The commands create and later delete resources on `ok-infra`. The teardown
deletes the workload cluster, its namespace, clone PVCs/PVs, Longhorn volumes,
temporary clone authorization, and the local render directory. It preserves
the shared Golden Image in `ok-images`.

Do not commit the generated cluster directory. It is runtime material for this
demo only.

## Prerequisites

Run from a clean checkout of the `ok-cluster` `main` branch:

```bash
cd /Users/arash/temp/kubernauts/ok/ok-cluster
git switch main
git status --short --branch
```

Required local tools and inputs:

- `make`, `python3`, `kubectl`, `helm`, and `/usr/bin/time`
- management kubeconfig at `$HOME/.kube/ok-infra.yaml`
- reachable and healthy `ok-infra`
- KubeVirt, CDI, Longhorn, and the reviewed Golden Image already installed
- sufficient resources for both VMs: at least 6 vCPU and 12 GiB memory, plus
  Longhorn capacity for the 20 GiB and 30 GiB boot clones

Verify management access:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" get node ok-infra
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" get storageclass ok-storage-block
```

## 1. Acquire and verify the pinned Cilium chart

The supported acquisition target downloads exactly Cilium `1.19.6`, verifies
SHA-256
`21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179`,
and atomically publishes it into the git-ignored `.tools` cache. A valid cached
artifact is reused.

```bash
make prepare-cilium-chart
make verify-cilium-chart
```

Expected artifact:

```text
/Users/arash/temp/kubernauts/ok/ok-cluster/.tools/cilium-1.19.6.tgz
```

For an offline or pre-downloaded artifact:

```bash
make prepare-cilium-chart \
  CILIUM_CHART_SOURCE=/absolute/path/to/cilium-1.19.6.tgz
```

The digest check remains mandatory.

## 2. Scaffold and render the cluster

Ensure that no previous local or live deployment with the same name exists:

```bash
test ! -e ok-talos-infra-node-meetup-demo
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo \
  get cluster ok-talos-infra-node-meetup-demo
```

The second command should return `NotFound`.

Create the cluster configuration and rendered manifests:

```bash
make new \
  CLUSTER=ok-talos-infra-node-meetup-demo \
  TYPE=talos \
  NODE_SELECTOR=ok-infra \
  CP_CORES=2 \
  CP_MEMORY=4Gi \
  CP_DISK=20Gi \
  WORKER_CORES=4 \
  WORKER_MEMORY=8Gi \
  WORKER_DISK=30Gi
```

`make new` renders immediately. If
`ok-talos-infra-node-meetup-demo/cluster-config.yaml` is edited afterwards,
regenerate the manifests before bootstrap:

```bash
make render CLUSTER=ok-talos-infra-node-meetup-demo
```

Rendering is local only. It does not create Kubernetes resources, VMs, PVCs,
or secrets on `ok-infra`.

Inspect the resolved configuration and rendered VM resources:

```bash
sed -n '1,120p' \
  ok-talos-infra-node-meetup-demo/cluster-config.yaml

grep -nE 'cores:|guest:|storage:' \
  ok-talos-infra-node-meetup-demo/cluster-base.yaml
```

Expected role resources:

```text
control plane: cores 2, guest memory 4Gi, storage 20Gi
worker:        cores 4, guest memory 8Gi, storage 30Gi
```

## 3. Run the guarded management preflight

```bash
make talos-golden-preflight \
  CLUSTER=ok-talos-infra-node-meetup-demo \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"
```

Continue only after a `PASS`. The preflight verifies the Talos identity and
Golden PVC, KubeVirt `ExpandDisks`, target node, clone StorageClass, snapshot
contract, and least-privilege clone authorization inputs.

## 4. Bootstrap and measure warm provisioning

The Golden Image has already been published. This measurement therefore
covers repeatable warm cluster provisioning, not the one-time public image
publication.

```bash
/usr/bin/time -p make bootstrap \
  CLUSTER=ok-talos-infra-node-meetup-demo \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"
```

The lifecycle:

1. repeats the Golden-Image preflight;
2. applies the CAPI, Talos, KubeVirt, clone-RBAC, and CDI objects;
3. waits for the control-plane and worker Golden-PVC clones;
4. waits for the Talos API;
5. writes `$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml`;
6. installs the verified local Cilium chart;
7. waits for both nodes to become Ready.

During the CDI phase the log currently says `DataVolume imports`. For this
Golden-Image path these are local source-PVC clone operations, not repeated
public HTTP image imports.

### Rehearsal baseline

The same resource shape was rehearsed on 2026-08-01 as `ok-talos-demo`:

```text
real 281.07 seconds (4 minutes 41 seconds)
Talos v1.9.6
Kubernetes v1.34.1
Cilium 1.19.6
```

Treat this as an observed baseline, not a fixed service-level guarantee.

## 5. Verify the workload cluster

Use explicit kubeconfig arguments during the demo to avoid accidental context
changes:

```bash
kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  get nodes -o wide

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  get pods -A

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  -n kube-system get daemonset cilium
```

Expected state:

- one Ready control-plane node and one Ready worker;
- all system Pods Running;
- Cilium desired/current/ready is `2/2/2`.

## 6. Verify KubeVirt resources and Golden clones

Verify VM placement, vCPU, memory, PVC size, StorageClass, and binding:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo get vmi \
  -o custom-columns=NAME:.metadata.name,NODE:.status.nodeName,CPU:.spec.domain.cpu.cores,MEMORY:.spec.domain.memory.guest,PHASE:.status.phase

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo get pvc \
  -o custom-columns=NAME:.metadata.name,SIZE:.spec.resources.requests.storage,SC:.spec.storageClassName,PHASE:.status.phase
```

Expected result:

| Role | Node | CPU | Memory | Disk | StorageClass | State |
|---|---|---:|---:|---:|---|---|
| control plane | `ok-infra` | 2 | 4Gi | 20Gi | `ok-storage-block` | Running/Bound |
| worker | `ok-infra` | 4 | 8Gi | 30Gi | `ok-storage-block` | Running/Bound |

Verify that the shared Golden Image is still present:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-images get pvc \
  talos-v1-9-6-ce4c980550dd-461d72d30750-amd64
```

It must remain `Bound` on `ok-storage-block`.

## 7. Optional workload-network smoke test

The following restricted Pod Security-compatible workload demonstrates Pod
scheduling and service networking without modifying the cluster contract:

```bash
kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: smoke-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: smoke-nginx
  template:
    metadata:
      labels:
        app: smoke-nginx
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginxinc/nginx-unprivileged:1.27-alpine
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
---
apiVersion: v1
kind: Service
metadata:
  name: smoke-nginx
spec:
  selector:
    app: smoke-nginx
  ports:
  - port: 80
    targetPort: 8080
YAML

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  rollout status deployment/smoke-nginx --timeout=180s

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: smoke-client
spec:
  restartPolicy: Never
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: curl
    image: curlimages/curl:8.10.1
    command: ["curl"]
    args: ["-fsS", "http://smoke-nginx"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
YAML

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/smoke-client --timeout=180s

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  logs smoke-client
```

The client should print the nginx welcome page. Remove the smoke workload:

```bash
kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  delete service smoke-nginx

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  delete deployment smoke-nginx

kubectl --kubeconfig \
  "$HOME/.kube/ok-talos-infra-node-meetup-demo.yaml" \
  delete pod smoke-client
```

## 8. Tear down the demo cluster

The command prompts before deleting anything. It records the cluster-owned PV
identities before namespace deletion, removes the CAPI cluster and namespace,
cleans retained PVs/Longhorn volumes and clone authorization, verifies the
Golden PVC, and removes the local render directory.

```bash
unset KUBECONFIG

make teardown \
  CLUSTER=ok-talos-infra-node-meetup-demo \
  TALOS_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml"
```

Answer `y` only after confirming the exact cluster name and listed PVs.

## 9. Verify cleanup and Golden-Image preservation

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get namespace ok-talos-infra-node-meetup-demo

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get pv | grep ok-talos-infra-node-meetup-demo || true

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get pv | grep Released || true

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-images get pvc \
  talos-v1-9-6-ce4c980550dd-461d72d30750-amd64

test ! -e ok-talos-infra-node-meetup-demo
git status --short --branch
```

Expected result:

- the demo namespace is `NotFound`;
- no demo-owned PV remains;
- no newly Released PV remains;
- the Talos Golden PVC remains `Bound`;
- the local demo directory is absent;
- the Git worktree is clean.

## Troubleshooting

### Clone PVCs remain Pending

Inspect CDI state, PVC events, StorageClass, and Longhorn capacity:

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo get datavolume,pvc

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo get events \
  --sort-by=.lastTimestamp

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  get storageclass ok-storage-block -o yaml

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n longhorn-system get volumes.longhorn.io
```

Host `df` output alone is not Longhorn schedulable-capacity evidence. Longhorn
also accounts for replica count, reserved space, minimum free-space policy,
eligible disks/nodes, existing volumes, and snapshot data.

### API wait or node readiness times out

```bash
kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo get \
  cluster,machine,machinedeployment,kubevirtmachine,vmi

kubectl --kubeconfig "$HOME/.kube/ok-infra.yaml" \
  -n ok-talos-infra-node-meetup-demo get events \
  --sort-by=.lastTimestamp
```

Do not manually replace the Golden Image or weaken its digest guard. Resolve
the failed infrastructure condition, then rerun the guarded lifecycle or tear
down the exact demo cluster.
