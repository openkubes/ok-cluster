---
# templates/talos/providers/openstack/cluster.yaml.tpl
# OpenStack (CAPO) + Talos workload cluster — OK-106 Proof B (spike; static render only).
#
# The provider-neutral core (Cluster / TalosControlPlane / TalosConfigTemplate /
# MachineDeployment) mirrors templates/talos/cluster-base.yaml.tpl. Only the
# infrastructure objects differ: OpenStackCluster / OpenStackMachineTemplate
# (CAPO v1beta2) instead of KubevirtCluster / KubevirtMachineTemplate.
#
# Control-plane endpoint: Octavia managed LoadBalancer — the Proof-B resolution of
# the endpointIP TODO (KubeVirt used a MetalLB LoadBalancer service / endpointIP).
# Control-plane provider is Talos (same as the native KubeVirt path) — the
# Kubeadm coupling only ever lived in the historical capi-platform-v4.2 runner.
apiVersion: v1
kind: Namespace
metadata:
  name: ${CLUSTER_NAME}
---
apiVersion: cluster.x-k8s.io/v1beta2
kind: Cluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: talos
    openkubes.io/provider: openstack
    openkubes.io/k8s-version: ${K8S_VERSION}
    openkubes.io/talos-version: ${TALOS_VERSION}
spec:
  clusterNetwork:
    pods:
      cidrBlocks:
      - ${POD_CIDR}
    services:
      cidrBlocks:
      - ${SERVICE_CIDR}
  controlPlaneRef:
    apiGroup: controlplane.cluster.x-k8s.io
    kind: TalosControlPlane
    name: ${CLUSTER_NAME}-cp
  infrastructureRef:
    apiGroup: infrastructure.cluster.x-k8s.io
    kind: OpenStackCluster
    name: ${CLUSTER_NAME}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: OpenStackCluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${CLUSTER_NAME}
spec:
  # Octavia-managed control-plane LoadBalancer (replaces KubeVirt MetalLB endpointIP).
  apiServer:
    managedLoadBalancer:
      enabled: true
  externalNetwork:
    filter:
      name: ${OS_EXTERNAL_NETWORK}
  identityRef:
    # Credentials are a PREREQUISITE (clouds.yaml / application credentials),
    # provided out of band as this Secret — no credential API is created here.
    cloudName: ${OS_CLOUD_NAME}
    name: ${OS_CREDENTIALS_SECRET}
  managedSecurityGroups:
    allowAllInClusterTraffic: true
  managedSubnets:
  - cidr: ${OS_SUBNET_CIDR}
    dnsNameservers:
    - ${OS_DNS}
---
apiVersion: controlplane.cluster.x-k8s.io/v1alpha3
kind: TalosControlPlane
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
spec:
  version: ${K8S_VERSION}
  replicas: ${CP_REPLICAS}
  infrastructureTemplate:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
    kind: OpenStackMachineTemplate
    name: ${CLUSTER_NAME}-cp
    namespace: ${CLUSTER_NAME}
  controlPlaneConfig:
    controlplane:
      generateType: controlplane
      talosVersion: ${TALOS_VERSION}
      configPatches:
      - op: add
        path: /cluster/network/cni
        value:
          name: none
      - op: add
        path: /cluster/proxy
        value:
          disabled: true
      - op: add
        path: /machine/features/hostDNS
        value:
          enabled: false
---
apiVersion: bootstrap.cluster.x-k8s.io/v1alpha3
kind: TalosConfigTemplate
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
      generateType: worker
      talosVersion: ${TALOS_VERSION}
      configPatches:
      - op: add
        path: /cluster/network/cni
        value:
          name: none
      - op: add
        path: /cluster/proxy
        value:
          disabled: true
      - op: add
        path: /machine/features/hostDNS
        value:
          enabled: false
---
apiVersion: cluster.x-k8s.io/v1beta2
kind: MachineDeployment
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
spec:
  clusterName: ${CLUSTER_NAME}
  replicas: ${WORKER_REPLICAS}
  selector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  template:
    spec:
      clusterName: ${CLUSTER_NAME}
      version: ${K8S_VERSION}
      bootstrap:
        configRef:
          apiGroup: bootstrap.cluster.x-k8s.io
          kind: TalosConfigTemplate
          name: ${CLUSTER_NAME}-workers
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: OpenStackMachineTemplate
        name: ${CLUSTER_NAME}-workers
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: OpenStackMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
      flavor:
        filter:
          name: ${OS_CP_FLAVOR}
      image:
        filter:
          name: ${OS_IMAGE_NAME}
      sshKeyName: ${OS_SSH_KEY}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: OpenStackMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
      flavor:
        filter:
          name: ${OS_NODE_FLAVOR}
      image:
        filter:
          name: ${OS_IMAGE_NAME}
      sshKeyName: ${OS_SSH_KEY}
# ── Proof B TODOs (NOT solved here; separate capability contracts) ────────────
# TODO(OCCM/Cinder): OpenStack cloud-provider (external) + Cinder CSI is a
#   separate capability contract (see OK-106); not wired into this manifest.
# TODO(bootstrap delivery): on OpenStack, CAPO delivers the Talos machine config
#   via config drive / user data (Talos openstack image). No talosctl apply-config
#   step as in the KubeVirt bootstrap.sh — validated at provisioning time (Proof B+).
