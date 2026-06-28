---
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
    openkubes.io/type: ubuntu
    openkubes.io/k8s-version: ${K8S_VERSION}
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
    kind: KubeadmControlPlane
    name: ${CLUSTER_NAME}-cp
  infrastructureRef:
    apiGroup: infrastructure.cluster.x-k8s.io
    kind: KubevirtCluster
    name: ${CLUSTER_NAME}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtCluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${CLUSTER_NAME}
spec:
  controlPlaneServiceTemplate:
    spec:
      type: LoadBalancer
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
      virtualMachineBootstrapCheck:
        checkStrategy: ssh
      virtualMachineTemplate:
        metadata:
          namespace: ${CLUSTER_NAME}
        spec:
          runStrategy: Always
          template:
            spec:
              nodeSelector:
                kubernetes.io/hostname: ${NODE_SELECTOR}
              domain:
                cpu:
                  cores: ${CP_CORES}
                devices:
                  disks:
                  - disk:
                      bus: virtio
                    name: containervolume
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${CP_MEMORY}
              evictionStrategy: External
              volumes:
              - containerDisk:
                  image: quay.io/capk/ubuntu-2404-container-disk:${K8S_VERSION}
                name: containervolume
---
apiVersion: controlplane.cluster.x-k8s.io/v1beta2
kind: KubeadmControlPlane
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
spec:
  replicas: ${CP_REPLICAS}
  version: ${K8S_VERSION}
  machineTemplate:
    spec:
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-cp
  kubeadmConfigSpec:
    initConfiguration:
      nodeRegistration:
        criSocket: /var/run/containerd/containerd.sock
    joinConfiguration:
      nodeRegistration:
        criSocket: /var/run/containerd/containerd.sock
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
      virtualMachineBootstrapCheck:
        checkStrategy: ssh
      virtualMachineTemplate:
        metadata:
          namespace: ${CLUSTER_NAME}
        spec:
          runStrategy: Always
          template:
            spec:
              nodeSelector:
                kubernetes.io/hostname: ${NODE_SELECTOR}
              domain:
                cpu:
                  cores: ${WORKER_CORES}
                devices:
                  disks:
                  - disk:
                      bus: virtio
                    name: containervolume
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${WORKER_MEMORY}
              evictionStrategy: External
              volumes:
              - containerDisk:
                  image: quay.io/capk/ubuntu-2404-container-disk:${K8S_VERSION}
                name: containervolume
---
apiVersion: bootstrap.cluster.x-k8s.io/v1beta2
kind: KubeadmConfigTemplate
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
      joinConfiguration:
        nodeRegistration:
          criSocket: /var/run/containerd/containerd.sock
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
          kind: KubeadmConfigTemplate
          name: ${CLUSTER_NAME}-workers
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-workers
