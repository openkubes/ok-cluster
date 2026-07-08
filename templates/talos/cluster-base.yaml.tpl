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
    openkubes.io/type: talos
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
apiVersion: controlplane.cluster.x-k8s.io/v1alpha3
kind: TalosControlPlane
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
spec:
  version: ${K8S_VERSION}
  replicas: ${CP_REPLICAS}
  infrastructureTemplate:
    apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
    kind: KubevirtMachineTemplate
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
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-workers
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
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
                    name: talos
                  - cdrom:
                      bus: sata
                      readonly: true
                    name: cloudinitdisk
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${CP_MEMORY}
              evictionStrategy: External
              volumes:
              - dataVolume:
                  name: ${CLUSTER_NAME}-cp-disk
                name: talos
              - cloudInitConfigDrive: {}
                name: cloudinitdisk
          dataVolumeTemplates:
          - metadata:
              name: ${CLUSTER_NAME}-cp-disk
              namespace: ${CLUSTER_NAME}
            spec:
              pvc:
                accessModes:
                - ReadWriteOnce
                resources:
                  requests:
                    storage: ${WORKER_DISK}
                storageClassName: ok-storage-block
              source:
                http:
                  url: "https://factory.talos.dev/image/${TALOS_SCHEMATIC_ID}/${TALOS_VERSION}/nocloud-amd64.raw.xz"
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
spec:
  template:
    spec:
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
                    name: talos
                  - cdrom:
                      bus: sata
                      readonly: true
                    name: cloudinitdisk
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${WORKER_MEMORY}
              evictionStrategy: External
              volumes:
              - dataVolume:
                  name: ${CLUSTER_NAME}-worker-disk
                name: talos
              - cloudInitConfigDrive: {}
                name: cloudinitdisk
          dataVolumeTemplates:
          - metadata:
              name: ${CLUSTER_NAME}-worker-disk
              namespace: ${CLUSTER_NAME}
            spec:
              pvc:
                accessModes:
                - ReadWriteOnce
                resources:
                  requests:
                    storage: ${WORKER_DISK}
                storageClassName: ok-storage-block
              source:
                http:
                  url: "https://factory.talos.dev/image/${TALOS_SCHEMATIC_ID}/${TALOS_VERSION}/nocloud-amd64.raw.xz"
