---
apiVersion: v1
kind: Namespace
metadata:
  name: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/golden-image-published: "${OS_GOLDEN_IMAGE_PUBLISHED}"
---
apiVersion: cluster.x-k8s.io/v1beta2
kind: Cluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/golden-image-published: "${OS_GOLDEN_IMAGE_PUBLISHED}"
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
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  controlPlaneServiceTemplate:
    spec:
      type: LoadBalancer
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp-${OS_IDENTITY_SHORT}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/golden-image-published: "${OS_GOLDEN_IMAGE_PUBLISHED}"
spec:
  template:
    spec:
      virtualMachineBootstrapCheck:
        checkStrategy: ${VM_BOOTSTRAP_CHECK_STRATEGY}
      virtualMachineTemplate:
        metadata:
          namespace: ${CLUSTER_NAME}
          labels:
            openkubes.io/type: flatcar
            openkubes.io/provider: ${INFRA_PROVIDER}
            openkubes.io/profile: ${OS_PROFILE}
            openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
            openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
            openkubes.io/deployable: "${OS_DEPLOYABLE}"
        spec:
          runStrategy: Always
          dataVolumeTemplates:
            - metadata:
                name: ${CLUSTER_NAME}-cp-${OS_IDENTITY_SHORT}-boot
              spec:
                source:
                  pvc:
                    namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
                    name: ${OS_GOLDEN_IMAGE_CLAIM}
                storage:
                  accessModes:
                    - ReadWriteOnce
                  resources:
                    requests:
                      storage: ${CP_DISK}
                  storageClassName: ${OS_GOLDEN_IMAGE_STORAGE_CLASS}
          template:
            metadata:
              labels:
                openkubes.io/type: flatcar
                openkubes.io/provider: ${INFRA_PROVIDER}
                openkubes.io/profile: ${OS_PROFILE}
                openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
                openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
                openkubes.io/deployable: "${OS_DEPLOYABLE}"
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
                      name: rootdisk
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${CP_MEMORY}
              evictionStrategy: External
              volumes:
                - dataVolume:
                    name: ${CLUSTER_NAME}-cp-${OS_IDENTITY_SHORT}-boot
                  name: rootdisk
---
apiVersion: controlplane.cluster.x-k8s.io/v1beta2
kind: KubeadmControlPlane
metadata:
  name: ${CLUSTER_NAME}-cp
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  replicas: ${CP_REPLICAS}
  version: ${K8S_VERSION}
  machineTemplate:
    spec:
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-cp-${OS_IDENTITY_SHORT}
  kubeadmConfigSpec:
    format: ${BOOTSTRAP_FORMAT}
    files: []
    ignition:
      containerLinuxConfig:
        additionalConfig: |
          systemd:
            units:
              - name: kubeadm.service
                enabled: true
                dropins:
                  - name: 10-flatcar.conf
                    contents: |
                      [Unit]
                      Requires=containerd.service
                      After=containerd.service
    clusterConfiguration:
      networking:
        dnsDomain: cluster.local
        podSubnet: ${POD_CIDR}
        serviceSubnet: ${SERVICE_CIDR}
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
  name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/golden-image-published: "${OS_GOLDEN_IMAGE_PUBLISHED}"
spec:
  template:
    spec:
      virtualMachineBootstrapCheck:
        checkStrategy: ${VM_BOOTSTRAP_CHECK_STRATEGY}
      virtualMachineTemplate:
        metadata:
          namespace: ${CLUSTER_NAME}
          labels:
            openkubes.io/type: flatcar
            openkubes.io/provider: ${INFRA_PROVIDER}
            openkubes.io/profile: ${OS_PROFILE}
            openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
            openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
            openkubes.io/deployable: "${OS_DEPLOYABLE}"
        spec:
          runStrategy: Always
          dataVolumeTemplates:
            - metadata:
                name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}-boot
              spec:
                source:
                  pvc:
                    namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
                    name: ${OS_GOLDEN_IMAGE_CLAIM}
                storage:
                  accessModes:
                    - ReadWriteOnce
                  resources:
                    requests:
                      storage: ${WORKER_DISK}
                  storageClassName: ${OS_GOLDEN_IMAGE_STORAGE_CLASS}
          template:
            metadata:
              labels:
                openkubes.io/type: flatcar
                openkubes.io/provider: ${INFRA_PROVIDER}
                openkubes.io/profile: ${OS_PROFILE}
                openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
                openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
                openkubes.io/deployable: "${OS_DEPLOYABLE}"
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
                      name: rootdisk
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${WORKER_MEMORY}
              evictionStrategy: External
              volumes:
                - dataVolume:
                    name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}-boot
                  name: rootdisk
---
apiVersion: bootstrap.cluster.x-k8s.io/v1beta2
kind: KubeadmConfigTemplate
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  template:
    spec:
      format: ${BOOTSTRAP_FORMAT}
      files: []
      ignition:
        containerLinuxConfig:
          additionalConfig: |
            systemd:
              units:
                - name: kubeadm.service
                  enabled: true
                  dropins:
                    - name: 10-flatcar.conf
                      contents: |
                        [Unit]
                        Requires=containerd.service
                        After=containerd.service
      joinConfiguration:
        nodeRegistration:
          criSocket: /var/run/containerd/containerd.sock
---
apiVersion: cluster.x-k8s.io/v1beta2
kind: MachineDeployment
metadata:
  name: ${CLUSTER_NAME}-workers
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  clusterName: ${CLUSTER_NAME}
  replicas: ${WORKER_REPLICAS}
  selector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  template:
    metadata:
      labels:
        cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
        openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
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
        name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}
