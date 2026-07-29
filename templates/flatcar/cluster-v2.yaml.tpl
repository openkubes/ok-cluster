---
apiVersion: v1
kind: Namespace
metadata:
  name: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/golden-image-published: "${OS_GOLDEN_IMAGE_PUBLISHED}"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${CLUSTER_NAME}-golden-image-cloner
  namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
rules:
  - apiGroups:
      - cdi.kubevirt.io
    resources:
      - datavolumes/source
    verbs:
      - create
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${CLUSTER_NAME}-golden-image-cloner
  namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
subjects:
  - kind: ServiceAccount
    name: default
    namespace: ${CLUSTER_NAME}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${CLUSTER_NAME}-golden-image-cloner
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
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  controlPlaneServiceTemplate:
    metadata:
      annotations:
        metallb.universe.tf/loadBalancerIPs: ${ENDPOINT_IP}
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
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
            openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
                openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  replicas: ${CP_REPLICAS}
  version: ${K8S_VERSION}
  rollout:
    strategy:
      type: RollingUpdate
      rollingUpdate:
        maxSurge: 1
  machineTemplate:
    spec:
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-cp-${OS_IDENTITY_SHORT}
  kubeadmConfigSpec:
    format: ${BOOTSTRAP_FORMAT}
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
                      Wants=kubelet.service
                      After=containerd.service
                      OnFailure=ok125-kubeadm-failure.service
                      [Service]
                      Environment=PATH=/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
                      TimeoutStartSec=0
                      StandardError=journal+console
                      ExecStartPost=/bin/sh -c 'echo OK125_KUBEADM_SUCCEEDED >/dev/ttyS0'
              - name: ok125-kubeadm-failure.service
                contents: |
                  [Unit]
                  Description=OK-125 redacted kubeadm failure marker

                  [Service]
                  Type=oneshot
                  ExecStart=/bin/sh -c '/bin/systemctl show kubeadm.service --property=Result --property=ExecMainStatus >/dev/ttyS0'
                  ExecStart=/bin/sh -c '/bin/journalctl -u kubeadm.service -b --no-pager -n 200 -o cat | /bin/grep -Ei "([[]ERROR |error execution phase|kubelet-check|control-plane|timed out|unable to|failed to|not found|unsupported|connection refused|deadline exceeded|CRI)" | /bin/grep -Eiv "(token|password|secret|certificate|private[ -]?key|client-key|key-data|discovery)" >/dev/ttyS0 || true'
              - name: kubelet.service
                enabled: true
                contents: |
                  [Unit]
                  Description=kubelet: Kubernetes Node Agent (Flatcar profile)
                  Wants=network-online.target
                  Requires=containerd.service
                  After=network-online.target containerd.service
                  StartLimitIntervalSec=0

                  [Service]
                  Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
                  Environment=KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml
                  EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
                  EnvironmentFile=-/etc/default/kubelet
                  ExecStart=/opt/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
                  Restart=always
                  RestartSec=10

                  [Install]
                  WantedBy=multi-user.target
    initConfiguration:
      skipPhases:
        - addon/kube-proxy
      nodeRegistration:
        criSocket: /var/run/containerd/containerd.sock
        kubeletExtraArgs:
          - name: node-labels
            value: openkubes.io/os-identity=${OS_IDENTITY_SHORT},openkubes.io/profile-revision=${OS_PROFILE_REVISION}
    joinConfiguration:
      nodeRegistration:
        criSocket: /var/run/containerd/containerd.sock
        kubeletExtraArgs:
          - name: node-labels
            value: openkubes.io/os-identity=${OS_IDENTITY_SHORT},openkubes.io/profile-revision=${OS_PROFILE_REVISION}
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
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
            openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
                openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
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
  name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: flatcar
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/profile: ${OS_PROFILE}
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  template:
    spec:
      format: ${BOOTSTRAP_FORMAT}
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
                        Wants=kubelet.service
                        After=containerd.service
                        OnFailure=ok125-kubeadm-failure.service
                        [Service]
                        Environment=PATH=/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
                        TimeoutStartSec=0
                        StandardError=journal+console
                        ExecStartPost=/bin/sh -c 'echo OK125_KUBEADM_SUCCEEDED >/dev/ttyS0'
                - name: ok125-kubeadm-failure.service
                  contents: |
                    [Unit]
                    Description=OK-125 redacted kubeadm failure marker

                    [Service]
                    Type=oneshot
                    ExecStart=/bin/sh -c '/bin/systemctl show kubeadm.service --property=Result --property=ExecMainStatus >/dev/ttyS0'
                    ExecStart=/bin/sh -c '/bin/journalctl -u kubeadm.service -b --no-pager -n 200 -o cat | /bin/grep -Ei "([[]ERROR |error execution phase|kubelet-check|control-plane|timed out|unable to|failed to|not found|unsupported|connection refused|deadline exceeded|CRI)" | /bin/grep -Eiv "(token|password|secret|certificate|private[ -]?key|client-key|key-data|discovery)" >/dev/ttyS0 || true'
                - name: kubelet.service
                  enabled: true
                  contents: |
                    [Unit]
                    Description=kubelet: Kubernetes Node Agent (Flatcar profile)
                    Wants=network-online.target
                    Requires=containerd.service
                    After=network-online.target containerd.service
                    StartLimitIntervalSec=0

                    [Service]
                    Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
                    Environment=KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml
                    EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
                    EnvironmentFile=-/etc/default/kubelet
                    ExecStart=/opt/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
                    Restart=always
                    RestartSec=10

                    [Install]
                    WantedBy=multi-user.target
      joinConfiguration:
        nodeRegistration:
          criSocket: /var/run/containerd/containerd.sock
          kubeletExtraArgs:
            - name: node-labels
              value: openkubes.io/os-identity=${OS_IDENTITY_SHORT},openkubes.io/profile-revision=${OS_PROFILE_REVISION}
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
    openkubes.io/profile-revision: "${OS_PROFILE_REVISION}"
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
    openkubes.io/adoption-status: ${OS_CANDIDATE_STATUS}
    openkubes.io/deployable: "${OS_DEPLOYABLE}"
spec:
  clusterName: ${CLUSTER_NAME}
  replicas: ${WORKER_REPLICAS}
  rollout:
    strategy:
      type: RollingUpdate
      rollingUpdate:
        maxSurge: 1
        maxUnavailable: 0
  selector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
  template:
    metadata:
      labels:
        cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
    spec:
      clusterName: ${CLUSTER_NAME}
      version: ${K8S_VERSION}
      bootstrap:
        configRef:
          apiGroup: bootstrap.cluster.x-k8s.io
          kind: KubeadmConfigTemplate
          name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-workers-${OS_IDENTITY_SHORT}
