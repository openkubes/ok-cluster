---
apiVersion: v1
kind: Namespace
metadata:
  name: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: talos
    openkubes.io/provider: ${INFRA_PROVIDER}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/golden-image-published: "${OS_GOLDEN_IMAGE_PUBLISHED}"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${CLUSTER_NAME}-talos-golden-image-cloner
  namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
  labels:
    openkubes.io/type: talos
    openkubes.io/consumer-cluster: ${CLUSTER_NAME}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
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
  name: ${CLUSTER_NAME}-talos-golden-image-cloner
  namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
  labels:
    openkubes.io/type: talos
    openkubes.io/consumer-cluster: ${CLUSTER_NAME}
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
subjects:
- kind: ServiceAccount
  name: default
  namespace: ${CLUSTER_NAME}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${CLUSTER_NAME}-talos-golden-image-cloner
---
apiVersion: cluster.x-k8s.io/v1beta2
kind: Cluster
metadata:
  name: ${CLUSTER_NAME}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: talos
    openkubes.io/provider: ${INFRA_PROVIDER}
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
${INFRA_CLUSTER_SECRET_REF}  controlPlaneServiceTemplate:
    metadata:
      namespace: ${CLUSTER_NAME}
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
    name: ${CLUSTER_NAME}-cp-${MACHINE_TEMPLATE_ID}
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
      # Runtime binding and every platform application require this exact
      # workload storage identity. Keeping the reviewed manifest inline makes
      # it part of the lifecycle artifact and plan digest; no unbound
      # post-bootstrap installer is needed.
      # Source: rancher/local-path-provisioner v0.0.30
      # deploy/local-path-storage.yaml
      # Upstream source SHA-256 before image pinning:
      # fe682186b00400fe7e2b72bae16f63e47a56a6dcc677938c6642139ef670045e
      - op: add
        path: /cluster/inlineManifests
        value:
        - name: local-path-provisioner-v0.0.30
          contents: |-
            apiVersion: v1
            kind: Namespace
            metadata:
              name: local-path-storage
              labels:
                pod-security.kubernetes.io/enforce: privileged
                pod-security.kubernetes.io/warn: privileged
                pod-security.kubernetes.io/audit: privileged

            ---
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: local-path-provisioner-service-account
              namespace: local-path-storage

            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: local-path-provisioner-role
              namespace: local-path-storage
            rules:
              - apiGroups: [""]
                resources: ["pods"]
                verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]

            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: local-path-provisioner-role
            rules:
              - apiGroups: [""]
                resources: ["nodes", "persistentvolumeclaims", "configmaps", "pods", "pods/log"]
                verbs: ["get", "list", "watch"]
              - apiGroups: [""]
                resources: ["persistentvolumes"]
                verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
              - apiGroups: [""]
                resources: ["events"]
                verbs: ["create", "patch"]
              - apiGroups: ["storage.k8s.io"]
                resources: ["storageclasses"]
                verbs: ["get", "list", "watch"]

            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata:
              name: local-path-provisioner-bind
              namespace: local-path-storage
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: Role
              name: local-path-provisioner-role
            subjects:
              - kind: ServiceAccount
                name: local-path-provisioner-service-account
                namespace: local-path-storage

            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata:
              name: local-path-provisioner-bind
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: local-path-provisioner-role
            subjects:
              - kind: ServiceAccount
                name: local-path-provisioner-service-account
                namespace: local-path-storage

            ---
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: local-path-provisioner
              namespace: local-path-storage
            spec:
              replicas: 1
              selector:
                matchLabels:
                  app: local-path-provisioner
              template:
                metadata:
                  labels:
                    app: local-path-provisioner
                spec:
                  serviceAccountName: local-path-provisioner-service-account
                  containers:
                    - name: local-path-provisioner
                      image: rancher/local-path-provisioner@sha256:9b914881170048f80ae9302f36e5b99b4a6b18af73a38adc1c66d12f65d360be
                      imagePullPolicy: IfNotPresent
                      command:
                        - local-path-provisioner
                        - --debug
                        - start
                        - --config
                        - /etc/config/config.json
                      volumeMounts:
                        - name: config-volume
                          mountPath: /etc/config/
                      env:
                        - name: POD_NAMESPACE
                          valueFrom:
                            fieldRef:
                              fieldPath: metadata.namespace
                        - name: CONFIG_MOUNT_PATH
                          value: /etc/config/
                  volumes:
                    - name: config-volume
                      configMap:
                        name: local-path-config

            ---
            apiVersion: storage.k8s.io/v1
            kind: StorageClass
            metadata:
              name: local-path
            provisioner: rancher.io/local-path
            volumeBindingMode: WaitForFirstConsumer
            reclaimPolicy: Delete

            ---
            kind: ConfigMap
            apiVersion: v1
            metadata:
              name: local-path-config
              namespace: local-path-storage
            data:
              config.json: |-
                {
                        "nodePathMap":[
                        {
                                "node":"DEFAULT_PATH_FOR_NON_LISTED_NODES",
                                "paths":["/opt/local-path-provisioner"]
                        }
                        ]
                }
              setup: |-
                #!/bin/sh
                set -eu
                mkdir -m 0777 -p "$VOL_DIR"
              teardown: |-
                #!/bin/sh
                set -eu
                rm -rf "$VOL_DIR"
              helperPod.yaml: |-
                apiVersion: v1
                kind: Pod
                metadata:
                  name: helper-pod
                spec:
                  priorityClassName: system-node-critical
                  tolerations:
                    - key: node.kubernetes.io/disk-pressure
                      operator: Exists
                      effect: NoSchedule
                  containers:
                  - name: helper-pod
                    image: busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
                    imagePullPolicy: IfNotPresent
      - op: add
        path: /machine/features/hostDNS
        value:
          enabled: false
---
apiVersion: bootstrap.cluster.x-k8s.io/v1alpha3
kind: TalosConfigTemplate
metadata:
  name: ${CLUSTER_NAME}-workers-${TALOS_VERSION_NAME}
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
            name: ${CLUSTER_NAME}-workers-${TALOS_VERSION_NAME}
      infrastructureRef:
        apiGroup: infrastructure.cluster.x-k8s.io
        kind: KubevirtMachineTemplate
        name: ${CLUSTER_NAME}-workers-${MACHINE_TEMPLATE_ID}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp-${MACHINE_TEMPLATE_ID}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: talos
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/provider-profile: ${PROVIDER_PROFILE_NAME}
    openkubes.io/provider-profile-identity: ${PROVIDER_PROFILE_IDENTITY}
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
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${CP_MEMORY}
              evictionStrategy: External
              volumes:
              - dataVolume:
                  name: ${CLUSTER_NAME}-cp-${MACHINE_TEMPLATE_ID}-disk
                name: talos
          dataVolumeTemplates:
          - metadata:
              name: ${CLUSTER_NAME}-cp-${MACHINE_TEMPLATE_ID}-disk
              namespace: ${CLUSTER_NAME}
            spec:
              pvc:
                accessModes:
                - ReadWriteOnce
                resources:
                  requests:
                    storage: ${CP_DISK}
                storageClassName: ${CLONE_TARGET_STORAGE_CLASS}
              source:
                pvc:
                  namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
                  name: ${OS_GOLDEN_IMAGE_CLAIM}
---
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubevirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-workers-${MACHINE_TEMPLATE_ID}
  namespace: ${CLUSTER_NAME}
  labels:
    openkubes.io/type: talos
    openkubes.io/os-identity: ${OS_IDENTITY_SHORT}
  annotations:
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
    openkubes.io/provider-profile: ${PROVIDER_PROFILE_NAME}
    openkubes.io/provider-profile-identity: ${PROVIDER_PROFILE_IDENTITY}
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
                  networkInterfaceMultiqueue: true
                memory:
                  guest: ${WORKER_MEMORY}
              evictionStrategy: External
              volumes:
              - dataVolume:
                  name: ${CLUSTER_NAME}-worker-${MACHINE_TEMPLATE_ID}-disk
                name: talos
          dataVolumeTemplates:
          - metadata:
              name: ${CLUSTER_NAME}-worker-${MACHINE_TEMPLATE_ID}-disk
              namespace: ${CLUSTER_NAME}
            spec:
              pvc:
                accessModes:
                - ReadWriteOnce
                resources:
                  requests:
                    storage: ${WORKER_DISK}
                storageClassName: ${CLONE_TARGET_STORAGE_CLASS}
              source:
                pvc:
                  namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
                  name: ${OS_GOLDEN_IMAGE_CLAIM}
