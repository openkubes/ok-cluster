---
# templates/talos/cluster-v2.yaml.tpl
# CAPK v2 format with ConfigDrive — rendered by render.py
# Extends cluster-base.yaml with explicit ConfigDrive source for openstack-amd64.qcow2
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubeVirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp-v2
  namespace: default
  annotations:
    openkubes.io/talos-schematic: ${TALOS_SCHEMATIC_ID}
spec:
  template:
    spec:
      virtualMachineTemplate:
        spec:
          runStrategy: Always
          template:
            spec:
              domain:
                cpu:
                  cores: ${CP_CORES}
                resources:
                  requests:
                    memory: ${CP_MEMORY}
              volumes:
                - name: bootvolume
                  dataVolume:
                    name: ${CLUSTER_NAME}-cp-v2-boot
                - name: cloudinitdisk
                  cloudInitConfigDrive: {}
              dataVolumeTemplates:
                - metadata:
                    name: ${CLUSTER_NAME}-cp-v2-boot
                  spec:
                    pvc:
                      accessModes: [ReadWriteOnce]
                      resources:
                        requests:
                          storage: 20Gi
                      storageClassName: local-path
                    source:
                      registry:
                        url: "docker://factory.talos.dev/installer/${TALOS_SCHEMATIC_ID}:${TALOS_VERSION}"
                        secretRef:
                          name: talos-registry-pull-secret
