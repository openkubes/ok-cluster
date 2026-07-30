---
# templates/talos/cluster-v2.yaml.tpl
# CAPK v2 format with ConfigDrive — rendered by render.py
# Legacy auxiliary ConfigDrive template; consumes the immutable Golden PVC.
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: KubeVirtMachineTemplate
metadata:
  name: ${CLUSTER_NAME}-cp-v2-${OS_IDENTITY_SHORT}
  namespace: ${CLUSTER_NAME}
  annotations:
    openkubes.io/talos-schematic: ${TALOS_SCHEMATIC_ID}
    openkubes.io/os-identity-full: ${OS_IDENTITY}
    openkubes.io/os-image-digest: ${OS_IMAGE_DIGEST}
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
                    name: ${CLUSTER_NAME}-cp-v2-${OS_IDENTITY_SHORT}-boot
                - name: cloudinitdisk
                  cloudInitConfigDrive: {}
              dataVolumeTemplates:
                - metadata:
                    name: ${CLUSTER_NAME}-cp-v2-${OS_IDENTITY_SHORT}-boot
                  spec:
                    pvc:
                      accessModes: [ReadWriteOnce]
                      resources:
                        requests:
                          storage: 20Gi
                      storageClassName: ok-storage-block
                    source:
                      pvc:
                        namespace: ${OS_GOLDEN_IMAGE_NAMESPACE}
                        name: ${OS_GOLDEN_IMAGE_CLAIM}
