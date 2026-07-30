# OK-125 Flatcar-only CNI profile.
# Chart: cilium 1.19.6
# Chart SHA-256: 21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179
#
# The KubeVirt control-plane Service is bound to ENDPOINT_IP by the sibling
# cluster template. No Talos KubePrism or Ubuntu runtime-discovery value is
# inherited here.
operator:
  replicas: 1

ipam:
  mode: kubernetes

kubeProxyReplacement: true
k8sServiceHost: ${ENDPOINT_IP}
k8sServicePort: 6443

routingMode: tunnel
tunnelProtocol: vxlan

cgroup:
  autoMount:
    enabled: true
  hostRoot: /sys/fs/cgroup
