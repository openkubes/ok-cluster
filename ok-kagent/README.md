# ok-kagent lab cluster (OK-129)

Disposable Talos/KubeVirt cluster for the standalone kagent evaluation.

This is a public repository. The committed configuration deliberately uses
`auto` for the API endpoint, pod CIDR, and service CIDR. The renderer resolves
those values from the environment. Resolved configuration and rendered
manifests are local-only and ignored by Git.

## Render

```bash
./ok-kagent/generate-manifest.sh
```

The script preserves the public `cluster-config.yaml`, writes the resolved
configuration to the ignored `cluster-config.local.yaml`, and leaves the
rendered bootstrap/manifests in `ok-kagent/`.

Before applying anything, inspect the local outputs and use only the dedicated
management-cluster procedure from the root runbook. Workload access must use
`~/.kube/ok-kagent.yaml`.
