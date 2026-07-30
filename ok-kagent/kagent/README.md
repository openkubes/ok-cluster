# Standalone kagent deployment (OK-129)

Cluster-specific lifecycle for kagent on the disposable `ok-kagent` lab.

```bash
export OLLAMA_URL='<private endpoint>'
make -C ok-kagent/kagent install
make -C ok-kagent/kagent status
make -C ok-kagent/kagent dashboard
make -C ok-kagent/kagent uninstall
```

`OLLAMA_URL` is substituted into `.values.local.yaml`, which is mode `0600` and
Git-ignored. Never place the private endpoint or credentials in the committed
template.

The Helm path is the recommended reproducible path. The kagent CLI install is
also exercised once for OK-129, but it is not the source of truth because its
generated configuration is less reviewable than the versioned Helm values.

The default tool server is cluster-readable but cannot write or read Secrets.
For the controlled write drill, install a second tool server whose ServiceAccount
has only a namespace Role:

```bash
make -C ok-kagent/kagent operator-tools-install
make -C ok-kagent/kagent operator-tools-status
```

Apply the corresponding Role, `RemoteMCPServer`, and gated Agent from
`openkubes/platform/ai/kagent-standalone/operator/`. Remove that separate tool
server after the drill with `make -C ok-kagent/kagent operator-tools-uninstall`.
