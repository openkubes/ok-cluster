# Standalone kagent deployment (OK-129)

Cluster-specific lifecycle for kagent on the disposable `ok-kagent` lab.

```bash
export OLLAMA_URL='<private endpoint>'
make -C ok-kagent/kagent install ACCESS_MODE=read-only
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

`ACCESS_MODE` is mandatory in operating procedures but defaults safely to
`read-only` for unattended invocations:

- `read-only`: the diagnostic Agent can inspect supported workload resources
  cluster-wide, but cannot write or read Secrets.
- `read-write`: keeps the read-only Agent and adds an approval-gated operator.
  The operator can change only ConfigMaps and Deployments in `kagent-lab`; it
  cannot read Secrets or write into another namespace.

The write profile deliberately does not set the upstream chart's
`rbac.readOnly=false`, because that setting grants the tool server cluster-admin
permissions. Instead it installs a second tool server with an explicit
namespace Role:

```bash
export OLLAMA_URL='<private endpoint>'
make -C ok-kagent/kagent install ACCESS_MODE=read-write
make -C ok-kagent/kagent verify-access ACCESS_MODE=read-write
```

The installer expects the `openkubes` and `ok-cluster` repositories to be
sibling directories. For another layout, pass the public repository explicitly:

```bash
make -C ok-kagent/kagent install \
  ACCESS_MODE=read-write \
  OPENKUBES_DIR=/path/to/openkubes
```

Switching back to `ACCESS_MODE=read-only` removes the gated Agent, its scoped
tool server, Role, and RoleBinding. The read-only diagnostic Agent remains.
