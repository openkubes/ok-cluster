# OpenClaw on ok1-talos — operational folder

The **canonical component** (Helm chart, kubectl image, CI workflow, full
docs) lives in the platform repo:
[`openkubes/platform/ai/openclaw`](../../openkubes/platform/ai/openclaw/) —
same split as Open WebUI (component in `openkubes`, provider values and
operations here).

This folder contains only:

- `Makefile` — operational targets against `ok1-talos`, with the **private
  provider values** (Ollama endpoint `192.168.100.202:11434`) that don't
  belong in the public platform repo
- `.token` — generated gateway token (gitignored)

```bash
make preflight           # 1: chart present, nodes, Ollama, Open WebUI env
make install             # 2: helm install from ../openkubes, token auto-generated
make status              # 3: pod/svc/gateway health
make validate            # 4: in-cluster /v1 contract test
make connect-openwebui   # 5: auto-register in Open WebUI (seeds fresh instances;
                         #    manually configured instances keep their UI config)
make verify-kubectl      # RBAC guardrails: reads OK, secrets/writes denied
```

Requires the `openkubes` repo cloned next to `ok-cluster` (checked by
`make preflight`). Image build/push and chart changes happen in the
component — see its README.
