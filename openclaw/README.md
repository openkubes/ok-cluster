# OpenClaw on ok-ai — operational folder

OpenClaw is an **Implementation Profile** behind the **Agent Interface
Contract v1** (ADR-Platform-015: OpenAI Chat Completions + Tool Calling) —
not a platform-owned component. ok-shared and ok-robotics are intended to
serve the same contract via OpenClaw with a kagent-based Skill Contract
backend instead (tracked as in-progress work, OK-87/OK-92 — not yet
deployed as of this writing); every instance registers into the single Open
WebUI (ok-ai) as a selectable model, so the frontend never has to know which
backend or cluster it's talking to.

The **reusable chart, kubectl image, CI workflow, and docs** live in the
platform repo: [`openkubes/platform/ai/openclaw`](../../openkubes/platform/ai/openclaw/).
This folder holds only the **concrete, cluster-specific deployment values**
for the ok-ai instance. Both `ok-cluster` and `openkubes` are public repos —
the split here is generic/reusable vs. instance-specific values, not access
control. (The Ollama endpoint below is a private-network/VPN-only address
regardless of repo visibility.)

This folder contains only:

- `Makefile` — operational targets against `ok-ai`, with this instance's
  real provider values (Ollama endpoint `192.168.100.202:11434`)
- `claim-ok-ai.yaml` — OpenClaw Crossplane Claim with the real provider
  values for this instance (see the component's `crossplane/` folder in
  `openkubes` for the generic XRD/example)
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
