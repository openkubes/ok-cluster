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

## Troubleshooting: "Unauthorized" / model missing in Open WebUI

Symptom: Open WebUI shows `Unauthorized` when chatting with `openclaw`, or
the `openclaw*` models disappear from the model dropdown entirely — usually
after `.token` was regenerated (e.g. a fresh checkout where the gitignored
`.token` file didn't exist yet) or after `make install`/`make upgrade`.

There is no single "reconnect" command for this today (see the Agent Backend
Registration Contract gap noted in the ADR-Platform-015 Addendum) — it's a
two-part check:

**1. Is the token actually live on the OpenClaw pod?**

```bash
make token-show
kubectl --kubeconfig ~/.kube/ok-ai.yaml -n openclaw exec deploy/openclaw -- env | grep -i token
```

If these two values don't match, `helm upgrade` alone did not roll the pod
(no restart despite "successfully rolled out" — the pod's *age* is the
tell). Force it:

```bash
kubectl --kubeconfig ~/.kube/ok-ai.yaml -n openclaw rollout restart deploy/openclaw
kubectl --kubeconfig ~/.kube/ok-ai.yaml -n openclaw rollout status deploy/openclaw
```

Re-check the env var, then confirm the contract works in isolation before
touching Open WebUI at all:

```bash
make validate   # GET /v1/models + POST /v1/chat/completions, both against OpenClaw directly
```

**2. Does Open WebUI actually see the new token?**

`make connect-openwebui` only *seeds* env vars on the Open WebUI
StatefulSet — on an instance that was ever configured manually via the Admin
UI (true for ok-ai today), Open WebUI's **persisted DB config always wins**
over the env var, silently. Running `connect-openwebui` again will not fix
an already-broken connection on this instance. Instead:

1. `make connect-info` — prints the URL and current token to copy
2. Open WebUI → **Admin Settings → Connections → OpenAI** → open the
   OpenClaw connection
3. Paste the current token from step 1 into **Authentication → Bearer**
4. Click the **refresh icon next to the URL** (re-triggers `GET /v1/models`
   against the new token) — this step is easy to miss and is the actual fix
5. **Save**

Only after step 2's refresh/save does the `openclaw*` model set reappear in
the chat model dropdown. Skipping the manual UI refresh (e.g. assuming the
env var from step 1 was enough) is the most common way to get stuck here.
