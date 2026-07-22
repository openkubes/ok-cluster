# Open WebUI on ok-ai — operational folder

Open WebUI is a self-service capability (ADR-Platform-005, `OpenWebUIClaim` XRD)
— any team/cluster may claim its own instance; a dedicated instance per cluster
is no longer the *only* supported topology (ADR-Platform-015 Addendum,
2026-07-21, amends ADR-005's documented default topology, core decisions
unchanged). Today only ok-ai has claimed one, and it's deployed: ok-shared and
ok-robotics are intended to run a kagent-backed ops agent instead of a
per-team chat UI (tracked as in-progress work, OK-87/OK-92 — not yet
deployed), registering their Agent Backend into this ok-ai instance as a
selectable model via the Agent Interface Contract v1, rather than each
cluster running its own Open WebUI. Open WebUI remains the
frontend half of the initial tandem Implementation Profile (ADR-015 Decision
4); no separate frontend-swap contract is needed since nothing requires Open
WebUI itself to be replaceable. The *registration* mechanism connecting
multiple clusters' backends into it (`make connect-openwebui`), however, is a
real cross-cluster forcing pattern without a formal contract yet — see the
ADR-015 Addendum.

The **reusable XRD, Composition, and generic ops Makefile** live in the
platform repo: [`openkubes/platform/ai/open-webui`](../../openkubes/platform/ai/open-webui/).
This folder holds only the **concrete, cluster-specific deployment values**
for the ok-ai instance. Both `ok-cluster` and `openkubes` are public repos —
the split is generic/reusable vs. instance-specific values, not access
control. (The Ollama endpoint below is a private-network/VPN-only address
regardless of repo visibility.)

This folder contains only:

- `claim-ok-ai.yaml` — Open WebUI Crossplane Claim with the real provider
  values for this instance (see the component's `crossplane/` folder in
  `openkubes` for the generic XRD/Composition/example and setup)

```bash
kubectl --kubeconfig ~/.kube/ok-mgmt.yaml apply -f claim-ok-ai.yaml
```

Requires `make setup` to have been run once in
`openkubes/platform/ai/open-webui/crossplane/` (applies the XRD + Composition
to ok-mgmt).
