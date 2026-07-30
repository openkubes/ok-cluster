# Profile A (kagent) on ok-ai — provider values (OK-92)

The **provider** side of the Read-Only Platform Diagnostics Contract (ADR-021),
deployed on ok-ai. This folder holds only the **private provider values**; the
generic manifests, facade and chart live in
[`openkubes/platform/ai/platform-diagnostics/profiles/kagent`](../../../openkubes/platform/ai/platform-diagnostics/profiles/kagent/)
(clone openkubes next to ok-cluster, same convention as `../../openclaw`).

> Not the same as `../` (the parent `kagent/` folder), which is the **OK-14
> evaluation** install of kagent. This subfolder is the **OK-92 Profile A**
> deployment: kagent as the contract's first provider profile. The eval install's
> `make install` (CRDs + controller) is the shared prerequisite.

## Deploy

```bash
make -C .. install          # once: kagent CRDs + controller (from the eval folder)
make preflight              # controller present + openkubes cloned
make deploy                 # RBAC + kagent CRs (real Ollama patched) + facade
make status
make validate               # calls the 3 contract functions (stub until mapping lands)
make verify-rbac            # ADR-021 test 2: reads OK, secrets/writes denied
```

Real Ollama endpoint (`192.168.100.202:11434`, VPN-only) is injected by
`kustomization.yaml`; the facade's provider values are in `facade-values.yaml`.

## How OpenClaw connects (the OK-87/OK-92 overlap)

OpenClaw is the **first consumer**, not kagent's frontend. The wire is:

```
Open WebUI ─► OpenClaw ─(Platform Diagnostics Skill = MCP adapter)─►
             facade (platform-diagnostics svc) ─► openkubes-platform-agent (kagent)
             ─► specialists ─► Kubernetes API (read-only SA)
```

`make connect-openclaw-info` prints the concrete steps. Two things matter:

1. **OpenClaw gets no cluster credentials.** It calls the contract endpoint via
   the MCP adapter only (ADR-021 Authorization model).
2. **RBAC handoff.** Today the openclaw chart carries the read-only Cluster
   Inspection RBAC. Under Profile A that inspection moves behind the contract
   into kagent's `openkubes-platform-agent` SA — so set `rbac.create=false` on
   the openclaw release once diagnostics run through the contract. Verified by
   `make verify-rbac` here + `make verify-kubectl` in `../../openclaw`.

Completing this satisfies **OK-87**'s open "kagent deployed and running on ok-ai /
wired as OpenClaw's backend" criterion and feeds **OK-14**'s kagent evaluation.

## Stop rule (guideline Part C)

Read-only only; secrets never. Do **not** register kagent as a second selectable
model in Open WebUI — here it is a provider *behind* the contract, not a parallel
chat backend (that would be an escalation, not an implementation detail).
