# kagent on ok-ai — OK-14 evaluation deployment

**Purpose:** answer the two kagent evaluation questions in
[OK-14](https://kubernauts.atlassian.net/browse/OK-14) (input to the
Go/No-Go for ADR-Platform-015). This is an **evaluation install, not a
platform offering** — per the stop rule (guideline Part C), *operating* a
second agent backend in parallel is a contract decision that requires
escalation. Evaluating it inside OK-14 is explicitly in scope.
**Uninstall after the evaluation.**

kagent: Solo.io, CNCF Sandbox — Kubernetes-native agent framework
(Agents/ModelConfigs/Tools as CRDs). Version pinned in the Makefile
(`0.9.9` as of 2026-07); charts via OCI from `ghcr.io/kagent-dev`.

## Config parity with OpenClaw (same LLM setup, fair comparison)

| | value |
|---|---|
| Ollama | `http://192.168.100.202:11434` (shared, ADR-005) |
| Model | `gpt-oss:20b` (function calling — required by kagent) |
| num_ctx | `32768` |

## Steps

```bash
make install             # CRDs + kagent (Helm OCI, pinned), default provider Ollama
make status              # pods, svc, ModelConfigs, Agents (default k8s-agent included)
make dashboard           # kagent's own UI -> http://localhost:8080
make eval-openai-compat  # evaluation question 1 (see below)
make uninstall           # after the evaluation
```

## The two OK-14 questions this install answers

1. **OpenAI-compatible backend behind Open WebUI, or own frontend?**
   `make eval-openai-compat` probes kagent services for `GET /v1/models`
   (what Open WebUI's connection verify calls). 200 + model list → kagent
   could carry Agent Interface Contract v1; otherwise kagent imposes its
   own frontend/A2A protocol, which would force a different contract cut.
   Also test in the dashboard: same troubleshooting scenarios as OpenClaw
   (CrashLoopBackOff, ImagePullBackOff, Pending pod) for a quality
   comparison.
2. **Maturity / release cadence as of decision date:** check
   [releases](https://github.com/kagent-dev/kagent/releases), open issues,
   CNCF status — current-state research, not cached knowledge (guideline).

Findings go into the OK-14 PoC report; the comparison drives the Go/No-Go
and, if kagent wins, a swap of the implementation profile **without
touching the contracts** — that is the point of the architecture.

## Notes

- kagent ships its own RBAC and default agents (k8s-agent etc.) — fine for
  the evaluation; not hardened to our guideline (that's what the
  evaluation is for, structurally: CRD-based agents map naturally onto the
  OK-15 Phase 2 XRD pattern).
- Shared GPU (AR-2): OpenClaw and kagent use the same Ollama/model, so no
  double VRAM — but avoid hammering both with parallel sessions.
- No token file here; kagent's UI is only reachable via port-forward.
