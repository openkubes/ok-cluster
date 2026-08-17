# OpenClaw on ok-ai — operational wrapper (OK-15 Phase 1)
# OWNER: openkubes/platform/ai/openclaw/Makefile is the canonical Makefile;
# this is a deliberate PoC copy (private provider values) — sync from there.
#
# Canonical component (chart, image, CI, docs):
#   ../openkubes/platform/ai/openclaw/          (referenced relatively, same
#   pattern as the root Makefile's OPENWEBUI_CLAIM)
# This folder holds only the PRIVATE provider values (Ollama endpoint) and
# the operational state (.token, gitignored).
#
# Steps: make preflight -> install -> status -> validate -> connect-openwebui

.PHONY: help preflight install upgrade uninstall status validate logs \
        token-show connect-info connect-openwebui fix-openwebui-ollama \
        prepare-diagnostics-consumer verify-mcp-consumer verify-mcp-live
.DEFAULT_GOAL := help

CLUSTER     ?= ok-ai
KUBECONFIG  ?= $(HOME)/.kube/$(CLUSTER).yaml
KUBECTL     := kubectl --kubeconfig $(KUBECONFIG)
NS          ?= openclaw
RELEASE     ?= openclaw
SELF_DIR    := $(dir $(lastword $(MAKEFILE_LIST)))
CHART       ?= $(SELF_DIR)../../openkubes/platform/ai/openclaw/charts/openclaw
TOKEN_FILE  := $(SELF_DIR).token
SVC_URL     := http://$(RELEASE).$(NS).svc.cluster.local:18789

# ── private provider values (this repo is the right place for them) ──────────
OLLAMA_URL      ?= http://192.168.100.202:11434
MODEL           ?=
OPENWEBUI_NS    ?= open-webui
OPENWEBUI_STS   ?= open-webui-$(CLUSTER)

help:
	@echo "OpenClaw on $(CLUSTER) — operational targets (component: openkubes/platform/ai/openclaw)"
	@echo ""
	@echo "  make preflight             # step 1: cluster/ollama/open-webui checks"
	@echo "  make install               # step 2: helm install (token auto-generated)"
	@echo "  make status                # step 3: pod, service, gateway health"
	@echo "  make validate              # step 4: in-cluster contract test (/v1)"
	@echo "  make connect-openwebui     # step 5: auto-register in Open WebUI (env seed)"
	@echo "  make connect-info          # step 5 alt: values for manual Admin-UI entry"
	@echo "  make verify-mcp-consumer   # render the chart and verify the MCP-only boundary"
	@echo "  make prepare-diagnostics-consumer # label namespace for adapter ingress"
	@echo "  make verify-mcp-live       # verify no token/kubectl and inspect MCP registration"
	@echo ""
	@echo "  make upgrade | logs | token-show | fix-openwebui-ollama | uninstall"
	@echo "  Model switch: make upgrade MODEL=<name:tag>   (pull on Ollama host first)"
	@echo "  Reusable chart/docs: see canonical component (make -C $(CHART)/../.. help)"

# ── step 1 ────────────────────────────────────────────────────────────────────
preflight:
	@echo "== chart present? =="
	@test -d $(CHART) || (echo "ERROR: chart not found at $(CHART) — clone/pull openkubes next to ok-cluster"; exit 1)
	@echo "OK: $(CHART)"
	@echo ""
	@echo "== kubeconfig / nodes =="
	@$(KUBECTL) get nodes
	@echo ""
	@echo "== Ollama reachable from inside the cluster? =="
	@$(KUBECTL) run openclaw-preflight --rm -i --restart=Never \
		--image=curlimages/curl:8.9.1 -- \
		curl -fsS --max-time 5 $(OLLAMA_URL)/api/tags \
		&& echo "OK: Ollama reachable — check the loaded models above" \
		|| echo "FAIL: Ollama not reachable from the cluster ($(OLLAMA_URL))"
	@echo ""
	@echo "== Open WebUI: OLLAMA_BASE_URL set? (known chart bug, guideline Part B) =="
	@$(KUBECTL) -n $(OPENWEBUI_NS) get sts $(OPENWEBUI_STS) \
		-o jsonpath='{.spec.template.spec.containers[0].env}' 2>/dev/null \
		| grep -q OLLAMA_BASE_URL \
		&& echo "OK: OLLAMA_BASE_URL is set" \
		|| echo "WARN: OLLAMA_BASE_URL missing — run 'make fix-openwebui-ollama'"

fix-openwebui-ollama:
	$(KUBECTL) -n $(OPENWEBUI_NS) set env sts/$(OPENWEBUI_STS) \
		OLLAMA_BASE_URL=$(OLLAMA_URL)

# ── step 2 ────────────────────────────────────────────────────────────────────
$(TOKEN_FILE):
	@umask 077 && openssl rand -hex 24 > $(TOKEN_FILE)
	@echo "Generated new gateway token -> $(TOKEN_FILE) (gitignored)"

prepare-diagnostics-consumer:
	@$(KUBECTL) create namespace $(NS) --dry-run=client -o yaml | $(KUBECTL) apply -f -
	@$(KUBECTL) label namespace $(NS) \
		openkubes.io/diagnostics-consumer=true --overwrite

install: $(TOKEN_FILE) prepare-diagnostics-consumer
	helm upgrade --install $(RELEASE) $(CHART) \
		--kubeconfig $(KUBECONFIG) \
		--namespace $(NS) --create-namespace \
		--set gateway.token=$$(cat $(TOKEN_FILE)) \
		--set ollama.baseUrl=$(OLLAMA_URL) \
		--set diagnostics.defaultCluster=$(CLUSTER) \
		$(if $(MODEL),--set ollama.model=$(MODEL))
	@$(KUBECTL) -n $(NS) rollout status deploy/$(RELEASE) --timeout=180s

upgrade: install

uninstall:
	helm uninstall $(RELEASE) --kubeconfig $(KUBECONFIG) -n $(NS) || true
	$(KUBECTL) delete namespace $(NS) --ignore-not-found

# ── step 3 ────────────────────────────────────────────────────────────────────
status:
	@$(KUBECTL) -n $(NS) get pods,svc
	@echo ""
	@echo "== gateway health (in-pod) =="
	@$(KUBECTL) -n $(NS) exec deploy/$(RELEASE) -- \
		node -e "fetch('http://127.0.0.1:18789/healthz').then(r=>{console.log('healthz:',r.status);return fetch('http://127.0.0.1:18789/readyz')}).then(r=>console.log('readyz: ',r.status)).catch(e=>{console.error(e.message);process.exit(1)})"

logs:
	$(KUBECTL) -n $(NS) logs deploy/$(RELEASE) -f --tail=100

# ── step 4: Agent Interface Contract v1 test (in-cluster) ────────────────────
validate: $(TOKEN_FILE)
	@echo "== GET /v1/models (model discovery — this is what Open WebUI calls) =="
	@$(KUBECTL) run openclaw-validate --rm -i --restart=Never \
		--image=curlimages/curl:8.9.1 -- \
		curl -fsS -H "Authorization: Bearer $$(cat $(TOKEN_FILE))" \
		$(SVC_URL)/v1/models
	@echo ""
	@echo "== POST /v1/chat/completions (end-to-end via Ollama) =="
	@$(KUBECTL) run openclaw-validate2 --rm -i --restart=Never \
		--image=curlimages/curl:8.9.1 -- \
		curl -fsS --max-time 120 \
		-H "Authorization: Bearer $$(cat $(TOKEN_FILE))" \
		-H "Content-Type: application/json" \
		-d '{"model":"openclaw/default","messages":[{"role":"user","content":"Reply with exactly: pong"}]}' \
		$(SVC_URL)/v1/chat/completions
	@echo ""
	@echo "OK: contract endpoint works"

# ── step 5 ────────────────────────────────────────────────────────────────────
# Auto-register OpenClaw as an OpenAI connection in Open WebUI.
# PersistentConfig note: env vars SEED a fresh instance's config DB; on an
# instance already configured via the Admin UI, the DB value wins (no-op).
# Real value: cluster rebuilds (make e2e) need zero manual UI steps.
connect-openwebui: $(TOKEN_FILE)
	$(KUBECTL) -n $(OPENWEBUI_NS) set env sts/$(OPENWEBUI_STS) \
		OPENAI_API_BASE_URL=$(SVC_URL)/v1 \
		OPENAI_API_KEY=$$(cat $(TOKEN_FILE))
	@echo "Open WebUI pod restarts; on a fresh instance 'openclaw/default' appears automatically."

token-show: $(TOKEN_FILE)
	@cat $(TOKEN_FILE)

connect-info: $(TOKEN_FILE)
	@echo "Open WebUI -> Admin Settings -> Connections -> OpenAI -> Add Connection"
	@echo ""
	@echo "  URL:     $(SVC_URL)/v1        (the /v1 suffix is REQUIRED)"
	@echo "  API Key: $$(cat $(TOKEN_FILE))"

# ── ADR-021 consumer guardrails ──────────────────────────────────────────────
verify-mcp-consumer:
	@$(MAKE) -C $(CHART)/../.. verify-mcp-consumer

verify-mcp-live:
	@echo "== no Kubernetes credential or client in the OpenClaw pod =="
	@$(KUBECTL) -n $(NS) exec deploy/$(RELEASE) -- sh -c \
		'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token && ! command -v kubectl'
	@echo "OK: ServiceAccount token and kubectl are absent"
	@echo ""
	@echo "== restricted MCP registration and adapter connectivity =="
	@$(KUBECTL) -n $(NS) exec deploy/$(RELEASE) -- \
		node dist/index.js mcp probe platform-diagnostics
