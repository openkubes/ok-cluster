# kagent on ok-ai — OK-14 EVALUATION deployment (not a platform offering!)
#
# Scope per guideline Part C: evaluating kagent INSIDE OK-14 is in scope;
# OPERATING a second agent backend in parallel as a platform offering is a
# contract decision -> escalate. Uninstall after the evaluation.
#
# Config parity with ../openclaw: same Ollama endpoint, same model, same
# num_ctx — so the comparison is about the framework, not the LLM setup.
#
# Steps: make install -> make status -> make dashboard -> make eval-openai-compat

.PHONY: help install uninstall status dashboard eval-openai-compat logs
.DEFAULT_GOAL := help

CLUSTER        ?= ok-ai
KUBECONFIG     ?= $(HOME)/.kube/$(CLUSTER).yaml
KUBECTL        := kubectl --kubeconfig $(KUBECONFIG)
HELM           := helm --kubeconfig $(KUBECONFIG)
NS             ?= kagent
# Chart/app version — pin; check https://github.com/kagent-dev/kagent/releases
KAGENT_VERSION ?= 0.9.9

# ── private provider values (identical to ../openclaw) ───────────────────────
OLLAMA_URL ?= http://192.168.100.202:11434
MODEL      ?= gpt-oss:20b
NUM_CTX    ?= 32768

help:
	@echo "kagent on $(CLUSTER) — OK-14 evaluation (see README, guideline Part C)"
	@echo ""
	@echo "  make install             # CRDs + kagent via Helm (OCI), Ollama/$(MODEL)"
	@echo "  make status              # pods, services, ModelConfigs, Agents"
	@echo "  make dashboard           # port-forward UI -> http://localhost:8080"
	@echo "  make eval-openai-compat  # OK-14 question 1: OpenAI-compatible endpoint?"
	@echo "  make logs                # controller logs"
	@echo "  make uninstall           # remove everything (do this after the eval)"

install:
	$(HELM) upgrade --install kagent-crds \
		oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
		--version $(KAGENT_VERSION) \
		--namespace $(NS) --create-namespace
	$(HELM) upgrade --install kagent \
		oci://ghcr.io/kagent-dev/kagent/helm/kagent \
		--version $(KAGENT_VERSION) \
		--namespace $(NS) \
		--set providers.default=ollama \
		--set-string providers.ollama.model=$(MODEL) \
		--set-string providers.ollama.config.host=$(OLLAMA_URL) \
		--set-string providers.ollama.config.options.num_ctx=$(NUM_CTX)
	@echo ""
	@$(KUBECTL) -n $(NS) get pods

uninstall:
	$(HELM) uninstall kagent -n $(NS) || true
	$(HELM) uninstall kagent-crds -n $(NS) || true
	$(KUBECTL) delete namespace $(NS) --ignore-not-found

status:
	@$(KUBECTL) -n $(NS) get pods,svc
	@echo ""
	@$(KUBECTL) -n $(NS) get modelconfigs,agents 2>/dev/null || echo "(CRDs not ready yet)"

dashboard:
	@echo "UI: http://localhost:8080  (Ctrl-C to stop)"
	$(KUBECTL) -n $(NS) port-forward svc/kagent-ui 8080:8080

logs:
	$(KUBECTL) -n $(NS) logs deploy/kagent-controller -f --tail=100 2>/dev/null || \
	$(KUBECTL) -n $(NS) logs -l app.kubernetes.io/name=kagent -f --tail=100

# ── OK-14 evaluation question 1 ───────────────────────────────────────────────
# "Can kagent serve as an OpenAI-compatible backend behind Open WebUI, or
#  does it impose its own frontend?"  — empirical probe: does any kagent
# service answer GET /v1/models (that is what Open WebUI's connection
# verify calls)? HTTP 200 + model list = contract v1 candidate;
# 404/connection refused everywhere = kagent imposes its own frontend/A2A.
eval-openai-compat:
	@echo "== kagent services =="
	@$(KUBECTL) -n $(NS) get svc
	@echo ""
	@echo "== probing /v1/models candidates =="
	@$(KUBECTL) run kagent-eval --rm -i --restart=Never \
		--image=curlimages/curl:8.9.1 -- sh -c '\
		for u in \
		  http://kagent-controller.$(NS).svc.cluster.local:8083/v1/models \
		  http://kagent-controller.$(NS).svc.cluster.local:8083/api/v1/models \
		  http://kagent-ui.$(NS).svc.cluster.local:8080/v1/models \
		; do printf "%-72s -> " "$$u"; \
		  curl -s -o /tmp/r -w "%{http_code}" --max-time 5 "$$u" || printf "unreachable"; \
		  echo ""; head -c 200 /tmp/r 2>/dev/null; echo ""; done'
	@echo ""
	@echo "Document the result in the OK-14 PoC report (kagent evaluation, question 1)."
