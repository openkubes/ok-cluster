# Standalone kagent lifecycle on the disposable ok-kagent lab (OK-129).
# Every cluster operation is hard-wired to the dedicated kubeconfig.

.PHONY: help context-check render-values install status dashboard logs uninstall verify-clean operator-tools-install operator-tools-status operator-tools-uninstall
.DEFAULT_GOAL := help

KUBECONFIG     := $(HOME)/.kube/ok-kagent.yaml
EXPECTED_CTX   := ok-kagent-admin@ok-kagent
KUBECTL        := kubectl --kubeconfig=$(KUBECONFIG)
HELM           := helm --kubeconfig=$(KUBECONFIG)
NS             := kagent
KAGENT_VERSION := 0.9.12
TOOLS_VERSION  := 0.2.1
CHART_ROOT     := oci://ghcr.io/kagent-dev/kagent/helm
TOOLS_CHART    := oci://ghcr.io/kagent-dev/tools/helm/kagent-tools
VALUES_TMPL    := values.yaml.tmpl
VALUES_LOCAL   := .values.local.yaml
LAB_NS         := kagent-lab

help:
	@echo "Standalone kagent on ok-kagent (OK-129)"
	@echo ""
	@echo "  make install       Render private values, then install CRDs and app"
	@echo "  make status        Show releases and workload/API status"
	@echo "  make dashboard     Port-forward the UI to http://localhost:8080"
	@echo "  make logs          Follow controller logs"
	@echo "  make operator-tools-install   Install the namespace-scoped write tool server"
	@echo "  make operator-tools-status    Show the scoped tool server"
	@echo "  make operator-tools-uninstall Remove the scoped tool server"
	@echo "  make uninstall     Remove releases, namespace, CRDs, and RBAC"
	@echo "  make verify-clean  Fail if kagent objects remain"

context-check:
	@test -r "$(KUBECONFIG)" || { echo "ERROR: missing $(KUBECONFIG)"; exit 1; }
	@actual="$$($(KUBECTL) config current-context)"; \
	  test "$$actual" = "$(EXPECTED_CTX)" || { \
	    echo "ERROR: expected $(EXPECTED_CTX), got $$actual"; exit 1; \
	  }

render-values:
	@: "$${OLLAMA_URL:?ERROR: set OLLAMA_URL outside Git}"
	@OLLAMA_URL="$${OLLAMA_URL}" envsubst '$${OLLAMA_URL}' \
	  < "$(VALUES_TMPL)" > "$(VALUES_LOCAL)"
	@chmod 600 "$(VALUES_LOCAL)"
	@! rg -q '\\$\\{OLLAMA_URL\\}' "$(VALUES_LOCAL)" || { \
	  echo "ERROR: unresolved OLLAMA_URL"; exit 1; \
	}

install: render-values
	@$(MAKE) context-check
	$(HELM) upgrade --install kagent-crds \
	  $(CHART_ROOT)/kagent-crds \
	  --version $(KAGENT_VERSION) \
	  --namespace $(NS) --create-namespace \
	  --wait --timeout 5m
	@$(MAKE) context-check
	$(HELM) upgrade --install kagent \
	  $(CHART_ROOT)/kagent \
	  --version $(KAGENT_VERSION) \
	  --namespace $(NS) \
	  --values $(VALUES_LOCAL) \
	  --wait --timeout 10m

status: context-check
	$(HELM) list --namespace $(NS)
	$(KUBECTL) --namespace $(NS) get pods,svc,pvc
	$(KUBECTL) api-resources | rg -i 'kagent|mcp'
	$(KUBECTL) --namespace $(NS) get modelconfigs,agents,remotemcpservers

dashboard: context-check
	@echo "UI: http://localhost:8080 (Ctrl-C to stop)"
	$(KUBECTL) --namespace $(NS) port-forward service/kagent-ui 8080:8080

logs: context-check
	$(KUBECTL) --namespace $(NS) logs deployment/kagent-controller --follow --tail=100

operator-tools-install: context-check
	$(KUBECTL) create namespace $(LAB_NS) --dry-run=client -o yaml | \
	  $(KUBECTL) apply -f -
	@$(MAKE) context-check
	$(HELM) upgrade --install kagent-lab-tools \
	  $(TOOLS_CHART) \
	  --version $(TOOLS_VERSION) \
	  --namespace $(LAB_NS) \
	  --values operator-tools-values.yaml \
	  --wait --timeout 5m

operator-tools-status: context-check
	$(HELM) list --namespace $(LAB_NS) --filter '^kagent-lab-tools$$'
	$(KUBECTL) --namespace $(LAB_NS) get deployment,service,serviceaccount \
	  -l app.kubernetes.io/instance=kagent-lab-tools

operator-tools-uninstall: context-check
	$(KUBECTL) --namespace $(NS) delete \
	  agent/cluster-operator-gated \
	  remotemcpserver/kagent-lab-tools \
	  --ignore-not-found
	$(KUBECTL) --namespace $(LAB_NS) delete \
	  role/kagent-lab-tools \
	  rolebinding/kagent-lab-tools \
	  configmap/ok-129-hitl-test \
	  --ignore-not-found
	@if $(HELM) --namespace $(LAB_NS) status kagent-lab-tools >/dev/null 2>&1; then \
	  $(HELM) --namespace $(LAB_NS) uninstall kagent-lab-tools --wait --timeout 5m; \
	fi

uninstall:
	@$(MAKE) context-check
	@$(MAKE) operator-tools-uninstall
	@echo "PVCs before namespace removal:"
	@$(KUBECTL) --namespace $(NS) get pvc 2>/dev/null || true
	@if $(HELM) --namespace $(NS) status kagent >/dev/null 2>&1; then \
	  $(HELM) --namespace $(NS) uninstall kagent --wait --timeout 5m; \
	fi
	@$(MAKE) context-check
	@if $(HELM) --namespace $(NS) status kagent-crds >/dev/null 2>&1; then \
	  $(HELM) --namespace $(NS) uninstall kagent-crds --wait --timeout 5m; \
	fi
	@$(MAKE) context-check
	$(KUBECTL) delete namespace $(NS) --ignore-not-found --wait=true --timeout=5m
	@$(MAKE) verify-clean

verify-clean: context-check
	@leftovers="$$($(KUBECTL) get crd -o name | rg -i 'kagent|mcp' || true)"; \
	  test -z "$$leftovers" || { echo "$$leftovers"; echo "ERROR: CRDs remain"; exit 1; }
	@leftovers="$$($(KUBECTL) get clusterrole,clusterrolebinding -o name | rg -i kagent || true)"; \
	  test -z "$$leftovers" || { echo "$$leftovers"; echo "ERROR: cluster RBAC remains"; exit 1; }
	@! $(KUBECTL) get namespace $(NS) >/dev/null 2>&1 || { \
	  echo "ERROR: namespace $(NS) remains"; exit 1; \
	}
	@echo "Clean: no kagent namespace, CRDs, or cluster RBAC."
