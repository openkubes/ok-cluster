# Profile A (kagent) on ok-ai — OK-92 operational wrapper.
#
# This is the PROVIDER of the Read-Only Platform Diagnostics Contract (ADR-021).
# Distinct from ../Makefile, which is the OK-14 *evaluation* install. Order:
#   (../) make install        # kagent CRDs + controller (shared with the eval)
#   make deploy               # RBAC + kagent CRs (patched Ollama) + facade
#   make status | validate | verify-rbac
#   make connect-openclaw-info
#
# Generic manifests/chart live in openkubes (cloned next to ok-cluster); this
# folder holds only the private provider values (Ollama endpoint).

.PHONY: help preflight deploy deploy-crs deploy-facade status validate \
        verify-rbac connect-openclaw-info uninstall
.DEFAULT_GOAL := help

CLUSTER    ?= ok-ai
KUBECONFIG ?= $(HOME)/.kube/$(CLUSTER).yaml
KUBECTL    := kubectl --kubeconfig $(KUBECONFIG)
HELM       := helm --kubeconfig $(KUBECONFIG)
NS         ?= platform-diagnostics
SA         ?= openkubes-platform-agent
SELF_DIR   := $(dir $(lastword $(MAKEFILE_LIST)))
FACADE_CHART := $(SELF_DIR)../../../openkubes/platform/ai/platform-diagnostics/profiles/kagent/charts/platform-diagnostics-facade
SVC_URL    := http://platform-diagnostics.$(NS).svc.cluster.local:8080

help:
	@echo "Profile A (kagent) on $(CLUSTER) — OK-92 (see README, ADR-021)"
	@echo ""
	@echo "  make preflight              # kagent controller present? openkubes cloned?"
	@echo "  make deploy                 # deploy-crs + deploy-facade"
	@echo "  make deploy-crs             # apply RBAC + kagent CRs (real Ollama patched in)"
	@echo "  make deploy-facade          # helm install the OpenAPI facade"
	@echo "  make status                 # pods, svc, ModelConfigs, Agents"
	@echo "  make validate               # call the 3 contract functions in-cluster"
	@echo "  make verify-rbac            # ADR-021 test 2: reads OK, secrets/writes denied"
	@echo "  make connect-openclaw-info  # how to wire OpenClaw as the consumer"
	@echo "  make uninstall"

preflight:
	@echo "== kagent controller present? (run ../Makefile 'make install' first) =="
	@$(KUBECTL) -n kagent get deploy >/dev/null 2>&1 && echo "OK: kagent namespace found" \
		|| (echo "FAIL: kagent not installed — run 'make -C .. install'"; exit 1)
	@echo "== openkubes repo cloned next to ok-cluster? =="
	@test -d $(FACADE_CHART) || (echo "FAIL: $(FACADE_CHART) missing — clone/pull openkubes"; exit 1)
	@echo "OK: facade chart found"

# ── RBAC + kagent CRs (ModelConfig/Agents/ToolServer) with the real Ollama IP ─
deploy-crs:
	$(KUBECTL) apply -k $(SELF_DIR)
	@echo "Applied Profile A CRs + read-only RBAC into ns/$(NS)."

deploy-facade:
	$(HELM) upgrade --install platform-diagnostics-facade $(FACADE_CHART) \
		--namespace $(NS) --create-namespace \
		-f $(SELF_DIR)facade-values.yaml
	@$(KUBECTL) -n $(NS) rollout status deploy/platform-diagnostics-facade --timeout=120s

deploy: deploy-crs deploy-facade

status:
	@$(KUBECTL) -n $(NS) get pods,svc
	@echo ""
	@$(KUBECTL) -n $(NS) get modelconfigs,toolservers,agents 2>/dev/null || echo "(kagent CRDs not ready yet)"

# ── contract smoke test: the three public functions (in-cluster) ─────────────
validate:
	@echo "== POST /v1/get_platform_health =="
	@$(KUBECTL) -n $(NS) run pd-validate --rm -i --restart=Never \
		--image=curlimages/curl:8.9.1 -- \
		curl -fsS -X POST -H "Content-Type: application/json" \
		-d '{"clusters":["ok-ai"]}' $(SVC_URL)/v1/get_platform_health
	@echo ""
	@echo "== POST /v1/investigate_workload =="
	@$(KUBECTL) -n $(NS) run pd-validate2 --rm -i --restart=Never \
		--image=curlimages/curl:8.9.1 -- \
		curl -fsS -X POST -H "Content-Type: application/json" \
		-d '{"cluster":"ok-ai","namespace":"kube-system","workload":"coredns"}' \
		$(SVC_URL)/v1/investigate_workload
	@echo ""
	@echo "NOTE: these call the openkubes-platform-agent over A2A — a real diagnosis"
	@echo "takes 30-120s (gpt-oss:20b + read-only tool calls). Output is ADR-021 schema."

# ── ADR-021 contract test 2: RBAC audit on the provider SA ────────────────────
verify-rbac:
	@echo "== positive: read is allowed =="
	@$(KUBECTL) auth can-i list pods -A --as=system:serviceaccount:$(NS):$(SA)
	@echo "== negative: secrets + writes must be DENIED =="
	@$(KUBECTL) auth can-i get secrets -A --as=system:serviceaccount:$(NS):$(SA) \
		| grep -qx no && echo "OK: secrets denied" \
		|| (echo "FAIL: secrets readable — ADR-021 test 2 violation, STOP (Part C)"; exit 1)
	@$(KUBECTL) auth can-i delete pods -A --as=system:serviceaccount:$(NS):$(SA) \
		| grep -qx no && echo "OK: delete denied" \
		|| (echo "FAIL: write verb allowed — STOP (Part C)"; exit 1)

connect-openclaw-info:
	@echo "OpenClaw is the CONSUMER (ADR-021) — it reaches diagnostics ONLY via the"
	@echo "MCP adapter in front of this facade; it gets NO cluster credentials."
	@echo ""
	@echo "  1. Deploy the MCP adapter (openkubes .../contract/mcp-adapter) pointed at:"
	@echo "       $(SVC_URL)   (the contract endpoint)"
	@echo "  2. Register it as a Skill/tool in OpenClaw's config (see ../../openclaw)."
	@echo "  3. RBAC handoff: set rbac.create=false on the openclaw chart — cluster"
	@echo "     inspection now lives behind the contract in kagent, not in OpenClaw."

uninstall:
	$(HELM) uninstall platform-diagnostics-facade -n $(NS) || true
	$(KUBECTL) delete -k $(SELF_DIR) || true
	@echo "Left namespace/$(NS) in place (delete manually if desired)."
