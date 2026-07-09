# OpenKubes Cluster Templating — Makefile
# Usage: make new CLUSTER=ok3 TYPE=ubuntu [HA=true] [WORKERS=3] [NODE_SELECTOR=ok-gpu]
.PHONY: new render install kubeconfig install-cni install-storage install-ingress register-cluster bootstrap annotate-pvcs upgrade clean teardown teardown-all e2e e2e-verify list status help
.DEFAULT_GOAL := help

CLUSTER       ?=
TYPE          ?= ubuntu
HA            ?= false
WORKERS       ?= 1
K8S_VERSION   ?=
TALOS_VERSION ?=
NODE_SELECTOR ?=
DRY_RUN       ?= false

SCRIPT_DIR    := $(shell pwd)
CLUSTERS_DIR  := $(SCRIPT_DIR)
OKB           := kubectl --kubeconfig ~/.kube/ok-infra.yaml

# ── guard helper ──────────────────────────────────────────────────────────────
require-cluster:
	@test -n "$(CLUSTER)" || (echo "ERROR: CLUSTER is required, e.g. make $(MAKECMDGOALS) CLUSTER=ok3"; exit 1)

# ── scaffold + render ─────────────────────────────────────────────────────────
new: require-cluster
	@CLUSTER=$(CLUSTER) TYPE=$(TYPE) HA=$(HA) WORKERS=$(WORKERS) \
	 K8S_VERSION=$(K8S_VERSION) TALOS_VERSION=$(TALOS_VERSION) \
	 NODE_SELECTOR=$(NODE_SELECTOR) \
	 bash $(SCRIPT_DIR)/new-cluster.sh

render: require-cluster
	@python3 $(SCRIPT_DIR)/render.py render --cluster $(CLUSTER)

# ── deploy ────────────────────────────────────────────────────────────────────
install: require-cluster
	@echo "Applying Ubuntu cluster manifests for $(CLUSTER)..."
	$(OKB) apply -f $(CLUSTERS_DIR)/$(CLUSTER)/cluster-v2.yaml
	@echo "⏳ Waiting for control plane to be Ready (this may take ~3 min)..."
	@until $(MAKE) --no-print-directory kubeconfig CLUSTER=$(CLUSTER) 2>/dev/null && \
		kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml get nodes \
		-l node-role.kubernetes.io/control-plane --no-headers 2>/dev/null | grep -q "Ready"; \
		do echo "  ⏳ Not ready yet, retrying in 15s..."; sleep 15; done
	@echo "✅ Control plane Ready — installing Cilium CNI..."
	@$(MAKE) --no-print-directory install-cni CLUSTER=$(CLUSTER)

kubeconfig: require-cluster
	@clusterctl --kubeconfig ~/.kube/ok-infra.yaml get kubeconfig $(CLUSTER) -n $(CLUSTER) > ~/.kube/$(CLUSTER).yaml 2>/dev/null
	@echo "✅ Kubeconfig saved to ~/.kube/$(CLUSTER).yaml"

install-cni: require-cluster kubeconfig
	@echo "Installing Cilium CNI on $(CLUSTER)..."
	@$(eval CLUSTER_TYPE := $(shell python3 -c "import yaml; print(yaml.safe_load(open('$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml')).get('type','ubuntu'))"))
	@echo "  Cluster type: $(CLUSTER_TYPE)"
	@helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
	@helm repo update cilium 2>/dev/null
	@if [ "$(CLUSTER_TYPE)" = "talos" ] || [ "$(CLUSTER_TYPE)" = "talos-mgmt" ]; then \
		echo "  Using Talos values (KubePrism localhost:7445, cgroup hostRoot, agent capabilities)"; \
		helm upgrade --install cilium cilium/cilium \
			--kubeconfig ~/.kube/$(CLUSTER).yaml \
			--namespace kube-system \
			--set operator.replicas=1 \
			--set ipam.mode=kubernetes \
			--set kubeProxyReplacement=true \
			--set k8sServiceHost=localhost \
			--set k8sServicePort=7445 \
			--set tunnelPort=8473 \
			--set k8sClientRateLimit.qps=10 \
			--set k8sClientRateLimit.burst=20 \
			--set securityContext.capabilities.ciliumAgent="{CHOWN,KILL,NET_ADMIN,NET_RAW,IPC_LOCK,SYS_ADMIN,SYS_RESOURCE,DAC_OVERRIDE,FOWNER,SETGID,SETUID}" \
			--set securityContext.capabilities.cleanCiliumState="{NET_ADMIN,SYS_ADMIN,SYS_RESOURCE}" \
			--set cgroup.autoMount.enabled=false \
			--set cgroup.hostRoot=/sys/fs/cgroup; \
	else \
		CLUSTER_CP_IP=$$(kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'); \
		echo "  Control plane IP: $$CLUSTER_CP_IP"; \
		helm upgrade --install cilium cilium/cilium \
			--kubeconfig ~/.kube/$(CLUSTER).yaml \
			--namespace kube-system \
			--set operator.replicas=1 \
			--set k8sServiceHost=$$CLUSTER_CP_IP \
			--set k8sServicePort=6443 \
			--set kubeProxyReplacement=true; \
	fi
	@echo ""
	@echo "✅ Cluster $(CLUSTER) ready!"
	@echo "   kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml get nodes"

install-storage: require-cluster kubeconfig ## Install local-path StorageClass (required for Talos clusters)
	@echo "Installing local-path-provisioner on $(CLUSTER)..."
	kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml apply -f \
		https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.30/deploy/local-path-storage.yaml
	@echo "Setting local-path as default StorageClass..."
	kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml patch storageclass local-path \
		-p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
	@echo "Labeling namespaces for privileged pod security (required on Talos)..."
	kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml label namespace local-path-storage \
		pod-security.kubernetes.io/enforce=privileged \
		pod-security.kubernetes.io/warn=privileged \
		pod-security.kubernetes.io/audit=privileged \
		--overwrite
	@echo "✅ local-path StorageClass installed and set as default on $(CLUSTER)"

install-ingress: require-cluster kubeconfig ## ingress controller (Traefik) + IngressClass ok-ingress + host-cluster LB proxy
	@echo "Installing Traefik ingress controller on $(CLUSTER)..."
	@helm repo add traefik https://traefik.github.io/charts 2>/dev/null || true
	@helm repo update traefik 2>/dev/null
	helm upgrade --install traefik traefik/traefik \
		--kubeconfig ~/.kube/$(CLUSTER).yaml \
		--namespace ingress \
		--create-namespace \
		--set deployment.replicas=1 \
		--set service.type=NodePort \
		--set ports.web.nodePort=30080 \
		--set ports.websecure.nodePort=30443 \
		--set ingressClass.enabled=true \
		--set ingressClass.name=ok-ingress \
		--set ingressClass.isDefaultClass=false \
		--set providers.kubernetesIngress.ingressClass=ok-ingress
	@echo "  Traefik deployed as NodePort (30080/30443) in $(CLUSTER)"
	@echo "  Creating host-cluster LoadBalancer proxy service on RKE2 (MetalLB)..."
	@printf 'apiVersion: v1\nkind: Service\nmetadata:\n  name: %s-ingress\n  namespace: %s\n  labels:\n    ok-cluster/ingress-proxy: "true"\n    ok-cluster/cluster: %s\nspec:\n  type: LoadBalancer\n  ports:\n    - name: http\n      port: 80\n      targetPort: 30080\n    - name: https\n      port: 443\n      targetPort: 30443\n  selector:\n    cluster.x-k8s.io/cluster-name: %s\n    cluster.x-k8s.io/role: worker\n' \
		"$(CLUSTER)" "$(CLUSTER)" "$(CLUSTER)" "$(CLUSTER)" \
		| $(OKB) apply -f -
	@echo "  Waiting for MetalLB to assign the host-cluster LoadBalancer IP..."
	@for i in $$(seq 1 30); do \
		LB_IP=$$($(OKB) get svc $(CLUSTER)-ingress -n $(CLUSTER) \
			-o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null); \
		if [ -n "$$LB_IP" ]; then \
			echo ""; \
			echo "✅ Ingress ready for $(CLUSTER)"; \
			echo "   Entry point : $$LB_IP (MetalLB on RKE2 host cluster)"; \
			echo "   Traffic path: client → $$LB_IP:80 → virt-launcher:30080 → Traefik → <app>.$(CLUSTER).internal"; \
			echo "   Contract    : ingressClassName: ok-ingress, hostname <app>.$(CLUSTER).internal"; \
			echo "   Interim DNS : echo \"$$LB_IP <app>.$(CLUSTER).internal\" | sudo tee -a /etc/hosts"; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "⚠️  No LoadBalancer IP after 60s — check MetalLB pool ok-pool on RKE2 host cluster"; exit 1

bootstrap: require-cluster
	@echo "Bootstrapping Talos cluster $(CLUSTER)..."
	$(OKB) apply -f $(CLUSTERS_DIR)/$(CLUSTER)/cluster-base.yaml
	@echo ""
	@$(MAKE) --no-print-directory annotate-pvcs CLUSTER=$(CLUSTER)
	@echo ""
	@echo "⏳ Waiting for control plane to register (nodes stay NotReady until CNI is installed)..."
	@i=0; until $(MAKE) --no-print-directory kubeconfig CLUSTER=$(CLUSTER) 2>/dev/null && \
		kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml get nodes \
		-l node-role.kubernetes.io/control-plane --no-headers 2>/dev/null | grep -q .; \
		do i=$$((i+1)); \
		if [ $$i -ge 40 ]; then echo "❌ Control plane not reachable after 10 min — check: make status CLUSTER=$(CLUSTER)"; exit 1; fi; \
		echo "  ⏳ API not reachable yet, retrying in 15s... ($$i/40)"; sleep 15; done
	@echo "✅ Control plane registered — installing Cilium CNI..."
	@$(MAKE) --no-print-directory install-cni CLUSTER=$(CLUSTER)
	@echo "⏳ Waiting for all nodes to become Ready..."
	@kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml wait --for=condition=Ready nodes --all --timeout=300s
	@echo ""
	@echo "✅ Talos cluster $(CLUSTER) bootstrapped with Cilium. Next steps:"
	@echo "   make install-storage CLUSTER=$(CLUSTER)"
	@echo "   make install-ingress CLUSTER=$(CLUSTER)"
	@echo "   make status          CLUSTER=$(CLUSTER)"

annotate-pvcs: require-cluster
	@$(eval NODE := $(shell python3 -c "import yaml; cfg=yaml.safe_load(open('$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml')); print(cfg.get('nodeSelector','ok-gpu'))"))
	@$(eval EXPECTED := $(shell python3 -c "import yaml; c=yaml.safe_load(open('$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml')); print(int(c['controlPlane']['replicas'])+int(c['workers']['replicas']))"))
	@echo "Annotating PVCs for $(CLUSTER) → $(NODE) (until $(EXPECTED) DataVolume imports succeed)..."
	@for i in $$(seq 1 20); do \
		for pvc in $$($(OKB) get pvc -n $(CLUSTER) --no-headers -o custom-columns='NAME:.metadata.name' 2>/dev/null); do \
			$(OKB) annotate pvc $$pvc -n $(CLUSTER) \
				volume.kubernetes.io/selected-node=$(NODE) --overwrite 2>/dev/null || true; \
		done; \
		DONE=$$($(OKB) get dv -n $(CLUSTER) --no-headers 2>/dev/null | grep -c Succeeded | tr -d ' '); \
		PENDING=$$($(OKB) get pvc -n $(CLUSTER) --no-headers 2>/dev/null | grep Pending | wc -l | tr -d ' '); \
		if [ "$$DONE" -ge "$(EXPECTED)" ] && [ "$$PENDING" = "0" ]; then \
			echo "  ✅ $$DONE/$(EXPECTED) DataVolume import(s) succeeded, no Pending PVCs."; \
			break; \
		fi; \
		echo "  ⏳ $$DONE/$(EXPECTED) imports done, $$PENDING PVC(s) Pending — retrying in 15s... ($$i/20)"; \
		sleep 15; \
	done

# ── upgrade ───────────────────────────────────────────────────────────────────
upgrade: require-cluster
	@test -n "$(K8S_VERSION)" || (echo "ERROR: K8S_VERSION is required"; exit 1)
	@CLUSTER=$(CLUSTER) K8S_VERSION=$(K8S_VERSION) TALOS_VERSION=$(TALOS_VERSION) \
	 DRY_RUN=$(DRY_RUN) bash $(SCRIPT_DIR)/upgrade-cluster.sh

# ── teardown ──────────────────────────────────────────────────────────────────
clean: require-cluster
	@echo "Deleting CAPI cluster $(CLUSTER)..."
	$(OKB) delete cluster/$(CLUSTER) -n $(CLUSTER) --ignore-not-found --cascade=foreground
	$(OKB) delete namespace $(CLUSTER) --ignore-not-found
	@echo "Removing local manifests..."
	rm -rf $(CLUSTERS_DIR)/$(CLUSTER)
	@echo "✅ Cluster $(CLUSTER) removed."

teardown: require-cluster
	@echo "Tearing down Talos cluster $(CLUSTER)..."; \
	PVS=$$($(OKB) get pvc -n $(CLUSTER) -o jsonpath='{range .items[*]}{.spec.volumeName}{"\n"}{end}' 2>/dev/null); \
	if [ -n "$$PVS" ]; then \
		echo "  VM disks use ok-storage-* (reclaimPolicy: Retain) -- these PV(s) survive cluster deletion by design and will be cleaned up here:"; \
		echo "$$PVS" | sed 's/^/    /'; \
	fi; \
	$(OKB) delete cluster/$(CLUSTER) -n $(CLUSTER) --ignore-not-found --cascade=foreground; \
	$(OKB) delete namespace $(CLUSTER) --ignore-not-found; \
	echo "Removing local cluster directory..."; \
	rm -rf $(CLUSTERS_DIR)/$(CLUSTER); \
	if [ -n "$$PVS" ]; then \
		echo "Cleaning up Retain-policy PVs and their underlying Longhorn volumes..."; \
		for pv in $$PVS; do \
			echo "  Deleting PV $$pv..."; \
			$(OKB) delete pv $$pv --ignore-not-found; \
			echo "  Deleting Longhorn volume $$pv (best-effort -- may already be gone)..."; \
			$(OKB) -n longhorn-system delete volumes.longhorn.io $$pv --ignore-not-found 2>/dev/null || true; \
		done; \
	fi; \
	echo "✅ Talos cluster $(CLUSTER) torn down (including Retain-policy PV cleanup)."

# ── e2e ───────────────────────────────────────────────────────────────────────
MGMT_CLUSTER       ?= ok-mgmt
MGMT_WORKERS       ?= 2
MGMT_NODE_SELECTOR ?= ok-infra
WORKLOAD_CLUSTER   ?= ok1-talos
WORKLOAD_WORKERS   ?= 1
OPENWEBUI_CLAIM    ?= $(SCRIPT_DIR)/../openkubes/platform/ai/open-webui/crossplane/examples/$(WORKLOAD_CLUSTER).yaml
OLLAMA_URL         ?=

# ── registration (ADR-Platform-013) ──────────────────────────────────────────
# Contract: secret <cluster>-kubeconfig in crossplane-system + ProviderConfig
# <cluster> (provider-helm). Replace semantics — safe to re-run after any
# re-bootstrap (cluster owner's responsibility). Reference implementation,
# non-normative. See openkubes/architecture/decisions/ADR-Platform-013.
KUBECONFIG_SRC     ?= $(HOME)/.kube/$(CLUSTER).yaml
MGMT_KUBECONFIG     = $(HOME)/.kube/$(MGMT_CLUSTER).yaml

register-cluster: require-cluster ## Register workload cluster with ok-mgmt (ADR-Platform-013): kubeconfig secret + ProviderConfig, idempotent
	@echo "━━━ Registering $(CLUSTER) with $(MGMT_CLUSTER) (ADR-Platform-013) ━━━"
	@test -f "$(KUBECONFIG_SRC)" || \
		(echo "❌ Kubeconfig not found: $(KUBECONFIG_SRC) (override with KUBECONFIG_SRC=...)"; exit 1)
	@echo "  [1/4] Validating source kubeconfig against $(CLUSTER)..."
	@kubectl --kubeconfig $(KUBECONFIG_SRC) get nodes --request-timeout=10s > /dev/null || \
		(echo "❌ $(KUBECONFIG_SRC) cannot reach $(CLUSTER) — refusing to register a dead kubeconfig"; exit 1)
	@echo "  [2/4] Applying secret $(CLUSTER)-kubeconfig (replace semantics)..."
	@kubectl --kubeconfig $(MGMT_KUBECONFIG) -n crossplane-system \
		create secret generic $(CLUSTER)-kubeconfig \
		--from-file=kubeconfig=$(KUBECONFIG_SRC) \
		--dry-run=client -o yaml | kubectl --kubeconfig $(MGMT_KUBECONFIG) apply -f -
	@echo "  [3/4] Applying ProviderConfig $(CLUSTER) (provider-helm)..."
	@printf 'apiVersion: helm.crossplane.io/v1beta1\nkind: ProviderConfig\nmetadata:\n  name: %s\nspec:\n  credentials:\n    source: Secret\n    secretRef:\n      namespace: crossplane-system\n      name: %s-kubeconfig\n      key: kubeconfig\n' "$(CLUSTER)" "$(CLUSTER)" \
		| kubectl --kubeconfig $(MGMT_KUBECONFIG) apply -f -
	@echo "  [4/4] Verifying registration..."
	@kubectl --kubeconfig $(MGMT_KUBECONFIG) get providerconfig.helm.crossplane.io $(CLUSTER) > /dev/null
	@echo "✅ $(CLUSTER) registered with $(MGMT_CLUSTER)"
	@echo "   Contract : secret crossplane-system/$(CLUSTER)-kubeconfig + ProviderConfig $(CLUSTER)"
	@echo "   Re-run this target after every re-bootstrap of $(CLUSTER) (cluster owner's job)"

teardown-all: ## Tear down ALL rendered clusters (every dir with a cluster-config.yaml)
	@for cfg in $(CLUSTERS_DIR)/*/cluster-config.yaml; do \
		[ -f "$$cfg" ] || continue; \
		c=$$(basename $$(dirname $$cfg)); \
		$(MAKE) --no-print-directory teardown CLUSTER=$$c; \
	done

e2e: ## Full clean rebuild: teardown-all → mgmt stack → workload cluster → Crossplane wiring → OpenWebUI claim → verify
	@echo "━━━ E2E [0/5]: teardown all clusters ━━━"
	@echo "  Removing OpenWebUI claim before teardown (prevents Crossplane finalizer hang)..."
	@kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml \
		delete openwebuiclaim $(WORKLOAD_CLUSTER) -n openkubes-system \
		--ignore-not-found 2>/dev/null || true
	@$(MAKE) --no-print-directory teardown-all
	@echo ""
	@echo "━━━ E2E [1/5]: $(MGMT_CLUSTER) (TYPE=talos-mgmt) ━━━"
	@$(MAKE) --no-print-directory new CLUSTER=$(MGMT_CLUSTER) TYPE=talos-mgmt WORKERS=$(MGMT_WORKERS) NODE_SELECTOR=$(MGMT_NODE_SELECTOR)
	@$(MAKE) --no-print-directory bootstrap CLUSTER=$(MGMT_CLUSTER)
	@echo ""
	@echo "━━━ E2E [2/5]: management stack (bootstrap-mgmt.sh) ━━━"
	KUBECONFIG=$$HOME/.kube/$(MGMT_CLUSTER).yaml \
		OPENKUBES_PATH=$(SCRIPT_DIR)/../openkubes \
		INFRA_KUBECONFIG_PATH=$$HOME/.kube/ok-infra.yaml \
		bash $(CLUSTERS_DIR)/$(MGMT_CLUSTER)/bootstrap-mgmt.sh
	@echo ""
	@echo "━━━ E2E [3/5]: $(WORKLOAD_CLUSTER) (TYPE=talos) ━━━"
	@$(MAKE) --no-print-directory new CLUSTER=$(WORKLOAD_CLUSTER) TYPE=talos WORKERS=$(WORKLOAD_WORKERS)
	@$(MAKE) --no-print-directory bootstrap CLUSTER=$(WORKLOAD_CLUSTER)
	@$(MAKE) --no-print-directory install-storage CLUSTER=$(WORKLOAD_CLUSTER)
	@echo ""
	@echo "━━━ E2E [4/5]: Crossplane wiring → $(WORKLOAD_CLUSTER) (register-cluster) ━━━"
	@$(MAKE) --no-print-directory register-cluster \
		CLUSTER=$(WORKLOAD_CLUSTER) MGMT_CLUSTER=$(MGMT_CLUSTER)
	@echo ""
	@echo "━━━ E2E [5/5]: OpenWebUI claim ━━━"
	@if [ -f "$(OPENWEBUI_CLAIM)" ]; then \
		kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml apply -f $(OPENWEBUI_CLAIM); \
		kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml wait --for=condition=Ready \
			openwebuiclaim/$(WORKLOAD_CLUSTER) -n openkubes-system --timeout=300s; \
		kubectl --kubeconfig ~/.kube/$(WORKLOAD_CLUSTER).yaml -n open-webui \
			wait --for=condition=Ready pod -l app.kubernetes.io/component=open-webui --timeout=300s 2>/dev/null || \
			kubectl --kubeconfig ~/.kube/$(WORKLOAD_CLUSTER).yaml -n open-webui get pods; \
		if [ -n "$(OLLAMA_URL)" ]; then \
			kubectl --kubeconfig ~/.kube/$(WORKLOAD_CLUSTER).yaml -n open-webui \
				set env statefulset/open-webui-$(WORKLOAD_CLUSTER) OLLAMA_BASE_URL=$(OLLAMA_URL); \
		else \
			echo "  (OLLAMA_URL not set — skipping OLLAMA_BASE_URL workaround)"; \
		fi; \
	else \
		echo "  (skipped — claim not found at $(OPENWEBUI_CLAIM); override with OPENWEBUI_CLAIM=...)"; \
	fi
	@echo ""
	@echo "━━━ E2E [5b/5]: install-ingress + update OpenWebUI claim ━━━"
	@$(MAKE) --no-print-directory install-ingress CLUSTER=$(WORKLOAD_CLUSTER)
	@echo "  Updating OpenWebUI claim with ingress: true..."
	@kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml patch openwebuiclaim $(WORKLOAD_CLUSTER) \
		-n openkubes-system --type=merge -p '{"spec":{"ingress":true}}' 2>/dev/null || true
	@echo ""
	@$(MAKE) --no-print-directory e2e-verify
	@echo ""
	@echo "━━━ E2E [post]: committing rendered cluster state to Git ━━━"
	@git add $(MGMT_CLUSTER)/ $(WORKLOAD_CLUSTER)/ 2>/dev/null || true
	@if git diff --cached --quiet; then \
		echo "  (no changes to rendered manifests — nothing to commit)"; \
	else \
		git commit -m "state: e2e $(MGMT_CLUSTER)+$(WORKLOAD_CLUSTER) $$(date +%Y-%m-%dT%H:%M) [ok-cluster]" && \
		git push && \
		echo "✅ Rendered cluster state committed and pushed (knowledge graph: state: prefix)"; \
	fi

e2e-verify: ## Verification matrix: nodes, cilium-health, kube-proxy absence, providers, claim
	@echo "━━━ Verification ━━━"
	@for c in $(MGMT_CLUSTER) $(WORKLOAD_CLUSTER); do \
		echo "--- $$c ---"; \
		kubectl --kubeconfig ~/.kube/$$c.yaml get nodes --no-headers 2>/dev/null || true; \
		printf "cilium-health: "; \
		kubectl --kubeconfig ~/.kube/$$c.yaml -n kube-system exec ds/cilium -- \
			cilium-health status 2>/dev/null | head -1 || echo "n/a"; \
		printf "kube-proxy:    "; \
		kubectl --kubeconfig ~/.kube/$$c.yaml -n kube-system get ds kube-proxy --no-headers 2>/dev/null \
			&& echo "⚠️ PRESENT (unexpected)" || echo "absent ✅"; \
		echo ""; \
	done
	@echo "--- crossplane ($(MGMT_CLUSTER)) ---"
	@kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml get providers 2>/dev/null || true
	@kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml get openwebuiclaim -n openkubes-system 2>/dev/null || true

# ── info ──────────────────────────────────────────────────────────────────────
list:
	@python3 $(SCRIPT_DIR)/render.py list

status: require-cluster
	@echo "=== CAPI Cluster ==="
	@$(OKB) get cluster/$(CLUSTER) -n $(CLUSTER) -o wide 2>/dev/null || echo "(not found)"
	@echo ""
	@echo "=== Machines ==="
	@$(OKB) get machines -n $(CLUSTER) 2>/dev/null || true
	@echo ""
	@echo "=== KubeVirt VMs ==="
	@$(OKB) get vmi -n $(CLUSTER) 2>/dev/null || true
	@echo ""
	@echo "=== Cluster config ==="
	@cat $(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml 2>/dev/null || echo "(not found)"

help:
	@echo ""
	@echo "OpenKubes Cluster Templating"
	@echo ""
	@echo "── Ubuntu Workflow ──────────────────────────────────────────────────"
	@echo "  make new     CLUSTER=ok1 TYPE=ubuntu [HA=true] [WORKERS=2] [NODE_SELECTOR=ok-gpu]"
	@echo "  make install CLUSTER=ok1   # apply + wait for Ready + install Cilium"
	@echo ""
	@echo "── Talos Workflow ───────────────────────────────────────────────────"
	@echo "  make new       CLUSTER=ok1-talos TYPE=talos [WORKERS=2] [K8S_VERSION=v1.36.2] [TALOS_VERSION=v1.13.4]"
	@echo "  make bootstrap CLUSTER=ok1-talos   # apply + annotate PVCs + Cilium CNI"
	@echo "  make kubeconfig CLUSTER=ok1-talos  # once nodes Running"
	@echo ""
	@echo "── All targets ──────────────────────────────────────────────────────"
	@echo "  make new           CLUSTER=ok1 [TYPE=ubuntu|talos] [HA=true] [WORKERS=2] [NODE_SELECTOR=ok-gpu]"
	@echo "  make render        CLUSTER=ok1"
	@echo "  make install       CLUSTER=ok1        # ubuntu: apply + cilium"
	@echo "  make kubeconfig    CLUSTER=ok1"
	@echo "  make install-cni   CLUSTER=ok1        # cilium only (manual)"
	@echo "  make install-storage CLUSTER=ok1-talos # local-path StorageClass (Talos)"
	@echo "  make install-ingress CLUSTER=ok1-talos # ingress controller (Traefik) + IngressClass ok-ingress"
	@echo "  make register-cluster CLUSTER=ok2-rmf [KUBECONFIG_SRC=~/path/kubeconfig] [MGMT_CLUSTER=ok-mgmt]  # ADR-013: secret + ProviderConfig in ok-mgmt"
	@echo "  make bootstrap     CLUSTER=ok1-talos  # talos: apply + annotate PVCs + cilium"
	@echo "  make annotate-pvcs CLUSTER=ok1-talos  # annotate PVCs manually"
	@echo "  make upgrade       CLUSTER=ok1 K8S_VERSION=v1.35.0"
	@echo "  make clean         CLUSTER=ok1"
	@echo "  make teardown      CLUSTER=ok1-talos"
	@echo "  make teardown-all                      # tear down ALL rendered clusters"
	@echo "  make e2e           [OLLAMA_URL=http://<ip>:11434]  # full clean rebuild + verify"
	@echo "  make e2e-verify                        # verification matrix only"
	@echo "  make list"
	@echo "  make status        CLUSTER=ok1"
	@echo ""
