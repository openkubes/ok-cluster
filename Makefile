# OpenKubes Cluster Templating — Makefile
# Usage: make new CLUSTER=ok3 TYPE=ubuntu [HA=true] [WORKERS=3] [NODE_SELECTOR=ok-gpu]
.PHONY: new render install kubeconfig install-cni install-storage bootstrap annotate-pvcs upgrade clean teardown list status help
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

bootstrap: require-cluster
	@echo "Bootstrapping Talos cluster $(CLUSTER)..."
	$(OKB) apply -f $(CLUSTERS_DIR)/$(CLUSTER)/cluster-base.yaml
	@echo ""
	@$(MAKE) --no-print-directory annotate-pvcs CLUSTER=$(CLUSTER)
	@echo ""
	@echo "⏳ Waiting for control plane to register (nodes stay NotReady until CNI is installed)..."
	@until $(MAKE) --no-print-directory kubeconfig CLUSTER=$(CLUSTER) 2>/dev/null && \
		kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml get nodes \
		-l node-role.kubernetes.io/control-plane --no-headers 2>/dev/null | grep -q .; \
		do echo "  ⏳ API not reachable yet, retrying in 15s..."; sleep 15; done
	@echo "✅ Control plane registered — installing Cilium CNI..."
	@$(MAKE) --no-print-directory install-cni CLUSTER=$(CLUSTER)
	@echo "⏳ Waiting for all nodes to become Ready..."
	@kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml wait --for=condition=Ready nodes --all --timeout=300s
	@echo ""
	@echo "✅ Talos cluster $(CLUSTER) bootstrapped with Cilium. Next steps:"
	@echo "   make install-storage CLUSTER=$(CLUSTER)"
	@echo "   make status          CLUSTER=$(CLUSTER)"

annotate-pvcs: require-cluster
	@$(eval NODE := $(shell python3 -c "import yaml; cfg=yaml.safe_load(open('$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml')); print(cfg.get('nodeSelector','ok-gpu'))"))
	@$(eval EXPECTED := $(shell python3 -c "import yaml; c=yaml.safe_load(open('$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml')); print(int(c['controlPlane']['replicas'])+int(c['workers']['replicas']))"))
	@echo "Annotating PVCs for $(CLUSTER) → $(NODE) (expecting ≥$(EXPECTED) PVCs, retrying until all Bound)..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
		for pvc in $$($(OKB) get pvc -n $(CLUSTER) --no-headers -o custom-columns='NAME:.metadata.name' 2>/dev/null); do \
			$(OKB) annotate pvc $$pvc -n $(CLUSTER) \
				volume.kubernetes.io/selected-node=$(NODE) --overwrite 2>/dev/null || true; \
		done; \
		TOTAL=$$($(OKB) get pvc -n $(CLUSTER) --no-headers 2>/dev/null | wc -l | tr -d ' '); \
		PENDING=$$($(OKB) get pvc -n $(CLUSTER) --no-headers 2>/dev/null | grep Pending | wc -l | tr -d ' '); \
		if [ "$$TOTAL" -ge "$(EXPECTED)" ] && [ "$$PENDING" = "0" ]; then \
			echo "  ✅ $$TOTAL PVC(s) present, all Bound."; \
			break; \
		fi; \
		echo "  ⏳ $$TOTAL/$(EXPECTED) PVC(s), $$PENDING Pending — retrying in 15s... ($$i/12)"; \
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
	@echo "Tearing down Talos cluster $(CLUSTER)..."
	$(OKB) delete cluster/$(CLUSTER) -n $(CLUSTER) --ignore-not-found --cascade=foreground
	$(OKB) delete namespace $(CLUSTER) --ignore-not-found
	@echo "Removing local cluster directory..."
	rm -rf $(CLUSTERS_DIR)/$(CLUSTER)
	@echo "✅ Talos cluster $(CLUSTER) torn down."

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
	@echo "  make bootstrap     CLUSTER=ok1-talos  # talos: apply + annotate PVCs + cilium"
	@echo "  make annotate-pvcs CLUSTER=ok1-talos  # annotate PVCs manually"
	@echo "  make upgrade       CLUSTER=ok1 K8S_VERSION=v1.35.0"
	@echo "  make clean         CLUSTER=ok1"
	@echo "  make teardown      CLUSTER=ok1-talos"
	@echo "  make list"
	@echo "  make status        CLUSTER=ok1"
	@echo ""
