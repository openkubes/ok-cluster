# OpenKubes Cluster Templating — Makefile
# Usage: make new CLUSTER=ok3 TYPE=ubuntu|talos|talos-mgmt|flatcar [HA=true] [WORKERS=3] [NODE_SELECTOR=ok-gpu|NODE=ok-gpu]
#        TYPE is REQUIRED — no silent default (OK-119).
.PHONY: new render install kubeconfig install-cni install-storage install-ingress install-observability register-cluster unregister-cluster bootstrap annotate-pvcs upgrade clean teardown teardown-all reap-orphaned-volumes e2e e2e-verify list status help prepare-cilium-chart verify-cilium-chart cilium-chart-tool-test configure-kubevirt-expand-disks
.DEFAULT_GOAL := help

CLUSTER       ?=
# No default on purpose (OK-119). TYPE decides both the VM OS and, via
# cluster-config.yaml, which Cilium value set install-cni applies. A silent
# default to `ubuntu` on a Talos cluster produced a config mismatched with the
# actual VM OS and a CNI that Talos rejects (SYS_MODULE). `new` requires it
# explicitly; both internal callers (e2e) already pass it.
TYPE          ?=
CLUSTER_TYPES := ubuntu talos talos-mgmt flatcar
HA            ?= false
WORKERS       ?= 1
K8S_VERSION   ?=
TALOS_VERSION ?=
PROVIDER      ?= kubevirt
ARCHITECTURE  ?= amd64
# OK-82: NODE= is an accepted alias for NODE_SELECTOR= (explicit NODE_SELECTOR wins)
NODE          ?=
NODE_SELECTOR ?= $(NODE)
DEMO_PROFILE  ?=
START_IP      ?=
DRY_RUN       ?= false

SCRIPT_DIR    := $(shell pwd)
CLUSTERS_DIR  := $(SCRIPT_DIR)
OKB           := kubectl --kubeconfig ~/.kube/ok-infra.yaml
OK_LINUX_PATH ?= $(SCRIPT_DIR)/../ok-linux
FLATCAR_INFRA_KUBECONFIG ?=
FLATCAR_CILIUM_CHART     ?=
FLATCAR_APPLY            ?= no
FLATCAR_TEARDOWN         ?= no
FLATCAR_WORKLOAD_KUBECONFIG ?=
TALOS_INFRA_KUBECONFIG ?= $(HOME)/.kube/ok-infra.yaml
CILIUM_CHART ?= $(SCRIPT_DIR)/.tools/cilium-1.19.6.tgz
CILIUM_CHART_SOURCE ?=
KUBEVIRT_EXPAND_DISKS_APPLY ?= no
OK130_REPLACEMENT_APPLY ?= no
OK128_BENCHMARK_APPLY ?= no
OK128_OS ?=
OK128_MANAGEMENT_KUBECONFIG ?=
OK128_WORKLOAD_KUBECONFIG ?=
OK128_OUTPUT_DIR ?=
OK128_RUN_ID ?=
OK128_TEST_ORDER ?=
OK128_FLATCAR_EVIDENCE ?=
OK128_TALOS_EVIDENCE ?=
OK128_GOLDEN_NAMESPACE ?= ok-images
OK128_GOLDEN_CLAIM ?=
OK128_GOLDEN_UID ?=
OK128_EXPECTED_PVS ?=

# ── observability (OK-79) ─────────────────────────────────────────────────────
# ok-cluster INSTALLS ok-observability, it does not OWN it — assets come from the
# sibling repo checkout. Provider Values (passwords) live in a git-ignored file,
# per cluster; override the path with OBSERVABILITY_VALUES=... if it lives elsewhere.
OK_OBSERVABILITY_PATH ?= $(SCRIPT_DIR)/../ok-observability
OBSERVABILITY_VALUES  ?= $(OK_OBSERVABILITY_PATH)/$(CLUSTER).provider-values.yaml
# Pin: WHICH ok-observability revision a run may consume. The consumer declares
# what it consumes, so the value lives here rather than in the capability repo — a
# file inside ok-observability would be self-referential (a checkout always reports
# its own revision, so it could never detect drift, and a re-runner needs the
# revision *before* they have a checkout to read). One line, tag or sha; bumping it
# is a visible diff. Override on the command line for a one-off. Empty/missing file
# = unpinned, and the resolved sha is printed as gate evidence either way
# (ADR-Platform-024 open item 1, OK-109).
OK_OBSERVABILITY_REF  ?= $(shell cat $(SCRIPT_DIR)/ok-observability.ref 2>/dev/null)

# ── datacenter secret profile: Vault + VSO (ADR-Platform-025, OK-117) ─────────
# Which mechanism populates ok-observability-credentials:
#   file  — ok-cluster writes it from a git-ignored provider-values file. The
#           offline-reconcilable profile: edge/air-gapped, and any cluster with no
#           Vault mount yet. Default, and it stays — not a phase to be replaced.
#   vault — a VaultStaticSecret (VSO) syncs it from the central Vault on ok-shared.
#           The datacenter-envelope profile.
# The two coexist by envelope (Secret Contract, ADR-Platform-011).
OBSERVABILITY_SECRET_SOURCE ?= file
OBSERVABILITY_SECRET_SOURCES := file vault

# VSO add-on, pinned and versioned as ADR-025 §Implementation & placement requires.
# 1.5.0 is the version proven on ok-robotics — pinned to the proven one, not to latest.
VSO_CHART_VERSION ?= 1.5.0
VSO_NAMESPACE     ?= vault-secrets-operator

# Provider Values for the vault path. Defaults match the ok-robotics evidence and
# ADR-025 Path A; VAULT_ADDR is environment-specific (the stable host-level LB for
# ok-shared ingress, MetalLB on ok-infra — not a VM node IP).
VAULT_ADDR            ?= https://192.168.100.207:443
VAULT_TLS_SERVER_NAME ?= vault.ok-shared.internal
VAULT_CA_SECRET       ?= vault-ca
KV_MOUNT              ?= secret
KV_PATH               ?= $(CLUSTER)/obs/observability-credentials
# The Vault role and the Kubernetes ServiceAccount are distinct identities that
# coincide by convention (the VaultConfig composition derives roleName from
# role.name). Kept separate on purpose — the role is *bound to* the SA, which is
# not the same as being named after it.
VAULT_ROLE            ?= sa-obs
VSO_SERVICE_ACCOUNT   ?= sa-obs
REFRESH_AFTER         ?= 60s

# ── guard helper ──────────────────────────────────────────────────────────────
require-cluster:
	@test -n "$(CLUSTER)" || (echo "ERROR: CLUSTER is required, e.g. make $(MAKECMDGOALS) CLUSTER=ok3"; exit 1)

.PHONY: require-not-flatcar
require-not-flatcar: require-cluster
	@if [ -r "$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml" ]; then \
		CLUSTER_TYPE="$$(python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])) or {}; print(d.get("type") or "")' "$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml")"; \
		if [ "$$CLUSTER_TYPE" = "flatcar" ]; then \
			echo "ERROR: generic target '$(MAKECMDGOALS)' is not a supported Flatcar lifecycle authority."; \
			echo "       Use make flatcar-preflight/install-flatcar/teardown-flatcar with explicit inputs."; \
			exit 2; \
		fi; \
	fi

# OK-119: TYPE must be explicit. It decides the VM OS *and* the Cilium value set
# install-cni later selects via cluster-config.yaml, so a wrong/implied value is
# not a cosmetic mismatch — it installs a CNI the OS rejects.
require-type:
	@if [ -z "$(TYPE)" ]; then \
		echo "ERROR: TYPE is required — it sets the VM OS and the CNI profile."; \
		echo "  make $(MAKECMDGOALS) CLUSTER=$(CLUSTER) TYPE=<$(shell echo '$(CLUSTER_TYPES)' | tr ' ' '|')> [WORKERS=3] [NODE_SELECTOR=ok-gpu]"; \
		echo "  It used to default to 'ubuntu' silently, which writes type: ubuntu into"; \
		echo "  cluster-config.yaml even on a Talos cluster — install-cni then applies the"; \
		echo "  non-Talos Cilium values and the agent fails on SYS_MODULE (OK-119)."; \
		exit 1; \
	fi
	@case " $(CLUSTER_TYPES) " in \
		*" $(TYPE) "*) ;; \
		*) echo "ERROR: TYPE='$(TYPE)' is not one of: $(CLUSTER_TYPES)"; exit 1 ;; \
	esac

# ── scaffold + render ─────────────────────────────────────────────────────────
new: require-cluster require-type
	@CLUSTER=$(CLUSTER) TYPE=$(TYPE) HA=$(HA) WORKERS=$(WORKERS) \
	 K8S_VERSION=$(K8S_VERSION) TALOS_VERSION=$(TALOS_VERSION) \
	 PROVIDER=$(PROVIDER) ARCHITECTURE=$(ARCHITECTURE) \
	 NODE_SELECTOR=$(NODE_SELECTOR) DEMO_PROFILE=$(DEMO_PROFILE) START_IP=$(START_IP) \
	 OK_LINUX_PATH=$(OK_LINUX_PATH) \
	 bash $(SCRIPT_DIR)/new-cluster.sh

render: require-cluster
	@START_IP=$(START_IP) python3 $(SCRIPT_DIR)/render.py render --cluster $(CLUSTER)

prepare-cilium-chart: ## Download/verify pinned Cilium 1.19.6 into .tools
	@python3 $(SCRIPT_DIR)/scripts/prepare_cilium_chart.py \
		--cache "$(CILIUM_CHART)" \
		$(if $(CILIUM_CHART_SOURCE),--source "$(CILIUM_CHART_SOURCE)")

verify-cilium-chart: ## Offline-verify an existing pinned Cilium chart
	@python3 $(SCRIPT_DIR)/scripts/prepare_cilium_chart.py \
		--verify-only \
		--cache "$(CILIUM_CHART)"

cilium-chart-tool-test: ## Offline-test Cilium acquisition/cache guards
	@PYTHONDONTWRITEBYTECODE=1 \
		python3 $(SCRIPT_DIR)/tests/cilium_chart_tool_test.py

# OK-125 candidate evidence is intentionally outside the ordinary TYPE allowlist.
# It consumes ok-linux profile truth and never applies resources.
.PHONY: ok125-render ok125-management-test ok125-management-ignition ok125-runtime-test ok125-runtime-preflight ok125-node-ready ok125-replacement ok125-cleanup flatcar-promotion-test flatcar-preflight install-flatcar teardown-flatcar ok128-benchmark-test ok128-benchmark-preflight ok128-benchmark-flatcar ok128-benchmark-talos ok128-benchmark-compare ok128-benchmark-cleanup-verify ok130-test ok135-test gpu-demo-test talos-golden-preflight talos-golden-runtime-evidence talos-golden-replacement-preflight talos-golden-replacement-apply
ok125-render: ## Render and validate the non-deployable OK-125 Flatcar candidate
	@OK_LINUX_PATH="$(OK_LINUX_PATH)" \
		python3 $(SCRIPT_DIR)/tests/ok125_flatcar_render_test.py \
		--cluster "$(or $(CLUSTER),ok125-flatcar)" \
		--profile-variant "$(or $(OK125_PROFILE_VARIANT),baseline)"

ok125-management-test: ## Offline-test the pinned CABPK/KCP Ignition management path
	@python3 $(SCRIPT_DIR)/tests/ok125_management_ignition_test.py

ok125-management-ignition: ## Preflight/apply pinned CABPK/KCP Ignition gates
	@OK125_KUBECONFIG="$(OK125_KUBECONFIG)" \
	 OK125_APPLY="$(or $(OK125_APPLY),no)" \
	 CLUSTERCTL_BIN="$(or $(CLUSTERCTL_BIN),clusterctl)" \
	 python3 $(SCRIPT_DIR)/scripts/adoption/OK-125/configure_management_ignition.py

ok125-runtime-test: ## Offline-test the bounded OK-125 runtime and cleanup guards
	@python3 $(SCRIPT_DIR)/tests/ok125_runtime_test.py

ok125-runtime-preflight: ## Read-only G1/G3 preflight for exactly ok125-flatcar
	@CLUSTER="$(or $(CLUSTER),ok125-flatcar)" \
	 OK125_KUBECONFIG="$(OK125_KUBECONFIG)" \
	 OK_LINUX_PATH="$(OK_LINUX_PATH)" \
	 python3 $(SCRIPT_DIR)/scripts/adoption/OK-125/runtime.py --preflight

ok125-node-ready: ## Run G1/G3 on the disposable ok125-flatcar cluster
	@CLUSTER="$(or $(CLUSTER),ok125-flatcar)" \
	 OK125_KUBECONFIG="$(OK125_KUBECONFIG)" \
	 OK_LINUX_PATH="$(OK_LINUX_PATH)" \
	 python3 $(SCRIPT_DIR)/scripts/adoption/OK-125/runtime.py --node-ready

ok125-replacement: ## Run healthy and failed G2 replacements on ok125-flatcar
	@CLUSTER="$(or $(CLUSTER),ok125-flatcar)" \
	 OK125_KUBECONFIG="$(OK125_KUBECONFIG)" \
	 OK_LINUX_PATH="$(OK_LINUX_PATH)" \
	 python3 $(SCRIPT_DIR)/scripts/adoption/OK-125/replacement.py --run

ok125-cleanup: ## Delete only the owned disposable OK-125 runtime
	@CLUSTER="$(or $(CLUSTER),ok125-flatcar)" \
	 OK125_KUBECONFIG="$(OK125_KUBECONFIG)" \
	 OK125_CLEANUP="$(OK125_CLEANUP)" \
	 python3 $(SCRIPT_DIR)/scripts/adoption/OK-125/runtime.py --cleanup

flatcar-promotion-test: ## Offline-test the exact ordinary Flatcar profile
	@OK_LINUX_PATH="$(OK_LINUX_PATH)" \
		python3 $(SCRIPT_DIR)/tests/flatcar_promotion_test.py

ok135-test: flatcar-promotion-test ok128-benchmark-test ## Offline-test Flatcar Longhorn clone contract

gpu-demo-test: flatcar-promotion-test ok130-test ## Offline-test Talos and Flatcar GPU demo profiles

flatcar-preflight: require-cluster ## Read-only production Flatcar preflight
	@OK_LINUX_PATH="$(OK_LINUX_PATH)" \
		python3 $(SCRIPT_DIR)/scripts/flatcar_lifecycle.py \
		--preflight \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(FLATCAR_INFRA_KUBECONFIG)" \
		--cilium-chart "$(FLATCAR_CILIUM_CHART)" \
		--workload-kubeconfig "$(FLATCAR_WORKLOAD_KUBECONFIG)"

install-flatcar: require-cluster ## Install constrained Flatcar (requires explicit paths and FLATCAR_APPLY=yes)
	@OK_LINUX_PATH="$(OK_LINUX_PATH)" \
	 FLATCAR_APPLY="$(FLATCAR_APPLY)" \
		python3 $(SCRIPT_DIR)/scripts/flatcar_lifecycle.py \
		--install \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(FLATCAR_INFRA_KUBECONFIG)" \
		--cilium-chart "$(FLATCAR_CILIUM_CHART)" \
		--workload-kubeconfig "$(FLATCAR_WORKLOAD_KUBECONFIG)"

teardown-flatcar: require-cluster ## Tear down only an owned constrained Flatcar cluster
	@OK_LINUX_PATH="$(OK_LINUX_PATH)" \
	 FLATCAR_TEARDOWN="$(FLATCAR_TEARDOWN)" \
		python3 $(SCRIPT_DIR)/scripts/flatcar_lifecycle.py \
		--teardown \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(FLATCAR_INFRA_KUBECONFIG)" \
		--workload-kubeconfig "$(FLATCAR_WORKLOAD_KUBECONFIG)"

ok128-benchmark-test: ## Offline-test the OK-128 observer and comparison gates
	@PYTHONDONTWRITEBYTECODE=1 \
		python3 $(SCRIPT_DIR)/tests/ok128_provisioning_benchmark_test.py

ok128-benchmark-preflight: require-cluster ## Read-only OK-128 envelope/source/Golden/load preflight
	@test "$(OK128_OS)" = "flatcar" -o "$(OK128_OS)" = "talos" || \
		(echo "ERROR: OK128_OS must be flatcar or talos"; exit 1)
	@test -n "$(OK128_MANAGEMENT_KUBECONFIG)" \
		-a -n "$(OK128_WORKLOAD_KUBECONFIG)" || \
		(echo "ERROR: explicit OK128 management/workload kubeconfig paths are required"; exit 1)
	@python3 $(SCRIPT_DIR)/scripts/provisioning_benchmark.py preflight \
		--os "$(OK128_OS)" \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(OK128_MANAGEMENT_KUBECONFIG)" \
		--workload-kubeconfig "$(OK128_WORKLOAD_KUBECONFIG)" \
		--cilium-chart "$(CILIUM_CHART)" \
		--ok-linux-path "$(OK_LINUX_PATH)"

ok128-benchmark-flatcar: require-cluster ## Observe exact install-flatcar lifecycle (requires runtime GO)
	@test -n "$(OK128_MANAGEMENT_KUBECONFIG)" \
		-a -n "$(OK128_WORKLOAD_KUBECONFIG)" \
		-a -n "$(OK128_OUTPUT_DIR)" \
		-a -n "$(OK128_RUN_ID)" \
		-a -n "$(OK128_TEST_ORDER)" || \
		(echo "ERROR: explicit OK128 management/workload kubeconfig, output, run ID, and order are required"; exit 1)
	@OK128_BENCHMARK_APPLY="$(OK128_BENCHMARK_APPLY)" \
		python3 $(SCRIPT_DIR)/scripts/provisioning_benchmark.py run \
		--os flatcar \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(OK128_MANAGEMENT_KUBECONFIG)" \
		--workload-kubeconfig "$(OK128_WORKLOAD_KUBECONFIG)" \
		--cilium-chart "$(CILIUM_CHART)" \
		--ok-linux-path "$(OK_LINUX_PATH)" \
		--output-dir "$(OK128_OUTPUT_DIR)" \
		--run-id "$(OK128_RUN_ID)" \
		--test-order "$(OK128_TEST_ORDER)" \
		-- make --no-print-directory install-flatcar \
			CLUSTER="$(CLUSTER)" \
			FLATCAR_INFRA_KUBECONFIG="$(OK128_MANAGEMENT_KUBECONFIG)" \
			FLATCAR_WORKLOAD_KUBECONFIG="$(OK128_WORKLOAD_KUBECONFIG)" \
			FLATCAR_CILIUM_CHART="$(CILIUM_CHART)" \
			FLATCAR_APPLY=yes

ok128-benchmark-talos: require-cluster ## Observe exact bootstrap lifecycle (requires runtime GO)
	@test -n "$(OK128_MANAGEMENT_KUBECONFIG)" \
		-a -n "$(OK128_WORKLOAD_KUBECONFIG)" \
		-a -n "$(OK128_OUTPUT_DIR)" \
		-a -n "$(OK128_RUN_ID)" \
		-a -n "$(OK128_TEST_ORDER)" || \
		(echo "ERROR: explicit OK128 management/workload kubeconfig, output, run ID, and order are required"; exit 1)
	@test "$$(cd "$$(dirname "$(OK128_MANAGEMENT_KUBECONFIG)")" && pwd)/$$(basename "$(OK128_MANAGEMENT_KUBECONFIG)")" = \
		"$$(cd "$(HOME)/.kube" && pwd)/ok-infra.yaml" || \
		(echo "ERROR: bootstrap currently consumes $(HOME)/.kube/ok-infra.yaml; benchmark path must match"; exit 1)
	@test "$$(cd "$$(dirname "$(OK128_WORKLOAD_KUBECONFIG)")" && pwd)/$$(basename "$(OK128_WORKLOAD_KUBECONFIG)")" = \
		"$$(cd "$(HOME)/.kube" && pwd)/$(CLUSTER).yaml" || \
		(echo "ERROR: bootstrap writes $(HOME)/.kube/$(CLUSTER).yaml; benchmark path must match"; exit 1)
	@OK128_BENCHMARK_APPLY="$(OK128_BENCHMARK_APPLY)" \
		python3 $(SCRIPT_DIR)/scripts/provisioning_benchmark.py run \
		--os talos \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(OK128_MANAGEMENT_KUBECONFIG)" \
		--workload-kubeconfig "$(OK128_WORKLOAD_KUBECONFIG)" \
		--cilium-chart "$(CILIUM_CHART)" \
		--ok-linux-path "$(OK_LINUX_PATH)" \
		--output-dir "$(OK128_OUTPUT_DIR)" \
		--run-id "$(OK128_RUN_ID)" \
		--test-order "$(OK128_TEST_ORDER)" \
		-- make --no-print-directory bootstrap \
			CLUSTER="$(CLUSTER)" \
			CILIUM_CHART="$(CILIUM_CHART)" \
			TALOS_INFRA_KUBECONFIG="$(OK128_MANAGEMENT_KUBECONFIG)"

ok128-benchmark-compare: ## Emit observed-only Markdown/CSV from two sanitized runs
	@test -n "$(OK128_FLATCAR_EVIDENCE)" \
		-a -n "$(OK128_TALOS_EVIDENCE)" \
		-a -n "$(OK128_OUTPUT_DIR)" || \
		(echo "ERROR: explicit Flatcar/Talos evidence and output paths are required"; exit 1)
	@python3 $(SCRIPT_DIR)/scripts/provisioning_benchmark.py compare \
		--flatcar "$(OK128_FLATCAR_EVIDENCE)" \
		--talos "$(OK128_TALOS_EVIDENCE)" \
		--output-dir "$(OK128_OUTPUT_DIR)"

ok128-benchmark-cleanup-verify: require-cluster ## Read-only cleanup/Golden-PVC preservation evidence
	@test -n "$(OK128_MANAGEMENT_KUBECONFIG)" \
		-a -n "$(OK128_WORKLOAD_KUBECONFIG)" \
		-a -n "$(OK128_OUTPUT_DIR)" \
		-a -n "$(OK128_RUN_ID)" \
		-a -n "$(OK128_GOLDEN_CLAIM)" \
		-a -n "$(OK128_GOLDEN_UID)" \
		-a -n "$(OK128_EXPECTED_PVS)" || \
		(echo "ERROR: explicit kubeconfigs, output, run ID, Golden identity and expected PVs are required"; exit 1)
	@python3 $(SCRIPT_DIR)/scripts/provisioning_benchmark.py verify-cleanup \
		--cluster "$(CLUSTER)" \
		--management-kubeconfig "$(OK128_MANAGEMENT_KUBECONFIG)" \
		--workload-kubeconfig "$(OK128_WORKLOAD_KUBECONFIG)" \
		--golden-namespace "$(OK128_GOLDEN_NAMESPACE)" \
		--golden-claim "$(OK128_GOLDEN_CLAIM)" \
		--golden-uid "$(OK128_GOLDEN_UID)" \
		$(foreach pv,$(OK128_EXPECTED_PVS),--expected-pv "$(pv)") \
		--run-id "$(OK128_RUN_ID)" \
		--output-dir "$(OK128_OUTPUT_DIR)"

ok130-test: ## Offline-test the Talos Golden-Image resolver/render/lifecycle
	@OK_LINUX_PATH="$(OK_LINUX_PATH)" \
		python3 $(SCRIPT_DIR)/tests/ok130_talos_golden_test.py

configure-kubevirt-expand-disks: ## Guardedly enable ExpandDisks on ok-infra (requires APPLY=yes)
	@if [ "$(KUBEVIRT_EXPAND_DISKS_APPLY)" != "yes" ]; then \
		echo "Refusing mutation: set KUBEVIRT_EXPAND_DISKS_APPLY=yes after approval."; \
		exit 1; \
	fi
	@python3 $(SCRIPT_DIR)/scripts/configure_kubevirt_expand_disks.py \
		--kubeconfig "$(TALOS_INFRA_KUBECONFIG)" \
		--apply

talos-golden-preflight: require-cluster ## Read-only Golden-PVC/RBAC preflight
	@CLUSTER_TYPE="$$(python3 -c 'import sys,yaml; print((yaml.safe_load(open(sys.argv[1])) or {}).get("type",""))' "$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml")"; \
	if [ "$$CLUSTER_TYPE" = "talos" ]; then \
		python3 $(SCRIPT_DIR)/scripts/talos_golden_lifecycle.py \
			--preflight \
			--cluster "$(CLUSTER)" \
			--kubeconfig "$(TALOS_INFRA_KUBECONFIG)" \
			--ok-linux-path "$(OK_LINUX_PATH)"; \
	else \
		echo "Skipping workload Talos Golden preflight for type=$$CLUSTER_TYPE"; \
	fi

talos-golden-runtime-evidence: require-cluster ## Record read-only warm provisioning evidence
	@python3 $(SCRIPT_DIR)/scripts/talos_golden_lifecycle.py \
		--runtime-evidence \
		--cluster "$(CLUSTER)" \
		--kubeconfig "$(TALOS_INFRA_KUBECONFIG)" \
		--ok-linux-path "$(OK_LINUX_PATH)" \
		--workload-kubeconfig "$(or $(TALOS_WORKLOAD_KUBECONFIG),$(HOME)/.kube/$(CLUSTER).yaml)" \
		--cilium-chart "$(CILIUM_CHART)"

talos-golden-replacement-preflight: require-cluster ## Read-only live-cluster/new-Golden replacement preflight
	@python3 $(SCRIPT_DIR)/scripts/talos_golden_lifecycle.py \
		--replacement-preflight \
		--cluster "$(CLUSTER)" \
		--kubeconfig "$(TALOS_INFRA_KUBECONFIG)" \
		--ok-linux-path "$(OK_LINUX_PATH)"

talos-golden-replacement-apply: require-cluster ## Apply identity-bound Talos replacement (OK130_REPLACEMENT_APPLY=yes)
	@test "$(OK130_REPLACEMENT_APPLY)" = "yes" || \
		(echo "ERROR: replacement requires OK130_REPLACEMENT_APPLY=yes"; exit 1)
	@$(MAKE) --no-print-directory talos-golden-replacement-preflight CLUSTER="$(CLUSTER)"
	kubectl --kubeconfig "$(TALOS_INFRA_KUBECONFIG)" apply \
		-f $(CLUSTERS_DIR)/$(CLUSTER)/cluster-base.yaml
	@python3 $(SCRIPT_DIR)/scripts/talos_golden_lifecycle.py \
		--replacement-wait \
		--cluster "$(CLUSTER)" \
		--kubeconfig "$(TALOS_INFRA_KUBECONFIG)" \
		--ok-linux-path "$(OK_LINUX_PATH)"

# ── deploy ────────────────────────────────────────────────────────────────────
install: require-not-flatcar
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
	@# OK-119: resolve the cluster type INSIDE the recipe shell. The previous
	@# `$$(eval ... $$(shell python3 ...))` had two silent defaults: a missing
	@# cluster-config.yaml made python throw while $$(shell) discarded the exit
	@# status, leaving the variable empty; and `.get('type','ubuntu')` turned a
	@# missing key into `ubuntu`. Either way the recipe fell through to the
	@# non-Talos branch and installed a CNI Talos rejects. $$(shell) cannot fail
	@# a recipe, so the read has to happen here to be able to abort.
	@set -e; \
	CFG="$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml"; \
	if [ ! -r "$$CFG" ]; then \
		echo "❌ cluster-config.yaml not found or unreadable for $(CLUSTER):"; \
		echo "     $$CFG"; \
		echo "   Render directories are per-machine and not committed. Was"; \
		echo "   'make new CLUSTER=$(CLUSTER) TYPE=...' run on THIS machine? Re-render or"; \
		echo "   re-sync it before install-cni — refusing to guess the CNI profile (OK-119)."; \
		exit 2; \
	fi; \
	CLUSTER_TYPE="$$(python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])) or {}; print(d.get("type") or "")' "$$CFG")" \
		|| { echo "❌ could not parse $$CFG — fix the YAML before installing a CNI"; exit 2; }; \
	if [ -z "$$CLUSTER_TYPE" ]; then \
		echo "❌ no 'type' key in $$CFG — refusing to guess the CNI profile."; \
		echo "   Expected one of: $(CLUSTER_TYPES). See OK-119."; \
		exit 2; \
	fi; \
		echo "  Cluster type: $$CLUSTER_TYPE (from $$CFG)"; \
	if [ "$$CLUSTER_TYPE" = "flatcar" ]; then \
		echo "❌ generic install-cni is not a Flatcar lifecycle authority."; \
		echo "   Use install-flatcar with the local digest-pinned Cilium chart."; \
		exit 2; \
	fi; \
	OS_IMG="$$(kubectl --kubeconfig ~/.kube/$(CLUSTER).yaml get nodes \
		-o jsonpath='{.items[0].status.nodeInfo.osImage}' 2>/dev/null || true)"; \
	if [ -z "$$OS_IMG" ]; then \
		echo "  (node OS not readable yet — skipping declared-vs-actual cross-check)"; \
	else \
		echo "  Node OS: $$OS_IMG"; \
		case "$$CLUSTER_TYPE" in \
			talos*) echo "$$OS_IMG" | grep -qi talos || { \
				echo "❌ cluster-config says '$$CLUSTER_TYPE' but the node OS is '$$OS_IMG'."; \
				echo "   Refusing to apply Talos Cilium values to a non-Talos node (OK-119)."; exit 2; } ;; \
			ubuntu) if echo "$$OS_IMG" | grep -qi talos; then \
				echo "❌ cluster-config says 'ubuntu' but the node OS is '$$OS_IMG'."; \
				echo "   This is exactly the OK-119 failure: the non-Talos Cilium values include"; \
				echo "   SYS_MODULE, which Talos rejects, and omit ipam.mode=kubernetes."; \
				echo "   Re-render with TYPE=talos (or TYPE=talos-mgmt) and retry."; exit 2; \
			fi ;; \
		esac; \
	fi; \
	if [ "$$CLUSTER_TYPE" = "talos" ] || [ "$$CLUSTER_TYPE" = "talos-mgmt" ]; then \
		python3 $(SCRIPT_DIR)/scripts/prepare_cilium_chart.py \
			--verify-only --cache "$(CILIUM_CHART)"; \
		echo "  Using Talos values (KubePrism localhost:7445, cgroup hostRoot, agent capabilities)"; \
		helm upgrade --install cilium "$(CILIUM_CHART)" \
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
		helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true; \
		helm repo update cilium 2>/dev/null; \
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

install-ingress: require-cluster kubeconfig ## ingress controller (Traefik) + IngressClass ok-ingress + allowCrossNamespace + host-cluster LB proxy
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
		--set providers.kubernetesIngress.ingressClass=ok-ingress \
		--set providers.kubernetesCRD.allowCrossNamespace=true
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

install-vso: require-cluster kubeconfig ## Install the pinned Vault Secrets Operator (datacenter envelope, ADR-025). Vars: VSO_CHART_VERSION, VSO_NAMESPACE
	@echo "Installing Vault Secrets Operator $(VSO_CHART_VERSION) on $(CLUSTER) (ns $(VSO_NAMESPACE))..."
	@# Namespace FIRST, labelled BEFORE any workload is admitted. The upstream chart sets
	@# neither capabilities.drop=[ALL] nor a seccompProfile, so a cluster ENFORCING Pod
	@# Security "restricted" rejects the install — including its pre-upgrade-crds hook Job.
	@# Labelling after helm would be too late: the pods are admitted during helm, not after.
	@# `baseline` is the least level that admits it; unlike node-exporter/fluent-bit, VSO's
	@# manager needs no host access, so `privileged` would over-grant.
	@kubectl --kubeconfig $(HOME)/.kube/$(CLUSTER).yaml create namespace $(VSO_NAMESPACE) \
		--dry-run=client -o yaml | kubectl --kubeconfig $(HOME)/.kube/$(CLUSTER).yaml apply -f -
	@kubectl --kubeconfig $(HOME)/.kube/$(CLUSTER).yaml label namespace $(VSO_NAMESPACE) \
		pod-security.kubernetes.io/enforce=baseline \
		pod-security.kubernetes.io/warn=baseline \
		pod-security.kubernetes.io/audit=baseline \
		--overwrite
	@helm repo add hashicorp https://helm.releases.hashicorp.com 2>/dev/null || true
	@helm repo update hashicorp 2>/dev/null
	@# --version pins it (ADR-025 wants explicit + versioned, not latest);
	@# upgrade --install makes it idempotent; --wait so the CRDs are established
	@# before anything applies a VaultConnection/VaultAuth/VaultStaticSecret.
	helm upgrade --install vault-secrets-operator hashicorp/vault-secrets-operator \
		--version $(VSO_CHART_VERSION) \
		--kubeconfig $(HOME)/.kube/$(CLUSTER).yaml \
		--namespace $(VSO_NAMESPACE) \
		--wait --timeout 5m
	@echo "✅ Vault Secrets Operator $(VSO_CHART_VERSION) installed on $(CLUSTER)"

install-observability: require-cluster kubeconfig ## Install ok-observability-standard profile + run the gated Contract Test (OK-79). Vars: OBSERVABILITY_SECRET_SOURCE=file|vault, OK_OBSERVABILITY_PATH, OK_OBSERVABILITY_REF, OBSERVABILITY_VALUES, CONTRACT_TEST_TIMEOUT, CONTRACT_TEST_RECEIVER_CAPTURE_URL
	@CLUSTER=$(CLUSTER) \
	 KUBECONFIG_PATH=$(HOME)/.kube/$(CLUSTER).yaml \
	 OK_OBSERVABILITY_PATH=$(OK_OBSERVABILITY_PATH) \
	 OK_OBSERVABILITY_REF=$(OK_OBSERVABILITY_REF) \
	 OBSERVABILITY_VALUES=$(OBSERVABILITY_VALUES) \
	 OBSERVABILITY_HELM_VALUES=$(OBSERVABILITY_HELM_VALUES) \
	 OBSERVABILITY_SECRET_SOURCE=$(OBSERVABILITY_SECRET_SOURCE) \
	 OBSERVABILITY_SECRET_SOURCES="$(OBSERVABILITY_SECRET_SOURCES)" \
	 VAULT_ADDR=$(VAULT_ADDR) \
	 VAULT_TLS_SERVER_NAME=$(VAULT_TLS_SERVER_NAME) \
	 VAULT_CA_SECRET=$(VAULT_CA_SECRET) \
	 KV_MOUNT=$(KV_MOUNT) \
	 KV_PATH=$(KV_PATH) \
	 VAULT_ROLE=$(VAULT_ROLE) \
	 VSO_SERVICE_ACCOUNT=$(VSO_SERVICE_ACCOUNT) \
	 REFRESH_AFTER=$(REFRESH_AFTER) \
	 CONTRACT_TEST_TIMEOUT=$(CONTRACT_TEST_TIMEOUT) \
	 CONTRACT_TEST_RECEIVER_CAPTURE_URL=$(CONTRACT_TEST_RECEIVER_CAPTURE_URL) \
	 bash $(SCRIPT_DIR)/install-observability.sh

bootstrap: require-not-flatcar
	@echo "Bootstrapping Talos cluster $(CLUSTER)..."
	@$(MAKE) --no-print-directory talos-golden-preflight CLUSTER=$(CLUSTER)
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
	@echo "   make install-storage       CLUSTER=$(CLUSTER)"
	@echo "   make install-ingress       CLUSTER=$(CLUSTER)"
	@echo "   make install-observability CLUSTER=$(CLUSTER)   # OK-79: deploy + gated contract test"
	@echo "   make status                CLUSTER=$(CLUSTER)"

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
upgrade: require-not-flatcar
	@test -n "$(K8S_VERSION)" || (echo "ERROR: K8S_VERSION is required"; exit 1)
	@CLUSTER=$(CLUSTER) K8S_VERSION=$(K8S_VERSION) TALOS_VERSION=$(TALOS_VERSION) \
	 DRY_RUN=$(DRY_RUN) bash $(SCRIPT_DIR)/upgrade-cluster.sh

# ── teardown ──────────────────────────────────────────────────────────────────
clean: require-not-flatcar
	@echo "Deleting CAPI cluster $(CLUSTER)..."
	$(OKB) delete cluster/$(CLUSTER) -n $(CLUSTER) --ignore-not-found --cascade=foreground
	$(OKB) delete namespace $(CLUSTER) --ignore-not-found
	@echo "Removing local manifests..."
	rm -rf $(CLUSTERS_DIR)/$(CLUSTER)
	@echo "✅ Cluster $(CLUSTER) removed."

teardown: require-not-flatcar ## Tear down a non-Flatcar cluster (Flatcar uses teardown-flatcar)
	@echo "Tearing down Talos cluster $(CLUSTER)..."; \
	PVS=$$($(OKB) get pvc -n $(CLUSTER) -o jsonpath='{range .items[*]}{.spec.volumeName}{"\n"}{end}' 2>/dev/null); \
	DV_UIDS=$$($(OKB) get datavolumes -n $(CLUSTER) -o jsonpath='{range .items[*]}{.metadata.uid}{","}{end}' 2>/dev/null); \
	if [ -n "$$PVS" ]; then \
		echo "  These cluster-owned VM disk PV(s) will be cleaned up here if the StorageClass has not already removed them:"; \
		echo "$$PVS" | sed 's/^/    /'; \
	fi; \
	if [ "$(CONFIRM)" != "yes" ]; then \
		printf "⚠️  This will TEAR DOWN %s: Cluster object, namespace, local render directory" "$(CLUSTER)"; \
		if [ -n "$$PVS" ]; then \
			PVCOUNT=$$(echo "$$PVS" | grep -c .); \
			printf ", and %s cluster-owned PV(s)/Longhorn volume(s)" "$$PVCOUNT"; \
		fi; \
		echo "."; \
		printf "Are you sure you want to tear down %s? [y/N] " "$(CLUSTER)"; \
		if [ -t 0 ]; then read -r ans; else read -r ans < /dev/tty || ans=n; fi; \
		case "$$ans" in \
			[yY]|[yY][eE][sS]) ;; \
			*) echo "Aborted. Re-run with CONFIRM=yes to skip this prompt (e.g. in CI)."; exit 1 ;; \
		esac; \
	fi; \
	$(OKB) delete cluster/$(CLUSTER) -n $(CLUSTER) --ignore-not-found --cascade=foreground; \
	$(OKB) delete namespace $(CLUSTER) --ignore-not-found; \
	HAS_TALOS_GOLDEN=$$(python3 -c 'import sys,yaml; c=yaml.safe_load(open(sys.argv[1])) or {}; print(str(c.get("type") == "talos" and bool(c.get("os",{}).get("goldenImage"))).lower())' "$(CLUSTERS_DIR)/$(CLUSTER)/cluster-config.yaml"); \
	if [ "$$HAS_TALOS_GOLDEN" = "true" ]; then \
		python3 $(SCRIPT_DIR)/scripts/talos_golden_lifecycle.py \
			--cleanup-authorization \
			--cluster "$(CLUSTER)" \
			--kubeconfig "$(TALOS_INFRA_KUBECONFIG)" \
			--ok-linux-path "$(OK_LINUX_PATH)" \
			--data-volume-uids "$$DV_UIDS"; \
	fi; \
	echo "Removing local cluster directory..."; \
	rm -rf $(CLUSTERS_DIR)/$(CLUSTER); \
	if [ -n "$$PVS" ]; then \
		echo "Cleaning up any remaining cluster-owned PVs and Longhorn volumes..."; \
		for pv in $$PVS; do \
			echo "  Deleting PV $$pv..."; \
			$(OKB) delete pv $$pv --ignore-not-found; \
			echo "  Deleting Longhorn volume $$pv (best-effort -- may already be gone)..."; \
			$(OKB) -n longhorn-system delete volumes.longhorn.io $$pv --ignore-not-found 2>/dev/null || true; \
		done; \
	fi; \
	echo "✅ Talos cluster $(CLUSTER) torn down (including cluster-owned PV cleanup)."

# ── e2e ───────────────────────────────────────────────────────────────────────
MGMT_CLUSTER       ?= ok-mgmt
MGMT_WORKERS       ?= 2
MGMT_NODE_SELECTOR ?= ok-infra
WORKLOAD_CLUSTER   ?= ok-ai
WORKLOAD_WORKERS   ?= 1
OPENWEBUI_CLAIM    ?= $(SCRIPT_DIR)/open-webui/claim-$(WORKLOAD_CLUSTER).yaml
OPENCLAW_CLAIM     ?= $(SCRIPT_DIR)/openclaw/claim-$(WORKLOAD_CLUSTER).yaml
OLLAMA_URL         ?=
CONFIRM            ?= false

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

unregister-cluster: require-cluster ## Deregister workload cluster from ok-mgmt (OK-62, ADR-Platform-013 follow-up): delete kubeconfig secret + ProviderConfig, idempotent
	@echo "━━━ Deregistering $(CLUSTER) from $(MGMT_CLUSTER) (ADR-Platform-013 follow-up) ━━━"
	@echo "  [1/3] Checking for Releases still using ProviderConfig $(CLUSTER)..."
	@RELEASES=$$(kubectl --kubeconfig $(MGMT_KUBECONFIG) get releases.helm.crossplane.io \
		-o jsonpath='{range .items[?(@.spec.providerConfigRef.name=="$(CLUSTER)")]}{.metadata.name}{"\n"}{end}' 2>/dev/null); \
	if [ -n "$$RELEASES" ] && [ "$(FORCE)" != "true" ]; then \
		echo "❌ Releases still reference providerConfigRef.name: $(CLUSTER):"; \
		echo "$$RELEASES" | sed 's/^/     /'; \
		echo "   Deleting the ProviderConfig now would leave Crossplane unable to reconcile or uninstall them."; \
		echo "   Delete the claims/Releases first, or re-run with FORCE=true."; \
		exit 1; \
	fi; \
	if [ -n "$$RELEASES" ]; then \
		echo "⚠️  FORCE=true — proceeding despite active Releases (Crossplane usage protection"; \
		echo "   will keep the ProviderConfig in Terminating until all Releases are gone):"; \
		echo "$$RELEASES" | sed 's/^/     /'; \
	fi
	@echo "  [2/3] Deleting ProviderConfig $(CLUSTER)..."
	@kubectl --kubeconfig $(MGMT_KUBECONFIG) delete providerconfig.helm.crossplane.io $(CLUSTER) \
		--ignore-not-found --wait=false
	@echo "  [3/3] Deleting secret $(CLUSTER)-kubeconfig..."
	@kubectl --kubeconfig $(MGMT_KUBECONFIG) -n crossplane-system delete secret $(CLUSTER)-kubeconfig \
		--ignore-not-found
	@echo "✅ $(CLUSTER) deregistered from $(MGMT_CLUSTER)"
	@echo "   Deliberately NOT part of 'make teardown' (ADR-013 trust boundary:"
	@echo "   teardown acts on the workload cluster, unregister writes to the management plane)"

teardown-all: ## Tear down ALL rendered clusters (every dir with a cluster-config.yaml) [CONFIRM=yes to skip prompt]
	@CLUSTERS=$$(for cfg in $(CLUSTERS_DIR)/*/cluster-config.yaml; do \
		[ -f "$$cfg" ] || continue; \
		basename $$(dirname $$cfg); \
	done); \
	if [ -z "$$CLUSTERS" ]; then \
		echo "(no rendered clusters found under $(CLUSTERS_DIR))"; \
		exit 0; \
	fi; \
	FLATCAR_CLUSTERS=$$(for c in $$CLUSTERS; do \
		CLUSTER_TYPE=$$(python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])) or {}; print(d.get("type") or "")' "$(CLUSTERS_DIR)/$$c/cluster-config.yaml"); \
		[ "$$CLUSTER_TYPE" = "flatcar" ] && echo "$$c"; \
	done); \
	if [ -n "$$FLATCAR_CLUSTERS" ]; then \
		echo "ERROR: teardown-all cannot own constrained Flatcar lifecycle:"; \
		echo "$$FLATCAR_CLUSTERS" | sed 's/^/   - /'; \
		echo "       Run teardown-flatcar explicitly for each listed cluster first."; \
		exit 2; \
	fi; \
	if [ "$(CONFIRM)" != "yes" ]; then \
		echo "⚠️  This will TEAR DOWN ALL of the following rendered clusters:"; \
		echo "$$CLUSTERS" | sed 's/^/   - /'; \
		printf "Are you sure you want to tear down ALL of these clusters? [y/N] "; \
		if [ -t 0 ]; then read -r ans; else read -r ans < /dev/tty || ans=n; fi; \
		case "$$ans" in \
			[yY]|[yY][eE][sS]) ;; \
			*) echo "Aborted. Re-run with CONFIRM=yes to skip this prompt (e.g. in CI)."; exit 1 ;; \
		esac; \
	fi; \
	for c in $$CLUSTERS; do \
		$(MAKE) --no-print-directory teardown CLUSTER=$$c CONFIRM=yes; \
	done

## reap-orphaned-volumes: list (dry-run) or delete orphaned Longhorn volumes left
## behind by CDI import artifacts that `make teardown` never sees (OK-118).
## Vars: MIN_AGE_HOURS (default 24), EXCLUDE_NAMESPACES, CONFIRM=yes to delete.
## See docs/longhorn-orphaned-volumes.md.
reap-orphaned-volumes:
	@./longhorn-orphan-reaper.sh

e2e: ## Full clean rebuild of ok-mgmt only: teardown+rebuild mgmt → reuse/create workload cluster → Crossplane wiring → OpenWebUI claim → verify (scope limited to mgmt, see OK-102) [CONFIRM=yes to skip prompt]
	@if [ "$(CONFIRM)" != "yes" ]; then \
		echo "⚠️  This will TEAR DOWN and RECREATE $(MGMT_CLUSTER)."; \
		echo "   $(WORKLOAD_CLUSTER) itself is kept (reused, not deleted)."; \
		echo "   Every OTHER cluster registered with $(MGMT_CLUSTER) (e.g. ok-shared, ok-robotics,"; \
		echo "   ok2-rmf) will need 'make register-cluster CLUSTER=<name>' run again afterward,"; \
		echo "   since $(MGMT_CLUSTER)'s Crossplane state (secrets/ProviderConfigs) is wiped."; \
		printf "   Are you sure you need to re-create %s? [y/N] " "$(MGMT_CLUSTER)"; \
		if [ -t 0 ]; then read -r ans; else read -r ans < /dev/tty || ans=n; fi; \
		case "$$ans" in \
			[yY]|[yY][eE][sS]) ;; \
			*) echo "Aborted. Re-run with CONFIRM=yes to skip this prompt (e.g. in CI)."; exit 1 ;; \
		esac; \
	fi
	@echo "━━━ E2E [0/5]: teardown $(MGMT_CLUSTER) only (scope limited to mgmt — see OK-102) ━━━"
	@echo "  Removing OpenWebUI claim before teardown (prevents Crossplane finalizer hang)..."
	@kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml \
		delete openwebuiclaim $(WORKLOAD_CLUSTER) -n openkubes-system \
		--ignore-not-found 2>/dev/null || true
	@$(MAKE) --no-print-directory teardown CLUSTER=$(MGMT_CLUSTER) CONFIRM=yes
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
	@if [ -d "$(CLUSTERS_DIR)/$(WORKLOAD_CLUSTER)" ]; then \
		echo "  $(WORKLOAD_CLUSTER) already rendered locally (not torn down — e2e scope is mgmt-only) — reusing existing manifests"; \
	else \
		$(MAKE) --no-print-directory new CLUSTER=$(WORKLOAD_CLUSTER) TYPE=talos WORKERS=$(WORKLOAD_WORKERS); \
	fi
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
	@echo "━━━ E2E [5a/5]: OpenClaw claim ━━━"
	@if [ -f "$(OPENCLAW_CLAIM)" ]; then \
		kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml apply -f $(OPENCLAW_CLAIM); \
		kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml wait --for=condition=Ready \
			openclawclaim/$(WORKLOAD_CLUSTER) -n openkubes-system --timeout=300s || \
			(echo "  WARN: OpenClaw claim not Ready — is the chart published? (make -C ../openkubes/platform/ai/openclaw chart-release)"; \
			 kubectl --kubeconfig ~/.kube/$(MGMT_CLUSTER).yaml get release.helm.crossplane.io openclaw-$(WORKLOAD_CLUSTER) 2>/dev/null || true); \
		kubectl --kubeconfig ~/.kube/$(WORKLOAD_CLUSTER).yaml -n openclaw \
			get pods 2>/dev/null || true; \
	else \
		echo "  (skipped — claim not found at $(OPENCLAW_CLAIM); override with OPENCLAW_CLAIM=...)"; \
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
	@echo "  make prepare-cilium-chart       # pinned .tools/cilium-1.19.6.tgz"
	@echo "  make new       CLUSTER=ok-ai TYPE=talos [WORKERS=2] [K8S_VERSION=v1.34.1] [TALOS_VERSION=v1.9.6]"
	@echo "  make bootstrap CLUSTER=ok-ai   # apply + annotate PVCs + Cilium CNI"
	@echo "  make kubeconfig CLUSTER=ok-ai  # once nodes Running"
	@echo "  GPU demo: DEMO_PROFILE=gpu-single-replica CP_DISK=20Gi WORKER_DISK=30Gi"
	@echo ""
	@echo "── Constrained Flatcar Workflow (ADR-009) ───────────────────────────"
	@echo "  make prepare-cilium-chart"
	@echo "  make new CLUSTER=ok-flatcar TYPE=flatcar"
	@echo "  make flatcar-preflight CLUSTER=ok-flatcar FLATCAR_INFRA_KUBECONFIG=<path> FLATCAR_CILIUM_CHART=$(CILIUM_CHART)"
	@echo "  make install-flatcar CLUSTER=ok-flatcar FLATCAR_INFRA_KUBECONFIG=<path> FLATCAR_CILIUM_CHART=$(CILIUM_CHART) FLATCAR_APPLY=yes"
	@echo "  make teardown-flatcar CLUSTER=ok-flatcar FLATCAR_INFRA_KUBECONFIG=<path> FLATCAR_TEARDOWN=yes"
	@echo "  Envelope: Flatcar 4593.2.4, amd64, KubeVirt, Kubernetes v1.34.1, 1 CP + 1 worker"
	@echo "  GPU demo: DEMO_PROFILE=gpu-single-replica CP_DISK=20Gi WORKER_DISK=30Gi"
	@echo "  Runbook: docs/gpu-demo-runbook.md (non-HA meetup workflow)"
	@echo ""
	@echo "── All targets ──────────────────────────────────────────────────────"
	@echo "  make prepare-cilium-chart [CILIUM_CHART_SOURCE=<predownloaded.tgz>]"
	@echo "  make verify-cilium-chart"
	@echo "  make gpu-demo-test                         # offline Talos + Flatcar demo guards"
	@echo "  make new           CLUSTER=ok1 TYPE=ubuntu|talos|talos-mgmt|flatcar [HA=true] [WORKERS=2] [NODE_SELECTOR=ok-gpu|NODE=ok-gpu] [START_IP=192.168.100.210]   # TYPE is required (OK-119)"
	@echo "  make render        CLUSTER=ok1"
	@echo "  make install       CLUSTER=ok1        # ubuntu: apply + cilium"
	@echo "  make kubeconfig    CLUSTER=ok1"
	@echo "  make install-cni   CLUSTER=ok1        # cilium only (manual)"
	@echo "  make install-storage CLUSTER=ok-ai # local-path StorageClass (Talos)"
	@echo "  make install-ingress CLUSTER=ok-ai # ingress controller (Traefik) + IngressClass ok-ingress"
	@echo "  make install-observability CLUSTER=ok-ai [OBSERVABILITY_VALUES=<path>] # OK-79: ok-observability-standard + gated contract test"
	@echo "  make register-cluster CLUSTER=ok2-rmf [KUBECONFIG_SRC=~/path/kubeconfig] [MGMT_CLUSTER=ok-mgmt]  # ADR-013: secret + ProviderConfig in ok-mgmt"
	@echo "  make bootstrap     CLUSTER=ok-ai  # talos: apply + annotate PVCs + cilium"
	@echo "  make annotate-pvcs CLUSTER=ok-ai  # annotate PVCs manually"
	@echo "  make unregister-cluster CLUSTER=ok2-rmf [FORCE=true] [MGMT_CLUSTER=ok-mgmt]  # OK-62: delete secret + ProviderConfig from ok-mgmt"
	@echo "  make upgrade       CLUSTER=ok1 K8S_VERSION=v1.35.0"
	@echo "  make clean         CLUSTER=ok1"
	@echo "  make teardown      CLUSTER=ok-ai"
	@echo "  make teardown-all                      # tear down ALL rendered clusters"
	@echo "  make reap-orphaned-volumes [MIN_AGE_HOURS=24] [EXCLUDE_NAMESPACES=ok-x] [CONFIRM=yes] # clean orphaned Longhorn volumes (OK-118)"
	@echo "  make e2e           [OLLAMA_URL=http://<ip>:11434] [CONFIRM=yes]  # asks for confirmation; rebuilds mgmt only; reuse/create WORKLOAD_CLUSTER; verify (OK-102)"
	@echo "  make e2e-verify                        # verification matrix only"
	@echo "  make list"
	@echo "  make status        CLUSTER=ok1"
	@echo ""
