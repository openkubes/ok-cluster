# Standalone kagent lifecycle on the disposable ok-kagent lab (OK-129).
#
# Every cluster operation is hard-wired to the dedicated kubeconfig.
#
# Permissions are NOT configured here. They come from access-config.yaml, which
# the renderer in openkubes turns into RBAC, the write tool server and the write
# Agent. Change the config, re-run `make install`, and the boundary follows.
#
# Portability: POSIX tools only (grep, sed, sort) plus python3, which ok-cluster
# already requires. No ripgrep, no envsubst, no BSD-only stat flags — the same
# targets run on macOS and Linux.

.PHONY: help preflight context-check assets-check render-values render-access \
        render-access-quiet access-summary access-test install configure-access \
        status evidence verify-access dashboard logs uninstall verify-clean \
        write-tools-install write-tools-status write-tools-uninstall

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
ACCESS_CONFIG  ?= access-config.yaml
ACCESS_OUT     := .access.local
PROFILE_ENV    := $(ACCESS_OUT)/profile.env
OPENKUBES_DIR  ?= $(abspath ../../../openkubes)
KAGENT_ASSETS  := $(OPENKUBES_DIR)/platform/ai/kagent-standalone
RENDER_ACCESS  := $(KAGENT_ASSETS)/access/render-access.py
OK129_ACCESS   := $(abspath ok129_access.py)
OK_CLUSTER_DIR := $(abspath ../..)
RBAC_RENDERED  := $(ACCESS_OUT)/manifests/20-rbac.yaml
VERIFY_MATRIX  := $(ACCESS_OUT)/verification.tsv
EVIDENCE_FILE  := $(ACCESS_OUT)/evidence.json
EVIDENCE_RESULT ?= OBSERVED

help:
	@echo "Standalone kagent on ok-kagent (OK-129)"
	@echo ""
	@echo "  make preflight        Check local tools and repository layout"
	@echo "  make install          Install kagent and apply the access profile"
	@echo "  make status           Show releases, workloads, CRs and active profile"
	@echo "  make evidence         Record repository SHAs, config digest and versions"
	@echo "  make verify-access    Assert the RBAC boundary the profile declares"
	@echo "  make access-summary   Print what the current profile grants"
	@echo "  make access-test      Run the access renderer's own tests"
	@echo "  make dashboard        Port-forward the UI to http://localhost:8080"
	@echo "  make logs             Follow controller logs"
	@echo "  make uninstall        Remove releases, namespaces, CRDs and RBAC"
	@echo "  make verify-clean     Fail if kagent objects remain"
	@echo ""
	@echo "Permissions come from $(ACCESS_CONFIG) (mode: read-only | read-write)."
	@echo "OK-129 only permits approval-gated ConfigMap writes in kagent-lab."
	@echo "Override with ACCESS_CONFIG=<path>"
	@echo "to keep several profiles side by side."

# ── local prerequisites ──────────────────────────────────────────────────────
preflight:
	@missing=''; \
	  for tool in kubectl helm python3; do \
	    command -v "$$tool" >/dev/null 2>&1 || missing="$$missing $$tool"; \
	  done; \
	  if [ -n "$$missing" ]; then \
	    echo "ERROR: missing required tool(s):$$missing"; exit 1; \
	  fi
	@python3 -c 'import yaml' 2>/dev/null || { \
	  echo "ERROR: python3 is present but PyYAML is not."; \
	  echo "       Install it (pip install pyyaml) or use the ok-cluster venv."; \
	  exit 1; \
	}
	@test -f "$(ACCESS_CONFIG)" || { \
	  echo "ERROR: access config not found: $(ACCESS_CONFIG)"; exit 1; \
	}
	@test -f "$(OK129_ACCESS)" || { \
	  echo "ERROR: OK-129 access guard not found: $(OK129_ACCESS)"; exit 1; \
	}
	@$(MAKE) --no-print-directory assets-check
	@echo "Preflight OK: tools present, access config and openkubes assets found."

context-check:
	@test -r "$(KUBECONFIG)" || { echo "ERROR: missing $(KUBECONFIG)"; exit 1; }
	@actual="$$($(KUBECTL) config current-context)"; \
	  test "$$actual" = "$(EXPECTED_CTX)" || { \
	    echo "ERROR: expected $(EXPECTED_CTX), got $$actual"; exit 1; \
	  }

assets-check:
	@test -f "$(KAGENT_ASSETS)/kustomization.yaml" || { \
	  echo "ERROR: kagent assets not found at $(KAGENT_ASSETS)"; \
	  echo "Set OPENKUBES_DIR to the local openkubes repository."; \
	  exit 1; \
	}
	@test -f "$(RENDER_ACCESS)" || { \
	  echo "ERROR: access renderer not found at $(RENDER_ACCESS)"; exit 1; \
	}

# ── rendering ────────────────────────────────────────────────────────────────
# The private model endpoint is substituted with python3 rather than envsubst,
# which is not installed by default on macOS. The guard below is a real check:
# if any placeholder survives, the rendered file is deleted rather than shipped.
render-values:
	@: "$${OLLAMA_URL:?ERROR: set OLLAMA_URL in your shell, never in Git}"
	@OLLAMA_URL="$$OLLAMA_URL" python3 -c 'import os,sys,pathlib;src=pathlib.Path(sys.argv[1]).read_text(encoding="utf-8");pathlib.Path(sys.argv[2]).write_text(src.replace("$${OLLAMA_URL}", os.environ["OLLAMA_URL"]), encoding="utf-8")' \
	  "$(VALUES_TMPL)" "$(VALUES_LOCAL)"
	@chmod 600 "$(VALUES_LOCAL)"
	@if grep -q '$${OLLAMA_URL}' "$(VALUES_LOCAL)"; then \
	  rm -f "$(VALUES_LOCAL)"; \
	  echo "ERROR: unresolved OLLAMA_URL placeholder — rendered file removed"; \
	  exit 1; \
	fi
	@mode="$$(python3 -c 'import os,sys;print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$(VALUES_LOCAL)")"; \
	  test "$$mode" = "600" || { \
	    echo "ERROR: $(VALUES_LOCAL) is mode $$mode, expected 600"; exit 1; \
	  }
	@echo "Rendered $(VALUES_LOCAL) (mode 600, git-ignored)."

render-access: assets-check
	@python3 "$(OK129_ACCESS)" validate --config "$(ACCESS_CONFIG)"
	@python3 "$(RENDER_ACCESS)" \
	  --config "$(ACCESS_CONFIG)" \
	  --out "$(ACCESS_OUT)" \
	  --tools-image-tag "$(TOOLS_VERSION)"
	@python3 "$(OK129_ACCESS)" matrix \
	  --config "$(ACCESS_CONFIG)" \
	  --rbac "$(RBAC_RENDERED)" \
	  --out "$(VERIFY_MATRIX)"

# Same render, without the per-file chatter — for targets that only need the
# output to be current. Boundary warnings are still printed.
render-access-quiet: assets-check
	@python3 "$(OK129_ACCESS)" validate --config "$(ACCESS_CONFIG)"
	@python3 "$(RENDER_ACCESS)" \
	  --config "$(ACCESS_CONFIG)" \
	  --out "$(ACCESS_OUT)" \
	  --tools-image-tag "$(TOOLS_VERSION)" \
	  --quiet
	@python3 "$(OK129_ACCESS)" matrix \
	  --config "$(ACCESS_CONFIG)" \
	  --rbac "$(RBAC_RENDERED)" \
	  --out "$(VERIFY_MATRIX)"

access-summary: render-access-quiet
	@sed '/^Verify, do not trust this table:/,$$d' "$(ACCESS_OUT)/SUMMARY.md"
	@echo "Executable API verification matrix: $(VERIFY_MATRIX)"

access-test: assets-check
	@python3 "$(KAGENT_ASSETS)/access/render_access_test.py"
	@PYTHONPYCACHEPREFIX=/tmp/ok129-pyc python3 "$(OK129_ACCESS)" validate --config "$(ACCESS_CONFIG)"
	@PYTHONPYCACHEPREFIX=/tmp/ok129-pyc python3 "$(abspath ok129_access_test.py)"

# ── install ──────────────────────────────────────────────────────────────────
install: preflight render-values render-access
	@$(MAKE) --no-print-directory context-check
	$(HELM) upgrade --install kagent-crds \
	  $(CHART_ROOT)/kagent-crds \
	  --version $(KAGENT_VERSION) \
	  --namespace $(NS) --create-namespace \
	  --wait --timeout 5m
	@$(MAKE) --no-print-directory context-check
	$(HELM) upgrade --install kagent \
	  $(CHART_ROOT)/kagent \
	  --version $(KAGENT_VERSION) \
	  --namespace $(NS) \
	  --values $(VALUES_LOCAL) \
	  --values $(ACCESS_OUT)/values-access.yaml \
	  --wait --timeout 10m
	@$(MAKE) --no-print-directory configure-access
	@$(MAKE) --no-print-directory verify-access
	@echo ""
	@echo "Active profile — full detail via 'make access-summary':"
	@sed -n '/^\*\*Mode/p' "$(ACCESS_OUT)/SUMMARY.md"

# Applies the read-path assets, then adds or removes the write path depending on
# the mode in the access config. Switching back to read-only removes the write
# objects instead of leaving them orphaned.
#
# The write targets are asserted before the tool server is installed, so a
# config naming a namespace that does not exist fails without leaving a running
# write release behind.
configure-access: context-check render-access-quiet
	$(KUBECTL) apply -k "$(KAGENT_ASSETS)"
	@. "$(PROFILE_ENV)"; \
	  if [ "$$KAGENT_ACCESS_MODE" = "read-write" ]; then \
	    for ns in $$KAGENT_WRITE_NAMESPACES; do \
	      $(KUBECTL) get namespace "$$ns" >/dev/null 2>&1 || { \
	        echo "ERROR: write target namespace '$$ns' does not exist."; \
	        echo "       The access profile never creates target namespaces."; \
	        exit 1; \
	      }; \
	    done; \
	    $(MAKE) --no-print-directory write-tools-install; \
	    $(KUBECTL) --namespace "$$KAGENT_WRITE_SA_NAMESPACE" get serviceaccount "$$KAGENT_WRITE_SA_NAME" >/dev/null 2>&1 || { \
	      echo "ERROR: ServiceAccount $$KAGENT_WRITE_SA_NAMESPACE/$$KAGENT_WRITE_SA_NAME was not created by the tools chart."; \
	      echo "       The generated RoleBindings would bind nothing. Check the chart version."; \
	      exit 1; \
	    }; \
	    $(KUBECTL) apply -f "$(ACCESS_OUT)/manifests/"; \
	  else \
	    $(MAKE) --no-print-directory write-tools-uninstall; \
	  fi

# ── inspection ───────────────────────────────────────────────────────────────
status: context-check render-access-quiet
	$(HELM) list --namespace $(NS)
	$(KUBECTL) --namespace $(NS) get pods,svc,pvc
	@$(KUBECTL) api-resources 2>/dev/null | grep -E -i 'kagent|mcp' || true
	$(KUBECTL) --namespace $(NS) get modelconfigs,agents,remotemcpservers
	@. "$(PROFILE_ENV)"; \
	  echo ""; \
	  echo "Access profile: $$KAGENT_ACCESS_MODE"; \
	  if [ "$$KAGENT_ACCESS_MODE" = "read-write" ]; then \
	    echo "  write scope     : $$KAGENT_WRITE_SCOPE $$KAGENT_WRITE_NAMESPACES"; \
	    echo "  write resources : $$KAGENT_WRITE_RESOURCES"; \
	    echo "  approval gate   : $$KAGENT_WRITE_REQUIRE_APPROVAL"; \
	    echo "  write identity  : system:serviceaccount:$$KAGENT_WRITE_SA_NAMESPACE:$$KAGENT_WRITE_SA_NAME"; \
	    $(KUBECTL) --namespace "$$KAGENT_WRITE_SA_NAMESPACE" get deployment,svc,serviceaccount \
	      -l app.kubernetes.io/instance="$$KAGENT_WRITE_RELEASE" 2>/dev/null || true; \
	  fi
	@$(MAKE) --no-print-directory evidence EVIDENCE_RESULT=OBSERVED

evidence: render-access-quiet
	@python3 "$(OK129_ACCESS)" evidence \
	  --ok-cluster "$(OK_CLUSTER_DIR)" \
	  --openkubes "$(OPENKUBES_DIR)" \
	  --config "$(ACCESS_CONFIG)" \
	  --out "$(EVIDENCE_FILE)" \
	  --kagent-version "$(KAGENT_VERSION)" \
	  --tools-version "$(TOOLS_VERSION)" \
	  --result "$(EVIDENCE_RESULT)"

# Asserts the boundary the profile declares — against the API server, not the
# manifests. This is the check that catches a chart change widening RBAC.
verify-access: context-check render-access-quiet
	@fail=0; \
	  check() { \
	    label="$$1"; subject="$$2"; verb="$$3"; resource="$$4"; expected="$$5"; \
	    scope="$$6"; namespace="$$7"; \
	    if [ "$$scope" = "all-namespaces" ]; then \
	      got="$$($(KUBECTL) auth can-i "$$verb" "$$resource" --as="$$subject" --all-namespaces 2>/dev/null)"; \
	      where='all namespaces'; \
	    else \
	      got="$$($(KUBECTL) auth can-i "$$verb" "$$resource" --as="$$subject" --namespace "$$namespace" 2>/dev/null)"; \
	      where="namespace $$namespace"; \
	    fi; \
	    if [ "$$got" != "$$expected" ]; then \
	      echo "  FAIL $$label: $$subject '$$verb $$resource' in $$where -> $$got (expected $$expected)"; \
	      fail=1; \
	    else \
	      echo "  ok   $$label: '$$verb $$resource' in $$where -> $$got"; \
	    fi; \
	  }; \
	  tab="$$(printf '\t')"; \
	  while IFS="$$tab" read -r label subject verb resource expected scope namespace; do \
	    check "$$label" "$$subject" "$$verb" "$$resource" "$$expected" "$$scope" "$$namespace"; \
	  done < "$(VERIFY_MATRIX)"; \
	  . "$(PROFILE_ENV)"; \
	  if [ "$$KAGENT_ACCESS_MODE" = "read-write" ]; then \
	    if ! $(KUBECTL) --namespace $(NS) get agent/"$$KAGENT_WRITE_AGENT" >/dev/null 2>&1; then \
	      echo "  FAIL write Agent $$KAGENT_WRITE_AGENT is not installed"; fail=1; \
	    else \
	      echo "  ok   write Agent $$KAGENT_WRITE_AGENT present"; \
	    fi; \
	  elif ! python3 "$(OK129_ACCESS)" assert-clean --kubeconfig "$(KUBECONFIG)"; then \
	    fail=1; \
	  fi; \
	  test "$$fail" -eq 0 || { echo "Access verification FAILED"; exit 1; }; \
	  echo "Access verification passed."
	@$(MAKE) --no-print-directory evidence EVIDENCE_RESULT=PASS

dashboard: context-check
	@echo "UI: http://localhost:8080  (Ctrl-C to stop)"
	$(KUBECTL) --namespace $(NS) port-forward service/kagent-ui 8080:8080

logs: context-check
	$(KUBECTL) --namespace $(NS) logs deployment/kagent-controller --follow --tail=100

# ── scoped write tool server ─────────────────────────────────────────────────
# The namespace comes from the rendered manifest, not from `kubectl create
# namespace`: only the rendered object carries the ownership labels that
# `write-tools-uninstall` discovers. An install that aborts halfway therefore
# still leaves a removable namespace behind, never an orphan.
write-tools-install: context-check render-access-quiet
	@. "$(PROFILE_ENV)"; \
	  test "$$KAGENT_ACCESS_MODE" = "read-write" || { \
	    echo "ERROR: profile is $$KAGENT_ACCESS_MODE; set 'mode: read-write' in $(ACCESS_CONFIG)"; \
	    exit 1; \
	  }; \
	  $(KUBECTL) apply -f "$(ACCESS_OUT)/manifests/10-namespace.yaml"; \
	  $(HELM) upgrade --install "$$KAGENT_WRITE_RELEASE" \
	    $(TOOLS_CHART) \
	    --version $(TOOLS_VERSION) \
	    --namespace "$$KAGENT_WRITE_SA_NAMESPACE" \
	    --values "$(ACCESS_OUT)/tools-values.yaml" \
	    --wait --timeout 5m

write-tools-status: context-check render-access-quiet
	@. "$(PROFILE_ENV)"; \
	  if [ -z "$$KAGENT_WRITE_RELEASE" ]; then \
	    echo "Read-only profile — no write tool server."; exit 0; \
	  fi; \
	  $(HELM) list --namespace "$$KAGENT_WRITE_SA_NAMESPACE" --filter "^$$KAGENT_WRITE_RELEASE\$$"; \
	  $(KUBECTL) --namespace "$$KAGENT_WRITE_SA_NAMESPACE" get deployment,service,serviceaccount \
	    -l app.kubernetes.io/instance="$$KAGENT_WRITE_RELEASE"

# Removes every write object a profile can create, including what a previous,
# wider profile left behind: generated RoleBindings are labelled, so their
# namespaces are discovered rather than assumed.
write-tools-uninstall: context-check
	@python3 "$(OK129_ACCESS)" cleanup --kubeconfig "$(KUBECONFIG)"

# ── uninstall ────────────────────────────────────────────────────────────────
uninstall:
	@$(MAKE) --no-print-directory context-check
	@$(MAKE) --no-print-directory write-tools-uninstall
	@if test -f "$(KAGENT_ASSETS)/kustomization.yaml"; then \
	  $(KUBECTL) delete -k "$(KAGENT_ASSETS)" --ignore-not-found; \
	fi
	@echo "PVCs before namespace removal:"
	@$(KUBECTL) --namespace $(NS) get pvc 2>/dev/null || true
	@if $(HELM) --namespace $(NS) status kagent >/dev/null 2>&1; then \
	  $(HELM) --namespace $(NS) uninstall kagent --wait --timeout 5m; \
	fi
	@$(MAKE) --no-print-directory context-check
	@if $(HELM) --namespace $(NS) status kagent-crds >/dev/null 2>&1; then \
	  $(HELM) --namespace $(NS) uninstall kagent-crds --wait --timeout 5m; \
	fi
	@$(MAKE) --no-print-directory context-check
	$(KUBECTL) delete namespace $(NS) --ignore-not-found --wait=true --timeout=5m
	@$(MAKE) --no-print-directory verify-clean

verify-clean: context-check
	@python3 "$(OK129_ACCESS)" assert-clean --kubeconfig "$(KUBECONFIG)"
	@leftovers="$$($(KUBECTL) get crd -o name 2>/dev/null | grep -E -i 'kagent|mcp' || true)"; \
	  test -z "$$leftovers" || { echo "$$leftovers"; echo "ERROR: CRDs remain"; exit 1; }
	@leftovers="$$($(KUBECTL) get clusterrole,clusterrolebinding -o name 2>/dev/null | grep -E -i kagent || true)"; \
	  test -z "$$leftovers" || { echo "$$leftovers"; echo "ERROR: cluster RBAC remains"; exit 1; }
	@for ns in $(NS) kagent-write kagent-lab; do \
	  if $(KUBECTL) get namespace "$$ns" >/dev/null 2>&1; then \
	    echo "ERROR: namespace $$ns remains"; exit 1; \
	  fi; \
	done
	@echo "Clean: no kagent namespaces, CRDs, or cluster RBAC."
