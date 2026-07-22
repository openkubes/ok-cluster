#!/usr/bin/env bash
# provider-infra.sh — OpenStack/CAPO infrastructure preparation
# Implementation Profile: openstack
# Rendered from templates/talos-mgmt/providers/openstack/provider-infra.sh.tpl
# Sourced by bootstrap-mgmt.sh (Step 5); runs in that shell — set -euo pipefail
# and the log/ok/fail helpers are inherited.
#
# SCOPE (OK-106 Proof A — provider selection only): asserts the CAPO controller and
# the presence of OpenStack credentials. It deliberately does NOT design a new
# credential API and does NOT provision anything.

# Wait for the CAPO infrastructure controller
kubectl wait deployment/capo-controller-manager \
  -n capo-system --for=condition=Available --timeout=300s
ok "CAPO infrastructure provider healthy"

# OpenStack credentials are a PREREQUISITE, not something this script creates.
# CAPO reads clouds.yaml (or application credentials) from a Secret referenced by
# OpenStackCluster/identityRef. Provide it out of band before bootstrap.
CAPO_CREDENTIALS_SECRET="${CAPO_CREDENTIALS_SECRET:-capo-clouds-yaml}"
CAPO_CREDENTIALS_NAMESPACE="${CAPO_CREDENTIALS_NAMESPACE:-capo-system}"

log "Asserting OpenStack credentials secret $CAPO_CREDENTIALS_SECRET in $CAPO_CREDENTIALS_NAMESPACE..."
if ! kubectl -n "$CAPO_CREDENTIALS_NAMESPACE" get secret "$CAPO_CREDENTIALS_SECRET" >/dev/null 2>&1; then
  fail "OpenStack credentials secret $CAPO_CREDENTIALS_SECRET not found in $CAPO_CREDENTIALS_NAMESPACE — create it from your clouds.yaml / application credentials before bootstrap (this profile does not create a credential API)"
fi
ok "OpenStack credentials present"

# ── Proof B TODOs (deliberately NOT solved in Proof A / OK-106) ───────────────
# TODO(Proof B): control-plane endpoint model. The KubeVirt path assumes a MetalLB
#   endpointIP; OpenStack uses an Octavia LoadBalancer / floating IP. This is a
#   deliberate Proof-B API decision, not resolved here.
# TODO(Proof B): control-plane provider. The historical capi-platform-v4.2 runner
#   couples to KubeadmControlPlane; the intended path is Talos. Resolved in Proof B.
