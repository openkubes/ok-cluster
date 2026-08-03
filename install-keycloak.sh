#!/usr/bin/env bash
# install-keycloak.sh — install the central Keycloak identity capability on ok-shared
# from a pinned `openkubes` revision, and stop before the approval-gated steps.
#
# ok-cluster INSTALLS the capability; it does not OWN it. Every asset — chart values,
# manifest templates, tooling, the Makefile that drives them — lives in the openkubes
# repo (default: ../openkubes) under platform/identity/keycloak. Nothing is copied
# here. This is the install-observability.sh analogue for identity.
#
# WHY THIS STOPS EARLY, rather than running the capability's own `install`:
# that target requires APPROVE_CUTOVER=yes AND an attended terminal, because it
# rewrites admin identity and applies traffic isolation. Wiring those through a
# `make install-keycloak` would give this repo one install-* target that cannot be
# scripted, unlike all its siblings. So this runs the ungated bootstrap and then
# PRINTS the remaining commands for a human to run attended. The gate stays a gate.
#
# The stop point is also not arbitrary: the capability deliberately orders
# `admin-cutover` BEFORE `verify`, so that a cutover or escrow failure cannot leave
# the final identity untested. Running verify here would invert that.
#
# Required env (set by the Makefile target):
#   CLUSTER            cluster name (kubeconfig at $KUBECONFIG_PATH)
#   KUBECONFIG_PATH    path to the target cluster's kubeconfig
#   MGMT_KUBECONFIG    ok-mgmt kubeconfig — READ-ONLY here, for the VaultConfig precheck
#   OPENKUBES_PATH     openkubes checkout that must contain OK_KEYCLOAK_REF
#   OK_KEYCLOAK_REF    revision to materialise and consume (from ok-keycloak.ref)
# Optional:
#   OK_KEYCLOAK_MODE   pinned (default) | worktree — worktree is explicitly
#                      non-reproducible and must be opted into
#   OK_KEYCLOAK_CACHE  cache root override
#   KEYCLOAK_NAMESPACE default: keycloak
#   CHART_DIR / CNPG_MANIFEST / OK_CLUSTER_PATH  vendor + callback overrides
set -Eeuo pipefail
trap 'exit 130' INT
trap 'exit 143' TERM

_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- helpers (duplicated from install-observability.sh on purpose) ------------
# Deliberately NOT factored into a shared library yet: that would mean editing a
# working, reviewed installer as a side effect of adding this one. The cost is that
# these two copies can drift; revisit if a third installer needs them.
sha_of() { git -C "$1" rev-parse HEAD 2>/dev/null || echo "unknown"; }
# --untracked-files=no on purpose: DIRTY must mean "tracked code was modified",
# which is what threatens reproducibility. Counting untracked files makes every
# fresh-cluster run report DIRTY, because rendering a cluster leaves an untracked
# <cluster>/ directory — i.e. it fires exactly when the clean marker matters most.
tracked_state_of() {
  local status
  status="$(git -C "$1" status --porcelain --untracked-files=no 2>/dev/null)" || { echo unknown; return; }
  [ -z "$status" ] && echo clean || echo DIRTY
}

KEYCLOAK_SOURCE_PATH="${OPENKUBES_PATH:-${_here}/../openkubes}"
KEYCLOAK_MODE="${OK_KEYCLOAK_MODE:-pinned}"
KEYCLOAK_NS="${KEYCLOAK_NAMESPACE:-keycloak}"
CAPABILITY_SUBDIR="platform/identity/keycloak"

# --- preconditions -----------------------------------------------------------
for bin in kubectl helm python3 git make tar flock jq openssl curl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "❌ required binary '$bin' not on PATH"; exit 2; }
done
[ -n "${CLUSTER:-}" ]           || { echo "❌ CLUSTER is required"; exit 2; }
[ -f "${KUBECONFIG_PATH:-}" ]   || { echo "❌ kubeconfig not found: ${KUBECONFIG_PATH:-<unset>} — run 'make kubeconfig CLUSTER=$CLUSTER'"; exit 2; }
[ -f "${MGMT_KUBECONFIG:-}" ]   || { echo "❌ MGMT_KUBECONFIG not found: ${MGMT_KUBECONFIG:-<unset>} — needed read-only for the VaultConfig precheck"; exit 2; }
[ -d "$KEYCLOAK_SOURCE_PATH" ]  || { echo "❌ openkubes checkout not found: $KEYCLOAK_SOURCE_PATH"; exit 2; }

case "$KEYCLOAK_MODE" in
  pinned|worktree) ;;
  *) echo "❌ OK_KEYCLOAK_MODE='$KEYCLOAK_MODE' is not one of: pinned worktree"; exit 2 ;;
esac
if [ "$KEYCLOAK_MODE" = pinned ] && [ -z "${OK_KEYCLOAK_REF:-}" ]; then
  echo "❌ OK_KEYCLOAK_REF is required in pinned mode"
  echo "   Set it to a locally available commit (ok-keycloak.ref supplies it), or opt"
  echo "   explicitly into the non-reproducible working tree with OK_KEYCLOAK_MODE=worktree."
  exit 2
fi

echo "── install-keycloak: cluster=$CLUSTER namespace=$KEYCLOAK_NS mode=$KEYCLOAK_MODE"
echo "   ok-cluster       $(sha_of "$_here") ($(tracked_state_of "$_here"))"
echo "   openkubes source $(sha_of "$KEYCLOAK_SOURCE_PATH") ($(tracked_state_of "$KEYCLOAK_SOURCE_PATH"))"

# --- materialise the pinned revision ----------------------------------------
# The pin has to be enforced, not documented: driving the capability Makefile from the
# working tree would install whatever happens to be checked out, which defeats the
# point of recording a revision at all.
if [ "$KEYCLOAK_MODE" = pinned ]; then
  # -q --verify: without it, rev-parse echoes an unresolvable arg back on stdout and
  # the variable ends up holding non-empty garbage.
  KEYCLOAK_SHA="$(git -C "$KEYCLOAK_SOURCE_PATH" rev-parse -q --verify "${OK_KEYCLOAK_REF}^{commit}" 2>/dev/null || true)"
  if [ -z "$KEYCLOAK_SHA" ]; then
    echo "❌ OK_KEYCLOAK_REF='${OK_KEYCLOAK_REF}' is not present in $KEYCLOAK_SOURCE_PATH"
    echo "   Fetch that revision into the local openkubes checkout, then re-run."
    exit 2
  fi

  if [ -n "${OK_KEYCLOAK_CACHE:-}" ]; then
    _cache_root="$OK_KEYCLOAK_CACHE"
  elif [ -n "${XDG_CACHE_HOME:-}" ]; then
    _cache_root="${XDG_CACHE_HOME}/ok-cluster/ok-keycloak"
  elif [ -n "${HOME:-}" ]; then
    _cache_root="${HOME}/.cache/ok-cluster/ok-keycloak"
  else
    echo "❌ cannot choose a cache root: set OK_KEYCLOAK_CACHE, XDG_CACHE_HOME, or HOME"
    exit 2
  fi
  _cache_tree="${_cache_root}/${KEYCLOAK_SHA}"
  _cache_marker="${_cache_tree}/.ok-cluster-cache-ready"
  mkdir -p "${_cache_root}/locks"
  chmod 700 "$_cache_root" "${_cache_root}/locks"
  # Per-SHA lock: two concurrent installs of the same revision must not race on the
  # same half-extracted tree.
  exec 9>"${_cache_root}/locks/${KEYCLOAK_SHA}.lock"
  flock 9

  if [ -f "$_cache_marker" ] &&
     [ "$(< "$_cache_marker")" = "$KEYCLOAK_SHA" ] &&
     [ -f "${_cache_tree}/${CAPABILITY_SUBDIR}/Makefile" ]; then
    echo "   cache reused: $_cache_tree"
  else
    echo "   materialising openkubes ${KEYCLOAK_SHA}"
    _tmp="$(mktemp -d "${_cache_root}/.${KEYCLOAK_SHA}.tmp.XXXXXX")"
    git -C "$KEYCLOAK_SOURCE_PATH" archive "$KEYCLOAK_SHA" | tar -x -C "$_tmp"
    # Structural check against the pinned revision, not against the working tree:
    # a ref that predates the capability must fail here rather than half-install.
    [ -f "${_tmp}/${CAPABILITY_SUBDIR}/Makefile" ] || {
      echo "❌ pinned revision ${KEYCLOAK_SHA} has no ${CAPABILITY_SUBDIR}/Makefile"
      rm -rf -- "$_tmp"; exit 2; }
    printf '%s' "$KEYCLOAK_SHA" > "${_tmp}/.ok-cluster-cache-ready"
    rm -rf -- "$_cache_tree"
    mv "$_tmp" "$_cache_tree"
  fi
  CAPABILITY_DIR="${_cache_tree}/${CAPABILITY_SUBDIR}"
else
  echo "   ⚠ worktree mode: installing whatever is checked out, NOT a pinned revision"
  CAPABILITY_DIR="${KEYCLOAK_SOURCE_PATH}/${CAPABILITY_SUBDIR}"
fi

# --- vendor inputs and the callback into this repo ----------------------------
# The capability resolves these from $(CURDIR)/../../../.. by default, which points
# inside the cache root once we run from a materialised tree. The pinned Keycloak
# chart and the CNPG manifest are SIBLING checkouts outside openkubes, so they are
# not in the archive at all and must be passed explicitly. OK_CLUSTER is the
# capability calling back into this repo for the VSO install.
_workspace="$(cd "${_here}/.." && pwd)"
CHART_DIR="${CHART_DIR:-${_workspace}/keycloak/charts/keycloakx}"
CNPG_MANIFEST="${CNPG_MANIFEST:-${_workspace}/cnpg/releases/cnpg-1.30.0.yaml}"
OK_CLUSTER_PATH="${OK_CLUSTER_PATH:-$_here}"
[ -d "$CHART_DIR" ]     || { echo "❌ pinned Keycloak chart checkout absent: $CHART_DIR (override CHART_DIR)"; exit 2; }
[ -r "$CNPG_MANIFEST" ] || { echo "❌ pinned CNPG manifest absent: $CNPG_MANIFEST (override CNPG_MANIFEST)"; exit 2; }

MAKE_ARGS=(
  -C "$CAPABILITY_DIR"
  CLUSTER="$CLUSTER"
  NAMESPACE="$KEYCLOAK_NS"
  KUBECONFIG="$KUBECONFIG_PATH"
  MGMT_KUBECONFIG="$MGMT_KUBECONFIG"
  CHART_DIR="$CHART_DIR"
  CNPG_MANIFEST="$CNPG_MANIFEST"
  OK_CLUSTER="$OK_CLUSTER_PATH"
)

# --- precheck: the privileged management-plane config must already exist ------
# vault-config applies to ok-mgmt and is never ours to run. Check it read-only and
# fail with the exact command, rather than failing four targets later inside `seed`
# with a confusing Vault permission error.
echo "── precheck: VaultConfig/$CLUSTER on ok-mgmt"
if ! kubectl --kubeconfig "$MGMT_KUBECONFIG" wait --for=condition=Synced=True "vaultconfig/$CLUSTER" --timeout=1s >/dev/null 2>&1 ||
   ! kubectl --kubeconfig "$MGMT_KUBECONFIG" wait --for=condition=Ready=True "vaultconfig/$CLUSTER" --timeout=1s >/dev/null 2>&1; then
  echo "❌ VaultConfig/$CLUSTER is not currently Synced=True and Ready=True on ok-mgmt."
  echo "   That apply is privileged and is not performed by this installer. Run:"
  echo "     make -C $CAPABILITY_DIR vault-config CLUSTER=$CLUSTER NAMESPACE=$KEYCLOAK_NS \\"
  echo "       KUBECONFIG=$KUBECONFIG_PATH MGMT_KUBECONFIG=$MGMT_KUBECONFIG APPROVE_MGMT=yes"
  exit 2
fi
echo "   ok — Synced=True and Ready=True"

# --- ungated bootstrap -------------------------------------------------------
# Same order as the capability's own `install`, minus the gated steps. Each target
# carries its own verification; stopping at the first failure is the contract.
for target in baseline install-vso identities seed vso-wiring database reachability keycloak; do
  echo "── make $target"
  make "${MAKE_ARGS[@]}" "$target"
done

cat <<EOF

✅ Ungated bootstrap complete on $CLUSTER (openkubes ${KEYCLOAK_SHA:-worktree}).

Keycloak is running and reachable, but the admin account is still Keycloak's own
TEMPORARY bootstrap admin — the console flags it, and the realm is not hardened yet.
The remaining steps rewrite admin identity and change live traffic isolation, so they
are approval-gated and must be run attended, in this order:

  make -C $CAPABILITY_DIR admin-cutover \\
    CLUSTER=$CLUSTER NAMESPACE=$KEYCLOAK_NS KUBECONFIG=$KUBECONFIG_PATH APPROVE_CUTOVER=yes

  make -C $CAPABILITY_DIR verify \\
    CLUSTER=$CLUSTER NAMESPACE=$KEYCLOAK_NS KUBECONFIG=$KUBECONFIG_PATH

  make -C $CAPABILITY_DIR harden \\
    CLUSTER=$CLUSTER NAMESPACE=$KEYCLOAK_NS KUBECONFIG=$KUBECONFIG_PATH APPROVE_NETWORK_POLICY=yes

  make -C $CAPABILITY_DIR post-check \\
    CLUSTER=$CLUSTER NAMESPACE=$KEYCLOAK_NS KUBECONFIG=$KUBECONFIG_PATH

verify runs AFTER admin-cutover deliberately: if it ran only before, a cutover or
escrow failure could leave the final identity untested. harden is not optional —
without it a rebuild comes back with no brute-force policy and no NetworkPolicies.
EOF
