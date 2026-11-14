#!/usr/bin/env bash
# OK-228: repeatable OpenKubes CLI build and acceptance (docs/release-process.md).
#
#   scripts/ok-rc-acceptance.sh --version v1.0.1-rc3 --commit <40-hex SHA> ...        acceptance build
#   scripts/ok-rc-acceptance.sh --release --version v1.0.1 --commit <40-hex SHA> ...  official release
#     [--ok-linux DIR] [--chart FILE] [--out DIR] [--work DIR] [--smoke-only]
#
# Versions follow SemVer and are shared by ok-cluster releases and the ok CLI.
# Acceptance builds are vX.Y.Z-rcN and go to ../rc-artifacts/<version>; an
# official vX.Y.Z needs --release, a local tag vX.Y.Z that already points at
# --commit (this script never creates or pushes tags), and goes to
# ../release-artifacts/<version>. The version and commit are always explicit;
# nothing is inferred from the current branch.
# Steps, in order (any failure stops and is recorded):
#   1. source:   ok-cluster HEAD == --commit and clean; for --release the tag
#                points at --commit; ok-linux at the commit pinned in
#                cmd/ok/cluster_provision.go and clean; the Cilium chart matches
#                the pinned SHA-256
#   2. tests:    go vet ./cmd/ok, go test ./cmd/ok, tests/release_bundle_test.py,
#                tests/install_ok_test.py (skipped with --smoke-only)
#   3. build:    darwin/arm64 and linux/amd64 bundles into a new --out; never
#                overwrites (skipped with --smoke-only, which uses existing ones)
#   4. verify:   each .tar.gz against its .sha256; release.txt version, platform
#                and both commits
#   5. smoke:    for the bundle native to this machine only: install-ok.sh into an
#                isolated prefix/bin, ok version, a second install is refused,
#                ok config init --yes and ok config show (text and -o json) with an
#                isolated HOME/XDG/config, ok cluster plan (read-only)
#   6. final:    ok-cluster still at --commit and clean; the user's ~/.local/bin/ok
#                and default config file are unchanged
# Writes <out>/acceptance-<version>-<UTC timestamp>.json (never overwritten).
#
# Reporting boundary and exit codes:
#   2  setup refused before the report location is known (arguments, version,
#      root, missing tools, ok-linux/chart paths, --out/--work location, an
#      existing report name). Nothing is built; no report is written, because
#      no accepted output directory exists yet; stderr says so.
#   1  any failure after that point (steps 1-6): always written to the report
#      with "result": "FAIL" and the failed step.
#   0  all steps passed; the report says "PASS".
#
# It never changes PATH or shell files, never touches ~/.local/bin/ok or the
# user's configuration, never runs ok up or ok destroy, never contacts a
# cluster, never tags or publishes. The smoke test needs no network; building
# uses the Go module cache/proxy as configured for `go build`.
set -euo pipefail
export LC_ALL=C

usage() { sed -n '3,4p' "$0" >&2; exit 2; }
# Until the report location is accepted (REPORTING=1), every refusal - including
# an unexpected command failure under set -e - exits 2 and says no report was written.
REPORTING=0
fail() {
  printf 'ERROR: %s\n' "$*" >&2
  (( REPORTING )) && exit 1
  printf '  setup refused before the report location was known: no report written (exit 2)\n' >&2
  exit 2
}
early_exit() {
  local code=$?
  (( code == 0 || code == 2 )) && return
  printf 'ERROR: setup failed (exit %s) before the report location was known: no report written (exit 2)\n' "$code" >&2
  exit 2
}
trap early_exit EXIT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="" COMMIT="" OK_LINUX="$ROOT/../ok-linux" CHART="$ROOT/.tools/cilium-1.19.6.tgz" OUT="" WORK="" SMOKE_ONLY=0 RELEASE=0
while (( $# )); do
  case "$1" in
    --version|--commit|--ok-linux|--chart|--out|--work)
      (( $# >= 2 )) || fail "missing value for $1"
      case "$1" in
        --version) VERSION=$2 ;; --commit) COMMIT=$2 ;; --ok-linux) OK_LINUX=$2 ;;
        --chart) CHART=$2 ;; --out) OUT=$2 ;; --work) WORK=$2 ;;
      esac
      shift 2 ;;
    --smoke-only) SMOKE_ONLY=1; shift ;;
    --release) RELEASE=1; shift ;;
    -h|--help) usage ;;
    *) fail "unknown argument: $1" ;;
  esac
done
if (( RELEASE )); then
  KIND=release
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "--release needs an official SemVer version like v1.0.1 (no -rc suffix)"
else
  KIND=release-candidate
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ ]] || fail "--version must be an acceptance build like v1.0.1-rc3; official versions need --release"
fi
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "--commit must be the full 40-character lowercase source SHA"
(( EUID != 0 )) || fail "run as an unprivileged user (install-ok.sh refuses root)"
for tool in git go python3 tar awk; do command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"; done
if command -v sha256sum >/dev/null 2>&1; then sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else fail "sha256sum or shasum is required"; fi

[[ -e "$OK_LINUX/.git" ]] || fail "ok-linux checkout not found: $OK_LINUX"
OK_LINUX="$(cd "$OK_LINUX" && pwd -P)"
[[ -f "$CHART" && ! -L "$CHART" ]] || fail "--chart must be the existing Cilium 1.19.6 chart file (missing: $CHART)"
if (( RELEASE )); then OUT="${OUT:-$ROOT/../release-artifacts/$VERSION}"; else OUT="${OUT:-$ROOT/../rc-artifacts/$VERSION}"; fi
# Decide before creating anything: an output inside a checkout would make it dirty.
OUT="$(python3 -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$OUT")"
case "$OUT/" in "$ROOT"/*|"$OK_LINUX"/*) fail "--out must be outside ok-cluster and ok-linux (it would make them dirty): $OUT" ;; esac
mkdir -p "$OUT"
if (( ! SMOKE_ONLY )) && [[ -n "$(ls -A "$OUT")" ]]; then fail "--out must be a new or empty directory; nothing is ever overwritten: $OUT"; fi
if [[ -z "$WORK" ]]; then WORK="$(mktemp -d "${TMPDIR:-/tmp}/ok-rc-acceptance-$VERSION.XXXXXX")"
else [[ ! -e "$WORK" ]] || fail "--work must not exist yet: $WORK"; mkdir -p "$WORK"; fi
WORK="$(cd "$WORK" && pwd -P)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$OUT/acceptance-$VERSION-$STAMP.json"
[[ ! -e "$REPORT" ]] || fail "report already exists: $REPORT"
STEPS="$WORK/steps.tsv" ARTIFACTS="$WORK/artifacts.tsv"
: > "$STEPS"; : > "$ARTIFACTS"
CURRENT="setup" FINISHED=0

record() { printf '%s\t%s\t%s\n' "$1" "$2" "${3//$'\t'/ }" >> "$STEPS"; printf '[%s] %s %s\n' "$2" "$1" "${3:-}"; }
write_report() {
  python3 -I - "$REPORT" "$1" "$CURRENT" "$KIND" "$VERSION" "$COMMIT" "${PIN:-}" "${CHART_SHA:-}" "$OUT" "$WORK" "$STEPS" "$ARTIFACTS" "$SMOKE_ONLY" "$STAMP" <<'PY'
import json, platform, subprocess, sys
report, status, current, kind, version, commit, pin, chart, out, work, steps, artifacts, smoke_only, stamp = sys.argv[1:]
def lines(path):
    with open(path) as f:
        return [l.rstrip("\n").split("\t") for l in f if l.strip()]
go = subprocess.run(["go", "version"], capture_output=True, text=True).stdout.strip()
data = {
    "schema": "ok-rc-acceptance/v1", "result": status, "failedStep": None if status == "PASS" else current,
    "kind": kind, "version": version, "commit": commit, "okLinuxCommit": pin, "ciliumChartSHA256": chart,
    "smokeOnly": smoke_only == "1", "startedUTC": stamp, "host": {"os": platform.system(), "arch": platform.machine(), "go": go},
    "outputDir": out, "workDir": work,
    "steps": [{"name": s[0], "status": s[1], "detail": s[2] if len(s) > 2 else ""} for s in lines(steps)],
    "artifacts": [{"file": a[0], "platform": a[1], "sha256": a[2], "nativeSmoke": a[3]} for a in lines(artifacts)],
    "notes": ["Checksums show integrity only; artifacts are not signed, notarized or attested.",
              "No tag, publication, ok up/destroy or cluster contact is part of this run.",
              "A PASS is not a stable-release approval: lifecycle acceptance on authorized disposable infrastructure is a separate gate."],
}
with open(report, "x") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}
on_exit() {
  local code=$?
  if (( ! FINISHED )); then
    record "$CURRENT" FAIL "exit $code"
    write_report FAIL || true
    printf '\nFAIL at step %s; report: %s\n' "$CURRENT" "$REPORT" >&2
  fi
}
trap on_exit EXIT
REPORTING=1

git_clean() { [[ -z "$(git -C "$1" status --porcelain --untracked-files=all)" ]]; }
user_state() { # fingerprint of what this run must never touch
  local link="$HOME/.local/bin/ok" config
  config="$(python3 -I -c 'import os,sys
base = os.path.expanduser("~/Library/Application Support") if sys.platform == "darwin" else os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
print(os.path.join(base, "ok", "config.json"))')"
  printf 'link=%s|%s config=%s|%s\n' "$(readlink "$link" 2>/dev/null || echo -)" "$( [[ -e "$link" ]] && sha256 "$link" || echo -)" \
    "$config" "$( [[ -f "$config" ]] && sha256 "$config" || echo -)"
}
USER_BEFORE="$(user_state)"

# 1. Source identity
CURRENT="source"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$COMMIT" ]] || fail "ok-cluster HEAD is $(git -C "$ROOT" rev-parse HEAD), not --commit $COMMIT"
git_clean "$ROOT" || fail "ok-cluster has local changes or untracked files"
if (( RELEASE )); then
  tagged="$(git -C "$ROOT" rev-parse -q --verify "refs/tags/$VERSION^{commit}" || true)"
  [[ -n "$tagged" ]] || fail "tag $VERSION does not exist locally; an official build needs the approved tag (this script never creates tags)"
  [[ "$tagged" == "$COMMIT" ]] || fail "tag $VERSION points at $tagged, not the approved commit $COMMIT"
fi
PIN="$(sed -n 's/^[[:space:]]*clusterProvisionReviewedOKLinux[[:space:]]*= "\([0-9a-f]\{40\}\)"$/\1/p' "$ROOT/cmd/ok/cluster_provision.go")"
[[ "$PIN" =~ ^[0-9a-f]{40}$ ]] || fail "cannot read the pinned ok-linux commit"
[[ "$(git -C "$OK_LINUX" rev-parse HEAD)" == "$PIN" ]] || fail "ok-linux is not at the pinned commit $PIN"
git_clean "$OK_LINUX" || fail "ok-linux has local changes or untracked files"
python3 -I "$ROOT/scripts/prepare_cilium_chart.py" --cache "$CHART" --verify-only >/dev/null || fail "Cilium chart does not match the pinned SHA-256"
CHART_SHA="$(sha256 "$CHART")"
record source PASS "$KIND $VERSION; ok-cluster $COMMIT clean$( (( RELEASE )) && printf '; tag %s -> commit' "$VERSION"); ok-linux $PIN clean; chart $CHART_SHA"

# 2. Tests (they build into temporary directories and leave the checkout clean)
if (( ! SMOKE_ONLY )); then
  CURRENT="tests"
  (cd "$ROOT" && go vet ./cmd/ok && go test -count=1 ./cmd/ok) > "$WORK/go-test.log" 2>&1 || { tail -30 "$WORK/go-test.log" >&2; fail "go vet/test ./cmd/ok failed (log: $WORK/go-test.log)"; }
  for test in release_bundle_test install_ok_test; do
    OK_LINUX_PATH="$OK_LINUX" CILIUM_CHART="$CHART" PYTHONDONTWRITEBYTECODE=1 python3 -B "$ROOT/tests/$test.py" > "$WORK/$test.log" 2>&1 ||
      { tail -30 "$WORK/$test.log" >&2; fail "$test failed (log: $WORK/$test.log)"; }
  done
  git_clean "$ROOT" || fail "tests left changes in ok-cluster"
  record tests PASS "go vet+test ./cmd/ok; release_bundle_test; install_ok_test (logs in $WORK)"
fi

# 3. Build
TARGETS="darwin-arm64 linux-amd64"
if (( ! SMOKE_ONLY )); then
  CURRENT="build"
  for target in $TARGETS; do
    bash "$ROOT/scripts/build_release_bundle.sh" --out "$OUT" --goos "${target%-*}" --goarch "${target#*-}" \
      --ok-linux "$OK_LINUX" --chart-source "$CHART" --version "$VERSION" > "$WORK/build-$target.log" 2>&1 ||
      { tail -30 "$WORK/build-$target.log" >&2; fail "build $target failed"; }
  done
  record build PASS "$TARGETS into $OUT"
fi

# 4. Verify every artifact
CURRENT="verify"
case "$(uname -s)/$(uname -m)" in Darwin/arm64) NATIVE=darwin-arm64 ;; Linux/x86_64|Linux/amd64) NATIVE=linux-amd64 ;; *) NATIVE=none ;; esac
for target in $TARGETS; do
  name="ok-$VERSION-$target" archive="$OUT/ok-$VERSION-$target.tar.gz"
  [[ -f "$archive" && -f "$archive.sha256" ]] || fail "missing $name.tar.gz or its .sha256 in $OUT"
  recorded="$(awk '{print $1; exit}' "$archive.sha256")" actual="$(sha256 "$archive")"
  [[ "$recorded" == "$actual" ]] || fail "$name.tar.gz does not match its .sha256"
  tar -tzf "$archive" > "$WORK/$name.list"
  grep -qx "$name/release.txt" "$WORK/$name.list" || fail "release.txt missing in $name"
  tar -xOzf "$archive" "$name/release.txt" > "$WORK/$name.release.txt"
  for want in "version: $VERSION" "platform: ${target%-*}/${target#*-}"; do
    grep -Fqx "$want" "$WORK/$name.release.txt" || fail "$name release.txt lacks '$want'"
  done
  grep -q "^ok-cluster commit: $COMMIT " "$WORK/$name.release.txt" || fail "$name was not built from $COMMIT"
  grep -q "^ok-linux commit: $PIN " "$WORK/$name.release.txt" || fail "$name does not pin ok-linux $PIN"
  smoke="no (not native to this machine)"; [[ "$target" == "$NATIVE" ]] && smoke="yes"
  printf '%s\t%s\t%s\t%s\n' "$name.tar.gz" "$target" "$actual" "$smoke" >> "$ARTIFACTS"
done
record verify PASS "checksums, release.txt version/platform/commits for $TARGETS"

# 5. Isolated, offline smoke test of the native bundle
CURRENT="smoke"
if [[ "$NATIVE" == none ]]; then
  record smoke SKIP "no bundle is native to $(uname -s)/$(uname -m)"
else
  name="ok-$VERSION-$NATIVE" archive="$OUT/ok-$VERSION-$NATIVE.tar.gz"
  digest="$(awk '{print $1; exit}' "$archive.sha256")"
  home="$WORK/home" prefix="$WORK/prefix" bin="$WORK/bin" config="$WORK/home/cfg/ok/config.json"
  mkdir -p "$home"
  run_isolated() {
    env -i HOME="$home" PATH="$PATH" LC_ALL=C XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$home/.local/state" \
      KUBECONFIG="$home/no-such-kubeconfig" TALOS_INFRA_KUBECONFIG="" "$@"
  }
  run_isolated sh "$ROOT/scripts/install-ok.sh" --archive "$archive" --sha256 "$digest" --prefix "$prefix" --bin-dir "$bin" --link \
    > "$WORK/smoke-install.log" 2>&1 || { cat "$WORK/smoke-install.log" >&2; fail "install-ok.sh failed"; }
  [[ "$(run_isolated "$bin/ok" version)" == "$VERSION $COMMIT" ]] || fail "installed ok version is not '$VERSION $COMMIT'"
  if run_isolated sh "$ROOT/scripts/install-ok.sh" --archive "$archive" --sha256 "$digest" --prefix "$prefix" --bin-dir "$bin" \
    > "$WORK/smoke-reinstall.log" 2>&1; then fail "a second install was not refused"; fi
  grep -q "never overwritten" "$WORK/smoke-reinstall.log" || fail "second install failed for an unexpected reason"
  if run_isolated "$bin/ok" config init --config "$config" < /dev/null > "$WORK/smoke-init-noyes.log" 2>&1; then
    fail "config init without a terminal saved without --yes"
  fi
  [[ ! -e "$config" ]] || fail "config init without --yes wrote a file"
  run_isolated "$bin/ok" config init --config "$config" --yes < /dev/null > "$WORK/smoke-init.log" 2>&1 ||
    { cat "$WORK/smoke-init.log" >&2; fail "ok config init --yes failed"; }
  grep -q "release bundle (release.txt matches)" "$WORK/smoke-init.log" || fail "init did not verify the release bundle"
  run_isolated "$bin/ok" config show --config "$config" > "$WORK/smoke-show.txt" 2>&1 || fail "ok config show failed"
  grep -q "Bundle:        verified (release bundle, release.txt matches)" "$WORK/smoke-show.txt" || fail "config show did not report a verified bundle"
  run_isolated "$bin/ok" config show --config "$config" -o json > "$WORK/smoke-show.json" 2> "$WORK/smoke-show.err" || fail "ok config show -o json failed"
  python3 -I - "$WORK/smoke-show.json" "$prefix/$name/ok-cluster" <<'PY' || fail "config show -o json does not describe the installed bundle"
import json, sys
shown = json.load(open(sys.argv[1]))
assert set(shown) == {"path", "config"}, shown
config = shown["config"]
assert config["format"] == "ok-cli-paths/v2" and config["topology"] == "same-plane", config
assert config["lifecycleRoot"] == sys.argv[2], config
assert "providerKubeconfig" not in config and "managementKubeconfig" not in config, config
PY
  cat > "$WORK/request.yaml" <<'EOF'
apiVersion: cli.openkubes.io/v1alpha1
kind: ClusterRequest
metadata:
  name: rc-plan-check
spec:
  profile: talos-kubevirt-reference
  network:
    endpoint: auto
    podCIDR: auto
    serviceCIDR: auto
EOF
  run_isolated "$bin/ok" cluster plan -f "$WORK/request.yaml" > "$WORK/smoke-plan.txt" 2>&1 || fail "ok cluster plan failed"
  grep -q "OpenKubes Cluster Plan (read-only)" "$WORK/smoke-plan.txt" || fail "unexpected ok cluster plan output"
  [[ ! -e "$home/.local/state/ok" ]] || fail "smoke test created lifecycle state"
  record smoke PASS "$name: install, refused reinstall, init (no --yes refused, --yes saved), show text+json, plan; isolated in $WORK"
fi

# 6. Nothing outside this run changed
CURRENT="final"
{ [[ "$(git -C "$ROOT" rev-parse HEAD)" == "$COMMIT" ]] && git_clean "$ROOT"; } || fail "ok-cluster changed during the run"
git_clean "$OK_LINUX" || fail "ok-linux changed during the run"
[[ "$(user_state)" == "$USER_BEFORE" ]] || fail "the user's ~/.local/bin/ok or default configuration changed"
record final PASS "sources unchanged; ~/.local/bin/ok and default config untouched"

FINISHED=1
write_report PASS
printf '\nPASS %s (%s)\nReport: %s\n' "$VERSION" "$COMMIT" "$REPORT"
(cd "$OUT" && for f in ok-"$VERSION"-*.tar.gz; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done)
