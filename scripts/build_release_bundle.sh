#!/usr/bin/env bash
# Build an installable ok release bundle from a clean checkout (OK-228).
#
#   ok-<version>-<os>-<arch>/
#     ok-cluster/   minimal Git copy of the release commit; .tools/ (ignored)
#                   holds bin/ok (built from that commit) and the pinned chart
#     ok-linux/     minimal Git copy of the ok-linux commit pinned in the CLI
#     release.txt   commits, versions and SHA-256 of the binary and chart
#   ok-<version>-<os>-<arch>.tar.gz + .tar.gz.sha256
#
# The bundle has the layout the CLI already verifies at runtime (HEAD equals
# its build revision, clean tree), so no runtime code changes. Git cleanliness
# is not release provenance: trust comes from the published SHA-256.
set -euo pipefail

usage() { echo "usage: $0 --out DIR --goos OS --goarch ARCH --ok-linux PATH [--chart-source FILE] [--version V]" >&2; exit 2; }
OUT="" GOOS_TARGET="" GOARCH_TARGET="" OK_LINUX="" CHART_SOURCE="" VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2" ;; --goos) GOOS_TARGET="$2" ;; --goarch) GOARCH_TARGET="$2" ;;
    --ok-linux) OK_LINUX="$2" ;; --chart-source) CHART_SOURCE="$2" ;; --version) VERSION="$2" ;;
    *) usage ;;
  esac
  shift 2 || usage
done
[[ -n "$OUT" && -n "$GOOS_TARGET" && -n "$GOARCH_TARGET" && -n "$OK_LINUX" ]] || usage

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "ERROR: $*" >&2; exit 1; }

clean_at() { # <checkout> <expected commit>
  [[ "$(git -C "$1" rev-parse HEAD)" == "$2" ]] || fail "$1 is not at $2"
  [[ -z "$(git -C "$1" status --porcelain --untracked-files=all)" ]] || fail "$1 has local changes or untracked files"
}
sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
clean_at "$ROOT" "$COMMIT"
OK_LINUX_COMMIT="$(sed -n 's/^[[:space:]]*clusterProvisionReviewedOKLinux[[:space:]]*= "\([0-9a-f]\{40\}\)"$/\1/p' "$ROOT/cmd/ok/cluster_provision.go")"
[[ "$OK_LINUX_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "cannot read the pinned ok-linux commit from cmd/ok/cluster_provision.go"
clean_at "$OK_LINUX" "$OK_LINUX_COMMIT"
VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always)}"
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || fail "unsafe version: $VERSION"
# An official version (vX.Y.Z) only for the commit its tag points at; any
# other build keeps a distinct preview version (git describe, or --version).
if [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  [[ "$(git -C "$ROOT" rev-parse -q --verify "refs/tags/$VERSION^{commit}" || true)" == "$COMMIT" ]] ||
    fail "$VERSION is an official release version, but tag $VERSION does not point at $COMMIT; use a preview version"
fi

NAME="ok-${VERSION}-${GOOS_TARGET}-${GOARCH_TARGET}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$OUT/$NAME"
[[ ! -e "$STAGE" && ! -e "$STAGE.tar.gz" ]] || fail "$STAGE already exists; choose an empty --out"

copy_commit() { # <source repo> <commit> <destination>: minimal Git copy, no remote
  git init -q "$3"
  git -C "$3" fetch -q --depth 1 "file://$1" "$2"
  git -C "$3" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
  clean_at "$3" "$2"
}
copy_commit "$ROOT" "$COMMIT" "$STAGE/ok-cluster"
copy_commit "$OK_LINUX" "$OK_LINUX_COMMIT" "$STAGE/ok-linux"

mkdir -p "$STAGE/ok-cluster/.tools/bin"
(cd "$ROOT" && CGO_ENABLED=0 GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" go build -mod=readonly -trimpath -buildvcs=false \
  -ldflags "-s -w -X=main.version=$VERSION -X=main.revision=$COMMIT" -o "$STAGE/ok-cluster/.tools/bin/ok" ./cmd/ok)
CHART="$STAGE/ok-cluster/.tools/cilium-1.19.6.tgz"
python3 "$ROOT/scripts/prepare_cilium_chart.py" --cache "$CHART" ${CHART_SOURCE:+--source "$CHART_SOURCE"} >/dev/null
python3 "$ROOT/scripts/prepare_cilium_chart.py" --cache "$CHART" --verify-only >/dev/null

# The ignored .tools/ content must not make either copy dirty.
clean_at "$STAGE/ok-cluster" "$COMMIT"
clean_at "$STAGE/ok-linux" "$OK_LINUX_COMMIT"

cat > "$STAGE/release.txt" <<EOF
version: $VERSION
platform: $GOOS_TARGET/$GOARCH_TARGET
ok-cluster commit: $COMMIT   (embedded in bin/ok as its revision; ok-cluster/ is checked out at it)
ok-linux commit: $OK_LINUX_COMMIT   (pinned in bin/ok; ok-linux/ is checked out at it)
bin/ok sha256: $(sha256_of "$STAGE/ok-cluster/.tools/bin/ok")
cilium-1.19.6.tgz sha256: $(sha256_of "$CHART")
go: $(go version | cut -d' ' -f3)
EOF

tar -czf "$STAGE.tar.gz" -C "$OUT" "$NAME"
(cd "$OUT" && if command -v sha256sum >/dev/null; then sha256sum "$NAME.tar.gz"; else shasum -a 256 "$NAME.tar.gz"; fi) > "$STAGE.tar.gz.sha256"
(cd "$OUT" && if command -v sha256sum >/dev/null; then sha256sum -c "$NAME.tar.gz.sha256"; else shasum -a 256 -c "$NAME.tar.gz.sha256"; fi) >/dev/null
echo "Built $STAGE.tar.gz"
cat "$STAGE.tar.gz.sha256"
