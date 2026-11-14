#!/bin/sh
# Install an OpenKubes CLI release bundle for the current user (OK-228).
#
#   sh install-ok.sh --archive ok-<version>-<os>-<arch>.tar.gz --sha256 <expected>
#                    [--prefix DIR] [--bin-dir DIR] [--link]
#
# 1. The archive's SHA-256 must equal --sha256, a value you obtained
#    independently (not the .sha256 file shipped next to the archive). Nothing
#    is extracted before this check.
# 2. The archive may contain only one top-level directory named like the
#    archive for this OS/architecture, with only regular files and
#    directories: no links, devices, absolute paths, '..', control characters
#    or setuid/setgid/sticky bits.
# 3. It is extracted into a private staging directory inside the prefix and
#    verified there: release.txt against the binary and the Cilium chart,
#    `ok version` against release.txt, and ok-cluster/ and ok-linux/ at their
#    recorded commits with clean Git trees.
# 4. Only then it is renamed to <prefix>/<bundle>. An existing installation is
#    never overwritten, the archive is never modified, no root is needed, no
#    shell startup file is edited and nothing else is downloaded or installed.
# 5. --link creates <bin-dir>/ok -> the bundle's ok, only if <bin-dir>/ok does
#    not exist yet. Without --link the command to create it is printed.
#
# Defaults: --prefix ~/.local/share/ok, --bin-dir ~/.local/bin.
set -eu
umask 077
LC_ALL=C
export LC_ALL

die() { printf 'install-ok: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
usage() {
  sed -n '3,4p' "$0" >&2 2>/dev/null || true
  exit 2
}

ARCHIVE="" EXPECTED="" PREFIX="" BINDIR="" LINK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --archive) [ $# -ge 2 ] || usage; ARCHIVE=$2; shift 2 ;;
    --archive=*) ARCHIVE=${1#*=}; shift ;;
    --sha256) [ $# -ge 2 ] || usage; EXPECTED=$2; shift 2 ;;
    --sha256=*) EXPECTED=${1#*=}; shift ;;
    --prefix) [ $# -ge 2 ] || usage; PREFIX=$2; shift 2 ;;
    --prefix=*) PREFIX=${1#*=}; shift ;;
    --bin-dir) [ $# -ge 2 ] || usage; BINDIR=$2; shift 2 ;;
    --bin-dir=*) BINDIR=${1#*=}; shift ;;
    --link) LINK=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done
[ -n "$ARCHIVE" ] || die "--archive is required"
[ -n "$EXPECTED" ] || die "--sha256 is required: the expected SHA-256 from an independent, trusted channel"
[ "$(id -u)" != 0 ] || die "run as your own user, not root; the bundle must be owned by the user who runs ok"
case "${HOME:-}" in /*) ;; *) die "HOME must be an absolute path" ;; esac
PREFIX=${PREFIX:-$HOME/.local/share/ok}
BINDIR=${BINDIR:-$HOME/.local/bin}
EXPECTED=$(printf '%s' "$EXPECTED" | tr 'A-F' 'a-f')
case "$EXPECTED" in *[!0-9a-f]*) die "--sha256 must be 64 hexadecimal characters" ;; esac
[ ${#EXPECTED} -eq 64 ] || die "--sha256 must be 64 hexadecimal characters"

# ok passes these paths to Make and Python: absolute and shell-safe only.
for value in "$PREFIX" "$BINDIR"; do
  case "$value" in /*) ;; *) die "$value must be an absolute path" ;; esac
  case "$value" in *[!A-Za-z0-9._/-]*) die "$value contains unsupported characters (allowed: A-Z a-z 0-9 . _ / -)" ;; esac
  case "/$value/" in */../*|*/./*) die "$value must be a normalized path" ;; esac
done
case "$ARCHIVE" in /*) ;; *) ARCHIVE="$(pwd)/$ARCHIVE" ;; esac
[ -f "$ARCHIVE" ] && [ ! -L "$ARCHIVE" ] || die "$ARCHIVE is not a regular file"

for tool in tar git uname mktemp find awk; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool"
done
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum or shasum is required"
fi

# 1. Checksum before anything reads the archive's contents.
ACTUAL=$(sha256 "$ARCHIVE")
[ "$ACTUAL" = "$EXPECTED" ] || die "SHA-256 mismatch for $ARCHIVE
  expected $EXPECTED
  actual   $ACTUAL
  nothing was extracted or installed"
say "Checksum OK: $ACTUAL"

case "$(uname -s)" in Darwin) OS=darwin ;; Linux) OS=linux ;; *) die "unsupported OS: $(uname -s)" ;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; x86_64|amd64) ARCH=amd64 ;; *) die "unsupported architecture: $(uname -m)" ;; esac
BASE=$(basename "$ARCHIVE")
case "$BASE" in ok-*.tar.gz) NAME=${BASE%.tar.gz} ;; *) die "archive must be named ok-<version>-<os>-<arch>.tar.gz" ;; esac
case "$NAME" in *[!A-Za-z0-9._-]*) die "unsupported archive name: $BASE" ;; esac
case "$NAME" in *-"$OS-$ARCH") ;; *) die "$BASE is not for this machine ($OS/$ARCH)" ;; esac
DEST=$PREFIX/$NAME
[ ! -e "$DEST" ] && [ ! -L "$DEST" ] || die "$DEST already exists; existing installations are never overwritten"

mkdir -p "$PREFIX"
[ -d "$PREFIX" ] && [ ! -L "$PREFIX" ] && [ -w "$PREFIX" ] || die "$PREFIX is not a writable directory"
STAGE=$(mktemp -d "$PREFIX/.install-$NAME.XXXXXX") || die "cannot create a staging directory in $PREFIX"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# 2. Inspect the listing before extracting.
tar -tzf "$ARCHIVE" > "$STAGE/.names" 2>"$STAGE/.err" || die "cannot list $BASE (corrupt or not a gzip tar): $(head -n 3 "$STAGE/.err")"
tar -tvzf "$ARCHIVE" > "$STAGE/.long" 2>/dev/null || die "cannot list $BASE"
[ -s "$STAGE/.names" ] || die "$BASE is empty"
# A name containing a newline would show up as extra lines in one listing.
[ "$(wc -l < "$STAGE/.names")" -eq "$(wc -l < "$STAGE/.long")" ] || die "$BASE has an entry with an unsupported name"
if grep -q '[[:cntrl:]]' "$STAGE/.names"; then die "$BASE has an entry name with control characters"; fi
awk -v name="$NAME" '
  { sub(/\/$/, "") }
  $0 == "" { bad = 1 }
  $0 != name && index($0, name "/") != 1 { print "outside " name "/: " $0; bad = 1 }
  $0 ~ /(^|\/)\.\.(\/|$)/ { print "parent reference: " $0; bad = 1 }
  END { exit bad }' "$STAGE/.names" >&2 || die "$BASE contains entries outside $NAME/ or with '..'"
awk '
  { type = substr($1, 1, 1); special = substr($1, 4, 1) substr($1, 7, 1) substr($1, 10, 1) }
  type != "-" && type != "d" { print "not a regular file or directory: " $0; bad = 1 }
  special ~ /[sStT]/ { print "setuid/setgid/sticky: " $0; bad = 1 }
  END { exit bad }' "$STAGE/.long" >&2 || die "$BASE contains links, special files or privileged modes"

# 3. Extract into staging (tar refuses absolute and '..' paths by default) and
#    re-check what is actually on disk.
mkdir "$STAGE/x"
(cd "$STAGE/x" && tar -xzf "$ARCHIVE") || die "extraction failed"
[ "$(ls -A "$STAGE/x")" = "$NAME" ] || die "$BASE must contain exactly one top-level directory $NAME/"
# bsdtar lists hard links as regular files, so also check link counts on disk.
BAD=$(find "$STAGE/x" \( ! -type f ! -type d \) -o \( -type f -links +1 \) -o -perm -4000 -o -perm -2000 -o -perm -1000 | head -n 1)
[ -z "$BAD" ] || die "$BASE contains links, special files or privileged modes (on disk: $BAD)"

B=$STAGE/x/$NAME
OKBIN=$B/ok-cluster/.tools/bin/ok
CHART=$B/ok-cluster/.tools/cilium-1.19.6.tgz
[ -f "$B/release.txt" ] && [ -f "$OKBIN" ] && [ -x "$OKBIN" ] && [ -f "$CHART" ] || die "$NAME is not a complete OpenKubes bundle (release.txt, ok, chart)"
field() { awk -v key="$1" 'index($0, key ": ") == 1 { sub(/^[^:]*: */, ""); split($0, v, " "); print v[1]; exit }' "$B/release.txt"; }
R_VERSION=$(field version)
R_PLATFORM=$(field platform)
R_CLUSTER=$(field "ok-cluster commit")
R_LINUX=$(field "ok-linux commit")
R_BIN=$(field "bin/ok sha256")
R_CHART=$(field "cilium-1.19.6.tgz sha256")
[ "$R_PLATFORM" = "$OS/$ARCH" ] || die "release.txt platform '$R_PLATFORM' is not $OS/$ARCH"
[ "$NAME" = "ok-$R_VERSION-$OS-$ARCH" ] || die "release.txt version '$R_VERSION' does not match $NAME"
[ "$(sha256 "$OKBIN")" = "$R_BIN" ] || die "ok binary does not match release.txt"
[ "$(sha256 "$CHART")" = "$R_CHART" ] || die "Cilium chart does not match release.txt"
REPORTED=$("$OKBIN" version 2>/dev/null) || die "the bundled ok does not run on this machine"
[ "$REPORTED" = "$R_VERSION $R_CLUSTER" ] || die "ok version reports '$REPORTED', release.txt says '$R_VERSION $R_CLUSTER'"
gitq() { GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "$@"; }
for pair in "ok-cluster:$R_CLUSTER" "ok-linux:$R_LINUX"; do
  tree=${pair%%:*} commit=${pair#*:}
  head=$(gitq "$B/$tree" rev-parse HEAD 2>/dev/null) || die "$tree is not a Git copy"
  [ "$head" = "$commit" ] || die "$tree is at $head, release.txt says $commit"
  [ -z "$(gitq "$B/$tree" status --porcelain --untracked-files=all)" ] || die "$tree has changes or untracked files"
done
say "Bundle verified: $R_VERSION, ok-cluster $R_CLUSTER, ok-linux $R_LINUX"

# 4. Install. A plain `mv "$B" "$DEST"` is not no-replace: if $DEST appeared in
#    the meantime as a directory (or a symlink to one) mv would move the bundle
#    inside it, and a rename can replace a file. Instead, claim $DEST with
#    mkdir, which fails atomically if anything exists there, then rename the
#    verified entries into the empty, private (0700) directory we just created.
[ "$(find "$B" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 3 ] && [ -d "$B/ok-cluster" ] && [ -d "$B/ok-linux" ] &&
  [ -f "$B/release.txt" ] || die "$NAME must contain exactly ok-cluster/, ok-linux/ and release.txt"
mkdir "$DEST" 2>/dev/null || die "$DEST already exists (an existing or concurrent installation); nothing replaced"
for entry in ok-cluster ok-linux release.txt; do
  mv "$B/$entry" "$DEST/$entry" || die "cannot move $entry into $DEST; the incomplete $DEST was left for inspection"
done
TARGET=$DEST/ok-cluster/.tools/bin/ok
say "Installed $DEST"
say "Archive left unchanged: $ARCHIVE"

# 5. PATH: never overwrite, never edit shell files.
if [ "$LINK" = 1 ]; then
  mkdir -p "$BINDIR"
  if [ -e "$BINDIR/ok" ] || [ -L "$BINDIR/ok" ]; then
    say "Left unchanged: $BINDIR/ok already exists."
    say "  Run this version directly: $TARGET"
    say "  or replace the link yourself: ln -sfn $TARGET $BINDIR/ok"
  else
    ln -s "$TARGET" "$BINDIR/ok"
    say "Linked $BINDIR/ok -> $TARGET"
  fi
else
  say "To put ok on your PATH (only if $BINDIR/ok does not exist yet):"
  say "  mkdir -p $BINDIR && ln -s $TARGET $BINDIR/ok"
fi
case ":${PATH:-}:" in
  *":$BINDIR:"*) ;;
  *) say "$BINDIR is not on your PATH; add it in your shell profile yourself, e.g.:"
     say "  export PATH=\"$BINDIR:\$PATH\"" ;;
esac
say ""
say "Next:"
say "  ok version"
say "  ok config init      (verifies this bundle and saves your management kubeconfig path)"
say "  ok up"
