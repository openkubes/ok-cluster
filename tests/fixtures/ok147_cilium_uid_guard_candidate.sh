# OFFLINE CANDIDATE FIXTURE, not an enabled probe command or deployment asset.
# The future invocation must use /bin/bash --noprofile --norc -p -c <body>
# ok147-uid-guard <independently selected UID>. Never interpolate the UID.
# OK147_PROBE_POD_UID must be installed as a unique metadata.uid fieldRef;
# a caller-supplied environment value is NOT authenticated Pod identity.
set -eu
export LC_ALL=C
if [[ $# -ne 1 ]]; then
    exit 42
fi
if [[ ! "$1" =~ ^[a-z0-9][-a-z0-9]{0,127}$ ]] ||
   [[ ! "${OK147_PROBE_POD_UID-}" =~ ^[a-z0-9][-a-z0-9]{0,127}$ ]] ||
   [[ "$1" != "$OK147_PROBE_POD_UID" ]]; then
    exit 42
fi
# A verified header distinguishes guard rejection from a health command that
# happens to exit with the same status. This framing is not a public protocol.
printf 'ok147-uid-guard-candidate/v1:%s\n' "$OK147_PROBE_POD_UID"
exec /usr/bin/cilium-health status --probe --output json
