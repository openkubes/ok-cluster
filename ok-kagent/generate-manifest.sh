#!/usr/bin/env bash
# Render private, environment-resolved manifests without dirtying the public
# allocation-safe source configuration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PUBLIC_CONFIG="${SCRIPT_DIR}/cluster-config.yaml"
LOCAL_CONFIG="${SCRIPT_DIR}/cluster-config.local.yaml"
BACKUP="$(mktemp)"

cp "${PUBLIC_CONFIG}" "${BACKUP}"
restore_public_config() {
  cp "${BACKUP}" "${PUBLIC_CONFIG}"
  rm -f "${BACKUP}"
}
trap restore_public_config EXIT

python3 "${ROOT_DIR}/render.py" render --cluster ok-kagent
cp "${PUBLIC_CONFIG}" "${LOCAL_CONFIG}"

echo "Rendered local-only manifests in ${SCRIPT_DIR}"
echo "Resolved configuration: ${LOCAL_CONFIG}"
