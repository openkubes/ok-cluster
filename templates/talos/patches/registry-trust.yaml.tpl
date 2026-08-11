# Parameterized Talos machine-config patch for an internal TLS registry.
# Values are hydrated in memory by scripts/talos_registry_trust.py. This file
# deliberately contains no estate address or CA material.
machine:
  registries:
    config:
      ${REGISTRY_HOST}:
        tls:
          ca: ${REGISTRY_CA_BASE64}
  network:
    extraHostEntries:
    - ip: ${REGISTRY_ADDRESS}
      aliases:
      - ${REGISTRY_HOST}
