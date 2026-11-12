# OK-226: Pinned read-only Kubernetes Authority DomainReader

**Status:** Experimental and disconnected. No new write permission, no live `ok up`, no production-ready Authority Profile.

## Scope

`internal/desiredauthority/kubernetes_domain_reader.go` adds a `DomainReader` implementation with exactly two read operations: `ReadNamespace` and `ReadFence`. Its constructor requires an independently pinned `DomainBinding`, a PEM CA certificate bundle and a dedicated short-lived bearer credential. It validates the semantic CA trust digest using the existing `kubeconfigtarget.TrustDigest` helper before constructing a TLS-only HTTP client.

The transport disables environment proxies, redirects, HTTP/2 alternative negotiation and keepalives; it uses explicit TLS roots, finite connection/header/request deadlines and bounded response size. Calls are exact-name HTTPS `GET` only, with fixed Accept headers: `PartialObjectMetadata` for Namespaces and JSON for the preexisting Fence ConfigMap. No list, watch, mutate, retry, installer or credential discovery is added.

The decoder uses `internal/jsonstrict` to reject duplicate object keys and checks protected case-alias fields, namespace identity, UID, resourceVersion, deletionTimestamp and ownerReferences. The Fence must be immutable and carry exactly the four expected data fields (format, state, namespaceUID and domainDigest). The existing `VerifyDomain` determines whether all observations match independently pinned identities.

## Bounded test intent

Fake HTTPS API tests cover an expected identity, namespace UID replacement and 404, host cluster UID change, Fence 404, UID and resourceVersion changes, disabled or mutable Fence, wrong digest, duplicate/case-alias JSON keys, API outages, redirects and invalid CA/token inputs.

**Review note:** These are synthetic fake TLS responses; they do not prove deployed Kubernetes RBAC/admission, anti-deletion/fork fencing, credential issuance/renewal, namespace control or live API behavior.

## Known remaining blockers

1. The constructor accepts a caller-provided bearer token, with no trusted Kubernetes audience, ServiceAccount TokenRequest, token expiry verification or secret lifecycle. The exact credential provisioning/rotation architecture must be independently reviewed.
2. The DomainReader only observes pinned identity. It neither creates a Fence nor proves that an attacker cannot delete/recreate the Fence, Namespace or desired-state record between reads. A **read-only pre/post guard is NOT an atomic write fence**.
3. The CAS adapter remains **disconnected** and still rejects missing records (`404 -> ErrUnverifiable`). An independently trusted initial `ABSENT` registration, source inventory/adoption proof and irreversible retention/fencing are absent.
4. Production CAS activation requires effective RBAC and admission authorization plus live negative tests of deletion/recreation, stale revisions, uncertainty, concurrent writers and restore/rollback. Record/policy/claim writers must use separate identities.
5. No part of this PR changes `ok up`, OK-147 Executor, M2b Make/Talos lifecycle, Golden Image/storage teardown or deployment resources.

**Next:** evaluate this read-only Reader on exact PR CI, then design and prove server-enforced Writer Isolation and anti-delete/recreate before any production Authority acceptance.
