# OK-226: Kubernetes-backed CAS adapter (experimental)

**Status:** Disconnected prototype only. Not an activated Authority Store or Policy authorization.

This adapter implements the `internal/desiredauthority.Store` interface over exact-name Kubernetes ConfigMaps via HTTPS. It uses POST for first acceptance and PUT with the observed `metadata.resourceVersion` and `metadata.uid` for subsequent acceptance. The full transition tuple and resulting desired revision are persisted together in the `state` data field. After a reported successful write, the adapter performs readback before returning `ACCEPTED`.

It does **not** retry after any unknown HTTP/write outcome. `409` represents a rejected concurrent attempt; an unavailable or contradictory readback is `INDETERMINATE` and requires controlled inspection. Exact-tuple replay returns `ALREADY_ACCEPTED` without a write. Local fake TLS API tests exercise initial acceptance, 24 concurrent create attempts with exactly one winner, duplicate replay, competing tuple, lost response after server-side persistence and denied requests.

## Important blockers before any production use

- The model tests use a **minimal ConfigMap response fixture**. Real Kubernetes responses include additional metadata; production-compatible parsing and defensive rejection of duplicate/protected JSON fields must be implemented and independently tested against representative API responses.
- A caller-supplied `http.Client` is trusted. Production wiring needs **explicit trust roots, fixed audience, scoped short-lived bearer credential, bounded timeouts, strict redirect/proxy restrictions, and endpoint/namespace UID fencing**. The constructor accepts HTTPS only and overrides redirects but this alone is insufficient.
- HTTP GET 404 is **not proof of `ABSENT`**. Deleted/recreated ConfigMaps, namespace reincarnation, stale caches and unknown/unmanaged M2b CAPI resources could make `CreateCluster` unsafe. Until server-side anti-delete/recreate and a verified immutable domain fence exist, **do not permit initial creation**.
- A ConfigMap PUT resourceVersion precondition is an atomic object write but is **not** sufficient evidence of durable desired-state authority, policy-verified CAS, admission isolation or crash-safe historical correlation. The latest record alone cannot prove history retention or prevent rollback/replay after delete/recreate.
- `AuthorizationDigest` is just unverified input. No independent Policy verifier, claim consumer, CAS authority ownership, trusted profile identity, original resource inventory check or signed evidence is wired here.
- `DeleteCluster` is a validated transition shape only; no delete execution or `ok down` implementation.
- Existing CLI, executor, Make/Python, M2b teardown and shared cluster resources are unchanged.

**Exit criteria for next slice:** realistic Kubernetes API response fixtures, known/unknown 404 distinction through protected domain registration, forced write timeout, 409 conflict, metadata/UID drift, redirect, credential restrictions, admission anti-deletion checks, concurrent writer isolation and independent readback/recovery.

This PR is not a substitute for the independently reviewed Same-Plane Authority Profile in ADR-034-SP-001.
