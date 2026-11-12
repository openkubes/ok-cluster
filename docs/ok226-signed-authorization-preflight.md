# OK-226: Signed Authorization Preflight (offline, non-authorizing proposal)

**Status: isolated read-only prototype. No CAS writer, no admission exception, no production activation.**

This slice adds `internal/desiredauthority/authorization_preflight.go`. An externally controlled Ed25519 Policy signer may sign one canonical statement binding:

- The **exact `Transition` tuple**: tenant, cluster, profile, predecessor revision, target revision, transition ID, request digest, resolved execution binding digest P and declared authorization digest.
- The independently pinned **Authority Domain digest**, intended service audience, Policy key identifier, statement nonce, issue timestamp and expiry timestamp (maximum 5 minutes).
- A domain-specific version marker `openkubes-authority-authorization/v1`.

`VerifyAuthorization` checks all of these against independently provisioned trust values and a trusted caller-supplied time source before verifying the detached Ed25519 signature. It accepts only the bounded **CreateCluster** operation as a statement shape; it does **not** permit real initial `ABSENT` registration or cluster creation. `AuthorizationStatementDigest` creates a deterministic evidence correlation identity; equality of digests alone is never a grant.

## Explicit security boundary

**A successful cryptographic preflight is necessary but NOT sufficient to execute or accept any desired-state mutation.** This verifier has no Store, HTTP client, Kubernetes credentials, signer private key, executor or write API. Multiple calls with an identical valid statement still pass cryptographic validation: it **cannot prevent replay** without a separately enforced server-side claim. The nonce is correlation data, not spent state.

Before connecting an authorized CAS writer, the following gates are mandatory:

1. Independently identify and authenticate the Policy signer. Key rotation, revocation, algorithm/key-usage constraints, trusted clock and signed-policy authorization semantics need an operational design. A signature from a trusted key does not itself prove that policy rules were correctly evaluated.
2. Implement a **single-use server-side grant/claim** bound to the statement, Transition ID, Authority Domain, principal, audience and expiry. Consume/claim atomically before any authorized CAS acceptance. Claims and acceptance evidence must survive crash, retry, rollback, restore and replay.
3. Prove the **protected server-side write fence** against deletion/recreation of namespace, record and fence, including privileged policy modification and independent history retention. The existing read-only `DomainReader` and deny-all admission candidate cannot provide a writable path.
4. Verify independently that the cluster is safe to adopt/create: existing CAPI/KubeVirt/M2b resources and external network/IP allocations cannot be inferred absent from a missing desired-state ConfigMap. Existing `404 -> INDETERMINATE` remains in effect.
5. Retain append-only accepted transition evidence and status/outcomes separately from agent claims. Do not treat `ACCEPTED` as successful cluster reconciliation.
6. Exercise integrated fake API and disposable Kind negative conformance for competing writers, 409, lost responses, cancellation, history rollback, changed identity and revoked/missing grants.

## Tests and rollout

Synthetic offline tests cover accepted signatures, altered scope/transition fields, wrong domain/audience/key, signature tampering, expired/not-yet-valid timestamps, unsupported operation, excessive TTL and repeated verification of the same signed statement. No private signing material is introduced in production code; tests generate a deterministic local Ed25519 key.

The operator's **previous successful Kind admission freeze** (node image `kindest/node:v1.37.0`, six admission and two scoped RBAC PASS assertions) demonstrates only deny-only rules on a disposable cluster. It does **not** authorize loosening that policy or deploying an Authority writer.

**No modification:** `deploy/ok226-authority-freeze-candidate.yaml`, `KubernetesStore.CompareAndSwap`, live `ok up`, OK-147 bounded executor, M2b lifecycle or existing credentials. ADR-034-SP-001 remains Proposed.
