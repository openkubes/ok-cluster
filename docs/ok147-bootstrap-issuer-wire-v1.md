# OK-147 bootstrap issuer wire envelope v1 (candidate)

Status: **local protocol candidate; not deployed, not wired to `ok`, and not an
authorization or permission to issue credentials**.

The implementation is in `internal/bootstrapauthority/wire.go`. Its purpose is
to make the issuer boundary explicit and testable before adding a controller
transport. It uses canonical compact JSON, rejects duplicate and unknown
fields, and enforces bounded request/result sizes. Byte slices use JSON's
standard base64 representation. Timestamps are UTC RFC3339Nano strings;
durations are signed 64-bit nanoseconds.

## Request

The top-level format is `ok147-bootstrap-issuer-request/v1`. It contains the
audience, request key id, immutable store-domain digest, operation nonce,
predecessor stage and receipt digest, active time window, polling budget, and
request signature. `request` contains the full plan/attempt/target/endpoint/
policy/source identity binding plus the public CSR bytes. The canonical encoded
document is limited to 64 KiB.

## Result

The top-level format is `ok147-bootstrap-issuer-result/v1`. It contains the
result audience and key id; slot, claim, authorization and request digests; the
public leaf certificate DER; issuance time; and result signature. The canonical
encoded document is limited to 128 KiB. It has no field for a private key,
kubeconfig, bearer token, or source Secret contents.

## Security boundary

Successful decoding proves only that bytes have the expected bounded canonical
shape. It does **not** authenticate the caller, verify either signature, prove
plan/predecessor evidence, establish the authoritative store domain, claim a
single-use slot, validate the source Secret, issue a credential, permit runner
execution, or prove cluster convergence. A controller must independently
establish all those inputs before invoking the existing authority/task checks.
Unknown or indeterminate claim/result writes remain terminal STOP; this wire
format adds no replay, retry, credential refresh, or fallback behavior.

The format is a candidate pending protocol/security review. No HTTP endpoint,
CRD, Kubernetes adapter, deployment, credential access, cluster mutation, or
runner integration is part of this slice.
