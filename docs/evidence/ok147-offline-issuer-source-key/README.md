# Offline issuer source/key correspondence candidate

Baseline: `main@b2e0c60cceb20289ba1ae68eb5100d0e8d7e541b`.
Initial source: `0955136561975d01f5b12a7e6a6b9ef97b112776`.
Corrected implementation/test source: `0c0daf0bb5e07a216c30abd72659532e880f2280`.
Subsequent evidence-only commits do not alter that executable/test source.

## Scope and authority

`internal/issuersourcecheck.Validate` is a side-effect-free experimental helper
for a future **privileged platform task**, not for the CLI or runner. It accepts
already supplied metadata-only bytes, public CA DER and private key PEM, plus
the existing independently expected observer Binding/SourceOwner. It returns
only nil/error, never a key, signer, verified capability, credential or receipt.
Real CA key material must remain inside the future privileged task. The helper
is absent from both CLI and bootstrapauthority dependency graphs.

No key file/Secret loader, network client, signer, issuance route, transport,
default identity/lifetime, installation asset or runner integration is added.
No existing package, supported profile, public schema, resolver approval or
security gate is changed. In particular no CAPI administrator certificate or
Stage 5-7 path is re-enabled. #452/#458 remain separate; ADR-030 item 9 OPEN.

## Checks performed

- Reuse #455's metadata-only validator for exact namespace/name/UID/RV and sole
  expected Cluster controller owner. Complete Secret objects are rejected.
- Match the exact supplied CA DER SHA-256 to the independently expected digest;
  require parseable CA constraints, certificate-signing key usage and no
  unhandled critical extensions.
- Bound CA DER to 64 KiB and PEM to 16 KiB. Accept only one unencrypted,
  headerless PKCS#8, PKCS#1 RSA or SEC1 EC PEM block, with no leading/trailing
  junk, second block or trailing outer DER value.
- Decode RSA/ECDSA/Ed25519 keys using the standard library and compare the
  resulting public-key encodings with the CA certificate. No additional
  private-key consistency validator or signing operation is performed by this
  helper. Decoding support is **not** approval of an algorithm, curve, key
  strength or issuer profile.
- Return one fixed redacted error for every failure; no parser error, metadata,
  endpoint, key bytes or private input is returned/logged. Caller buffers remain
  unchanged. Go-managed temporary key allocations are not a secure-erasure or
  process-compromise containment guarantee.

## Explicit limits

Matching supplied values does not authenticate their provenance, prove current
API state or that metadata and key material came from one authorized read. A
future privileged task must bind source identity to its actual key-source read,
recheck immediately before use, and fail on source drift. This helper does not
select a provider version, Secret layout/data key or live key source.

The envelope checks are not canonical validation of every inner ASN.1 element.
Optional embedded public-key fields or extra inner elements may be ignored by
the standard-library parser; correspondence uses its resulting public key, not
an assertion that those embedded fields agree. The future task's actual key use
and parser/profile still need review. Multi-block EC PARAMETERS plus EC PRIVATE
KEY output is rejected; no implicit stripping/conversion is implemented.

It does not validate issuance-time CA validity/chain/profile, authenticate the
operation/request/authoritative predecessor, claim a durable slot, establish
store continuity or issue a certificate. A deliberately expired-CA test still
passes **correspondence only**, making that distinction explicit; it is not a
requirement to retain that behavior if an issuance-time policy is added. Existing
Binding roles remain observer-only; `target-access` is rejected rather than
inventing a privileged profile. Existing #455/#456 request/result/profile/time
checks, platform delegation, key isolation and all remaining store/issuer/
Stage-7 acceptance requirements still apply. Nil is not permission to sign.

## Tests and environment

All keys/certificates are generated in memory by tests. No real kubeconfig,
Secret, private key, credential renewal or cluster connection is used.

Cases cover RSA/ECDSA/Ed25519 and supported encodings; public/private mismatch;
wrong CA fingerprint; malformed/non-CA/non-signing certificates; metadata UID,
RV and owner drift; missing expectations; privileged role rejection; input size
bounds; encrypted/unsupported/multiple PEM blocks; malformed RSA/EC/PKCS#8 DER;
non-signing X25519 PKCS#8; trailing DER hidden inside PEM; redaction and unchanged
inputs. The trailing-DER negative initially exposed permissive x509 parsing and
was fixed with an explicit complete outer-sequence check; that intermediate FAIL
is not counted as PASS.

Local environment: Go 1.26.7 / macOS amd64. Initial-head `b7f3f6b` Linux/Go 1.21
CI is green and Suchit independently reproduced the suite/vet/race (including
45s PEM-input fuzzing) on Go 1.21.13. That is review evidence for the initial
head, not a result for this corrected head. New-head CI is separate and pending
until reported; the corrected-head local checks are listed below.

| Check | Result |
| --- | --- |
| Package tests | PASS |
| `go test -mod=readonly ./... -count=1` on final implementation source | PASS, all packages |
| `go test -race -mod=readonly ./internal/issuersourcecheck -count=10` | PASS |
| Package statement coverage after review correction | 94.6% |
| `go vet -mod=readonly ./...` | PASS |
| `go list -deps ./cmd/ok` and `./internal/bootstrapauthority` | New helper absent |
| `git diff --check` | PASS |

Review corrections remove the redundant post-parser RSA/EC/Ed25519 consistency
blocks and narrow the claims above. New tests isolate otherwise-valid material:
PEM at 16383/16384/16385 bytes; bound CA certificates at 65535/65536/65537 bytes;
a valid key with a Comment header; valid plaintext under an encrypted label;
and an ASN.1 EncryptedPrivateKeyInfo/PBES2 envelope with opaque synthetic
ciphertext (no password/decryption correctness claim). Critical/non-critical
extension controls exercise the new fail-closed critical-extension check.

Nine focused local mutation checks each FAIL as intended: removing the header
guard, removing either size bound, shifting each bound one byte in either
direction, routing the encrypted label to the plaintext parser, and removing
critical-extension rejection. Source was restored after every mutation; the
normal final tests PASS. These are isolated local negative experiments, not
production changes or a claim that all possible mutants were tested.

Full-repo race and live issuer/storage/authorization/runner/Stage-7/Console integration
are NOT RUN on this branch. No live cluster contact/mutation, credential action,
runner invocation, image publication, CLI installation or automatic merge. Original
dirty checkout, untracked files, Candidates and historical evidence unchanged.
