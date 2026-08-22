# OK-147 bounded DEV stage authority

The bounded stage authority is the external grant issuer required by the
runner's `/v1/stage-authorizations` client. It is an authorization service, not
a Cluster lifecycle controller. It never renders Contracts, submits Kubernetes
objects, observes convergence or repairs CAPI, CAAPH, Cilium or Argo CD.

## Authority boundary

The service accepts only one protocol:

```text
POST /v1/stage-authorizations
Content-Type: application/vnd.openkubes.stage-authorization-request+json
Accept: application/vnd.openkubes.stage-authorization+json
Authorization: Bearer <private runtime token>
```

The request must be canonical JSON produced by the runner. The authority binds
it to one immutable policy derived directly from a verified staged execution
plan:

```text
verified Plan
    -> exact R / E / P / FixtureDigest
    -> exact mutating stage identities and digests
    -> bounded authority policy
```

No caller may author a second list of stage operations through the policy CLI.
Read-only stages are excluded automatically. The server validates the plan,
Contract identity, R/E/P/Fixture, stage order, stage digest, operation,
authority and predecessor shape before signing.

The signed grant is still independently verified and cursor-bound by the
runner. A fabricated predecessor digest therefore cannot authorize a runner
whose current verified receipt prefix differs.

## Single-use and fail-closed behavior

Every permitted request digest is claimed create-only as a private `0600`
record before a response is signed. The state directory must be absolute,
non-symlinked and inaccessible to group or other users. A duplicate request is
rejected after process restart as long as that directory is retained.

Invalid credentials, changed identities, non-canonical JSON, unsupported media
types and replay fail closed. A claim is never removed automatically. There is
no retry, rollback, cleanup, Kubernetes credential or generic proxy surface.

The first implementation deliberately rejects target-credential and
target-registration recovery media types. Recovery requires a separate policy
checkpoint and must not inherit normal-stage authorization implicitly.

## Offline policy derivation

`ok authority stage policy` verifies the source plan against independently
supplied identities and writes one new canonical policy file create-only:

```bash
ok authority stage policy \
  --plan /private/plan.json \
  --contract-namespace disposable-ok147 \
  --contract-name disposable-ok147 \
  --intent-revision sha256:<R> \
  --enablement-revision sha256:<E> \
  --platform-revision sha256:<P> \
  --execution-fixture sha256:<FixtureDigest> \
  --infrastructure-authority ok-infra \
  --management-authority ok-mgmt \
  --gitops-authority ok-shared \
  --output /private/stage-authority-policy.json
```

This operation has `mutationAllowed: false` and does not create a key, token,
TLS identity, listener or grant.

## DEV runtime

`ok authority stage serve` opens already provisioned private material and
serves the exact protocol over TLS 1.3:

```bash
ok authority stage serve \
  --policy /private/stage-authority-policy.json \
  --expected-policy-digest sha256:<reviewed-policy-digest> \
  --private-key /private/stage-authority-ed25519.key \
  --token-file /private/runner-token \
  --state-directory /private/single-use-state \
  --listen 0.0.0.0:8443 \
  --tls-cert /private/tls.crt \
  --tls-key /private/tls.key \
  --grant-valid-for 10m
```

The signing key, bearer token, TLS key and claim directory must remain private.
The bearer token must be at least 32 characters and use the bounded
alphanumeric/base64url-safe alphabet.
The service emits only a redaction-safe opening receipt containing policy and
public-key identities.

## Offline runtime package

`ok authority stage package` builds one private `0600` installation package
from the reviewed policy, a digest-pinned runner image, TLS/signing material,
one client token and the pinned runtime template. The package contains exactly:

```text
immutable private Secret
ServiceAccount without automounted token
64Mi (configurable) restart-safe claim PVC
Service with an exact private ClusterIP
deny-by-default NetworkPolicy
single-replica StatefulSet
```

The init container accepts the Kubernetes projected Secret symlinks, verifies
the policy, key and TLS pair, and copies exactly five files into a memory-backed
private directory as regular `0600` files. It also creates or reopens the
private claim directory on the PVC. Partial materialization is preserved and
never cleaned up or overwritten automatically.

The package receipt contains only component digests, public key identity,
image identity, a digest of the fixed Service IP and object kinds. The fixed
address lets the TLS identity, runner authorization endpoint and single-address
NetworkPolicy egress agree before any object is created; the raw address stays
inside the private package. The package itself contains secrets and must remain
a private `0600` artifact.

```bash
ok authority stage package \
  --policy /private/stage-authority-policy.json \
  --expected-policy-digest sha256:<reviewed-policy-digest> \
  --private-key /private/stage-authority-ed25519.key \
  --token-file /private/runner-token \
  --tls-cert /private/tls.crt \
  --tls-key /private/tls.key \
  --template deploy/bounded-stage-authority.yaml.tpl \
  --template-digest sha256:<reviewed-template-digest> \
  --image ghcr.io/openkubes/ok-cluster-runner@sha256:<image-digest> \
  --storage-class local-path \
  --storage-request 64Mi \
  --service-ip <reviewed-unused-private-cluster-ip> \
  --output /private/ok147-stage-authority-package.yaml
```

## Bounded installation launcher

`ok authority stage launch prepare` replays the private package from a `0600`
file, binds its exact public receipt and produces the six-object installation
plan without opening a Kubernetes credential or contacting a cluster:

```bash
ok authority stage launch prepare \
  --package /private/ok147-stage-authority-package.yaml \
  --package-receipt /reviewed/ok147-stage-authority-package-receipt.json \
  --expected-package-receipt-digest sha256:<receipt-file-digest> \
  --installer-authority ok-mgmt
```

The plan fixes the complete absence preflight and create sequence:

```text
Secret -> ServiceAccount -> PersistentVolumeClaim
       -> Service -> NetworkPolicy -> StatefulSet
```

`ok authority stage launch execute --execute` additionally requires the exact
private package digest, a short-lived installer token, an independently bound
CA digest and the IP-literal HTTPS endpoint of `ok-mgmt`. It repeats all six
exact-name GETs before the first POST and then creates the six objects in the
fixed order. Existing state stops with zero writes. An attempted or uncertain
write stops as partial state. The launcher is single-use and exposes no update,
patch, apply, adoption, delete, cleanup, rollback, list, watch or retry path.

```bash
ok authority stage launch execute \
  --package /private/ok147-stage-authority-package.yaml \
  --package-receipt /reviewed/ok147-stage-authority-package-receipt.json \
  --expected-package-receipt-digest sha256:<receipt-file-digest> \
  --expected-package-digest sha256:<private-package-digest> \
  --installer-authority ok-mgmt \
  --installer-api-endpoint https://<ok-mgmt-api-ip>:6443 \
  --installer-token-file /private/installer.token \
  --installer-ca-file /private/installer-ca.crt \
  --installer-ca-digest sha256:<ca-digest> \
  --execute
```

The receipt contains only package identity plus digests of the UID and
resourceVersion returned for each verified created object. It never records
the Secret, token, endpoint, raw UID or raw resourceVersion.

## Activation and ownership limits

The presence of this launcher does not authorize a live installation. A live
activation checkpoint must separately bind the verified package digest and
verify:

- exactly one replica for the bounded DEV run;
- durable private claim state across process restarts;
- a pinned policy, public key identity and immutable runner image;
- separately provisioned TLS and bearer-token material;
- deny-by-default network policy with only the runner-to-authority path; and
- an explicit cleanup and key-destruction decision after the run.

The independent observability collector remains separate. It must derive
receiver-delivery and autonomy claims from real independent observations; this
stage authority must never manufacture those values.
