# OK-147 target-admission local runtime

This document describes the local server entry point only. It is not an
installation authorization or a recommendation to deploy the webhook.
Build the local binary with `make ok-target-admission-build`; this target only
compiles `cmd/ok-target-admission` and makes no cluster/API contact.

For a local runtime-image build, `make ok-target-admission-image-build`
requires `OK_TARGET_ADMISSION_IMAGE_BUILD=yes` and loads the result into the
local Docker image store only. `Containerfile.ok147-target-admission` pins the
builder and distroless runtime by digest, copies only the admission command and
its internal packages, and runs as UID/GID 65532. This build target contains
no push, registry login, or publication step. A local tag is not a trusted
deployment reference; activation plans still require an independently
reviewed immutable registry digest.
Its Dockerfile-specific ignore file keeps test files and unrelated packages
out of this build context without narrowing the shared context used by the
existing runner image.

After building, `make ok-target-admission-image-smoke` checks the local image
configuration (UID/GID 65532 and the expected executable) and starts its help
path with networking disabled, a read-only root filesystem, all capabilities
dropped, and `no-new-privileges`. This is a local packaging smoke test only;
it does not verify a registry artifact, vulnerability status, Kubernetes
deployment behavior, or admission activation.

The image also records `org.opencontainers.image.revision`: local builds label
the source `local-worktree` by default, while CI supplies its checked-out
commit SHA. This is descriptive metadata, not a signature or independent
provenance attestation.

## Trust and startup sequence

`cmd/ok-target-admission` requires explicit files for the signed policy,
out-of-band Ed25519 public-key pin, target API endpoint and CA, a read-only
API token, webhook serving certificate/key, and the CA bundle that the API
server will pin for the webhook. Before opening its listener, it:

1. verifies the signed policy with the supplied pinned 32-byte public key;
2. issues one HTTPS GET to
   `/api/v1/namespaces/kube-system`, validating the API certificate against
   the explicitly supplied CA and hostname;
3. requires the returned Namespace UID to equal the independently signed
   target binding; and
4. issues one HTTPS GET to `/version` against the same endpoint and requires
   a stable Kubernetes 1.30-or-newer version (vendor build metadata is
   accepted; alpha/beta/RC versions are not); and
5. validates the webhook serving certificate's service DNS SAN, validity
   interval and ServerAuth usage, and verifies its chain against that exact
   webhook CA bundle.

Any failure exits non-zero before the listener is opened. The process does not
retry, renew credentials, install resources, or mutate the cluster. Its stdout
contains only the policy digest and public-key fingerprint; errors are
redacted. `READY` means these startup checks passed and the listener was
opened, not that the webhook has been installed or is receiving API-server
traffic.
Kubernetes readiness and liveness probes use the HTTPS `GET /healthz` endpoint;
it accepts only GET and performs no target API calls or mutations.

The token should be issued to a dedicated ServiceAccount with only `get` on
the cluster-scoped `namespaces` resource and `resourceNames: [kube-system]`,
plus non-resource `get` on the exact `/version` endpoint. Both permissions are
needed by the current startup identity/version preflight and no other URL or
resource is authorized. Use a short-lived projected token and a read-only
mounted volume. The webhook does not renew that token. If it expires before a
restart, startup fails closed. It does not need permission to create, update,
patch, list or watch.

## Required files

- `--bundle-file`: private, signed bundle; mode must deny group/other access.
- `--policy-public-key-file`: exactly 32 raw Ed25519 public-key bytes. Obtain
  its fingerprint through the independent review channel, not from this file's
  source location alone.
- `--target-api-endpoint`, `--target-api-ca-file`: explicit HTTPS API endpoint
  and pinned CA bundle.
- `--target-read-token-file`: short-lived token with the single GET permission
  above; mode must deny group/other access.
- `--tls-certificate-file`, `--tls-private-key-file`, `--service-dns`: the
  serving certificate/key and exact Service SAN
  `ok147-target-admission.ok147-target-admission-system.svc`; the private key
  must deny group/other access. Any other DNS name is rejected even if the
  supplied certificate would validate for it.
- `--webhook-ca-file`: CA bundle supplied to
  `RenderWebhookConfiguration`; startup rejects a serving certificate not
  chained to this exact bundle.
- `--listen`: host/port; standalone default is `127.0.0.1:8443`. A cluster
  deployment must explicitly bind the Pod listener (the generated Deployment
  uses `:8443`) so the Service can reach it.

The signed bundle contains private runtime UIDs, raw allowlisted objects, and
a canonical, non-overlapping `apiServerSourceCidrs` allowlist. The HTTPS
`/validate-target-access` route checks the actual TCP peer address against
those signed CIDRs; it does not trust `X-Forwarded-For` or other caller
headers. The platform signer must derive these ranges from independently
verified target network evidence. If the API server's source as observed by the
webhook cannot be established reliably, do not activate the webhook. The
health route is separate and never makes admission decisions.

Keep the bundle in a private mounted Secret or equivalent protected store,
never in Git, public receipts or logs. The policy signing private key is not
read by this server and must remain with the independent platform authority.

## Webhook registration

`targetadmission.RenderWebhookConfiguration` separately renders the
fail-closed validating configuration from the verified in-memory policy and
the webhook CA. It matches only CREATE operations for the exact object names,
resource kinds and namespaces. The API server authenticates the webhook server
using that CA and Service DNS name. The standard Service webhook connection
does not provide mutual TLS client authentication for the API server. Keep the
Service reachable only through the intended API-server path and use
stable Kubernetes 1.30+ for CEL match conditions. The installing authority must obtain
the target API server's `gitVersion` from that same bound endpoint and reject
versions below 1.30 with `ValidateWebhookKubernetesVersion` before creating
the configuration.

The local code does not create the Secret, ServiceAccount, ClusterRole,
ClusterRoleBinding, Deployment, Service, NetworkPolicy, or
ValidatingWebhookConfiguration. It also has no durable activation receipt or
independent signer service. Those installation/delivery pieces require a
separate reviewed platform handoff. No live cluster operations are performed
by this executable until an operator deliberately runs it in a deployed
environment; no such run was part of this implementation.

For infrastructure review only, the binary also supports
`--render-install-set --image-ref <registry/image@sha256:...>`. This is a
local, stdout-only renderer for six scaffold objects: a restricted namespace,
a non-automount service account, a single-resource identity-reader role and
binding, a hardened one-replica deployment, and a ClusterIP service. The image
reference must be digest-pinned. This mode rejects server inputs and performs
no API contact, credential creation, or apply.

`--render-activation-plan` additionally verifies the signed policy against the
provided public-key pin, then emits a digest-addressed JSON plan with two
separate phases: scaffold first, `ValidatingWebhookConfiguration` last. It
contains a digest of the signed target-binding UIDs, not the raw UIDs. The plan
is explicitly `PLAN_ONLY_AWAITING_TARGET_CHECKS`: it has not contacted the
target, verified its Kubernetes version, authorized writes, or activated the
webhook. A future installer must recheck the exact target and version at the
write boundary and retain immutable success/partial/unknown receipts.

`--verify-activation-plan-file <plan.json>` regenerates that exact plan from the
same signed bundle, public-key pin, and webhook CA and rejects any byte-level
manifest drift. Its receipt is `VERIFIED_OFFLINE_PLAN_ONLY_NO_GO`; it confirms
plan integrity only, not target identity, version, install, or activation.

`--preflight-target` is the next, separate read-only boundary. It requires the
saved activation plan, same signed bundle and trust pins, plus an explicit
target API endpoint, pinned API CA, and private read-only token file. The
command verifies the plan offline, then performs exactly two TLS-pinned GETs
to the same endpoint (`kube-system` Namespace and `/version`). It rejects a
namespace UID mismatch and Kubernetes versions below 1.30. Its JSON evidence
reports `apiAccessed=true`, `mutationAllowed=false`,
`webhookActive=false`, and `recheckRequiredAtWrite=true`. This is point-in-time
observation only—not approval, installation, a durable operation receipt, or
evidence reusable at a future write boundary. No retries, credential renewal,
server startup, or mutation occur in this mode.

The scaffold renderer is deliberately incomplete and not install-ready: the signed
policy Secret, out-of-band public-key ConfigMap, serving TLS Secret, network
exposure controls, and target-bound ValidatingWebhookConfiguration are
excluded. These need separate review and a deployment path that binds to the
actual target before webhook activation. Do not apply the scaffold by itself;
it does not provide an active or secured admission boundary.
