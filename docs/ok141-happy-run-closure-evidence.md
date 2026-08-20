# OK-141 Happy-Run closure evidence

Date: 2026-08-20

Environment: DEV

Outcome: `HAPPY-RUN-SUCCEEDED`

This checkpoint records only verified, redacted identities and outcomes. Raw
API objects, endpoints, tokens, Secrets, kubeconfigs, UIDs, resourceVersions,
logs, and capability output are excluded.

## Bound semantic identities

- `R`: `sha256:47bb651f6bc0bdb3a7a567efcd4ca4c776f872a63496fa55c2a6aed77d6fa995`
- `E`: `sha256:2a849d69e9c64344e907c1bce3bb1abf3d8f77217377081a5be055d62c213300`
- `P`: `sha256:2956184005f4860607e91672fce82164095dee6ebcbe57e5af883951a199c427`
- `FixtureDigest`: `sha256:438a6882d8e22b644c826cb0a6f2856850afd7c7ef71badb44cd66e8db0393ec`
- Platform source revision: `c09c18759aeb7526d22106ccb001599f5f06bc4e`

## Durable stage results

- Stage 11 `platform-observation`: `SUCCEEDED`, receipt
  `sha256:92a5811cb8926744655f8f6ee20c91ab426b803fb7912ae35f6f4e9379d1a2b0`
- Original Stage 12 `aggregate-evidence`: `FAILED`, immutable receipt
  `sha256:7cc777468a200d32df21633fd010a86deaf14a04f2d30582b44531d488694ea4`
- Corrected Stage 12 retry: `SUCCEEDED`, digest-addressed attempt receipt
  `sha256:51c3481ea38b8d41284f4f1d6d9a900c4bf40f86318c7bee4825f10eb08ae3d2`
- Final redacted Happy-Run summary:
  `sha256:8945f0c0e84605e432d012ddaef7eb1c7aeac40e6de2899c55e15b74efd592ae`

The original failed receipt remains the deterministic first receipt. The
successful result is a separate immutable retry attempt; no receipt was
overwritten or deleted.

## Runtime proofs

- Current Platform convergence: all three required Applications were
  `Synced/Healthy` at the exact bound Git revision. Redacted evidence digest:
  `sha256:04913cfb938a1a00fd58af3f946c6929ab7b05000b90e8b6469223323f7a6f66`.
- Exact synthetic Platform capability test: `PASS-CAPABILITY`; cleanup of its
  temporary kubeconfig, tools, port-forward logs, and synthetic Kubernetes
  objects completed. Redacted evidence digest:
  `sha256:46144f93619c13b1e3c377140c24e51eb70789dbe0a17f9650c45e36e3dafe5e`.
- The refreshed Argo target credential was never retained outside the bound
  Secret and was never emitted. Argo convergence after the refresh and a
  graceful cache restart is the functional proof. Redacted restart evidence:
  `sha256:abc953dc84b953b516f91aa01e2fd14f5a85f1ed40915cd9b3be06e56bc60bc0`.

## Corrections proven by execution

1. Argo may omit `spec.source.directory.recurse=false` from the observed API
   representation. The collector now canonicalizes the omitted value to the
   explicit semantic default before comparing the Application identity.
2. Cilium health cache freshness follows the previously approved rule:
   advertised probe interval must be positive and no greater than 300 seconds;
   maximum accepted age is advertised interval plus 60 seconds publication
   allowance plus 10 seconds scheduling/clock tolerance.
3. A failed evaluation may be retried only by binding the exact immutable
   digest of an existing `FAILED` receipt. The original receipt remains intact.

## Safety boundary

- No failure injection or outage was performed.
- No cluster, VM, Namespace, PV, or persistent data was deleted.
- No Force Delete, finalizer mutation, wildcard RBAC expansion, or permanent
  local credential was used.
- Raw execution evidence remains outside Git under private local paths.
