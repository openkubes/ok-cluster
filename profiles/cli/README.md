# Bounded CLI runner recipes

These versioned files are credential-free desired-state inputs for the existing
runner, not credentials, authority policies, grants, stage outcomes or live approval.
The CLI reads the recipe from its selected trusted lifecycle checkout. There is
no arbitrary recipe override, additional user command or runtime dependency on a
historical Candidate directory.

## OS coverage

| Profile family | Existing lifecycle source | Bounded friendly-YAML runner preparation |
| --- | --- | --- |
| Talos/KubeVirt | Talos resolver, provider templates and OK-147 projection | Static seven-stage plan; still NO-GO pending authority, credentials and full manifest/evidence |
| Flatcar | Flatcar resolver and templates | Not enabled; requires its own bootstrap, projection, convergence and lifecycle coverage |
| Ubuntu | Ubuntu templates | Not enabled; requires its own bootstrap, projection, convergence and lifecycle coverage |

The selection surface remains `spec.profile`. Do not alias another OS to the
Talos recipe or reuse Talos-specific Cilium settings. Existing renderer templates
alone are not evidence of a complete CLI provisioning/cleanup integration.

## Talos/KubeVirt MVP v1

`talos-kubevirt-mvp-v1.json` promotes only the non-secret desired-state semantics
of the successful `ok-cli-mvp-3` run into a reusable recipe. The permitted
parameter is a validated fresh cluster name. No historical Candidate identity, UID,
resourceVersion, execution-fixture digest, intent revision, outcome, credential,
grant or candidate-status marker is retained. Current R/F carriers are generated
only after the new Contract/projection have been verified.

Preserved baseline:

- Cilium OCI source, version, three externally enforced artifact/values pins,
  literal Talos values and Helm options are unchanged. No network download or
  new publication verification is claimed by local recipe loading.
- The HCP semantic digest must equal the reviewed profile. The HRP digest is
  derived for the new Cluster reference by the existing observation owner.
- Network image pins, expected node count and cache/probe limits are unchanged.
- Target-access inventory is still exactly 16 objects, including the five
  existing Platform ClusterRole prerequisites. Rule arrays, roleRefs, subjects,
  scopes, Pod Security levels and static names are unchanged. The cluster-scoped
  observability release name/labels use the new name; dynamic annotations are
  rebuilt. Existing broad Platform prerequisite rules are not narrowed or expanded
  as part of this promotion. This does not install any of this RBAC.
- The reviewed E/P revisions must exactly match the supplied canonical Contract.
  Mismatches fail closed and never silently replace operator intent.
- The local fixture binds the recipe bytes. Changes produce a new F and therefore
  a new policy/plan identity; no existing authority is rebound automatically.

The plan builder reuses `internal/stageplan`'s required sequence and verifier.
It requires eight explicit immutable stage inputs and creates only an ordinary
seven-stage NO-GO plan, never an attempt/recovery plan or deferred network mode.
Lifecycle and runtime-binding input documents are static requirements, not
readiness evidence, runtime bindings, UID assertions or permission to replay.
The live observer and durable receipt/convergence requirements remain unchanged;
this does not implement OK-197 or OK-198.

Review recipe changes together with the pinned baseline digest in the recipe
tests. A passing static plan does not make `--prepare` successful or YAML live
available: authority policies, existing private access, full-run manifest and
independent evidence still require their own verified bindings.

## Automatic Contract compilation

`talos-kubevirt-mvp-contract-v1.json` declares the existing internal Contract
schema/kind and fixed connectivity/endpoint/condition and E/P profile policies.
It is a reviewed recipe, not a historical Contract or runtime resource. The
existing resolver supplies OS/image/provider/sizing values; the runner recipe
supplies the reviewed E/P revisions. The compiler accepts only the friendly
intent and trusted profile path, with network/process calls blocked. The same
canonicalizer and projection verifier still validate the complete result.
Source digests are included in the generated binding/fixture identity.

Normal `ok up` and bare YAML `--prepare` now generate this Contract, the static
seven-stage plan and a bounded Stage Authority policy request automatically.
Platform authority/credential issuance is NOT implemented or implicitly granted;
without a separately supplied request-bound platform handoff the result remains
`AWAITING_PLATFORM_AUTHORITY`. Existing expert `--contract` inputs are preserved,
never silently replaced. Full preparation still requires independent evidence,
the existing manifest verifier and later separate live confirmation/convergence.
