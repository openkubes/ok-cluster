# Provider access ownership boundary

Status: responsibility boundary agreed; concrete rotation integration not implemented.
This note does not accept or amend ADR-030/031 and grants no live authority.

## Decision

The **lifecycle operator** is responsible for valid provider access for as long
as the external infrastructure controller needs it. This names an operational
responsibility, not a mandatory new component or particular secret-management
product. Ending an `ok` execution does not end controller reconciliation.

The bounded `ok` CLI verifies and consumes explicitly supplied, policy-bound
access for one authorized workflow. It does not become a renewal controller,
choose a longer credential lifetime, broaden RBAC, restart source controllers,
or repair provider access by replaying lifecycle operations.

## Minimal current CLI integration

`ok cluster create --help` explains this responsibility and the limits of
offline validation. `ok cluster create requirements` adds a descriptive
`providerAccessOwnership` object with:

- `lifecycleOwner: lifecycle-operator`;
- `requiredAfterExecution: true`;
- `automaticRenewalByCli: false`;
- `offlineValidationProvesOngoingAccess: false`; and
- operator handoff topics: validity window, rotation responsibility and current
  convergence evidence.

This is additive requirements-output metadata, not a new manifest schema or
authorization input. Existing requirements fields and their meaning remain
unchanged. Renderer/packaging consumers should treat it as operator guidance,
not as evidence that rotation is configured or access has been verified live.

The accepted manifest versions, `providerAccess.policyPath` and
`providerAccess.kubeconfigFile`, static credential validation, exact immutable
Secret policy, digest calculations, single-use grants and live gates are
unchanged. No owner declaration is inserted into an existing bound manifest.
No external authentication plugin, managed-secret protocol or background task
is enabled by this addition.

## Handoff contract

The lifecycle operator must distinguish credential validity from run completion.
The private operational handoff should identify the provider authority and
access reference, responsible operator, validity window or established renewal
mechanism, and current generation-correlated convergence evidence. It must not
publish tokens, private kubeconfigs, bootstrap data or signing keys.

The CLI's offline `--prepare` proves neither successful authentication nor
continuing access after execution. Likewise, completed immutable receipts do
not promise future availability. Report a later access regression independently
without changing earlier operation outcomes or claiming a new successful run.

## Deferred integration decisions

A concrete lifecycle-owned renewal implementation must separately specify:

1. Who may issue credentials and install or replace the controller's access.
2. How it preserves the current authority/namespace/subject boundaries.
3. How renewal works with the immutable Secret contract and existing references;
   changing that contract needs explicit versioning/review, not an in-place bypass.
4. How expiry, failed renewal, incomplete replacement and current convergence are
   evidenced, without automatic replay of provisioning.

No particular mechanism or TTL is selected here. A separately approved one-hour
Secret recovery remains a bounded MVP intervention, not the durable integration.
Do not infer permission to delete/create a Secret, issue another credential,
establish an automation, or implement OK-197/OK-198 from this ownership decision.
