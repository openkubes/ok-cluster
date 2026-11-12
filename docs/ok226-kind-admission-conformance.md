# OK-226 — Disposable Kind Admission Conformance (manual-only)

**Status:** A manual opt-in test harness, **not executed in a real Kubernetes environment by this PR**. This is NOT evidence that production Authority is protected.

## Scope and usage

From the `ok-cluster` repository root, on a machine with `kind`, `kubectl`, a working local Docker/Podman runtime, and a Kubernetes release supporting `admissionregistration.k8s.io/v1` ValidatingAdmissionPolicy:

```bash
bash -n scripts/ok226-admission-conformance-kind.sh
OK226_ALLOW_DISPOSABLE_KIND=yes bash scripts/ok226-admission-conformance-kind.sh
```

This script **always creates a new, fixed-name disposable Kind cluster** called `ok226-admission-conformance` and explicitly uses the `kind-ok226-admission-conformance` kubectl context on all requests. It refuses to run if a Kind cluster already exists with that name. It does not use the current user-selected kubectl context. It creates the `openkubes-authority` namespace and two test-only ConfigMaps **before** installing the frozen admission candidate. It installs only into that fresh Kind cluster; it never installs into any existing OpenKubes, production or shared cluster. It attempts best-effort teardown on script exit after successful cluster creation.

The script explicitly requires `OK226_ALLOW_DISPOSABLE_KIND=yes`; without this opt-in it exits before creating resources. Do not run it on machines where a local container runtime is unavailable or where a disposable Kind cluster cannot be created safely.

## Evidence required for a positive result

The harness fails unless all these independently observed checks succeed:

- A ConfigMap cannot be created in `openkubes-authority`.
- An existing Authority test-record ConfigMap cannot be patched or deleted.
- An existing test Fence ConfigMap cannot be deleted.
- The exact Authority Namespace cannot be updated or deleted.
- **Each admission denial must name the expected ValidatingAdmissionPolicy**; generic RBAC `Forbidden`, timeouts and unknown API errors are **not** counted as policy conformance.
- Two test ServiceAccount identities (executor and observer) cannot create, update, patch or delete ConfigMaps according to `kubectl auth can-i`. These RBAC checks are separate from admission.
- Namespace, Fence and record Kubernetes UIDs remain identical to their pre-test values, record data remains unchanged, and the attempted new ConfigMap does not exist.

The harness prints an explicit PASS line for each negative check but is not considered successful unless the process exits zero. Capture the Kind Kubernetes version and complete stdout/stderr as external evidence; the script does not automatically upload artifacts or write to Jira.

## Threat-model limitations

- Test-only records are **not valid production Authority Fence or Desired State records**. They do not establish independent identity, trusted `ABSENT`, authorized CAS acceptance, history retention, signed Policy, or executor single-use grants.
- A valid deny-all policy stops **every** ConfigMap mutation in the authority namespace, including legitimate provisioning or maintenance. This candidate must never be promoted as an active writable Authority profile.
- The test uses a local cluster-admin client to demonstrate admission denials, but does **not** show that privileged principals cannot remove or modify the admission rules themselves. A malicious cluster-admin or API-server owner remains outside the demonstrated boundary.
- The RBAC checks use impersonation and require the fresh Kind admin's ability to perform `impersonate` SubjectAccessReview checks; any impersonation failure yields test failure, not success.
- No admission-service outage, control-plane partition, policy-removal attack, namespace reincarnation/ABA across deleted resources, disaster recovery, namespace ownership controls, or server-side transactional CAS is covered.
- Real Kubernetes may behave differently across supported versions, particularly admission matching during namespace teardown. This is why the test runs on an actual disposable API server and checks the returned policy identity instead of trusting YAML syntax alone.
- Tests must not be invoked implicitly by default CI or `ok up`. The existing `go test` suite checks only harness source-level guardrails, not real Kind results.

## Next gates

1. Run the manual Kind test on a reviewed Kubernetes version and retain logs. If any denial unexpectedly succeeds or returns a different error, investigate before expanding scope.
2. Test privileged removal/reinstallation and namespace deletion/recreation in a separate disposable, independently secured environment without making production trust claims.
3. Design and prove a narrow, independently verified **policy-authorized, server-side fenced CAS writer**, retained acceptance evidence and secure bootstrap/adoption.
4. Keep ADR-034-SP-001 Proposed and the desired-state Authority disconnected until independent live conformance.

**No changes:** production clusters, CLI lifecycle, OK-147 Executor, M2b provision/destroy, operational installation.
