package main

// clusterProvisionReviewedNonLifecycleRev freezes the exact reviewed set of
// files added after M2a that are NOT provisioner's Make/lifecycle sources.
// This is an immutable full Git object ID, not HEAD or a moving branch.
// Every permitted path is enumerated; no prefix, directory or glob allowlist.
const clusterProvisionReviewedNonLifecycleRev = "6e9dff0619d9a076fd59c199cf349f2943152c67"

var clusterProvisionReviewedNonLifecyclePaths = []string{
	"deploy/ok226-authority-freeze-candidate.yaml",
	"docs/ok148-operator-up-v1-release-candidate.md",
	"docs/ok226-authority-domain-fence-phase2.md",
	"docs/ok226-authority-domain-hardening-phase1.md",
	"docs/ok226-desired-authority-cas-contract.md",
	"docs/ok226-kind-admission-conformance.md",
	"docs/ok226-kubernetes-cas-adapter.md",
	"docs/ok226-kubernetes-claim-store-candidate.md",
	"docs/ok226-pinned-kubernetes-domain-reader.md",
	"docs/ok226-shortest-path-operator-mvp.md",
	"docs/ok226-signed-authorization-preflight.md",
	"docs/ok226-single-use-claim-contract.md",
	"docs/ok226-writer-isolation-phase3-freeze.md",
	"internal/desiredauthority/admission_freeze_test.go",
	"internal/desiredauthority/admission_kind_harness_test.go",
	"internal/desiredauthority/authorization_preflight.go",
	"internal/desiredauthority/authorization_preflight_test.go",
	"internal/desiredauthority/contract.go",
	"internal/desiredauthority/contract_test.go",
	"internal/desiredauthority/domain_fence.go",
	"internal/desiredauthority/domain_fence_test.go",
	"internal/desiredauthority/kubernetes_claim_store.go",
	"internal/desiredauthority/kubernetes_claim_store_test.go",
	"internal/desiredauthority/kubernetes_domain_reader.go",
	"internal/desiredauthority/kubernetes_domain_reader_test.go",
	"internal/desiredauthority/kubernetes_store.go",
	"internal/desiredauthority/kubernetes_store_test.go",
	"internal/desiredauthority/single_use_claim.go",
	"internal/desiredauthority/single_use_claim_test.go",
	"scripts/ok226-admission-conformance-kind.sh",
}
