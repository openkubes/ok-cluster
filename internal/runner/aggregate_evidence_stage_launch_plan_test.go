package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanAggregateEvidenceStageLaunchBindsRequiredRuntimeAndNineCreates(t *testing.T) {
	stage, credentials, privateInputs, runtime, tokens := aggregateEvidenceStageLaunchFixture(t)
	plan, err := PlanAggregateEvidenceStageLaunch(stage, credentials, privateInputs, runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := stage.Receipt()
	credentialReceipt, _ := credentials.Receipt()
	privateReceipt, _ := privateInputs.Receipt()
	runtimeReceipt, _ := runtime.Receipt()
	if plan.Format != AggregateEvidenceStageLaunchPlanFormat || plan.State != "VERIFIED" || plan.StageID != "aggregate-evidence" || plan.Authority != "ok-mgmt" || plan.EvidencePackageDigest != stageReceipt.PackageDigest || plan.CredentialPackageDigest != credentialReceipt.PackageDigest || plan.PrivateInputPackageDigest != privateReceipt.PackageDigest || plan.RuntimeManifestDigest != runtimeReceipt.ManifestDigest || plan.PreflightBarrier != "RUNTIME_BINDING_REQUIRED_THEN_ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT" || plan.MutationAllowed {
		t.Fatalf("unexpected aggregate evidence launch identity: %#v", plan)
	}
	wantKinds := []string{"ServiceAccount", "Secret", "ConfigMap", "NetworkPolicy", "Secret", "Secret", "Secret", "Secret", "Secret", "Job"}
	wantPhases := []string{"runtime", "private-runtime", "stage-prerequisites", "stage-prerequisites", "credentials", "credentials", "credentials", "credentials", "private-capability", "job"}
	if len(plan.Preflights) != 10 || len(plan.Creates) != 9 {
		t.Fatalf("unexpected aggregate launch count: %d %d", len(plan.Preflights), len(plan.Creates))
	}
	creates := map[int]SubmissionStageLaunchCreate{}
	for _, create := range plan.Creates {
		creates[create.Order] = create
	}
	for index, preflight := range plan.Preflights {
		order := index + 1
		if preflight.Order != order || preflight.Phase != wantPhases[index] || preflight.Kind != wantKinds[index] || preflight.Method != "GET" || preflight.ResponseMode != "FULL_OBJECT" {
			t.Fatalf("aggregate preflight %d differs: %#v", order, preflight)
		}
		create, exists := creates[order]
		if order == 2 {
			if exists || preflight.ExistingPolicy != "REQUIRE_EXACT_EXISTING" {
				t.Fatalf("runtime binding may not have a create path: %#v %#v", preflight, create)
			}
			continue
		}
		if !exists || create.Phase != preflight.Phase || create.Kind != preflight.Kind || create.Name != preflight.Name || create.Namespace != preflight.Namespace || create.ObjectDigest != preflight.ObjectDigest || create.Method != "POST" {
			t.Fatalf("aggregate create %d differs: %#v %#v", order, preflight, create)
		}
		if order == 1 {
			if preflight.ExistingPolicy != "VERIFY_EXACT" || create.CreatePolicy != "CREATE_IF_ABSENT_OR_VERIFY_EXISTING" {
				t.Fatalf("runtime ServiceAccount policy differs: %#v %#v", preflight, create)
			}
		} else if preflight.ExistingPolicy != "VERIFY_EXACT_GLOBAL_STATE" || create.CreatePolicy != "CREATE_ONLY_AFTER_GLOBAL_ABSENCE" {
			t.Fatalf("global create policy differs at %d: %#v %#v", order, preflight, create)
		}
	}
	public, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens, credentials.objects[0].raw, credentials.objects[1].raw, credentials.objects[2].raw, credentials.objects[3].raw, privateInputs.objects[0].raw, privateInputs.objects[1].raw, runtime.raw, stage.raw) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("aggregate evidence launch plan exposed private object content")
		}
	}
}

func TestPlanAggregateEvidenceStageLaunchRejectsMismatchedComponents(t *testing.T) {
	stage, credentials, privateInputs, runtime, _ := aggregateEvidenceStageLaunchFixture(t)
	tests := map[string]func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite){
		"empty stage": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			return VerifiedAggregateEvidenceStagePackage{}, credentials, privateInputs, runtime
		},
		"empty credentials": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			return stage, VerifiedAggregateEvidenceStageCredentialPackage{}, privateInputs, runtime
		},
		"empty private inputs": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			return stage, credentials, VerifiedAggregateEvidenceStagePrivateInputPackage{}, runtime
		},
		"empty runtime": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			return stage, credentials, privateInputs, VerifiedAggregateEvidenceStageRuntimePrerequisite{}
		},
		"foreign credential package": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			changed := credentials
			changed.receipt.StagePackageDigest = digest.SHA256([]byte("foreign"))
			return stage, changed, privateInputs, runtime
		},
		"foreign private inputs": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			changed := privateInputs
			changed.receipt.EvidencePackageDigest = digest.SHA256([]byte("foreign"))
			return stage, credentials, changed, runtime
		},
		"foreign runtime": func() (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite) {
			changed := runtime
			changed.receipt.EvidencePackageDigest = digest.SHA256([]byte("foreign"))
			return stage, credentials, privateInputs, changed
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			candidateStage, candidateCredentials, candidatePrivate, candidateRuntime := values()
			if _, err := PlanAggregateEvidenceStageLaunch(candidateStage, candidateCredentials, candidatePrivate, candidateRuntime); err == nil {
				t.Fatal("mismatched aggregate evidence launch components accepted")
			}
		})
	}
}

func aggregateEvidenceStageLaunchFixture(t *testing.T) (VerifiedAggregateEvidenceStagePackage, VerifiedAggregateEvidenceStageCredentialPackage, VerifiedAggregateEvidenceStagePrivateInputPackage, VerifiedAggregateEvidenceStageRuntimePrerequisite, [][]byte) {
	t.Helper()
	credentialConfig, tokens := aggregateEvidenceCredentialConfig(t)
	stage := credentialConfig.Package
	credentials, err := BuildAggregateEvidenceStageCredentialPackage(credentialConfig)
	if err != nil {
		t.Fatal(err)
	}
	privateInputs, err := BuildAggregateEvidenceStagePrivateInputPackage(stage)
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildAggregateEvidenceStageRuntimePrerequisite(stage, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return stage, credentials, privateInputs, runtime, tokens
}
