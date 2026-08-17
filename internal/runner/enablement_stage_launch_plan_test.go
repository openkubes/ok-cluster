package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanEnablementStageLaunchBindsSixObjectsBehindOneBarrier(t *testing.T) {
	stage, credentials, runtime, ledgerToken, writerToken := enablementStageLaunchFixture(t)
	plan, err := PlanEnablementStageLaunch(stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := stage.Receipt()
	credentialReceipt, _ := credentials.Receipt()
	runtimeReceipt, _ := runtime.Receipt()
	if plan.Format != EnablementStageLaunchPlanFormat || plan.State != "VERIFIED" || plan.StageID != "enablement" || plan.Authority != "ok-mgmt" || plan.EnablementPackageDigest != stageReceipt.PackageDigest || plan.CredentialPackageDigest != credentialReceipt.PackageDigest || plan.RuntimeManifestDigest != runtimeReceipt.ManifestDigest || plan.PreflightBarrier != "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT" || plan.MutationAllowed {
		t.Fatalf("unexpected enablement launch identity: %#v", plan)
	}
	wantKinds := []string{"ServiceAccount", "ConfigMap", "NetworkPolicy", "Secret", "Secret", "Job"}
	wantPhases := []string{"runtime", "stage-prerequisites", "stage-prerequisites", "credentials", "credentials", "job"}
	if len(plan.Preflights) != len(wantKinds) || len(plan.Creates) != len(wantKinds) {
		t.Fatalf("unexpected enablement launch object count: %d %d", len(plan.Preflights), len(plan.Creates))
	}
	for index := range wantKinds {
		preflight, create := plan.Preflights[index], plan.Creates[index]
		if preflight.Order != index+1 || create.Order != index+1 || preflight.Phase != wantPhases[index] || create.Phase != wantPhases[index] || preflight.Kind != wantKinds[index] || create.Kind != wantKinds[index] || preflight.Name != create.Name || preflight.Namespace != create.Namespace || preflight.ObjectDigest != create.ObjectDigest || preflight.Method != "GET" || create.Method != "POST" || preflight.ResponseMode != "FULL_OBJECT" {
			t.Fatalf("enablement launch step %d differs: %#v %#v", index+1, preflight, create)
		}
		if index == 0 {
			if preflight.ExistingPolicy != "VERIFY_EXACT" || create.CreatePolicy != "CREATE_IF_ABSENT_OR_VERIFY_EXISTING" {
				t.Fatalf("runtime policy differs: %#v %#v", preflight, create)
			}
		} else if preflight.ExistingPolicy != "VERIFY_EXACT_GLOBAL_STATE" || create.CreatePolicy != "CREATE_ONLY_AFTER_GLOBAL_ABSENCE" {
			t.Fatalf("global policy differs at %d: %#v %#v", index+1, preflight, create)
		}
	}
	public, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{ledgerToken, writerToken, credentials.objects[0].raw, credentials.objects[1].raw, runtime.raw, stage.raw} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("enablement launch plan exposed private object content")
		}
	}
}

func TestPlanEnablementStageLaunchRejectsMismatchedComponents(t *testing.T) {
	stage, credentials, runtime, _, _ := enablementStageLaunchFixture(t)
	tests := map[string]func() (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite){
		"empty stage": func() (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite) {
			return VerifiedEnablementStagePackage{}, credentials, runtime
		},
		"empty credentials": func() (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite) {
			return stage, VerifiedEnablementStageCredentialPackage{}, runtime
		},
		"empty runtime": func() (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite) {
			return stage, credentials, VerifiedEnablementStageRuntimePrerequisite{}
		},
		"foreign credential package": func() (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite) {
			changed := credentials
			changed.receipt.EnablementPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, changed, runtime
		},
		"foreign runtime package": func() (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite) {
			changed := runtime
			changed.receipt.EnablementPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, credentials, changed
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			candidateStage, candidateCredentials, candidateRuntime := values()
			if _, err := PlanEnablementStageLaunch(candidateStage, candidateCredentials, candidateRuntime); err == nil {
				t.Fatal("mismatched enablement launch components accepted")
			}
		})
	}
}

func enablementStageLaunchFixture(t *testing.T) (VerifiedEnablementStagePackage, VerifiedEnablementStageCredentialPackage, VerifiedEnablementStageRuntimePrerequisite, []byte, []byte) {
	t.Helper()
	credentialConfig, ledgerToken, writerToken := enablementCredentialConfig(t)
	stage := credentialConfig.Package
	credentials, err := BuildEnablementStageCredentialPackage(credentialConfig)
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildEnablementStageRuntimePrerequisite(stage, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return stage, credentials, runtime, ledgerToken, writerToken
}
