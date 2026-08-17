package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanTargetAccessStageLaunchBindsSixObjectsBehindOneBarrier(t *testing.T) {
	stage, credentials, runtime, tokens := targetAccessStageLaunchFixture(t)
	plan, err := PlanTargetAccessStageLaunch(stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := stage.Receipt()
	credentialReceipt, _ := credentials.Receipt()
	runtimeReceipt, _ := runtime.Receipt()
	if plan.Format != TargetAccessStageLaunchPlanFormat || plan.State != "VERIFIED" || plan.StageID != "target-access" || plan.Authority != "ok-shared" || plan.TargetAccessPackageDigest != stageReceipt.PackageDigest || plan.CredentialPackageDigest != credentialReceipt.PackageDigest || plan.RuntimeManifestDigest != runtimeReceipt.ManifestDigest || plan.PreflightBarrier != "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT" || plan.MutationAllowed {
		t.Fatalf("unexpected target-access launch identity: %#v", plan)
	}
	wantKinds := []string{"ServiceAccount", "ConfigMap", "NetworkPolicy", "Secret", "Secret", "Job"}
	wantPhases := []string{"runtime", "stage-prerequisites", "stage-prerequisites", "credentials", "credentials", "job"}
	if len(plan.Preflights) != len(wantKinds) || len(plan.Creates) != len(wantKinds) {
		t.Fatalf("unexpected target-access launch object count: %d %d", len(plan.Preflights), len(plan.Creates))
	}
	for index := range wantKinds {
		preflight, create := plan.Preflights[index], plan.Creates[index]
		if preflight.Order != index+1 || create.Order != index+1 || preflight.Phase != wantPhases[index] || create.Phase != wantPhases[index] || preflight.Kind != wantKinds[index] || create.Kind != wantKinds[index] || preflight.Name != create.Name || preflight.Namespace != create.Namespace || preflight.ObjectDigest != create.ObjectDigest || preflight.Method != "GET" || create.Method != "POST" || preflight.ResponseMode != "FULL_OBJECT" {
			t.Fatalf("target-access launch step %d differs: %#v %#v", index+1, preflight, create)
		}
		if index == 0 {
			if preflight.ExistingPolicy != "VERIFY_EXACT" || create.CreatePolicy != "CREATE_IF_ABSENT_OR_VERIFY_EXISTING" {
				t.Fatalf("runtime policy differs: %#v %#v", preflight, create)
			}
		} else if preflight.ExistingPolicy != "VERIFY_EXACT_GLOBAL_STATE" || create.CreatePolicy != "CREATE_ONLY_AFTER_GLOBAL_ABSENCE" {
			t.Fatalf("global policy differs at %d: %#v %#v", index+1, preflight, create)
		}
	}
	if plan.Creates[5].Kind != "Job" {
		t.Fatal("target-access Job was not held behind both credentials")
	}
	public, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{tokens[0], tokens[1], credentials.objects[0].raw, credentials.objects[1].raw, runtime.raw, stage.raw} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("target-access launch plan exposed private object content")
		}
	}
}

func TestPlanTargetAccessStageLaunchRejectsMismatchedComponents(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	tests := map[string]func() (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite){
		"empty stage": func() (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite) {
			return VerifiedTargetAccessStagePackage{}, credentials, runtime
		},
		"empty credentials": func() (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite) {
			return stage, VerifiedTargetAccessStageCredentialPackage{}, runtime
		},
		"empty runtime": func() (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite) {
			return stage, credentials, VerifiedTargetAccessStageRuntimePrerequisite{}
		},
		"foreign credential package": func() (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite) {
			changed := credentials
			changed.receipt.TargetAccessPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, changed, runtime
		},
		"foreign runtime package": func() (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite) {
			changed := runtime
			changed.receipt.TargetAccessPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, credentials, changed
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			candidateStage, candidateCredentials, candidateRuntime := values()
			if _, err := PlanTargetAccessStageLaunch(candidateStage, candidateCredentials, candidateRuntime); err == nil {
				t.Fatal("mismatched target-access launch components accepted")
			}
		})
	}
}

func targetAccessStageLaunchFixture(t *testing.T) (VerifiedTargetAccessStagePackage, VerifiedTargetAccessStageCredentialPackage, VerifiedTargetAccessStageRuntimePrerequisite, [][]byte) {
	t.Helper()
	credentialConfig, tokens := targetAccessCredentialConfig(t)
	stage := credentialConfig.Package
	credentials, err := BuildTargetAccessStageCredentialPackage(credentialConfig)
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildTargetAccessStageRuntimePrerequisite(stage, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return stage, credentials, runtime, tokens
}
