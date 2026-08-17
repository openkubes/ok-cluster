package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanNetworkObservationStageLaunchBindsSevenObjectsBehindOneBarrier(t *testing.T) {
	stage, credentials, runtime, tokens := networkObservationStageLaunchFixture(t)
	plan, err := PlanNetworkObservationStageLaunch(stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := stage.Receipt()
	credentialReceipt, _ := credentials.Receipt()
	runtimeReceipt, _ := runtime.Receipt()
	if plan.Format != NetworkObservationStageLaunchPlanFormat || plan.State != "VERIFIED" || plan.StageID != "network-observation" || plan.Authority != "ok-mgmt" || plan.ObservationPackageDigest != stageReceipt.PackageDigest || plan.CredentialPackageDigest != credentialReceipt.PackageDigest || plan.RuntimeManifestDigest != runtimeReceipt.ManifestDigest || plan.PreflightBarrier != "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT" || plan.MutationAllowed {
		t.Fatalf("unexpected network observation launch identity: %#v", plan)
	}
	wantKinds := []string{"ServiceAccount", "ConfigMap", "NetworkPolicy", "Secret", "Secret", "Secret", "Job"}
	wantPhases := []string{"runtime", "stage-prerequisites", "stage-prerequisites", "credentials", "credentials", "credentials", "job"}
	if len(plan.Preflights) != len(wantKinds) || len(plan.Creates) != len(wantKinds) {
		t.Fatalf("unexpected launch object count: %d %d", len(plan.Preflights), len(plan.Creates))
	}
	for index := range wantKinds {
		preflight, create := plan.Preflights[index], plan.Creates[index]
		if preflight.Order != index+1 || create.Order != index+1 || preflight.Phase != wantPhases[index] || create.Phase != wantPhases[index] || preflight.Kind != wantKinds[index] || create.Kind != wantKinds[index] || preflight.Name != create.Name || preflight.Namespace != create.Namespace || preflight.ObjectDigest != create.ObjectDigest || preflight.Method != "GET" || create.Method != "POST" || preflight.ResponseMode != "FULL_OBJECT" {
			t.Fatalf("network observation launch step %d differs: %#v %#v", index+1, preflight, create)
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
	for _, forbidden := range append(tokens, credentials.objects[0].raw, credentials.objects[1].raw, credentials.objects[2].raw, runtime.raw, stage.raw) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("network observation launch plan exposed private object content")
		}
	}
}

func TestPlanNetworkObservationStageLaunchRejectsMismatchedComponents(t *testing.T) {
	stage, credentials, runtime, _ := networkObservationStageLaunchFixture(t)
	tests := map[string]func() (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite){
		"empty stage": func() (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite) {
			return VerifiedNetworkObservationStagePackage{}, credentials, runtime
		},
		"empty credentials": func() (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite) {
			return stage, VerifiedNetworkObservationStageCredentialPackage{}, runtime
		},
		"empty runtime": func() (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite) {
			return stage, credentials, VerifiedNetworkObservationStageRuntimePrerequisite{}
		},
		"foreign credential package": func() (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite) {
			changed := credentials
			changed.receipt.ObservationPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, changed, runtime
		},
		"foreign runtime package": func() (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite) {
			changed := runtime
			changed.receipt.ObservationPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, credentials, changed
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			candidateStage, candidateCredentials, candidateRuntime := values()
			if _, err := PlanNetworkObservationStageLaunch(candidateStage, candidateCredentials, candidateRuntime); err == nil {
				t.Fatal("mismatched network observation launch components accepted")
			}
		})
	}
}

func networkObservationStageLaunchFixture(t *testing.T) (VerifiedNetworkObservationStagePackage, VerifiedNetworkObservationStageCredentialPackage, VerifiedNetworkObservationStageRuntimePrerequisite, [][]byte) {
	t.Helper()
	credentialConfig, tokens := networkObservationCredentialConfig(t)
	stage := credentialConfig.Package
	credentials, err := BuildNetworkObservationStageCredentialPackage(credentialConfig)
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildNetworkObservationStageRuntimePrerequisite(stage, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return stage, credentials, runtime, tokens
}
