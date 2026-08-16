package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanLifecycleObservationStageLaunchBindsSixObjectsBehindOneBarrier(t *testing.T) {
	stage, credentials, runtime, ledgerToken, observerToken := lifecycleObservationStageLaunchFixture(t)
	plan, err := PlanLifecycleObservationStageLaunch(stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := stage.Receipt()
	credentialReceipt, _ := credentials.Receipt()
	runtimeReceipt, _ := runtime.Receipt()
	if plan.Format != LifecycleObservationStageLaunchPlanFormat || plan.State != "VERIFIED" || plan.StageID != "lifecycle-observation" || plan.Authority != "ok-mgmt" || plan.ObservationPackageDigest != stageReceipt.PackageDigest || plan.CredentialPackageDigest != credentialReceipt.PackageDigest || plan.RuntimeManifestDigest != runtimeReceipt.ManifestDigest || plan.PreflightBarrier != "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT" || plan.MutationAllowed {
		t.Fatalf("unexpected lifecycle observation launch identity: %#v", plan)
	}
	wantKinds := []string{"ServiceAccount", "ConfigMap", "NetworkPolicy", "Secret", "Secret", "Job"}
	wantPhases := []string{"runtime", "stage-prerequisites", "stage-prerequisites", "credentials", "credentials", "job"}
	if len(plan.Preflights) != len(wantKinds) || len(plan.Creates) != len(wantKinds) {
		t.Fatalf("unexpected launch object count: %d %d", len(plan.Preflights), len(plan.Creates))
	}
	for index := range wantKinds {
		preflight, create := plan.Preflights[index], plan.Creates[index]
		if preflight.Order != index+1 || create.Order != index+1 || preflight.Phase != wantPhases[index] || create.Phase != wantPhases[index] || preflight.Kind != wantKinds[index] || create.Kind != wantKinds[index] || preflight.Name != create.Name || preflight.Namespace != create.Namespace || preflight.ObjectDigest != create.ObjectDigest || preflight.Method != "GET" || create.Method != "POST" || preflight.ResponseMode != "FULL_OBJECT" {
			t.Fatalf("lifecycle observation launch step %d differs: %#v %#v", index+1, preflight, create)
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
	for _, forbidden := range [][]byte{ledgerToken, observerToken, credentials.objects[0].raw, credentials.objects[1].raw, runtime.raw, stage.raw} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("lifecycle observation launch plan exposed private object content")
		}
	}
}

func TestPlanLifecycleObservationStageLaunchRejectsMismatchedComponents(t *testing.T) {
	stage, credentials, runtime, _, _ := lifecycleObservationStageLaunchFixture(t)
	tests := map[string]func() (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite){
		"empty stage": func() (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite) {
			return VerifiedLifecycleObservationStagePackage{}, credentials, runtime
		},
		"empty credentials": func() (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite) {
			return stage, VerifiedLifecycleObservationStageCredentialPackage{}, runtime
		},
		"empty runtime": func() (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite) {
			return stage, credentials, VerifiedLifecycleObservationStageRuntimePrerequisite{}
		},
		"foreign credential package": func() (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite) {
			changed := credentials
			changed.receipt.ObservationPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, changed, runtime
		},
		"foreign runtime package": func() (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite) {
			changed := runtime
			changed.receipt.ObservationPackageDigest = digest.SHA256([]byte("foreign"))
			return stage, credentials, changed
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			candidateStage, candidateCredentials, candidateRuntime := values()
			if _, err := PlanLifecycleObservationStageLaunch(candidateStage, candidateCredentials, candidateRuntime); err == nil {
				t.Fatal("mismatched lifecycle observation launch components accepted")
			}
		})
	}
}

func lifecycleObservationStageLaunchFixture(t *testing.T) (VerifiedLifecycleObservationStagePackage, VerifiedLifecycleObservationStageCredentialPackage, VerifiedLifecycleObservationStageRuntimePrerequisite, []byte, []byte) {
	t.Helper()
	credentialConfig, ledgerToken, observerToken := lifecycleObservationCredentialConfig(t)
	stage := credentialConfig.Package
	credentials, err := BuildLifecycleObservationStageCredentialPackage(credentialConfig)
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildLifecycleObservationStageRuntimePrerequisite(stage, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return stage, credentials, runtime, ledgerToken, observerToken
}
