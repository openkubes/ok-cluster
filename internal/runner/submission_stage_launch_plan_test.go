package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanSubmissionStageLaunchBindsSixObjectsBehindOneBarrier(t *testing.T) {
	stage, credentials, runtime, ledgerToken, authorityToken := submissionStageLaunchFixture(t)
	plan, err := PlanSubmissionStageLaunch(stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, err := stage.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	credentialReceipt, err := credentials.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	runtimeReceipt, err := runtime.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != SubmissionStageLaunchPlanFormat || plan.State != "VERIFIED" || plan.StageID != stageReceipt.StageID || plan.Authority != "ok-mgmt" || plan.StagePackageDigest != stageReceipt.PackageDigest || plan.CredentialPackageDigest != credentialReceipt.PackageDigest || plan.RuntimeManifestDigest != runtimeReceipt.ManifestDigest || plan.PreflightBarrier != "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT" || plan.MutationAllowed {
		t.Fatalf("unexpected launch identity: %#v", plan)
	}
	if len(plan.Preflights) != 6 || len(plan.Creates) != 6 {
		t.Fatalf("launch object count differs: preflights=%d creates=%d", len(plan.Preflights), len(plan.Creates))
	}
	wantKinds := []string{"ServiceAccount", "Secret", "Secret", "ConfigMap", "NetworkPolicy", "Job"}
	wantPhases := []string{"runtime", "credentials", "credentials", "stage-package", "stage-package", "stage-package"}
	for index := range wantKinds {
		preflight, create := plan.Preflights[index], plan.Creates[index]
		if preflight.Order != index+1 || create.Order != index+1 || preflight.Phase != wantPhases[index] || create.Phase != wantPhases[index] || preflight.Kind != wantKinds[index] || create.Kind != wantKinds[index] || preflight.Name != create.Name || preflight.Namespace != create.Namespace || preflight.ObjectDigest != create.ObjectDigest || preflight.Method != "GET" || create.Method != "POST" {
			t.Fatalf("launch step %d differs: preflight=%#v create=%#v", index+1, preflight, create)
		}
		if index == 0 {
			if preflight.ResponseMode != "FULL_OBJECT" || preflight.ExistingPolicy != "VERIFY_EXACT" || create.CreatePolicy != "CREATE_IF_ABSENT_OR_VERIFY_EXISTING" {
				t.Fatalf("runtime policy differs: %#v %#v", preflight, create)
			}
			continue
		}
		if preflight.ExistingPolicy != "VERIFY_EXACT_GLOBAL_STATE" || create.CreatePolicy != "CREATE_ONLY_AFTER_GLOBAL_ABSENCE" {
			t.Fatalf("idempotent global policy differs at step %d: %#v %#v", index+1, preflight, create)
		}
		if preflight.ResponseMode != "FULL_OBJECT" {
			t.Fatalf("stage object preflight mode differs: %#v", preflight)
		}
	}
	public, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{ledgerToken, authorityToken, credentials.objects[0].raw, credentials.objects[1].raw, runtime.raw, stage.raw} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("launch plan exposed private object or credential content")
		}
	}
}

func TestPlanSubmissionStageLaunchRejectsUnverifiedOrMismatchedComponents(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	tests := map[string]func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite){
		"empty stage": func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite) {
			return VerifiedSubmissionStagePackage{}, credentials, runtime
		},
		"empty credentials": func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite) {
			return stage, VerifiedSubmissionStageCredentialPackage{}, runtime
		},
		"empty runtime": func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite) {
			return stage, credentials, VerifiedSubmissionStageRuntimePrerequisite{}
		},
		"changed credential package identity": func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite) {
			changed := credentials
			changed.receipt.StagePackageDigest = digest.SHA256([]byte("foreign-stage"))
			return stage, changed, runtime
		},
		"changed runtime stage identity": func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite) {
			changed := runtime
			changed.receipt.StagePackageDigest = digest.SHA256([]byte("foreign-stage"))
			return stage, credentials, changed
		},
		"changed runtime object": func() (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite) {
			changed := runtime
			changed.raw = append([]byte(nil), runtime.raw...)
			changed.raw[0] = 'x'
			return stage, credentials, changed
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			candidateStage, candidateCredentials, candidateRuntime := values()
			if _, err := PlanSubmissionStageLaunch(candidateStage, candidateCredentials, candidateRuntime); err == nil {
				t.Fatal("invalid launch components were accepted")
			}
		})
	}
}

func submissionStageLaunchFixture(t *testing.T) (VerifiedSubmissionStagePackage, VerifiedSubmissionStageCredentialPackage, VerifiedSubmissionStageRuntimePrerequisite, []byte, []byte) {
	t.Helper()
	config, ledgerToken, authorityToken := submissionStageCredentialConfig(t)
	stage := config.Package
	credentials, err := BuildSubmissionStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildSubmissionStageRuntimePrerequisite(stage, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return stage, credentials, runtime, ledgerToken, authorityToken
}
