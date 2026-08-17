package runner

import (
	"bytes"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPrepareRuntimeBindingStageInstallationRecoversExactPublicObjects(t *testing.T) {
	stage, _, _, _ := runtimeBindingStageLaunchFixture(t)
	plan, objects, err := prepareRuntimeBindingStageInstallation(stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || len(plan.Creates) != 3 {
		t.Fatalf("unexpected public object count: %d %d", len(objects), len(plan.Creates))
	}
	for index, object := range objects {
		if object.plan != plan.Creates[index] || digest.SHA256(object.raw) != plan.Creates[index].ObjectDigest {
			t.Fatalf("public install object %d differs", index)
		}
	}
}

func TestPrepareRuntimeBindingStageCredentialInstallationRecoversPrivateSecrets(t *testing.T) {
	_, credentials, _, tokens := runtimeBindingStageLaunchFixture(t)
	receipt, objects, err := prepareRuntimeBindingStageCredentialInstallation(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PackageDigest != credentials.receipt.PackageDigest || len(objects) != 3 {
		t.Fatalf("unexpected private material receipt: %#v objects=%d", receipt, len(objects))
	}
	wantRoles := []string{"ledger-writer", "persistence-writer", "workload-observer"}
	for index, object := range objects {
		if object.order != index+4 || object.role != wantRoles[index] || object.name != receipt.Credentials[index].Name || object.objectDigest != receipt.Credentials[index].ObjectDigest || digest.SHA256(object.raw) != object.objectDigest || !bytes.Equal(object.token, tokens[index]) {
			t.Fatalf("private install object %d differs: %#v", index, object)
		}
	}
}

func TestPrepareRuntimeBindingStageInstallMaterialFailsClosedOnTamper(t *testing.T) {
	stage, credentials, _, _ := runtimeBindingStageLaunchFixture(t)
	stage.raw = append(stage.raw, '\n')
	if _, _, err := prepareRuntimeBindingStageInstallation(stage); err == nil {
		t.Fatal("changed public material was recovered")
	}
	credentials.objects[1].raw = append(credentials.objects[1].raw, '\n')
	if _, _, err := prepareRuntimeBindingStageCredentialInstallation(credentials); err == nil {
		t.Fatal("changed private material was recovered")
	}
}
