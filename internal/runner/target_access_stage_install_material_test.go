package runner

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPrepareTargetAccessStageInstallationRecoversExactObjects(t *testing.T) {
	stage, _, _, _ := targetAccessStageLaunchFixture(t)
	plan, objects, err := prepareTargetAccessStageInstallation(stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || len(plan.Creates) != 3 {
		t.Fatalf("unexpected target-access installation material count: %d %d", len(objects), len(plan.Creates))
	}
	for index, object := range objects {
		if object.plan != plan.Creates[index] || digest.SHA256(object.raw) != plan.Creates[index].ObjectDigest {
			t.Fatalf("target-access installation object %d differs", index)
		}
	}
	objects[0].raw[0] = 'x'
	_, again, err := prepareTargetAccessStageInstallation(stage)
	if err != nil || again[0].raw[0] == 'x' {
		t.Fatal("caller mutated retained target-access installation material")
	}
}

func TestPrepareTargetAccessStageCredentialInstallationRecoversTwoSecrets(t *testing.T) {
	_, credentials, _, tokens := targetAccessStageLaunchFixture(t)
	receipt, objects, err := prepareTargetAccessStageCredentialInstallation(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 || len(receipt.Credentials) != 2 {
		t.Fatalf("unexpected target-access credential count: %d %d", len(objects), len(receipt.Credentials))
	}
	for index, object := range objects {
		if object.order != index+4 || object.role != receipt.Credentials[index].Role || object.authority != receipt.Credentials[index].Authority || object.name != receipt.Credentials[index].Name || object.objectDigest != receipt.Credentials[index].ObjectDigest || digest.SHA256(object.raw) != object.objectDigest || string(object.token) != string(tokens[index]) {
			t.Fatalf("target-access credential installation object %d differs: %#v", index, object)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		_, hasBinding := secret["data"].(map[string]any)["binding.json"]
		if hasBinding != (index == 1) {
			t.Fatalf("target-access credential %d binding presence differs", index)
		}
	}
	objects[1].raw[0] = 'x'
	_, again, err := prepareTargetAccessStageCredentialInstallation(credentials)
	if err != nil || again[1].raw[0] == 'x' {
		t.Fatal("caller mutated retained private target-access credentials")
	}
}

func TestPrepareTargetAccessStageCredentialInstallationRejectsChangedBinding(t *testing.T) {
	_, credentials, _, _ := targetAccessStageLaunchFixture(t)
	var secret map[string]any
	if err := json.Unmarshal(credentials.objects[1].raw, &secret); err != nil {
		t.Fatal(err)
	}
	data := secret["data"].(map[string]any)
	bindingRaw, err := base64.StdEncoding.DecodeString(data["binding.json"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var binding WorkloadAuthorityBinding
	if err := json.Unmarshal(bindingRaw, &binding); err != nil {
		t.Fatal(err)
	}
	binding.Endpoint = "https://192.0.2.99:6443"
	changed, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	data["binding.json"] = base64.StdEncoding.EncodeToString(changed)
	credentials.objects[1].raw, err = json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	credentials.receipt.Credentials[1].ObjectDigest = digest.SHA256(credentials.objects[1].raw)
	if _, _, err := prepareTargetAccessStageCredentialInstallation(credentials); err == nil {
		t.Fatal("changed private workload binding was accepted")
	}
}
