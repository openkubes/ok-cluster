package runner

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPrepareNetworkObservationStageInstallationRecoversExactObjects(t *testing.T) {
	stage, _, _, _ := networkObservationStageLaunchFixture(t)
	plan, objects, err := prepareNetworkObservationStageInstallation(stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || len(plan.Creates) != 3 {
		t.Fatalf("unexpected network installation material count: %d %d", len(objects), len(plan.Creates))
	}
	for index, object := range objects {
		if object.plan != plan.Creates[index] || digest.SHA256(object.raw) != plan.Creates[index].ObjectDigest {
			t.Fatalf("network installation object %d differs", index)
		}
	}
	objects[0].raw[0] = 'x'
	_, again, err := prepareNetworkObservationStageInstallation(stage)
	if err != nil || again[0].raw[0] == 'x' {
		t.Fatal("caller mutated retained network installation material")
	}
}

func TestPrepareNetworkObservationStageCredentialInstallationRecoversThreeSecrets(t *testing.T) {
	_, credentials, _, tokens := networkObservationStageLaunchFixture(t)
	receipt, objects, err := prepareNetworkObservationStageCredentialInstallation(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || len(receipt.Credentials) != 3 {
		t.Fatalf("unexpected network credential material count: %d %d", len(objects), len(receipt.Credentials))
	}
	for index, object := range objects {
		if object.order != index+4 || object.role != receipt.Credentials[index].Role || object.authority != receipt.Credentials[index].Authority || object.name != receipt.Credentials[index].Name || object.objectDigest != receipt.Credentials[index].ObjectDigest || digest.SHA256(object.raw) != object.objectDigest || string(object.token) != string(tokens[index]) {
			t.Fatalf("network credential installation object %d differs: %#v", index, object)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		data := secret["data"].(map[string]any)
		_, hasBinding := data["binding.json"]
		if hasBinding != (index == 2) {
			t.Fatalf("network credential %d binding presence differs", index)
		}
	}
	objects[2].raw[0] = 'x'
	_, again, err := prepareNetworkObservationStageCredentialInstallation(credentials)
	if err != nil || again[2].raw[0] == 'x' {
		t.Fatal("caller mutated retained private network credentials")
	}
}

func TestPrepareNetworkObservationStageCredentialInstallationRejectsChangedBinding(t *testing.T) {
	_, credentials, _, _ := networkObservationStageLaunchFixture(t)
	var secret map[string]any
	if err := json.Unmarshal(credentials.objects[2].raw, &secret); err != nil {
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
	credentials.objects[2].raw, err = json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	credentials.receipt.Credentials[2].ObjectDigest = digest.SHA256(credentials.objects[2].raw)
	if _, _, err := prepareNetworkObservationStageCredentialInstallation(credentials); err == nil {
		t.Fatal("changed private workload binding was accepted")
	}
}
