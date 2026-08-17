package runner

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildTargetAccessStageInputCapturesOnlyPublicBoundArtifacts(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	input, err := BuildTargetAccessStageInput(fixture.config, "ok147-target-access-input")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := input.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := input.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != TargetAccessStageInputFormat || receipt.State != "VERIFIED" || receipt.StageID != "target-access" || receipt.ConfigMapDigest != digest.SHA256(raw) || receipt.TargetAccessDigest != digest.SHA256(runnerTargetAccessYAML()) || receipt.TargetIdentityDigest != digest.SHA256([]byte(targetAccessRuntimeUID)) || len(receipt.DataKeys) != 11 {
		t.Fatalf("unexpected target-access input receipt: %#v", receipt)
	}
	var object submissionStageInputConfigMap
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if !object.Immutable || object.Metadata.Namespace != submissionStageInputNamespace || object.Metadata.Labels["openkubes.io/stage-id"] != "target-access" || object.Metadata.Annotations["openkubes.io/target-identity-digest"] != receipt.TargetIdentityDigest || len(object.Data) != 11 {
		t.Fatalf("unexpected target-access ConfigMap: %#v", object)
	}
	for _, forbidden := range []string{"token", "ca.crt", "kubeconfig", "workload-binding.json", "runtime-binding-private.json"} {
		if _, exists := object.Data[forbidden]; exists {
			t.Fatalf("private target-access input %q was packaged", forbidden)
		}
	}
	if _, exists := object.Data["runtime-binding-receipt.json"]; !exists {
		t.Fatal("public runtime-binding receipt is absent")
	}

	raw[0] = 'x'
	again, err := input.Bytes()
	if err != nil || again[0] != '{' {
		t.Fatal("caller mutated retained target-access input")
	}
	receipt.DataKeys[0] = "changed"
	againReceipt, err := input.Receipt()
	if err != nil || againReceipt.DataKeys[0] == "changed" {
		t.Fatal("caller mutated retained target-access receipt")
	}
}

func TestBuildTargetAccessStageInputFailsClosed(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	if _, err := BuildTargetAccessStageInput(fixture.config, "not-ok147"); err == nil {
		t.Fatal("foreign ConfigMap name was accepted")
	}
	fixture = targetAccessBundleFixture(t)
	fixture.config.Receipts = fixture.config.Receipts[:5]
	if _, err := BuildTargetAccessStageInput(fixture.config, "ok147-target-access-input"); err == nil {
		t.Fatal("incomplete receipt prefix was accepted")
	}
	fixture = targetAccessBundleFixture(t)
	if err := os.WriteFile(fixture.config.ArtifactPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildTargetAccessStageInput(fixture.config, "ok147-target-access-input"); err == nil {
		t.Fatal("changed target-access artifact was accepted")
	}
	if _, err := (VerifiedTargetAccessStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified target-access input exposed bytes")
	}
	if _, err := (VerifiedTargetAccessStageInput{}).Receipt(); err == nil {
		t.Fatal("unverified target-access input exposed receipt")
	}
}
