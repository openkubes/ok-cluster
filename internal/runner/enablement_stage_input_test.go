package runner

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildEnablementStageInputCapturesOnlyPublicBoundArtifacts(t *testing.T) {
	fixture := enablementBundleFixture(t)
	input, err := BuildEnablementStageInput(fixture.config, "ok147-enablement-input")
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
	if receipt.Format != EnablementStageInputFormat || receipt.State != "VERIFIED" || receipt.StageID != "enablement" || receipt.ConfigMapDigest != digest.SHA256(raw) || receipt.EnablementDigest == "" || len(receipt.DataKeys) != 8 {
		t.Fatalf("unexpected enablement input receipt: %#v", receipt)
	}
	var object submissionStageInputConfigMap
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if !object.Immutable || object.Metadata.Namespace != submissionStageInputNamespace || object.Metadata.Labels["openkubes.io/stage-id"] != "enablement" || len(object.Data) != 8 {
		t.Fatalf("unexpected enablement ConfigMap: %#v", object)
	}
	for _, forbidden := range []string{"token", "ca.crt", "kubeconfig", "projection-manifest.json", "authority-map.json", "ok-mgmt-lifecycle.yaml"} {
		if _, exists := object.Data[forbidden]; exists {
			t.Fatalf("private or foreign input %q was packaged", forbidden)
		}
	}
}

func TestBuildEnablementStageInputFailsClosed(t *testing.T) {
	fixture := enablementBundleFixture(t)
	if _, err := BuildEnablementStageInput(fixture.config, "not-ok147"); err == nil {
		t.Fatal("foreign ConfigMap name was accepted")
	}
	fixture = enablementBundleFixture(t)
	fixture.config.Receipts = fixture.config.Receipts[:2]
	if _, err := BuildEnablementStageInput(fixture.config, "ok147-enablement-input"); err == nil {
		t.Fatal("incomplete receipt prefix was accepted")
	}
	fixture = enablementBundleFixture(t)
	if err := os.WriteFile(fixture.config.ArtifactPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildEnablementStageInput(fixture.config, "ok147-enablement-input"); err == nil {
		t.Fatal("changed HCP input was accepted")
	}
	if _, err := (VerifiedEnablementStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified enablement input exposed bytes")
	}
}
