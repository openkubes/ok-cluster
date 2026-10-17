package runner

import (
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestFullRunExecutionFixtureVerificationIsReadOnlyAndExact(t *testing.T) {
	raw := []byte("opaque caller-owned fixture")
	manifest := VerifiedFullRunExecutionManifest{verified: true, receipt: FullRunExecutionManifestReceipt{State: "VERIFIED"}, plan: stageplan.Binding{ExecutionFixture: digest.SHA256(raw)}}
	if err := manifest.VerifyExecutionFixture(raw); err != nil {
		t.Fatal(err)
	}
	if err := manifest.VerifyExecutionFixture(append(raw, '\n')); err == nil {
		t.Fatal("changed fixture accepted")
	}
	if err := (VerifiedFullRunExecutionManifest{}).VerifyExecutionFixture(raw); err == nil {
		t.Fatal("unverified manifest accepted")
	}
}
