package runner

import (
	"os"
	"testing"
)

func TestVerifyIndependentEvidencePublicKeyPreservesReviewedIdentity(t *testing.T) {
	path, _ := fullRunEvidencePublicKeyFixture(t, t.TempDir())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := fullRunBundleEvidenceKeyID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIndependentEvidencePublicKey(path, id); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIndependentEvidencePublicKey(path, "foreign"); err == nil {
		t.Fatal("foreign key accepted")
	}
	if err := os.WriteFile(path, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIndependentEvidencePublicKey(path, id); err == nil {
		t.Fatal("changed key accepted")
	}
}
