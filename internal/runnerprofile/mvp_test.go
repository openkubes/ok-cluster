package runnerprofile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const e = "sha256:2a849d69e9c64344e907c1bce3bb1abf3d8f77217377081a5be055d62c213300"
const p = "sha256:2956184005f4860607e91672fce82164095dee6ebcbe57e5af883951a199c427"

func recipeRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../profiles/cli/talos-kubevirt-mvp-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMVPRecipePreservesReviewedBaselineWithoutHistoricalIdentity(t *testing.T) {
	raw := recipeRaw(t)
	if digest.SHA256(raw) != "sha256:b070e6d9d790156b4605209c0159710271c9098f13cb3a98ac3f78c9299f51e7" {
		t.Fatal("review recipe and update the reviewed baseline digest explicitly")
	}
	for _, forbidden := range []string{"ok-cli-mvp-3", "candidate-status", "resourceVersion", "execution-fixture", "intent-revision", "PRIVATE KEY", "kubeconfig", "tokenFile"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("historical/private source carrier in recipe: %s", forbidden)
		}
	}
	recipe, err := Load(raw, TalosMVP, e, p)
	if err != nil {
		t.Fatal(err)
	}
	id := contract.Identity{Name: "fresh-cluster", Namespace: "fresh-cluster"}
	r, f := digest.SHA256([]byte("fresh-contract")), digest.SHA256([]byte("fresh-fixture"))
	first, err := recipe.Render(id, r, f)
	if err != nil {
		t.Fatal(err)
	}
	again, err := recipe.Render(id, r, f)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, raw := range first.Files {
		if !bytes.Equal(raw, again.Files[name]) {
			t.Fatal("same recipe/identity changed rendered bytes")
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(first.TargetAccessObjects) != 16 {
		t.Fatal("target authority inventory changed")
	}
	if _, err := submission.LoadEnablement(filepath.Join(root, "enablement.yaml"), submission.EnablementExpected{
		ArtifactDigest: digest.SHA256(first.Files["enablement.yaml"]), ContractIdentity: id, IntentRevision: r, EnablementRevision: e, ExecutionFixture: f, ManagementAuthority: "ok-mgmt", ObjectIdentity: first.EnablementObject,
	}); err != nil {
		t.Fatal(err)
	}
	target := digest.SHA256([]byte("only-a-static-verification-placeholder"))
	if _, err := submission.LoadTargetAccess(filepath.Join(root, "target-access.yaml"), submission.TargetAccessExpected{
		ArtifactDigest: digest.SHA256(first.Files["target-access.yaml"]), ContractIdentity: id, IntentRevision: r, PlatformRevision: p, ExecutionFixture: f, TargetIdentityDigest: target, WorkloadAuthority: target, Objects: first.TargetAccessObjects,
	}); err != nil {
		t.Fatal(err)
	}
	other, err := recipe.Render(contract.Identity{Name: "other-cluster", Namespace: "other-cluster"}, r, f)
	if err != nil {
		t.Fatal(err)
	}
	if other.NetworkProfile.ExpectedHCPSpecDigest != first.NetworkProfile.ExpectedHCPSpecDigest || other.NetworkProfile.ExpectedHRPSpecDigest == first.NetworkProfile.ExpectedHRPSpecDigest {
		t.Fatal("HCP/HRP identity derivation drift")
	}
	if !bytes.Equal(raw, recipeRaw(t)) {
		t.Fatal("source recipe mutated")
	}
}

func TestMVPRecipeRejectsUnsupportedOSAndRevisionDrift(t *testing.T) {
	raw := recipeRaw(t)
	for _, profile := range []string{"flatcar-kubevirt-mvp", "ubuntu-kubevirt-mvp", "flatcar", "ubuntu", "talos-openstack-mvp"} {
		if _, err := Load(raw, profile, e, p); err == nil {
			t.Fatalf("unsupported profile silently fell back: %s", profile)
		}
	}
	for _, input := range [][]byte{nil, append(raw, []byte("{}")...), bytes.Replace(raw, []byte(`"profile":`), []byte(`"profile":"duplicate","profile":`), 1)} {
		if _, err := Load(input, TalosMVP, e, p); err == nil {
			t.Fatal("invalid recipe accepted")
		}
	}
	if _, err := Load(raw, TalosMVP, p, e); err == nil {
		t.Fatal("Contract revisions replaced by profile")
	}
	if _, err := (Recipe{}).Render(contract.Identity{Name: "fresh", Namespace: "fresh"}, e, p); err == nil {
		t.Fatal("unverified recipe rendered")
	}
	recipe, err := Load(raw, TalosMVP, e, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipe.Render(contract.Identity{Name: "../escape", Namespace: "../escape"}, e, p); err == nil {
		t.Fatal("unsafe template identity")
	}
	bad := bytes.Replace(raw, []byte(`"1.19.6"`), []byte(`"1.19.7"`), 1)
	changed, err := Load(bad, TalosMVP, e, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Render(contract.Identity{Name: "fresh", Namespace: "fresh"}, e, p); err == nil {
		t.Fatal("HCP spec drift passed reviewed network digest")
	}
}
