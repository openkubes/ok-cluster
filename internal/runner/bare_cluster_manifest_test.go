package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func bareClusterDraftFixture(t *testing.T) (BareClusterManifestConfig, string, fullRunExecutionManifestDocument, func()) {
	t.Helper()
	manifest, cleanup := fullRunExecutionManifestFixture(t)
	doc, plan := readFullRunExecutionFixture(t, manifest)
	doc.Plan.Expected.CompletionMode = stageplan.CompletionModeBareClusterMVP
	plan["completionMode"] = stageplan.CompletionModeBareClusterMVP
	plan["stages"] = plan["stages"].([]any)[:7]
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeBundleFile(t, root, "staged-plan.json", mustJSON(t, plan))
	public, _ := fullRunEvidencePublicKeyFixture(t, root)
	inputs := bareClusterRuntimeInputs{Format: "ok-cli-cluster-runtime-inputs/v1", Ledger: doc.ProviderPrerequisites.Ledger,
		Infrastructure: doc.ProviderPrerequisites.Authority, Management: doc.ClusterLifecycle.Authority,
		ProviderAccessKubeconfigFile: doc.ProviderAccess.KubeconfigFile, IndependentEvidencePublicKeyPath: public}
	inputs.Authorization.Endpoint = doc.Authorization.Endpoint
	inputs.Authorization.TokenFile = doc.Authorization.TokenFile
	inputs.Authorization.CAFile = doc.Authorization.CAFile
	inputs.Authorization.PublicKeyPath = doc.Authorization.PublicKeyPath
	path := writeBundleFile(t, root, "explicit-runtime-inputs.json", mustJSON(t, inputs))
	return BareClusterManifestConfig{Root: root, Expected: fullRunPlanExpected(doc.Plan.Expected), NetworkProfileDigest: doc.Profiles.Network.Digest,
		EnablementObject: doc.Enablement.ExpectedObject, TargetAccessObjects: doc.TargetAccess.ExpectedObjects}, path, doc, cleanup
}

func TestBuildBareClusterManifestLoadsThroughExistingOwnerWithoutRuntimeExecution(t *testing.T) {
	config, inputsPath, source, cleanup := bareClusterDraftFixture(t)
	defer cleanup()
	before, err := os.ReadFile(inputsPath)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := BuildBareClusterManifest(inputsPath, config)
	if err != nil {
		t.Fatal(err)
	}
	var runtimeInputs bareClusterRuntimeInputs
	if err := json.Unmarshal(before, &runtimeInputs); err != nil || draft.IndependentEvidencePublicKeyPath != runtimeInputs.IndependentEvidencePublicKeyPath {
		t.Fatal("draft did not preserve the explicitly verified evidence key path")
	}
	if draft.RuntimeInputsDigest != digest.SHA256(before) || draft.IndependentEvidenceKeyID == "" {
		t.Fatal("missing explicit input/trust bindings")
	}
	again, err := BuildBareClusterManifest(inputsPath, config)
	if err != nil || !bytes.Equal(draft.Raw, again.Raw) {
		t.Fatal("handoff draft is not deterministic")
	}
	var generated fullRunExecutionManifestDocument
	if err := json.Unmarshal(draft.Raw, &generated); err != nil {
		t.Fatal(err)
	}
	if generated.ProviderPrerequisites.Authority != source.ProviderPrerequisites.Authority || generated.ClusterLifecycle.Authority != source.ClusterLifecycle.Authority || generated.ProviderAccess.KubeconfigFile != source.ProviderAccess.KubeconfigFile {
		t.Fatal("explicit authority or credential reference changed")
	}
	for _, dir := range []string{"projection", "runtime", "receipts", "authorizations"} {
		if err := os.Mkdir(filepath.Join(config.Root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for target, original := range map[string]string{"provider-access-policy.json": source.ProviderAccess.PolicyPath, "enablement.yaml": source.Enablement.ArtifactPath,
		"network-profile.json": source.Profiles.Network.Path, "target-access.yaml": source.TargetAccess.ArtifactPath} {
		raw, err := os.ReadFile(original)
		if err != nil {
			t.Fatal(err)
		}
		writeBundleFile(t, config.Root, target, raw)
	}
	projectionRoot := filepath.Join(config.Root, "projection")
	raw, err := os.ReadFile(source.Projection.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	writeBundleFile(t, projectionRoot, "manifest.json", raw)
	for _, name := range []string{"authority-map.json", "ok-infra-prerequisites.yaml", "ok-mgmt-lifecycle.yaml", "renderer-input.yaml", "renderer-source.yaml", "resolved-renderer-input.yaml"} {
		raw, err := os.ReadFile(filepath.Join(source.Projection.Root, name))
		if err != nil {
			t.Fatal(err)
		}
		writeBundleFile(t, projectionRoot, name, raw)
	}
	manifestPath := writeBundleFile(t, config.Root, "full-run-manifest.json", draft.Raw)
	_, receipt, err := LoadFullRunExecutionManifest(manifestPath)
	if err != nil || receipt.State != "VERIFIED" || receipt.CompletionMode != stageplan.CompletionModeBareClusterMVP || receipt.MutationAllowed {
		t.Fatalf("draft failed the real full-run verifier: %v", err)
	}
	after, _ := os.ReadFile(inputsPath)
	if !bytes.Equal(before, after) {
		t.Fatal("source runtime inputs mutated")
	}
	for _, dir := range []string{"runtime", "receipts", "authorizations"} {
		entries, err := os.ReadDir(filepath.Join(config.Root, dir))
		if err != nil || len(entries) != 0 {
			t.Fatal("offline verification wrote runtime state")
		}
	}
}

func TestBuildBareClusterManifestRejectsPrivateInputAndAuthorityDrift(t *testing.T) {
	config, path, _, cleanup := bareClusterDraftFixture(t)
	defer cleanup()
	original, _ := os.ReadFile(path)
	for _, mutate := range []func(map[string]any){
		func(x map[string]any) { x["plan"] = map[string]any{"path": "/historical/manifest"} },
		func(x map[string]any) {
			x["independentEvidencePublicKeyPath"] = x["authorization"].(map[string]any)["publicKeyPath"]
		},
		func(x map[string]any) {
			x["management"].(map[string]any)["tokenFile"] = x["infrastructure"].(map[string]any)["tokenFile"]
		},
		func(x map[string]any) { x["infrastructure"].(map[string]any)["caBundleDigest"] = runnerStageSHA("f") },
		func(x map[string]any) { x["ledger"].(map[string]any)["tokenFile"] = "/not-present" },
	} {
		var input map[string]any
		json.Unmarshal(original, &input)
		mutate(input)
		if err := os.WriteFile(path, mustJSON(t, input), 0o600); err != nil {
			t.Fatal(err)
		}
		if draft, err := BuildBareClusterManifest(path, config); err == nil || draft.Raw != nil {
			t.Fatal("invalid authority/runtime inputs produced a draft")
		}
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(original, []byte(`"format":`), []byte(`"format":"duplicate","format":`), 1)
	if err := os.WriteFile(path, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildBareClusterManifest(path, config); err == nil {
		t.Fatal("duplicate runtime input keys accepted")
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildBareClusterManifest(path, config); err == nil {
		t.Fatal("non-private runtime inputs accepted")
	}
	if _, err := os.Lstat(filepath.Join(config.Root, "runtime")); !os.IsNotExist(err) {
		t.Fatal("builder opened/materialized runtime state")
	}
}

func TestBareClusterRuntimeInputsAreBoundedPrivateAndNotHistoricalManifests(t *testing.T) {
	root := t.TempDir()
	path := writeBundleFile(t, root, "inputs.json", []byte(`{"format":"ok-cli-cluster-runtime-inputs/v1"}`))
	if _, err := readBareClusterRuntimeInputs(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{root, link, filepath.Join(root, "absent")} {
		if _, err := readBareClusterRuntimeInputs(bad); err == nil {
			t.Fatal("unsafe file metadata accepted")
		}
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte("x"), 64*1024+1)} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBareClusterRuntimeInputs(path); err == nil {
			t.Fatal("empty/oversized private inputs accepted")
		}
	}
}
