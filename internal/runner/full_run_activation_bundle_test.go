package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildFullRunExecutionBundleIsDeterministicAndSelfContained(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	publicKeyPath, keyID := fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
	bindFullRunEvidenceKeyID(t, manifestPath, keyID)

	source, sourceReceipt, err := LoadFullRunExecutionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildFullRunExecutionBundle(FullRunExecutionBundleConfig{
		ManifestPath: manifestPath, IndependentEvidencePublicKey: publicKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := bundle.Receipt()
	if err != nil || receipt.State != "VERIFIED" || receipt.KubernetesMutationAllowed ||
		receipt.SourceManifestDigest != sourceReceipt.ManifestDigest || receipt.PlanDigest != sourceReceipt.PlanDigest ||
		receipt.EvidenceKeyID != keyID || receipt.FileCount != len(fullRunExecutionBundleFiles) {
		t.Fatalf("unexpected bundle receipt: %#v err=%v", receipt, err)
	}
	second, err := BuildFullRunExecutionBundle(FullRunExecutionBundleConfig{
		ManifestPath: manifestPath, IndependentEvidencePublicKey: publicKeyPath,
	})
	if err != nil || !bytes.Equal(bundle.indexRaw, second.indexRaw) || bundle.receipt != second.receipt {
		t.Fatalf("bundle identity was not deterministic: second=%#v err=%v", second.receipt, err)
	}

	var rewritten fullRunExecutionManifestDocument
	if err := json.Unmarshal(bundle.files[fullRunExecutionManifestPath], &rewritten); err != nil {
		t.Fatal(err)
	}
	path := func(relative string) string { return filepath.Join(fullRunExecutionWorkspaceRoot, relative) }
	if rewritten.Plan.Path != path("input/staged-plan.json") ||
		rewritten.Projection.Root != path("input/projection") ||
		rewritten.ProviderPrerequisites.Authority.TokenFile != path("credentials/infrastructure-token") ||
		rewritten.ProviderAccess.PolicyPath != path("input/provider-access-policy.json") ||
		rewritten.ProviderAccess.KubeconfigFile != path("credentials/provider-access-kubeconfig") ||
		rewritten.ClusterLifecycle.Authority.TokenFile != path("credentials/management-token") ||
		rewritten.TargetRegistration.GitOps.TokenFile != path("credentials/gitops-token") ||
		rewritten.NetworkObservation.Workload.BindingPath != path("work/workload-authority.json") ||
		rewritten.AggregateEvidence.WorkloadTokenFile != "" ||
		rewritten.AggregateEvidence.WorkloadKubeconfigFile != path("work/workload-kubeconfig.yaml") ||
		rewritten.PlatformObservation.Capability.IndependentEvidencePath != fullRunExecutionHandoffRoot+"/observability-evidence.json" ||
		rewritten.ReceiptDirectory != path("work/receipts") {
		t.Fatalf("rewritten manifest escaped fixed roots: %#v", rewritten)
	}
	if rewritten.Plan.Expected != source.document.Plan.Expected ||
		rewritten.Enablement.ExpectedObject != source.document.Enablement.ExpectedObject ||
		rewritten.TargetRegistration.TargetName != source.document.TargetRegistration.TargetName ||
		rewritten.PlatformObservation.Capability.IndependentEvidenceKeyID != keyID {
		t.Fatal("semantic full-run identity changed during path rewrite")
	}
	for relative, sourcePath := range map[string]string{
		"input/staged-plan.json":                        source.document.Plan.Path,
		"input/enablement.yaml":                         source.document.Enablement.ArtifactPath,
		"input/platform-applications.yaml":              source.document.PlatformApplications.ArtifactPath,
		"input/provider-access-policy.json":             source.document.ProviderAccess.PolicyPath,
		"credentials/provider-access-kubeconfig":        source.document.ProviderAccess.KubeconfigFile,
		"input/independent-evidence.pub":                publicKeyPath,
		"input/projection/renderer-input.yaml":          filepath.Join(source.document.Projection.Root, "renderer-input.yaml"),
		"input/projection/renderer-source.yaml":         filepath.Join(source.document.Projection.Root, "renderer-source.yaml"),
		"input/projection/resolved-renderer-input.yaml": filepath.Join(source.document.Projection.Root, "resolved-renderer-input.yaml"),
	} {
		want, readErr := os.ReadFile(sourcePath)
		if readErr != nil || !bytes.Equal(bundle.files[relative], want) {
			t.Fatalf("source artifact %s was not preserved: %v", relative, readErr)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{filepath.Dir(manifestPath), "token", "endpoint", "kubeconfig", "certificate"} {
		if strings.Contains(strings.ToLower(string(public)), strings.ToLower(forbidden)) {
			t.Fatalf("public receipt disclosed %q: %s", forbidden, public)
		}
	}
}

func TestBuildFullRunExecutionBundleRejectsForeignOrIncompleteSources(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, *FullRunExecutionBundleConfig){
		"foreign evidence key": func(t *testing.T, manifestPath string, config *FullRunExecutionBundleConfig) {
			config.IndependentEvidencePublicKey, _ = fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
		},
		"invalid evidence key": func(t *testing.T, manifestPath string, config *FullRunExecutionBundleConfig) {
			config.IndependentEvidencePublicKey = writeBundleFile(t, filepath.Dir(manifestPath), "invalid-evidence.pub", []byte("not-a-key\n"))
		},
		"missing manifest": func(_ *testing.T, manifestPath string, config *FullRunExecutionBundleConfig) {
			config.ManifestPath = manifestPath + ".missing"
		},
		"missing renderer provenance": func(t *testing.T, manifestPath string, _ *FullRunExecutionBundleConfig) {
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var document fullRunExecutionManifestDocument
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(document.Projection.Root, "renderer-source.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"invalid authorization token": func(t *testing.T, manifestPath string, _ *FullRunExecutionBundleConfig) {
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var document fullRunExecutionManifestDocument
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(document.Authorization.TokenFile, []byte(" token-with-whitespace "), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			manifestPath, cleanup := fullRunExecutionManifestFixture(t)
			defer cleanup()
			publicKeyPath, keyID := fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
			bindFullRunEvidenceKeyID(t, manifestPath, keyID)
			config := FullRunExecutionBundleConfig{ManifestPath: manifestPath, IndependentEvidencePublicKey: publicKeyPath}
			mutate(t, manifestPath, &config)
			if bundle, err := BuildFullRunExecutionBundle(config); err == nil || bundle.verified {
				t.Fatalf("unsafe full-run bundle was accepted: %#v err=%v", bundle.receipt, err)
			}
		})
	}
}

func TestVerifiedFullRunExecutionBundleRejectsTampering(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	publicKeyPath, keyID := fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
	bindFullRunEvidenceKeyID(t, manifestPath, keyID)
	bundle, err := BuildFullRunExecutionBundle(FullRunExecutionBundleConfig{
		ManifestPath: manifestPath, IndependentEvidencePublicKey: publicKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	tamperedContent := bundle
	tamperedContent.files = cloneFullRunBundleFiles(bundle.files)
	tamperedContent.files["input/enablement.yaml"][0] ^= 0xff
	if _, err := tamperedContent.Receipt(); err == nil {
		t.Fatal("tampered bundle content was accepted")
	}
	tamperedIndex := bundle
	tamperedIndex.indexRaw = append([]byte(nil), bundle.indexRaw...)
	tamperedIndex.indexRaw[len(tamperedIndex.indexRaw)-1] ^= 0x01
	if _, err := tamperedIndex.Receipt(); err == nil {
		t.Fatal("tampered bundle index was accepted")
	}
	tamperedReceipt := bundle
	tamperedReceipt.receipt.EvidenceKeyID = strings.Repeat("sha256:0", 1) + strings.Repeat("0", 57)
	if _, err := tamperedReceipt.Receipt(); err == nil {
		t.Fatal("tampered bundle receipt was accepted")
	}
}

func cloneFullRunBundleFiles(source map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(source))
	for path, raw := range source {
		clone[path] = append([]byte(nil), raw...)
	}
	return clone
}
