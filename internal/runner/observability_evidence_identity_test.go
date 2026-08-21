package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestDeriveObservabilityIndependentEvidenceIdentityUsesVerifiedRuntimeTruth(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	manifest, _, err := LoadFullRunExecutionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	runtime := evidenceIdentityRuntime(t, manifest, "cluster-uid-runtime-a")
	first, err := deriveObservabilityIndependentEvidenceIdentity(manifest, runtime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveObservabilityIndependentEvidenceIdentity(manifest, runtime)
	if err != nil || first != second {
		t.Fatalf("identity derivation is not deterministic: first=%#v second=%#v err=%v", first, second, err)
	}
	if first.Format != ObservabilityIndependentEvidenceIdentityFormat || first.State != "RUNTIME_BOUND" ||
		first.TargetClusterUID != "cluster-uid-runtime-a" || !strings.HasPrefix(first.RunID, "ok147-") ||
		!stageReceiptPrefixDigestPattern.MatchString(first.FixtureDigest) || !stageReceiptPrefixDigestPattern.MatchString(first.ProfileDigest) {
		t.Fatalf("derived evidence identity is incomplete: %#v", first)
	}
	changed, err := deriveObservabilityIndependentEvidenceIdentity(manifest, evidenceIdentityRuntime(t, manifest, "cluster-uid-runtime-b"))
	if err != nil {
		t.Fatal(err)
	}
	if changed.RunID == first.RunID || changed.FixtureDigest == first.FixtureDigest {
		t.Fatalf("runtime target change did not change derived identities: first=%#v changed=%#v", first, changed)
	}
}

func TestLoadObservabilityIndependentEvidenceIdentityIsPrivateCanonicalAndDigestBound(t *testing.T) {
	material := ObservabilityIndependentEvidenceIdentityMaterial{
		Format: ObservabilityIndependentEvidenceIdentityFormat, State: "RUNTIME_BOUND",
		ManifestDigest: evidenceIdentitySHA("1"), RuntimeBindingDigest: evidenceIdentitySHA("2"),
		RunID: "ok147-0123456789abcdef01234567", TargetClusterUID: "cluster-uid-runtime-a",
		FixtureDigest: evidenceIdentitySHA("3"), ProfileDigest: evidenceIdentitySHA("4"),
	}
	raw, err := canonicalObservabilityIndependentEvidenceIdentity(material)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "identity.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadObservabilityIndependentEvidenceIdentity(path, digest.SHA256(raw))
	if err != nil || identity.RunID != material.RunID || identity.TargetClusterUID != material.TargetClusterUID ||
		identity.FixtureDigest != material.FixtureDigest || identity.ProfileDigest != material.ProfileDigest {
		t.Fatalf("private identity did not replay: identity=%#v err=%v", identity, err)
	}
	if _, err := LoadObservabilityIndependentEvidenceIdentity(path, evidenceIdentitySHA("9")); err == nil {
		t.Fatal("foreign expected digest was accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadObservabilityIndependentEvidenceIdentity(path, digest.SHA256(raw)); err == nil {
		t.Fatal("public identity permissions were accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "identity-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadObservabilityIndependentEvidenceIdentity(link, digest.SHA256(raw)); err == nil {
		t.Fatal("symlink identity was accepted")
	}
}

func evidenceIdentityRuntime(t *testing.T, manifest VerifiedFullRunExecutionManifest, targetUID string) VerifiedRuntimeBindingMaterial {
	t.Helper()
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND",
		PlanDigest: manifest.plan.PlanDigest, IntentRevision: manifest.plan.IntentRevision,
		EnablementRevision: manifest.plan.EnablementRevision, PlatformRevision: manifest.plan.PlatformRevision,
		ExecutionFixture: manifest.plan.ExecutionFixture,
		Target: RuntimeBindingTarget{
			Name: manifest.plan.ContractIdentity.Name, CAPIClusterUID: targetUID, TargetIdentityScheme: "capi-cluster-uid/v1",
			WorkloadAPIEndpoint: "https://192.0.2.10:6443", WorkloadAPICAData: "Y2E=", WorkloadAPICADigest: evidenceIdentitySHA("3"),
			KubeSystemUID: "kube-system-uid-runtime",
		},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "storage-class-uid-runtime", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: evidenceIdentitySHA("4"), NetworkEvidenceDigest: evidenceIdentitySHA("5")},
	}
	raw, err := canonicalRuntimeBinding(material)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding",
		PlanDigest: material.PlanDigest, IntentRevision: material.IntentRevision,
		TargetClusterUIDDigest: digest.SHA256([]byte(targetUID)), WorkloadAPICADigest: material.Target.WorkloadAPICADigest,
		KubeSystemUIDDigest:       digest.SHA256([]byte(material.Target.KubeSystemUID)),
		LocalPathStorageUIDDigest: digest.SHA256([]byte(material.Storage.UID)),
		LifecycleEvidenceDigest:   material.Evidence.LifecycleEvidenceDigest, NetworkEvidenceDigest: material.Evidence.NetworkEvidenceDigest,
		PrivateMaterialDigest: digest.SHA256(raw), PersistentMutationAllowed: false,
	}
	return VerifiedRuntimeBindingMaterial{material: material, raw: raw, receipt: receipt, verified: true}
}

func evidenceIdentitySHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
