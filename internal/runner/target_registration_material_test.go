package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildTargetRegistrationMaterialReplacesOnlyBoundPlaceholdersInMemory(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, err := BuildTargetRegistrationMaterial(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != TargetRegistrationMaterialReceiptFormat || receipt.State != "VERIFIED" || receipt.StageID != "target-registration" ||
		receipt.PlanDigest != fixture.bundle.plan.PlanDigest || receipt.TargetIdentityDigest != fixture.bundle.receipt.TargetIdentityDigest ||
		receipt.ProjectDigest != fixture.bundle.receipt.ProjectDigest || receipt.RegistrationTemplateDigest != fixture.bundle.receipt.RegistrationTemplateDigest ||
		receipt.RuntimeBindingDigest != fixture.runtime.receipt.PrivateMaterialDigest || receipt.CredentialIssueReceiptDigest == "" ||
		receipt.MaterializationBindingDigest == "" || receipt.CredentialBytesInReceipt || receipt.MaterializedSecretDigestRetained || receipt.MutationAllowed {
		t.Fatalf("unexpected material receipt: %#v", receipt)
	}
	if !bytes.Equal(material.project, fixture.bundle.projection.Project.Raw) {
		t.Fatal("AppProject changed during materialization")
	}
	var secret map[string]any
	if err := json.Unmarshal(material.registration, &secret); err != nil {
		t.Fatal(err)
	}
	metadata := secret["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	data := secret["stringData"].(map[string]any)
	if annotations["openkubes.io/capi-cluster-uid"] != fixture.runtime.material.Target.CAPIClusterUID ||
		annotations["openkubes.io/workload-kube-system-uid"] != fixture.runtime.material.Target.KubeSystemUID ||
		annotations["openkubes.io/workload-api-ca-sha256"] != fixture.runtime.material.Target.WorkloadAPICADigest ||
		annotations["openkubes.io/token-expiration"] != fixture.credential.receipt.ExpiresAt ||
		data["server"] != fixture.runtime.material.Target.WorkloadAPIEndpoint {
		t.Fatal("runtime placeholders were not replaced exactly")
	}
	var secretConfig targetRegistrationSecretConfig
	if err := json.Unmarshal([]byte(data["config"].(string)), &secretConfig); err != nil {
		t.Fatal(err)
	}
	if secretConfig.BearerToken != string(fixture.credential.token) || secretConfig.TLSClientConfig.CAData != fixture.runtime.material.Target.WorkloadAPICAData || secretConfig.TLSClientConfig.Insecure {
		t.Fatal("Argo credential config differs from verified in-memory authority")
	}

	publicRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{
		string(fixture.credential.token), string(fixture.credential.caBundle), fixture.credential.endpoint,
		fixture.runtime.material.Target.CAPIClusterUID, fixture.runtime.material.Target.KubeSystemUID,
		fixture.runtime.material.Target.WorkloadAPICAData, material.registrationDigest,
	} {
		if bytes.Contains(publicRaw, []byte(private)) {
			t.Fatalf("public receipt leaked private material %q", private)
		}
	}
	if _, err := (VerifiedTargetRegistrationMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified material exposed a receipt")
	}
}

func TestBuildTargetRegistrationMaterialFailsClosed(t *testing.T) {
	tests := map[string]func(*targetRegistrationMaterialTestFixture){
		"unverified bundle": func(f *targetRegistrationMaterialTestFixture) { f.config.Bundle.verified = false },
		"mutated projection": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Bundle.projection.Registration.Raw[0] ^= 1
		},
		"unverified runtime": func(f *targetRegistrationMaterialTestFixture) { f.config.Runtime.verified = false },
		"foreign plan": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Runtime.material.PlanDigest = runnerStageSHA("9")
			refreshTargetRegistrationRuntime(t, &f.config.Runtime)
		},
		"foreign target": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Runtime.material.Target.CAPIClusterUID = "foreign-runtime-uid"
			refreshTargetRegistrationRuntime(t, &f.config.Runtime)
		},
		"unverified credential": func(f *targetRegistrationMaterialTestFixture) { f.config.Credential.verified = false },
		"credential target mismatch": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Credential.targetIdentity = runnerStageSHA("8")
		},
		"credential evidence mismatch": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Credential.receipt.RequestDigest = runnerStageSHA("6")
		},
		"credential endpoint mismatch": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Credential.endpoint = "https://192.0.2.148:6443"
		},
		"credential CA mismatch": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Credential.caBundle = []byte("foreign-ca")
		},
		"credential token tamper": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Credential.token[0] ^= 1
		},
		"credential near expiry": func(f *targetRegistrationMaterialTestFixture) {
			f.config.Credential.expiresAt = f.config.MaterializationTime.Add(29 * time.Minute)
			f.config.Credential.receipt.ExpiresAt = f.config.Credential.expiresAt.Format(time.RFC3339)
			f.config.Credential.privateDigest, _ = targetCredentialPrivateDigest(f.config.Credential)
		},
		"materialization before issue": func(f *targetRegistrationMaterialTestFixture) {
			f.config.MaterializationTime = f.config.MaterializationTime.Add(-time.Minute)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := targetRegistrationMaterialFixture(t)
			mutate(&fixture)
			if _, err := BuildTargetRegistrationMaterial(fixture.config); err == nil {
				t.Fatal("invalid target-registration materialization was accepted")
			}
		})
	}
}

type targetRegistrationMaterialTestFixture struct {
	bundle       VerifiedTargetRegistrationStageBundle
	bundleConfig TargetRegistrationStageBundleConfig
	runtime      VerifiedRuntimeBindingMaterial
	credential   VerifiedTargetCredentialMaterial
	config       TargetRegistrationMaterializeConfig
}

func targetRegistrationMaterialFixture(t *testing.T) targetRegistrationMaterialTestFixture {
	t.Helper()
	bundleFixture := targetRegistrationBundleFixture(t)
	bundle, err := LoadTargetRegistrationStageBundle(bundleFixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ca := []byte("-----BEGIN CERTIFICATE-----\nok147-test-ca\n-----END CERTIFICATE-----\n")
	runtime := VerifiedRuntimeBindingMaterial{verified: true}
	runtime.material = RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND",
		PlanDigest: bundle.plan.PlanDigest, IntentRevision: bundle.plan.IntentRevision,
		EnablementRevision: bundle.plan.EnablementRevision, PlatformRevision: bundle.plan.PlatformRevision,
		ExecutionFixture: bundle.plan.ExecutionFixture,
		Target: RuntimeBindingTarget{
			Name: bundle.plan.ContractIdentity.Name, CAPIClusterUID: targetAccessRuntimeUID,
			TargetIdentityScheme: "capi-cluster-uid/v1", WorkloadAPIEndpoint: "https://192.0.2.147:6443",
			WorkloadAPICAData: base64.StdEncoding.EncodeToString(ca), WorkloadAPICADigest: digest.SHA256(ca),
			KubeSystemUID: "kube-system-runtime-uid-147",
		},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "local-path-runtime-uid-147", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: runnerStageSHA("1"), NetworkEvidenceDigest: runnerStageSHA("2")},
	}
	refreshTargetRegistrationRuntime(t, &runtime)
	now := time.Date(2026, 8, 17, 18, 1, 0, 0, time.UTC)
	token := []byte("header.payload.signature-" + strings.Repeat("x", 96))
	credential := VerifiedTargetCredentialMaterial{
		token: token, caBundle: ca, endpoint: runtime.material.Target.WorkloadAPIEndpoint,
		targetIdentity: bundle.receipt.TargetIdentityDigest, expiresAt: now.Add(2 * time.Hour), verified: true,
	}
	credential.receipt = targetRegistrationCredentialReceipt(now.Add(-time.Minute), targetCredentialPolicyDocument{TargetIdentityDigest: bundle.receipt.TargetIdentityDigest})
	credential.privateDigest, err = targetCredentialPrivateDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	config := TargetRegistrationMaterializeConfig{Bundle: bundle, Runtime: runtime, Credential: credential, MaterializationTime: now}
	return targetRegistrationMaterialTestFixture{bundle: bundle, bundleConfig: bundleFixture.config, runtime: runtime, credential: credential, config: config}
}

func refreshTargetRegistrationRuntime(t *testing.T, runtime *VerifiedRuntimeBindingMaterial) {
	t.Helper()
	raw, err := canonicalRuntimeBinding(runtime.material)
	if err != nil {
		t.Fatal(err)
	}
	runtime.raw = raw
	runtime.receipt = RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding",
		PlanDigest: runtime.material.PlanDigest, IntentRevision: runtime.material.IntentRevision,
		TargetClusterUIDDigest:    digest.SHA256([]byte(runtime.material.Target.CAPIClusterUID)),
		WorkloadAPICADigest:       runtime.material.Target.WorkloadAPICADigest,
		KubeSystemUIDDigest:       digest.SHA256([]byte(runtime.material.Target.KubeSystemUID)),
		LocalPathStorageUIDDigest: digest.SHA256([]byte(runtime.material.Storage.UID)),
		LifecycleEvidenceDigest:   runtime.material.Evidence.LifecycleEvidenceDigest,
		NetworkEvidenceDigest:     runtime.material.Evidence.NetworkEvidenceDigest,
		PrivateMaterialDigest:     digest.SHA256(raw), PersistentMutationAllowed: false,
	}
}
