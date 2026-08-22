package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildPostRuntimeExecutionActivationPackageBindsPrivateSecretAndJob(t *testing.T) {
	config, cleanup := postRuntimeActivationPackageFixture(t)
	defer cleanup()
	packaged, err := BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != PostRuntimeExecutionActivationPackageFormat || receipt.State != "VERIFIED" || receipt.ActivationSecret != config.ActivationSecret ||
		receipt.ManagementAuthority != "ok-mgmt" || !stageReceiptPrefixDigestPattern.MatchString(receipt.PlanDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.TargetIdentityDigest) || receipt.PrivateFileCount != len(postRuntimeExecutionBundleFiles) ||
		receipt.MutationAllowed || len(receipt.ObjectKinds) != 3 {
		t.Fatalf("unexpected activation package receipt: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "/private/", "endpoint", "certificate", "kubeconfig"} {
		if strings.Contains(strings.ToLower(string(public)), forbidden) {
			t.Fatalf("activation package receipt disclosed %q", forbidden)
		}
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || digest.SHA256(parts[0]) != receipt.SecretObjectDigest || digest.SHA256(parts[1]) != receipt.JobEnvelopeDigest {
		t.Fatal("activation package component identity differs")
	}
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(parts[0], &secret); err != nil {
		t.Fatal(err)
	}
	if secret.Kind != "Secret" || !secret.Immutable || secret.Type != "Opaque" || secret.Metadata.Name != config.ActivationSecret ||
		len(secret.Data) != len(postRuntimeExecutionBundleFiles)+1 {
		t.Fatalf("unexpected private activation Secret: %#v", secret)
	}
	indexRaw, err := base64.StdEncoding.DecodeString(secret.Data[postRuntimeExecutionBundleIndexName])
	if err != nil {
		t.Fatal(err)
	}
	var index postRuntimeExecutionBundleIndex
	if err := json.Unmarshal(indexRaw, &index); err != nil || index.ManifestDigest != receipt.ManifestDigest {
		t.Fatalf("private activation index differs: %#v %v", index, err)
	}
	if bundleDigest, err := canonicalPostRuntimeExecutionBundleIndexDigest(index); err != nil || bundleDigest != receipt.BundleDigest {
		t.Fatalf("private activation bundle identity differs: %q %v", bundleDigest, err)
	}
	objects := decodeJobObjects(t, parts[1])
	jobAnnotations := objectAt(t, objectAt(t, objects["Job"], "metadata"), "annotations")
	if jobAnnotations["openkubes.io/bundle-digest"] != receipt.BundleDigest || jobAnnotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest {
		t.Fatalf("Job does not bind private package identity: %#v", jobAnnotations)
	}
}

func TestPostRuntimeExecutionActivationPackageMaterializesExactSecret(t *testing.T) {
	config, cleanup := postRuntimeActivationPackageFixture(t)
	defer cleanup()
	packaged, err := BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := packaged.Receipt()
	raw, _ := packaged.PrivateBytes()
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(parts[0], &secret); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "projection")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	indexRaw, _ := base64.StdEncoding.DecodeString(secret.Data[postRuntimeExecutionBundleIndexName])
	if err := os.WriteFile(filepath.Join(source, postRuntimeExecutionBundleIndexName), indexRaw, 0o440); err != nil {
		t.Fatal(err)
	}
	for _, path := range postRuntimeExecutionBundleFiles {
		encoded := secret.Data[strings.ReplaceAll(path, "/", ".")]
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(source, path)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	materialized, err := MaterializePostRuntimeExecutionBundle(PostRuntimeExecutionBundleMaterializationConfig{
		SourceDirectory: source, DestinationDirectory: filepath.Join(root, "workspace"), ExpectedBundleDigest: receipt.BundleDigest,
	})
	if err != nil || materialized.State != "MATERIALIZED_VERIFIED" || materialized.ManifestDigest != receipt.ManifestDigest {
		t.Fatalf("packaged Secret did not materialize exactly: %#v %v", materialized, err)
	}
}

func TestPostRuntimeExecutionRecoveryActivationCarriesHistoricalReceipts(t *testing.T) {
	config, cleanup := postRuntimeActivationPackageFixture(t)
	defer cleanup()
	config.ManifestPath = postRuntimeRecoveryManifestFixture(t, config.ManifestPath, true)
	packaged, err := BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RecoveryMode != "target-registration" || receipt.PrivateFileCount != len(postRuntimeExecutionBundleFiles)+2 {
		t.Fatalf("recovery activation identity is incomplete: %#v", receipt)
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	var secret postRuntimeActivationSecret
	if len(parts) != 2 || json.Unmarshal(parts[0], &secret) != nil {
		t.Fatal("decode recovery activation Secret")
	}
	indexRaw, err := base64.StdEncoding.DecodeString(secret.Data[postRuntimeExecutionBundleIndexName])
	if err != nil {
		t.Fatal(err)
	}
	var index postRuntimeExecutionBundleIndex
	if json.Unmarshal(indexRaw, &index) != nil || index.Format != PostRuntimeExecutionRecoveryBundleFormat ||
		index.RecoveryMode != "target-registration" || len(index.Files) != receipt.PrivateFileCount {
		t.Fatalf("unexpected recovery bundle index: %#v", index)
	}
	for _, relative := range postRuntimeExecutionRecoveryReceiptFiles {
		if secret.Data[strings.ReplaceAll(relative, "/", ".")] == "" {
			t.Fatalf("recovery receipt %s is absent from private activation", relative)
		}
	}
	plan, err := PlanPostRuntimeExecutionActivationInstallation(packaged)
	if err != nil || plan.State != "VERIFIED" || plan.MutationAllowed {
		t.Fatalf("recovery activation installation plan failed: %#v %v", plan, err)
	}

	root := t.TempDir()
	source := filepath.Join(root, "projection")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, postRuntimeExecutionBundleIndexName), indexRaw, 0o440); err != nil {
		t.Fatal(err)
	}
	for _, file := range index.Files {
		encoded := secret.Data[strings.ReplaceAll(file.Path, "/", ".")]
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(source, file.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	materialized, err := MaterializePostRuntimeExecutionBundle(PostRuntimeExecutionBundleMaterializationConfig{
		SourceDirectory: source, DestinationDirectory: filepath.Join(root, "workspace"), ExpectedBundleDigest: receipt.BundleDigest,
	})
	if err != nil || materialized.State != "MATERIALIZED_VERIFIED" || materialized.FileCount != receipt.PrivateFileCount {
		t.Fatalf("recovery activation did not materialize exactly: %#v %v", materialized, err)
	}
}

func TestBuildPostRuntimeExecutionActivationPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *PostRuntimeExecutionActivationPackageConfig){
		"wrong template digest": func(_ *testing.T, config *PostRuntimeExecutionActivationPackageConfig) {
			config.JobTemplateDigest = bundleSHA("f")
		},
		"foreign Secret": func(_ *testing.T, config *PostRuntimeExecutionActivationPackageConfig) {
			config.ActivationSecret = "foreign-secret"
		},
		"broad workload network": func(_ *testing.T, config *PostRuntimeExecutionActivationPackageConfig) {
			config.WorkloadAPICIDR = "192.0.2.0/24"
		},
		"changed aggregate token": func(t *testing.T, config *PostRuntimeExecutionActivationPackageConfig) {
			document, _, err := loadPostRuntimeExecutionManifest(config.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(config.ManifestPath), "foreign-workload-token")
			if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			document.AggregateEvidence.WorkloadTokenFile = path
			writePostRuntimeActivationManifest(t, config.ManifestPath, document)
		},
		"divergent GitOps source": func(t *testing.T, config *PostRuntimeExecutionActivationPackageConfig) {
			document, _, err := loadPostRuntimeExecutionManifest(config.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			document.PlatformApplications.GitOps.AuthorityIdentity = "different-authority"
			writePostRuntimeActivationManifest(t, config.ManifestPath, document)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, cleanup := postRuntimeActivationPackageFixture(t)
			defer cleanup()
			mutate(t, &config)
			if _, err := BuildPostRuntimeExecutionActivationPackage(config); err == nil {
				t.Fatal("unsafe post-runtime activation package was accepted")
			}
		})
	}
}

func TestPostRuntimeExecutionActivationPackageRejectsTampering(t *testing.T) {
	config, cleanup := postRuntimeActivationPackageFixture(t)
	defer cleanup()
	packaged, err := BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.raw[0] ^= 0xff
	if _, err := packaged.PrivateBytes(); err == nil {
		t.Fatal("tampered private activation package was accepted")
	}
}

func postRuntimeActivationPackageFixture(t *testing.T) (PostRuntimeExecutionActivationPackageConfig, func()) {
	t.Helper()
	manifest, _, cleanup := postRuntimeManifestFixture(t)
	document, _, err := loadPostRuntimeExecutionManifest(manifest)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	root := filepath.Dir(manifest)
	caRaw, err := os.ReadFile(document.TargetCredential.Ledger.CAFile)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	caDigest := digest.SHA256(caRaw)
	runtimeRaw, err := os.ReadFile(document.RuntimeBinding.MaterialPath)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	var runtimeMaterial RuntimeBindingMaterial
	if err := json.Unmarshal(runtimeRaw, &runtimeMaterial); err != nil {
		cleanup()
		t.Fatal(err)
	}
	runtimeMaterial.Target.WorkloadAPICAData = base64.StdEncoding.EncodeToString(caRaw)
	runtimeMaterial.Target.WorkloadAPICADigest = caDigest
	runtimeRaw, err = canonicalRuntimeBinding(runtimeMaterial)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	var runtimeReceipt RuntimeBindingMaterialReceipt
	runtimeReceiptRaw, err := os.ReadFile(document.RuntimeBinding.ReceiptPath)
	if err != nil || json.Unmarshal(runtimeReceiptRaw, &runtimeReceipt) != nil {
		cleanup()
		t.Fatal("read runtime binding receipt")
	}
	runtimeReceipt.WorkloadAPICADigest = caDigest
	runtimeReceipt.PrivateMaterialDigest = digest.SHA256(runtimeRaw)
	if err := os.WriteFile(document.RuntimeBinding.MaterialPath, runtimeRaw, 0o600); err != nil {
		cleanup()
		t.Fatal(err)
	}
	runtimeReceiptRaw, err = json.Marshal(runtimeReceipt)
	if err != nil || os.WriteFile(document.RuntimeBinding.ReceiptPath, runtimeReceiptRaw, 0o600) != nil {
		cleanup()
		t.Fatal("write runtime binding receipt")
	}
	workloadBindingRaw, err := os.ReadFile(document.TargetCredential.Workload.Path)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	var workloadBinding WorkloadAuthorityBinding
	if err := json.Unmarshal(workloadBindingRaw, &workloadBinding); err != nil {
		cleanup()
		t.Fatal(err)
	}
	workloadBinding.Endpoint = runtimeMaterial.Target.WorkloadAPIEndpoint
	workloadBinding.CABundleDigest = caDigest
	workloadBindingRaw, err = json.Marshal(workloadBinding)
	if err != nil || os.WriteFile(document.TargetCredential.Workload.Path, workloadBindingRaw, 0o600) != nil {
		cleanup()
		t.Fatal("write workload binding")
	}
	document.TargetCredential.Workload.ExpectedBindingDigest, err = WorkloadAuthorityBindingDigest(workloadBinding)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	gitOps := document.TargetRegistration.GitOps
	gitOps.TokenFile = writeBundleFile(t, root, "gitops-token", []byte("gitops-token"))
	gitOps.CAFile = writeBundleFile(t, root, "gitops-ca.crt", caRaw)
	gitOps.CABundleDigest = caDigest
	document.TargetRegistration.GitOps = gitOps
	document.PlatformApplications.GitOps = gitOps
	document.PlatformObservation.Argo = gitOps
	document.AggregateEvidence.Argo = gitOps
	management := document.AggregateEvidence.Management
	management.Endpoint = document.TargetCredential.Ledger.Endpoint
	management.TokenFile = writeBundleFile(t, root, "management-token", []byte("management-token"))
	management.CAFile = writeBundleFile(t, root, "management-ca.crt", caRaw)
	management.CABundleDigest = caDigest
	document.AggregateEvidence.Management = management
	document.AggregateEvidence.WorkloadTokenFile = document.TargetCredential.Workload.TokenFile
	document.AggregateEvidence.WorkloadCAFile = document.TargetCredential.Workload.CAFile
	writePostRuntimeActivationManifest(t, manifest, document)
	template := postRuntimeExecutionJobTemplate(t)
	return PostRuntimeExecutionActivationPackageConfig{
		ManifestPath: manifest, ActivationSecret: "ok147-post-runtime-activation-01",
		JobTemplate: template, JobTemplateDigest: digest.SHA256(template), RunID: "ok147-post-runtime-01",
		ImageDigest:       "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		ManagementAPICIDR: "127.0.0.1/32", WorkloadAPICIDR: "192.0.2.20/32",
		ArgoAPICIDR: "192.0.2.11/32", AuthorizationAPICIDR: "127.0.0.1/32",
	}, cleanup
}

func writePostRuntimeActivationManifest(t *testing.T, path string, document postRuntimeExecutionManifestDocument) {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
