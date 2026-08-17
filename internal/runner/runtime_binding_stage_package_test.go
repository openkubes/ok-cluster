package runner

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildRuntimeBindingStagePackageCorrelatesPublicAndPrivateInputs(t *testing.T) {
	config := runtimeBindingStagePackageConfig(t)
	packaged, err := BuildRuntimeBindingStagePackage(config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := packaged.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 3 || objects["ConfigMap"] == nil || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected runtime binding package: %#v", objects)
	}
	if bytes.Contains(raw, []byte(`"targetClusterUid"`)) || bytes.Contains(raw, []byte(`"targetIdentityScheme"`)) || bytes.Contains(raw, []byte(`"caBundleDigest"`)) {
		t.Fatal("private workload binding was copied into runtime binding package")
	}
	if receipt.Format != RuntimeBindingStagePackageFormat || receipt.StageID != "runtime-binding" || receipt.PackageDigest != digest.SHA256(raw) || receipt.AuthorizationState != "NOT_REQUIRED" || receipt.MutationAllowed || receipt.WorkloadBindingDigest != config.ExpectedWorkloadBindingDigest {
		t.Fatalf("unexpected runtime binding package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) || !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "NetworkPolicy", "Job"}) {
		t.Fatal("runtime binding package component identities differ")
	}
	raw[0] = 'x'
	again, _ := packaged.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained runtime binding package")
	}
}

func TestBuildRuntimeBindingStagePackageFailsClosed(t *testing.T) {
	valid := runtimeBindingStagePackageConfig(t)
	for name, mutate := range map[string]func(*RuntimeBindingStagePackageConfig){
		"changed template": func(config *RuntimeBindingStagePackageConfig) { config.JobTemplate = append(config.JobTemplate, '\n') },
		"shared credentials": func(config *RuntimeBindingStagePackageConfig) {
			config.PersistenceCredentialSecret = config.LedgerCredentialSecret
		},
		"binding endpoint differs": func(config *RuntimeBindingStagePackageConfig) {
			config.WorkloadAPIURL, config.WorkloadAPICIDR = "https://192.0.2.21:6443", "192.0.2.21/32"
		},
		"foreign binding digest": func(config *RuntimeBindingStagePackageConfig) { config.ExpectedWorkloadBindingDigest = bundleSHA("e") },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildRuntimeBindingStagePackage(config); err == nil {
				t.Fatal("unsafe runtime binding package was accepted")
			}
		})
	}
	if _, err := (VerifiedRuntimeBindingStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified runtime binding package bytes were exposed")
	}
	if _, err := (VerifiedRuntimeBindingStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified runtime binding package receipt was exposed")
	}
}

func runtimeBindingStagePackageConfig(t *testing.T) RuntimeBindingStagePackageConfig {
	t.Helper()
	bundleConfig := runtimeBindingBundleConfig(t)
	plan, _, prefix, err := loadStageResumeWithPrefix(bundleConfig)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := prefix[1].Receipt()
	const targetUID = "cluster-runtime-uid-147"
	if digest.SHA256([]byte(targetUID)) != lifecycle.TargetClusterUIDDigest {
		t.Fatal("test target differs from lifecycle receipt")
	}
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: plan.IntentRevision,
		TargetClusterUID: targetUID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: "https://192.0.2.20:6443", CABundleDigest: bundleSHA("9"),
	}
	bindingPath := writeBundleFile(t, t.TempDir(), "binding.json", mustJSON(t, binding))
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	template := runtimeBindingJobTemplate(t)
	return RuntimeBindingStagePackageConfig{
		Bundle: bundleConfig, InputConfigMap: "ok147-runtime-binding-input",
		JobTemplate: template, JobTemplateDigest: digest.SHA256(template), RunID: "ok147-runtime-binding-01",
		ImageDigest:  "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-binding",
		PersistenceCredentialSecret: "ok147-persistence-binding",
		WorkloadAPIURL:              binding.Endpoint, WorkloadAPICIDR: "192.0.2.20/32", WorkloadCredentialSecret: "ok147-workload-binding",
		WorkloadBindingPath: bindingPath, ExpectedWorkloadBindingDigest: bindingDigest,
	}
}
