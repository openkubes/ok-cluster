package runner

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildTargetAccessStagePackageCorrelatesPublicAndPrivateInputs(t *testing.T) {
	config := targetAccessStagePackageConfig(t)
	packaged, err := BuildTargetAccessStagePackage(config)
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
		t.Fatalf("unexpected target-access package object set: %#v", objects)
	}
	if bytes.Contains(raw, []byte(`"targetClusterUid"`)) || bytes.Contains(raw, []byte(`"caBundleDigest"`)) || bytes.Contains(raw, []byte("target-access-workload-token")) {
		t.Fatal("private workload authority was copied into target-access package")
	}
	if receipt.Format != TargetAccessStagePackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "target-access" || receipt.PackageDigest != digest.SHA256(raw) || receipt.AuthorizationState != "VERIFIED" || receipt.MutationAllowed || receipt.WorkloadBindingDigest != config.ExpectedWorkloadBindingDigest {
		t.Fatalf("unexpected target-access package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) || !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "NetworkPolicy", "Job"}) {
		t.Fatal("target-access package component identities differ")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, config.ExpectedWorkloadBindingDigest)
	if err != nil || receipt.TargetIdentityDigest != digest.SHA256([]byte(binding.TargetClusterUID)) {
		t.Fatal("target-access package does not correlate the private runtime target")
	}
	job := objects["Job"]
	container := arrayAt(t, objectAt(t, objectAt(t, objectAt(t, job, "spec"), "template"), "spec"), "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if argumentValue(args, "--workload-binding-digest") != config.ExpectedWorkloadBindingDigest || argumentValue(args, "--cluster-role") != config.ClusterRole {
		t.Fatalf("target-access Job and package bindings differ: %v", args)
	}
	raw[0] = 'x'
	again, err := packaged.Bytes()
	if err != nil || again[0] != '{' {
		t.Fatal("caller mutated retained target-access package")
	}
	receipt.ObjectKinds[0] = "Changed"
	againReceipt, err := packaged.Receipt()
	if err != nil || againReceipt.ObjectKinds[0] != "ConfigMap" {
		t.Fatal("caller mutated retained target-access package receipt")
	}
}

func TestBuildTargetAccessStagePackageFailsClosed(t *testing.T) {
	valid := targetAccessStagePackageConfig(t)
	for name, mutate := range map[string]func(*TargetAccessStagePackageConfig){
		"changed template": func(config *TargetAccessStagePackageConfig) { config.JobTemplate = append(config.JobTemplate, '\n') },
		"shared credentials": func(config *TargetAccessStagePackageConfig) {
			config.WorkloadCredentialSecret = config.LedgerCredentialSecret
		},
		"binding endpoint differs": func(config *TargetAccessStagePackageConfig) {
			config.WorkloadAPIURL, config.WorkloadAPICIDR = "https://192.0.2.21:6443", "192.0.2.21/32"
		},
		"foreign binding digest": func(config *TargetAccessStagePackageConfig) { config.ExpectedWorkloadBindingDigest = bundleSHA("e") },
		"wrong object identity":  func(config *TargetAccessStagePackageConfig) { config.ClusterRole = "another-role" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildTargetAccessStagePackage(config); err == nil {
				t.Fatal("unsafe target-access stage package was accepted")
			}
		})
	}
	if _, err := (VerifiedTargetAccessStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified target-access package bytes were exposed")
	}
	if _, err := (VerifiedTargetAccessStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified target-access package receipt was exposed")
	}
}

func targetAccessStagePackageConfig(t *testing.T) TargetAccessStagePackageConfig {
	t.Helper()
	fixture := targetAccessBundleFixture(t)
	runtimeConfig := targetAccessRuntime(t, fixture.plan)
	values := validTargetAccessStageJobValues()
	template := targetAccessStageJobTemplate(t)
	return TargetAccessStagePackageConfig{
		Bundle: fixture.config, JobTemplate: template, JobTemplateDigest: digest.SHA256(template),
		RunID: values.RunID, ImageDigest: values.ImageDigest, InputConfigMap: values.InputConfigMap,
		ObservabilityNamespace: values.ObservabilityNamespace, ManagerServiceAccount: values.ManagerServiceAccount,
		ClusterRole: values.ClusterRole, ClusterRoleBinding: values.ClusterRoleBinding,
		PlatformRole: values.PlatformRole, PlatformRoleBinding: values.PlatformRoleBinding,
		KubeSystemRole: values.KubeSystemRole, KubeSystemRoleBinding: values.KubeSystemRoleBinding,
		LedgerAPIURL: values.LedgerAPIURL, LedgerAPICIDR: values.LedgerAPICIDR, LedgerCredentialSecret: values.LedgerCredentialSecret,
		WorkloadAPIURL: "https://192.0.2.147:6443", WorkloadAPICIDR: "192.0.2.147/32", WorkloadCredentialSecret: values.WorkloadCredentialSecret,
		WorkloadBindingPath: runtimeConfig.Workload.Path, ExpectedWorkloadBindingDigest: runtimeConfig.Workload.ExpectedBindingDigest,
	}
}
