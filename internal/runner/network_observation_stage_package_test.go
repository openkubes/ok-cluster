package runner

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildNetworkObservationStagePackageBindsPublicAndPrivateIdentities(t *testing.T) {
	config := networkObservationStagePackageConfig(t)
	packaged, err := BuildNetworkObservationStagePackage(config)
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
		t.Fatalf("unexpected network observation package: %#v", objects)
	}
	if bytes.Contains(raw, []byte(`"targetClusterUid"`)) || bytes.Contains(raw, []byte(`"targetIdentityScheme"`)) || bytes.Contains(raw, []byte(`"caBundleDigest"`)) {
		t.Fatal("private workload binding was copied into public package output")
	}
	if receipt.Format != NetworkObservationStagePackageFormat || receipt.StageID != "network-observation" || receipt.PackageDigest != digest.SHA256(raw) || receipt.AuthorizationState != "NOT_REQUIRED" || receipt.MutationAllowed {
		t.Fatalf("unexpected network observation package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) {
		t.Fatal("network observation package component digests differ")
	}
	if !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "NetworkPolicy", "Job"}) || receipt.WorkloadBindingDigest != config.ExpectedWorkloadBindingDigest {
		t.Fatalf("network observation package identities differ: %#v", receipt)
	}
	raw[0] = 'x'
	again, _ := packaged.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained network package")
	}
}

func TestBuildNetworkObservationStagePackageFailsClosed(t *testing.T) {
	valid := networkObservationStagePackageConfig(t)
	for name, mutate := range map[string]func(*NetworkObservationStagePackageConfig){
		"changed template": func(config *NetworkObservationStagePackageConfig) {
			config.JobTemplate = append(config.JobTemplate, '\n')
		},
		"wrong template digest": func(config *NetworkObservationStagePackageConfig) {
			config.JobTemplateDigest = bundleSHA("f")
		},
		"shared credentials": func(config *NetworkObservationStagePackageConfig) {
			config.WorkloadCredentialSecret = config.ManagementCredentialSecret
		},
		"binding endpoint differs": func(config *NetworkObservationStagePackageConfig) {
			config.WorkloadAPIURL = "https://192.0.2.21:6443"
			config.WorkloadAPICIDR = "192.0.2.21/32"
		},
		"foreign binding digest": func(config *NetworkObservationStagePackageConfig) {
			config.ExpectedWorkloadBindingDigest = bundleSHA("e")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildNetworkObservationStagePackage(config); err == nil {
				t.Fatal("unsafe network observation package was accepted")
			}
		})
	}
	if _, err := (VerifiedNetworkObservationStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified network package bytes were exposed")
	}
	if _, err := (VerifiedNetworkObservationStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified network package receipt was exposed")
	}
}

func networkObservationStagePackageConfig(t *testing.T) NetworkObservationStagePackageConfig {
	t.Helper()
	input := networkObservationStageInputConfig(t)
	plan, _, prefix, err := loadStageResumeWithPrefix(input.Bundle)
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
	template := networkObservationJobTemplate(t)
	return NetworkObservationStagePackageConfig{
		Input: input, JobTemplate: template, JobTemplateDigest: digest.SHA256(template),
		RunID: "ok147-network-observation-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-network",
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32", ManagementCredentialSecret: "ok147-management-network",
		WorkloadAPIURL: binding.Endpoint, WorkloadAPICIDR: "192.0.2.20/32", WorkloadCredentialSecret: "ok147-workload-network",
		WorkloadBindingPath: bindingPath, ExpectedWorkloadBindingDigest: bindingDigest,
		PollInterval: 15 * time.Second, PollTimeout: 5 * time.Minute,
	}
}
