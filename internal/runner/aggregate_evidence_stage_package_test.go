package runner

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildAggregateEvidenceStagePackageBindsPublicAndPrivateIdentities(t *testing.T) {
	config := aggregateEvidenceStagePackageConfig(t)
	packaged, err := BuildAggregateEvidenceStagePackage(config)
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
		t.Fatalf("unexpected aggregate evidence package: %#v", objects)
	}
	runtimeRaw, _ := readBoundedRegular(config.RuntimeBindingMaterialPath, maximumRuntimeBindingMaterialFileBytes)
	capabilityRaw, _ := readBoundedRegular(config.PlatformCapabilityPath, maximumPlatformCapabilityBytes)
	if bytes.Contains(raw, runtimeRaw) || bytes.Contains(raw, capabilityRaw) || bytes.Contains(raw, []byte(targetAccessRuntimeUID)) {
		t.Fatal("private aggregate runtime or capability was copied into public package output")
	}
	if receipt.Format != AggregateEvidenceStagePackageFormat || receipt.StageID != "aggregate-evidence" || receipt.PackageDigest != digest.SHA256(raw) || receipt.AuthorizationState != "NOT_REQUIRED" || receipt.MutationAllowed {
		t.Fatalf("unexpected aggregate evidence package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) {
		t.Fatal("aggregate evidence package component digests differ")
	}
	if !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "NetworkPolicy", "Job"}) || receipt.PlatformCapabilityDigest != config.ExpectedPlatformCapabilityDigest {
		t.Fatalf("aggregate evidence package identities differ: %#v", receipt)
	}
	raw[0] = 'x'
	again, _ := packaged.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained aggregate evidence package")
	}
}

func TestBuildAggregateEvidenceStagePackageFailsClosed(t *testing.T) {
	valid := aggregateEvidenceStagePackageConfig(t)
	for name, mutate := range map[string]func(*AggregateEvidenceStagePackageConfig){
		"changed template": func(config *AggregateEvidenceStagePackageConfig) {
			config.JobTemplate = append(config.JobTemplate, '\n')
		},
		"wrong template digest": func(config *AggregateEvidenceStagePackageConfig) { config.JobTemplateDigest = bundleSHA("f") },
		"shared credentials": func(config *AggregateEvidenceStagePackageConfig) {
			config.ArgoCredentialSecret = config.ManagementCredentialSecret
		},
		"runtime endpoint differs": func(config *AggregateEvidenceStagePackageConfig) {
			config.WorkloadAPIURL, config.WorkloadAPICIDR = "https://192.0.2.21:6443", "192.0.2.21/32"
		},
		"foreign capability": func(config *AggregateEvidenceStagePackageConfig) {
			config.ExpectedPlatformCapabilityDigest = bundleSHA("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildAggregateEvidenceStagePackage(config); err == nil {
				t.Fatal("unsafe aggregate evidence package was accepted")
			}
		})
	}
	if _, err := (VerifiedAggregateEvidenceStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified aggregate evidence package bytes were exposed")
	}
	if _, err := (VerifiedAggregateEvidenceStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified aggregate evidence package receipt was exposed")
	}
}

func aggregateEvidenceStagePackageConfig(t *testing.T) AggregateEvidenceStagePackageConfig {
	t.Helper()
	fixture := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(fixture)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	aggregatePath := writeAggregateEvidenceProfile(t, root, fixture.Profile)
	networkPath, networkDigest, platformPath, platformDigest := writeAggregateSourceProfiles(t, root, fixture)
	input := AggregateEvidenceStageInputConfig{
		Bundle: fixture.StageResumeConfig, AggregateEvidenceProfilePath: aggregatePath,
		ExpectedAggregateProfileDigest: fixture.ExpectedProfileDigest,
		NetworkProfilePath:             networkPath, ExpectedNetworkProfileDigest: networkDigest,
		PlatformProfilePath: platformPath, ExpectedPlatformProfileDigest: platformDigest,
		ConfigMapName: "ok147-aggregate-evidence-input",
	}
	runtime := aggregateRuntimeBindingMaterial(t, bundle)
	lifecycleReceipt, err := bundle.prefix[1].Receipt()
	if err != nil {
		t.Fatal(err)
	}
	networkReceipt, err := bundle.prefix[4].Receipt()
	if err != nil {
		t.Fatal(err)
	}
	runtime.material.Evidence.LifecycleEvidenceDigest = lifecycleReceipt.EvidenceDigest
	runtime.material.Evidence.NetworkEvidenceDigest = networkReceipt.EvidenceDigest
	runtime.receipt.LifecycleEvidenceDigest = lifecycleReceipt.EvidenceDigest
	runtime.receipt.NetworkEvidenceDigest = networkReceipt.EvidenceDigest
	runtime.raw, err = canonicalRuntimeBinding(runtime.material)
	if err != nil {
		t.Fatal(err)
	}
	runtime.receipt.PrivateMaterialDigest = digest.SHA256(runtime.raw)
	runtimePath, runtimeReceiptPath := writeRuntimeBindingReplayFiles(t, runtime)
	_, platformProfile := runnerPlatformApplications(t, bundleExpected(bundle))
	capability := aggregateCapabilityState(t, bundle, platformProfile, time.Date(2026, 8, 17, 23, 0, 0, 0, time.UTC))
	capabilityRaw, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	capabilityPath := writeBundleFile(t, root, "platform-capability.json", capabilityRaw)
	template := aggregateEvidenceJobTemplate(t)
	return AggregateEvidenceStagePackageConfig{
		Input: input, JobTemplate: template, JobTemplateDigest: digest.SHA256(template),
		RunID: "ok147-aggregate-evidence-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-aggregate",
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32", ManagementCredentialSecret: "ok147-management-aggregate",
		WorkloadAPIURL: runtime.material.Target.WorkloadAPIEndpoint, WorkloadAPICIDR: "192.0.2.40/32", WorkloadCredentialSecret: "ok147-workload-aggregate",
		ArgoAPIURL: "https://192.0.2.30:6443", ArgoAPICIDR: "192.0.2.30/32", ArgoCredentialSecret: "ok147-argo-aggregate",
		RuntimeBindingSecret: "ok147-runtime-binding-run-01", RuntimeBindingMaterialPath: runtimePath, RuntimeBindingReceiptPath: runtimeReceiptPath,
		PlatformCapabilitySecret: "ok147-platform-capability-01", PlatformCapabilityPath: capabilityPath,
		ExpectedPlatformCapabilityDigest: capability.EvidenceDigest,
	}
}
