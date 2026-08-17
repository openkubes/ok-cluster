package runner

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestLoadAggregateEvidenceStageFileRuntimeBindsPrivateRuntimeInputs(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(fixture)
	if err != nil {
		t.Fatal(err)
	}
	_, _, prefix, err := loadStageResumeWithPrefix(fixture.StageResumeConfig)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleReceipt, _ := prefix[1].Receipt()
	networkReceipt, _ := prefix[4].Receipt()
	runtime := aggregateRuntimeBindingMaterial(t, bundle)
	runtime.material.Evidence.LifecycleEvidenceDigest = lifecycleReceipt.EvidenceDigest
	runtime.material.Evidence.NetworkEvidenceDigest = networkReceipt.EvidenceDigest
	runtime.receipt.LifecycleEvidenceDigest = lifecycleReceipt.EvidenceDigest
	runtime.receipt.NetworkEvidenceDigest = networkReceipt.EvidenceDigest
	runtime.raw, err = canonicalRuntimeBinding(runtime.material)
	if err != nil {
		t.Fatal(err)
	}
	runtime.receipt.PrivateMaterialDigest = digest.SHA256(runtime.raw)
	runtimePath, receiptPath := writeRuntimeBindingReplayFiles(t, runtime)

	expected := bundleExpected(bundle)
	networkProfile := runnerAggregateNetworkProfile(expected)
	_, platformProfile := runnerPlatformApplications(t, expected)
	capability := aggregateCapabilityState(t, bundle, platformProfile, time.Date(2026, 8, 17, 22, 1, 0, 0, time.UTC))
	capabilityRaw, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	capabilityPath := writeBundleFile(t, root, "platform-capability.json", capabilityRaw)
	argoCA := testCA(t)
	argoCAPath := writeBundleFile(t, root, "argo-ca.crt", argoCA)
	workloadCAPath := writeBundleFile(t, root, "workload-ca.crt", testCA(t))
	workloadTokenPath := writeBundleFile(t, root, "workload-token", []byte("short-lived-workload-token"))

	config := AggregateEvidenceStageFileRuntimeConfig{
		Bundle: fixture.StageResumeConfig, NetworkProfile: networkProfile, PlatformProfile: platformProfile,
		Ledger:                   KubernetesLedgerConfig{Endpoint: "https://192.0.2.12:6443", Namespace: "openkubes-execution-system", TokenFile: "ledger-token", CAFile: "ledger-ca"},
		Management:               KubernetesAuthorityConfig{Endpoint: "https://192.0.2.12:6443", AuthorityIdentity: expected.ManagementAuthority, TokenFile: "management-token", CAFile: "management-ca"},
		Argo:                     KubernetesAuthorityConfig{Endpoint: "https://192.0.2.13:6443", AuthorityIdentity: expected.GitOpsAuthority, TokenFile: "argo-token", CAFile: argoCAPath},
		ExpectedWorkloadEndpoint: runtime.material.Target.WorkloadAPIEndpoint,
		WorkloadTokenFile:        workloadTokenPath, WorkloadCAFile: workloadCAPath,
		RuntimeMaterialPath: runtimePath, RuntimeReceiptPath: receiptPath,
		CapabilityPath: capabilityPath, ExpectedCapabilityDigest: capability.EvidenceDigest,
		Clock: func() time.Time { return time.Date(2026, 8, 17, 22, 2, 0, 0, time.UTC) },
	}
	loaded, err := LoadAggregateEvidenceStageFileRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Observer.Argo.CABundleDigest != digest.SHA256(argoCA) || loaded.Observer.ExpectedManagementAuthority != expected.ManagementAuthority || loaded.Observer.ExpectedArgoAuthority != expected.GitOpsAuthority {
		t.Fatalf("aggregate authority binding differs: %#v", loaded.Observer)
	}
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: expected.IntentRevision,
		EnablementRevision: expected.EnablementRevision, PlatformRevision: expected.PlatformRevision,
		TargetClusterUID: runtime.material.Target.CAPIClusterUID,
		Required:         []string{"InfrastructureReady", "ControlPlaneAvailable", "NetworkReady", "PlatformReady"},
	}
	authority, err := loaded.Observer.WorkloadAuthority.ResolveWorkloadAuthority(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Endpoint != runtime.material.Target.WorkloadAPIEndpoint || authority.AuthorityIdentity != runtime.material.Target.CAPIClusterUID || authority.CABundleDigest != runtime.material.Target.WorkloadAPICADigest || authority.TokenFile != workloadTokenPath || authority.CAFile != workloadCAPath {
		t.Fatalf("runtime-bound workload authority differs: %#v", authority)
	}
	source, err := loaded.Observer.PlatformCapability.ResolvePlatformCapability(context.Background(), policy, platformProfile)
	if err != nil {
		t.Fatal(err)
	}
	observedCapability, err := source.Capability(context.Background())
	if err != nil || observedCapability != capability {
		t.Fatalf("runtime-bound platform capability differs: %#v %v", observedCapability, err)
	}

	foreign := policy
	foreign.TargetClusterUID = "foreign-target-uid"
	if _, err := loaded.Observer.WorkloadAuthority.ResolveWorkloadAuthority(context.Background(), foreign); err == nil {
		t.Fatal("foreign runtime target was accepted")
	}

	config.ExpectedWorkloadEndpoint = "https://192.0.2.99:6443"
	if _, err := LoadAggregateEvidenceStageFileRuntime(config); err == nil {
		t.Fatal("foreign workload endpoint was accepted")
	}
	config.ExpectedWorkloadEndpoint = runtime.material.Target.WorkloadAPIEndpoint
	config.Argo.CAFile = ""
	if _, err := LoadAggregateEvidenceStageFileRuntime(config); err == nil {
		t.Fatal("missing GitOps CA was accepted")
	}
}

func TestLoadAggregateEvidenceStageFileRuntimeRequiresPrivateCredentials(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(fixture)
	if err != nil {
		t.Fatal(err)
	}
	runtime := aggregateRuntimeBindingMaterial(t, bundle)
	_, _, prefix, err := loadStageResumeWithPrefix(fixture.StageResumeConfig)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleReceipt, _ := prefix[1].Receipt()
	networkReceipt, _ := prefix[4].Receipt()
	runtime.material.Evidence.LifecycleEvidenceDigest = lifecycleReceipt.EvidenceDigest
	runtime.material.Evidence.NetworkEvidenceDigest = networkReceipt.EvidenceDigest
	runtime.receipt.LifecycleEvidenceDigest = lifecycleReceipt.EvidenceDigest
	runtime.receipt.NetworkEvidenceDigest = networkReceipt.EvidenceDigest
	runtime.raw, _ = canonicalRuntimeBinding(runtime.material)
	runtime.receipt.PrivateMaterialDigest = digest.SHA256(runtime.raw)
	runtimePath, receiptPath := writeRuntimeBindingReplayFiles(t, runtime)
	_, platformProfile := runnerPlatformApplications(t, bundleExpected(bundle))
	capability := aggregateCapabilityState(t, bundle, platformProfile, time.Now().UTC())
	capabilityRaw, _ := json.Marshal(capability)
	root := t.TempDir()
	config := AggregateEvidenceStageFileRuntimeConfig{
		Bundle: fixture.StageResumeConfig, NetworkProfile: runnerAggregateNetworkProfile(bundleExpected(bundle)), PlatformProfile: platformProfile,
		Argo:                     KubernetesAuthorityConfig{CAFile: writeBundleFile(t, root, "argo-ca.crt", testCA(t))},
		ExpectedWorkloadEndpoint: runtime.material.Target.WorkloadAPIEndpoint,
		RuntimeMaterialPath:      runtimePath, RuntimeReceiptPath: receiptPath,
		CapabilityPath: writeBundleFile(t, root, "capability.json", capabilityRaw), ExpectedCapabilityDigest: capability.EvidenceDigest,
	}
	if _, err := LoadAggregateEvidenceStageFileRuntime(config); err == nil {
		t.Fatal("missing workload credential files were accepted")
	}
	if _, err := os.Stat(runtimePath); err != nil {
		t.Fatal(err)
	}
}
