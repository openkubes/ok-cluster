package runner

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestLoadPlatformObservationStageFileRuntimeCorrelatesPrivateTargetAndCapability(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, err := LoadPlatformObservationStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := platformObservationRuntimeMaterial(t, bundle)
	_, _, prefix, err := loadStageResumeWithPrefix(fixture.config.StageResumeConfig)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := prefix[1].Receipt()
	network, _ := prefix[4].Receipt()
	runtime.material.Evidence.LifecycleEvidenceDigest = lifecycle.EvidenceDigest
	runtime.material.Evidence.NetworkEvidenceDigest = network.EvidenceDigest
	runtime.receipt.LifecycleEvidenceDigest = lifecycle.EvidenceDigest
	runtime.receipt.NetworkEvidenceDigest = network.EvidenceDigest
	runtime.raw, err = canonicalRuntimeBinding(runtime.material)
	if err != nil {
		t.Fatal(err)
	}
	runtime.receipt.PrivateMaterialDigest = digest.SHA256(runtime.raw)
	runtimePath, runtimeReceiptPath := writeRuntimeBindingReplayFiles(t, runtime)
	capability := observation.PlatformCapabilityState{
		Format: observation.PlatformCapabilityFormat, ObservedAt: "2026-08-17T20:05:00Z",
		TargetClusterUID: runtime.material.Target.CAPIClusterUID, IntentRevision: bundle.plan.IntentRevision,
		PlatformRevision: bundle.plan.PlatformRevision, ExecutionFixture: bundle.plan.ExecutionFixture,
		ContractDigest: bundle.profile.CapabilityContractDigest, ExecutableDigest: bundle.profile.CapabilityExecutableDigest, Passed: true,
	}
	capability.EvidenceDigest, err = observation.PlatformCapabilityDigest(capability)
	if err != nil {
		t.Fatal(err)
	}
	rawCapability, _ := json.Marshal(capability)
	capabilityPath := writeBundleFile(t, t.TempDir(), "platform-capability.json", rawCapability)
	config := PlatformObservationStageFileRuntimeConfig{
		Bundle: fixture.config.StageResumeConfig, Profile: fixture.config.Profile,
		Ledger:              KubernetesLedgerConfig{Endpoint: "https://192.0.2.10:6443", Namespace: "openkubes-execution-system", TokenFile: "/private/tmp/ledger-token", CAFile: "/private/tmp/ledger-ca"},
		Argo:                KubernetesAuthorityConfig{Endpoint: "https://192.0.2.30:6443", AuthorityIdentity: "ok-shared", TokenFile: "/private/tmp/argo-token", CAFile: "/private/tmp/argo-ca", CABundleDigest: runnerStageSHA("8")},
		RuntimeMaterialPath: runtimePath, RuntimeReceiptPath: runtimeReceiptPath,
		CapabilityPath: capabilityPath, ExpectedCapabilityDigest: capability.EvidenceDigest,
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	}
	loaded, err := LoadPlatformObservationStageFileRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	loadedCapability, err := loaded.Capability.Capability(context.Background())
	if err != nil || loadedCapability != capability {
		t.Fatalf("capability differs from runtime-bound evidence: %#v %v", loadedCapability, err)
	}
	loadedReceipt, err := loaded.Runtime.Receipt()
	if err != nil || loadedReceipt.TargetClusterUIDDigest != lifecycle.TargetClusterUIDDigest {
		t.Fatalf("runtime target differs from lifecycle history: %#v %v", loadedReceipt, err)
	}

	foreign := capability
	foreign.TargetClusterUID = "replacement-cluster-uid"
	foreign.EvidenceDigest, _ = observation.PlatformCapabilityDigest(foreign)
	foreignRaw, _ := json.Marshal(foreign)
	config.CapabilityPath = writeBundleFile(t, filepath.Dir(capabilityPath), "foreign-capability.json", foreignRaw)
	config.ExpectedCapabilityDigest = foreign.EvidenceDigest
	if _, err := LoadPlatformObservationStageFileRuntime(config); err == nil {
		t.Fatal("capability for a replacement target was accepted")
	}
}
