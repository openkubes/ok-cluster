package runner

import (
	"context"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestPlatformObservationStageBundleLoadsExactReadOnlyCursor(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, err := LoadPlatformObservationStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "platform-observation" || decision.Authority != "gitops" || decision.RequiresAuthorization || decision.Operation != "" {
		t.Fatalf("unexpected platform observation decision: %#v %v", decision, err)
	}
	if _, err := (VerifiedPlatformObservationStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified platform observation bundle exposed decision")
	}
}

func TestPlatformObservationStageBundleRejectsProfileOrHistoryMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*platformObservationBundleTestFixture){
		"incomplete prefix": func(f *platformObservationBundleTestFixture) { f.config.Receipts = f.config.Receipts[:9] },
		"foreign digest":    func(f *platformObservationBundleTestFixture) { f.config.ExpectedProfileDigest = runnerStageSHA("f") },
		"foreign profile": func(f *platformObservationBundleTestFixture) {
			f.config.Profile.PlatformRevision = runnerStageSHA("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := platformObservationBundleFixture(t)
			mutate(&fixture)
			if _, err := LoadPlatformObservationStageBundle(fixture.config); err == nil {
				t.Fatal("invalid platform observation bundle was accepted")
			}
		})
	}
}

func TestPlatformObservationStageBundleOpensWithoutClusterContact(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, err := LoadPlatformObservationStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := platformObservationRuntime(t, bundle, "ledger-token", "argo-reader-token")
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.verified {
		t.Fatal("opened platform observation stage is not verified")
	}
	if _, err := (OpenedPlatformObservationStage{}).Run(context.Background()); err == nil {
		t.Fatal("unopened platform observation stage could run")
	}

	runtime = platformObservationRuntime(t, bundle, "shared-token", "shared-token")
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared ledger/Argo credential opened platform observation")
	}
	runtime = platformObservationRuntime(t, bundle, "ledger-token", "argo-reader-token")
	runtime.Runtime.material.Target.CAPIClusterUID = "replacement-runtime-uid"
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("replacement runtime target opened platform observation")
	}
}

type platformObservationBundleTestFixture struct {
	config PlatformObservationStageBundleConfig
}

func platformObservationBundleFixture(t *testing.T) platformObservationBundleTestFixture {
	t.Helper()
	base := platformApplicationsBundleFixture(t)
	_, _, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{PlanPath: base.config.PlanPath, PlanExpected: base.config.PlanExpected, Receipts: base.config.Receipts})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 17, 20, 1, 0, 0, time.UTC)
	receipt, err := stagereceipt.New(base.plan, "platform-applications", []stagereceipt.Verified{prefix[8]}, "SUCCEEDED", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2"), at)
	if err != nil {
		t.Fatal(err)
	}
	receipts := appendStageReceipt(t, t.TempDir(), base.config.Receipts, receipt, "platform-applications.json")
	return platformObservationBundleTestFixture{config: PlatformObservationStageBundleConfig{
		StageResumeConfig: StageResumeConfig{PlanPath: base.config.PlanPath, PlanExpected: base.config.PlanExpected, Receipts: receipts},
		Profile:           base.config.Expected.Profile, ExpectedProfileDigest: base.profileDigest,
	}}
}

func platformObservationRuntime(t *testing.T, bundle VerifiedPlatformObservationStageBundle, ledgerToken, argoToken string) PlatformObservationStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ca := testCA(t)
	ledgerTokenPath := writeBundleFile(t, root, "ledger-token", []byte(ledgerToken))
	argoTokenPath := writeBundleFile(t, root, "argo-token", []byte(argoToken))
	caPath := writeBundleFile(t, root, "ca.crt", ca)
	runtime := platformObservationRuntimeMaterial(t, bundle)
	return PlatformObservationStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{Endpoint: "https://192.0.2.10:6443", Namespace: "openkubes-execution-system", TokenFile: ledgerTokenPath, CAFile: caPath},
		Argo: KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.30:6443", AuthorityIdentity: bundle.plan.Authorities.GitOps,
			TokenFile: argoTokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
		},
		Runtime: runtime, Capability: inertPlatformCapabilitySource{}, PollInterval: time.Second, PollTimeout: time.Minute,
		Clock: time.Now, Wait: func(context.Context, time.Duration) error { return nil },
	}
}

func platformObservationRuntimeMaterial(t *testing.T, bundle VerifiedPlatformObservationStageBundle) VerifiedRuntimeBindingMaterial {
	t.Helper()
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND", PlanDigest: bundle.plan.PlanDigest,
		IntentRevision: bundle.plan.IntentRevision, EnablementRevision: bundle.plan.EnablementRevision,
		PlatformRevision: bundle.plan.PlatformRevision, ExecutionFixture: bundle.plan.ExecutionFixture,
		Target:   RuntimeBindingTarget{Name: bundle.plan.ContractIdentity.Name, CAPIClusterUID: targetAccessRuntimeUID, TargetIdentityScheme: "capi-cluster-uid/v1", WorkloadAPIEndpoint: "https://192.0.2.20:6443", WorkloadAPICAData: "Y2E=", WorkloadAPICADigest: runnerStageSHA("1"), KubeSystemUID: "kube-system-runtime-uid"},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "local-path-runtime-uid", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: runnerStageSHA("2"), NetworkEvidenceDigest: runnerStageSHA("3")},
	}
	raw, err := canonicalRuntimeBinding(material)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding", PlanDigest: bundle.plan.PlanDigest,
		IntentRevision: bundle.plan.IntentRevision, TargetClusterUIDDigest: runnerStageSHA("0"), WorkloadAPICADigest: runnerStageSHA("1"),
		KubeSystemUIDDigest: runnerStageSHA("4"), LocalPathStorageUIDDigest: runnerStageSHA("5"),
		LifecycleEvidenceDigest: runnerStageSHA("2"), NetworkEvidenceDigest: runnerStageSHA("3"),
		PrivateMaterialDigest: runnerStageSHA("6"), PersistentMutationAllowed: false,
	}
	receipt.TargetClusterUIDDigest = digestForTest(material.Target.CAPIClusterUID)
	receipt.KubeSystemUIDDigest = digestForTest(material.Target.KubeSystemUID)
	receipt.LocalPathStorageUIDDigest = digestForTest(material.Storage.UID)
	receipt.PrivateMaterialDigest = digestForBytes(raw)
	return VerifiedRuntimeBindingMaterial{material: material, raw: raw, receipt: receipt, verified: true}
}

func digestForTest(value string) string  { return digest.SHA256([]byte(value)) }
func digestForBytes(value []byte) string { return digest.SHA256(value) }

var _ observation.PlatformCapabilitySource = inertPlatformCapabilitySource{}
