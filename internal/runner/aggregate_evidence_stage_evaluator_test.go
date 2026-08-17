package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestAggregateEvidenceStageEvaluatorMapsDeterministicReadiness(t *testing.T) {
	for readiness, outcome := range map[string]string{"True": "SUCCEEDED", "False": "FAILED", "Unknown": "STOPPED"} {
		t.Run(readiness, func(t *testing.T) {
			config := aggregateEvidenceBundleFixture(t)
			bundle, err := LoadAggregateEvidenceStageBundle(config)
			if err != nil {
				t.Fatal(err)
			}
			source := &aggregateEvaluationSource{at: time.Date(2026, 8, 17, 22, 30, 0, 0, time.UTC), readiness: readiness}
			evaluator, err := NewAggregateEvidenceStageEvaluator(AggregateEvidenceStageEvaluatorConfig{
				Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: targetAccessRuntimeUID,
				Profile: bundle.profile, Source: source,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.Evaluate(context.Background())
			if err != nil || result.Outcome != outcome || result.EvidenceDigest == "" || result.CompletedAt != source.at || source.calls != 1 {
				t.Fatalf("unexpected aggregate result: %#v calls=%d err=%v", result, source.calls, err)
			}
			stage, stageDigest, _ := bundle.plan.Stage("aggregate-evidence")
			if evaluator.Binding() != (execution.StageEvaluationBinding{PlanDigest: bundle.plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest, Authority: "runner", ContractRevision: bundle.plan.IntentRevision}) {
				t.Fatal("aggregate evaluator binding differs from verified stage")
			}
		})
	}
}

func TestAggregateEvidenceStageEvaluatorFailsClosed(t *testing.T) {
	config := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAggregateEvidenceStageEvaluator(AggregateEvidenceStageEvaluatorConfig{Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: "replacement-runtime-uid", Profile: bundle.profile, Source: &aggregateEvaluationSource{}}); err == nil {
		t.Fatal("replacement target opened aggregate evaluator")
	}
	evaluator, err := NewAggregateEvidenceStageEvaluator(AggregateEvidenceStageEvaluatorConfig{Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: targetAccessRuntimeUID, Profile: bundle.profile, Source: &aggregateEvaluationSource{err: errors.New("sensitive endpoint detail")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluator.Evaluate(context.Background()); err == nil || err.Error() != "bounded aggregate evidence collection failed" {
		t.Fatalf("raw source failure escaped aggregate evaluator: %v", err)
	}
}

func TestAggregateEvidenceStageBundleOpensWithoutClusterContact(t *testing.T) {
	config := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := aggregateEvidenceRuntime(t, bundle, "ledger-token", "management-token", "argo-token")
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.verified {
		t.Fatal("opened aggregate evidence stage is not verified")
	}
	if _, err := (OpenedAggregateEvidenceStage{}).Run(context.Background()); err == nil {
		t.Fatal("unopened aggregate evidence stage could run")
	}

	runtime = aggregateEvidenceRuntime(t, bundle, "shared-token", "shared-token", "argo-token")
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared ledger/management credential opened aggregate evidence")
	}
	runtime = aggregateEvidenceRuntime(t, bundle, "shared-token", "management-token", "shared-token")
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared ledger/Argo credential opened aggregate evidence")
	}
	runtime = aggregateEvidenceRuntime(t, bundle, "ledger-token", "shared-token", "shared-token")
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared management/Argo credential opened aggregate evidence")
	}
	runtime = aggregateEvidenceRuntime(t, bundle, "ledger-token", "management-token", "argo-token")
	runtime.Observer.NetworkProfile.ExpectedNodeCount++
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("changed Network profile opened aggregate evidence")
	}
}

type aggregateEvaluationSource struct {
	at        time.Time
	readiness string
	err       error
	calls     int
}

func (source *aggregateEvaluationSource) Observe(_ context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	source.calls++
	if source.err != nil {
		return observation.VerifiedResult{}, source.err
	}
	evidence := []observation.Evidence{
		aggregateRunnerEvidence(policy, "InfrastructureReady"),
		aggregateRunnerEvidence(policy, "ControlPlaneAvailable"),
		aggregateRunnerEvidence(policy, "NetworkReady"),
		aggregateRunnerEvidence(policy, "PlatformReady"),
	}
	if source.readiness == "False" {
		evidence[2].Status, evidence[2].Reason = "False", "NetworkUnavailable"
	} else if source.readiness == "Unknown" {
		evidence = evidence[:3]
	}
	return observation.Evaluate(policy, observation.Bundle{
		Format: observation.BundleFormat, IntentRevision: policy.IntentRevision,
		EvaluatedAt: source.at.UTC().Format(time.RFC3339Nano), Evidence: evidence,
	})
}

func aggregateEvidenceRuntime(t *testing.T, bundle VerifiedAggregateEvidenceStageBundle, ledgerToken, managementToken, argoToken string) AggregateEvidenceStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ca := testCA(t)
	caPath := writeBundleFile(t, root, "ca.crt", ca)
	ledgerTokenPath := writeBundleFile(t, root, "ledger-token", []byte(ledgerToken))
	managementTokenPath := writeBundleFile(t, root, "management-token", []byte(managementToken))
	argoTokenPath := writeBundleFile(t, root, "argo-token", []byte(argoToken))
	planExpected := bundleExpected(bundle)
	_, platformProfile := runnerPlatformApplications(t, planExpected)
	networkProfile := runnerAggregateNetworkProfile(planExpected)
	runtime := aggregateRuntimeBindingMaterial(t, bundle)
	return AggregateEvidenceStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{Endpoint: "https://192.0.2.10:6443", Namespace: "openkubes-execution-system", TokenFile: ledgerTokenPath, CAFile: caPath},
		Observer: KubernetesAggregateObserverConfig{
			Management:                  KubernetesAuthorityConfig{Endpoint: "https://192.0.2.20:6443", AuthorityIdentity: bundle.plan.Authorities.Management, TokenFile: managementTokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca)},
			ExpectedManagementAuthority: bundle.plan.Authorities.Management,
			Argo:                        KubernetesAuthorityConfig{Endpoint: "https://192.0.2.30:6443", AuthorityIdentity: bundle.plan.Authorities.GitOps, TokenFile: argoTokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca)},
			ExpectedArgoAuthority:       bundle.plan.Authorities.GitOps,
			Namespace:                   bundle.plan.ContractIdentity.Namespace, Name: bundle.plan.ContractIdentity.Name, HCPName: bundle.plan.ContractIdentity.Name + "-cilium",
			NetworkProfile: networkProfile, PlatformProfile: platformProfile,
			WorkloadAuthority: WorkloadAuthorityResolverFunc(func(_ context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
				return KubernetesAuthorityConfig{AuthorityIdentity: policy.TargetClusterUID}, nil
			}),
			PlatformCapability: PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
				return inertPlatformCapabilitySource{}, nil
			}),
			Clock: time.Now,
		},
		Runtime: runtime,
	}
}

func bundleExpected(bundle VerifiedAggregateEvidenceStageBundle) stageplan.Expected {
	return stageplan.Expected{
		ContractIdentity: bundle.plan.ContractIdentity, IntentRevision: bundle.plan.IntentRevision,
		EnablementRevision: bundle.plan.EnablementRevision, PlatformRevision: bundle.plan.PlatformRevision,
		ExecutionFixture: bundle.plan.ExecutionFixture, InfrastructureAuthority: bundle.plan.Authorities.Infrastructure,
		ManagementAuthority: bundle.plan.Authorities.Management, GitOpsAuthority: bundle.plan.Authorities.GitOps,
	}
}

func aggregateRuntimeBindingMaterial(t *testing.T, bundle VerifiedAggregateEvidenceStageBundle) VerifiedRuntimeBindingMaterial {
	t.Helper()
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND", PlanDigest: bundle.plan.PlanDigest,
		IntentRevision: bundle.plan.IntentRevision, EnablementRevision: bundle.plan.EnablementRevision,
		PlatformRevision: bundle.plan.PlatformRevision, ExecutionFixture: bundle.plan.ExecutionFixture,
		Target:   RuntimeBindingTarget{Name: bundle.plan.ContractIdentity.Name, CAPIClusterUID: targetAccessRuntimeUID, TargetIdentityScheme: "capi-cluster-uid/v1", WorkloadAPIEndpoint: "https://192.0.2.40:6443", WorkloadAPICAData: "Y2E=", WorkloadAPICADigest: runnerStageSHA("1"), KubeSystemUID: "kube-system-runtime-uid"},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "local-path-runtime-uid", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: runnerStageSHA("2"), NetworkEvidenceDigest: runnerStageSHA("3")},
	}
	raw, err := canonicalRuntimeBinding(material)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding", PlanDigest: bundle.plan.PlanDigest,
		IntentRevision: bundle.plan.IntentRevision, TargetClusterUIDDigest: digest.SHA256([]byte(material.Target.CAPIClusterUID)), WorkloadAPICADigest: runnerStageSHA("1"),
		KubeSystemUIDDigest: digest.SHA256([]byte(material.Target.KubeSystemUID)), LocalPathStorageUIDDigest: digest.SHA256([]byte(material.Storage.UID)),
		LifecycleEvidenceDigest: runnerStageSHA("2"), NetworkEvidenceDigest: runnerStageSHA("3"),
		PrivateMaterialDigest: digest.SHA256(raw), PersistentMutationAllowed: false,
	}
	return VerifiedRuntimeBindingMaterial{material: material, raw: raw, receipt: receipt, verified: true}
}
