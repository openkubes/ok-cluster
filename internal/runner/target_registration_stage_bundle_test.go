package runner

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestLoadTargetRegistrationStageBundleBindsPrefixGrantProjectionAndAuthority(t *testing.T) {
	fixture := targetRegistrationBundleFixture(t)
	bundle, err := LoadTargetRegistrationStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "target-registration" || decision.Kind != "Submission" || decision.Operation != "RegisterTarget" || decision.Authority != "gitops" || !decision.RequiresAuthorization {
		t.Fatalf("unexpected target-registration decision: %#v %v", decision, err)
	}
	receipt, err := bundle.Receipt()
	if err != nil || receipt.Format != TargetRegistrationStageBundleReceiptFormat || receipt.State != "VERIFIED" || receipt.PlanDigest != fixture.plan.PlanDigest || receipt.ArtifactDigest != fixture.artifactDigest || receipt.TargetIdentityDigest != digest.SHA256([]byte(targetAccessRuntimeUID)) || receipt.AuthorizationDigest == "" || receipt.ProjectDigest == "" || receipt.RegistrationTemplateDigest == "" || receipt.Authority != "ok-shared" || receipt.CredentialMaterialPresent || receipt.MutationAllowed {
		t.Fatalf("unexpected target-registration receipt: %#v %v", receipt, err)
	}
}

func TestLoadTargetRegistrationStageBundleFailsClosed(t *testing.T) {
	tests := map[string]func(*targetRegistrationBundleTestFixture){
		"implicit prefix":   func(f *targetRegistrationBundleTestFixture) { f.config.Receipts = nil },
		"incomplete prefix": func(f *targetRegistrationBundleTestFixture) { f.config.Receipts = f.config.Receipts[:7] },
		"changed artifact": func(f *targetRegistrationBundleTestFixture) {
			raw, _ := os.ReadFile(f.config.ArtifactPath)
			_ = os.WriteFile(f.config.ArtifactPath, append(raw, '\n'), 0o600)
		},
		"foreign target": func(f *targetRegistrationBundleTestFixture) {
			f.config.Expected.TargetIdentityDigest = runnerStageSHA("f")
		},
		"foreign authority": func(f *targetRegistrationBundleTestFixture) { f.config.Expected.ArgoAuthority = "foreign-gitops" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := targetRegistrationBundleFixture(t)
			mutate(&fixture)
			if _, err := LoadTargetRegistrationStageBundle(fixture.config); err == nil {
				t.Fatal("invalid target-registration bundle was accepted")
			}
		})
	}
	if _, err := (VerifiedTargetRegistrationStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified target-registration bundle exposed decision")
	}
	if _, err := (VerifiedTargetRegistrationStageBundle{}).Receipt(); err == nil {
		t.Fatal("unverified target-registration bundle exposed receipt")
	}
}

type targetRegistrationBundleTestFixture struct {
	config         TargetRegistrationStageBundleConfig
	plan           stageplan.Binding
	artifactDigest string
}

func targetRegistrationBundleFixture(t *testing.T) targetRegistrationBundleTestFixture {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 17, 18, 0, 0, 0, time.UTC)
	expectedPlan := stageplan.Expected{
		ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision:   runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	access := runnerTargetAccessYAML()
	policy := targetCredentialPolicyDocument{
		Format: TargetCredentialPolicyFormat, TargetIdentityDigest: digest.SHA256([]byte(targetAccessRuntimeUID)),
		ServiceAccount:     targetCredentialServiceAccount{Namespace: "kube-system", Name: "ok147-argocd-manager"},
		RequestedAudiences: []string{}, ExpirationSeconds: 10800, CredentialUse: "argocd-target-registration", Retention: "memory-only",
	}
	policyRaw, _ := json.Marshal(policy)
	registration := runnerTargetRegistrationYAML(expectedPlan)
	artifactDigest := digest.SHA256(registration)
	planRaw := submissionBundlePlan(t, expectedPlan, runnerStageSHA("1"), runnerStageSHA("2"))
	var document map[string]any
	if err := json.Unmarshal(planRaw, &document); err != nil {
		t.Fatal(err)
	}
	stages := document["stages"].([]any)
	stages[6].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-access", "digest": digest.SHA256(access)}}
	stages[7].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-credential", "digest": digest.SHA256(policyRaw)}}
	stages[8].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-registration", "digest": artifactDigest}}
	planPath := writeBundleFile(t, root, "staged-plan.json", mustJSON(t, document))
	plan, err := stageplan.Load(planPath, expectedPlan)
	if err != nil {
		t.Fatal(err)
	}

	receipts := make([]StageReceiptSource, 0, 8)
	predecessors := []stagereceipt.Verified{}
	results := []struct{ id, mutation, operation, evidence string }{
		{"provider-prerequisites", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2")},
		{"cluster-lifecycle", "ATTEMPTED", runnerStageSHA("3"), runnerStageSHA("4")},
		{"lifecycle-observation", "NOT_APPLICABLE", "", runnerStageSHA("5")},
		{"enablement", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7")},
		{"network-observation", "NOT_APPLICABLE", "", runnerStageSHA("9")},
		{"runtime-binding", "NOT_APPLICABLE", "", runnerStageSHA("0")},
		{"target-access", "ATTEMPTED", runnerStageSHA("e"), runnerStageSHA("f")},
		{"target-credential", "ATTEMPTED", runnerStageSHA("8"), runnerStageSHA("a")},
	}
	for index, result := range results {
		var receipt stagereceipt.Verified
		if result.id == "cluster-lifecycle" {
			receipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, digest.SHA256([]byte(targetAccessRuntimeUID)), at.Add(time.Duration(index-8)*time.Minute))
		} else {
			receipt, err = stagereceipt.New(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, at.Add(time.Duration(index-8)*time.Minute))
		}
		if err != nil {
			t.Fatal(err)
		}
		receipts = appendStageReceipt(t, root, receipts, receipt, result.id+".json")
		predecessors = []stagereceipt.Verified{receipt}
	}
	grantPath, keyPath := writeSubmissionStageGrant(t, root, plan, "target-registration", predecessors, at)
	expectedRegistration := submission.TargetRegistrationExpected{
		ArtifactDigest: artifactDigest, ContractIdentity: expectedPlan.ContractIdentity,
		IntentRevision: expectedPlan.IntentRevision, PlatformRevision: expectedPlan.PlatformRevision, ExecutionFixture: expectedPlan.ExecutionFixture,
		TargetIdentityDigest: digest.SHA256([]byte(targetAccessRuntimeUID)), ArgoAuthority: "ok-shared", ArgoNamespace: "argocd",
		ProjectName: "openkubes-disposable", RegistrationName: "disposable-ok147-cluster", TargetName: "disposable-ok147",
		SourceRepository: "https://github.com/openkubes/ok-observability.git", TargetNamespaces: []string{"ok-observability", "kube-system"},
	}
	return targetRegistrationBundleTestFixture{
		config: TargetRegistrationStageBundleConfig{
			PlanPath: planPath, PlanExpected: expectedPlan, Receipts: receipts,
			GrantPath: grantPath, GrantPublicKeyPath: keyPath, EvaluationTime: at,
			ArtifactPath: writeBundleFile(t, root, "target-registration.yaml", registration), Expected: expectedRegistration,
		},
		plan: plan, artifactDigest: artifactDigest,
	}
}

func runnerTargetRegistrationYAML(expected stageplan.Expected) []byte {
	annotations := map[string]any{
		"openkubes.io/intent-revision": expected.IntentRevision, "openkubes.io/platform-revision": expected.PlatformRevision,
		"openkubes.io/execution-fixture": expected.ExecutionFixture, "openkubes.io/target-identity-digest": digest.SHA256([]byte(targetAccessRuntimeUID)),
	}
	project := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "AppProject",
		"metadata": map[string]any{"name": "openkubes-disposable", "namespace": "argocd", "annotations": annotations},
		"spec": map[string]any{
			"description": "bounded OK-147 target", "permitOnlyProjectScopedClusters": true,
			"sourceRepos": []any{"https://github.com/openkubes/ok-observability.git"}, "sourceNamespaces": []any{"argocd"},
			"destinations":               []any{map[string]any{"name": "disposable-ok147", "namespace": "ok-observability"}, map[string]any{"name": "disposable-ok147", "namespace": "kube-system"}},
			"clusterResourceWhitelist":   []any{map[string]any{"group": "apiextensions.k8s.io", "kind": "CustomResourceDefinition"}, map[string]any{"group": "rbac.authorization.k8s.io", "kind": "ClusterRole"}},
			"namespaceResourceWhitelist": []any{map[string]any{"group": "", "kind": "ConfigMap"}, map[string]any{"group": "apps", "kind": "Deployment"}},
			"orphanedResources":          map[string]any{"warn": true},
		},
	}
	secretAnnotations := map[string]any{}
	for key, value := range annotations {
		secretAnnotations[key] = value
	}
	secretAnnotations["openkubes.io/capi-cluster-uid"] = submission.RegistrationCAPIUIDPlaceholder
	secretAnnotations["openkubes.io/workload-kube-system-uid"] = submission.RegistrationWorkloadUIDPlaceholder
	secretAnnotations["openkubes.io/workload-api-ca-sha256"] = submission.RegistrationCADigestPlaceholder
	secretAnnotations["openkubes.io/token-expiration"] = submission.RegistrationExpirationPlaceholder
	secret := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata":   map[string]any{"name": "disposable-ok147-cluster", "namespace": "argocd", "labels": map[string]any{"argocd.argoproj.io/secret-type": "cluster"}, "annotations": secretAnnotations},
		"stringData": map[string]any{"name": "disposable-ok147", "server": submission.RegistrationEndpointPlaceholder, "namespaces": "ok-observability,kube-system", "clusterResources": "true", "project": "openkubes-disposable", "config": submission.RegistrationConfigPlaceholder},
	}
	projectRaw, _ := json.Marshal(project)
	secretRaw, _ := json.Marshal(secret)
	return append(append(append([]byte{}, projectRaw...), '\n', '-', '-', '-', '\n'), secretRaw...)
}
