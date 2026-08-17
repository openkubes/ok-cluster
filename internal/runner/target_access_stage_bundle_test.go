package runner

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestLoadTargetAccessStageBundleBindsPrefixGrantArtifactAndTarget(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	bundle, err := LoadTargetAccessStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "target-access" || decision.Operation != "CreateTargetAccess" || decision.Authority != "workload" || !decision.RequiresAuthorization {
		t.Fatalf("unexpected target-access decision: %#v %v", decision, err)
	}
	receipt, err := bundle.Receipt()
	if err != nil || receipt.Format != TargetAccessStageBundleReceiptFormat || receipt.State != "VERIFIED" || receipt.PlanDigest != fixture.plan.PlanDigest || receipt.TargetIdentityDigest != runnerStageSHA("8") || receipt.AuthorizationDigest == "" || len(receipt.ObjectDigests) != 8 || receipt.MutationAllowed {
		t.Fatalf("unexpected target-access bundle receipt: %#v %v", receipt, err)
	}
	if bundle.projection.Workload.Identity != runnerStageSHA("8") || len(bundle.projection.Workload.Objects) != 8 {
		t.Fatalf("target-access projection differs: %#v", bundle.projection)
	}
}

func TestLoadTargetAccessStageBundleFailsClosed(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	fixture.config.Receipts = nil
	if _, err := LoadTargetAccessStageBundle(fixture.config); err == nil {
		t.Fatal("implicit target-access receipt prefix was accepted")
	}

	fixture = targetAccessBundleFixture(t)
	fixture.config.Receipts = fixture.config.Receipts[:5]
	if _, err := LoadTargetAccessStageBundle(fixture.config); err == nil {
		t.Fatal("incomplete target-access receipt prefix was accepted")
	}

	fixture = targetAccessBundleFixture(t)
	raw, err := os.ReadFile(fixture.config.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.config.ArtifactPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargetAccessStageBundle(fixture.config); err == nil {
		t.Fatal("changed target-access artifact was accepted")
	}

	fixture = targetAccessBundleFixture(t)
	fixture.config.ExpectedObjects[7].Name = "foreign-binding"
	if _, err := LoadTargetAccessStageBundle(fixture.config); err == nil {
		t.Fatal("foreign target-access object identity was accepted")
	}

	if _, err := (VerifiedTargetAccessStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified target-access bundle exposed a decision")
	}
	if _, err := (VerifiedTargetAccessStageBundle{}).Receipt(); err == nil {
		t.Fatal("unverified target-access bundle exposed a receipt")
	}
}

type targetAccessBundleTestFixture struct {
	config TargetAccessStageBundleConfig
	plan   stageplan.Binding
}

func targetAccessBundleFixture(t *testing.T) targetAccessBundleTestFixture {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	expected := stageplan.Expected{
		ContractIdentity: runnerStagedPlan(t).ContractIdentity,
		IntentRevision:   runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	artifact := runnerTargetAccessYAML()
	planRaw := submissionBundlePlan(t, expected, runnerStageSHA("1"), runnerStageSHA("2"))
	var document map[string]any
	if err := json.Unmarshal(planRaw, &document); err != nil {
		t.Fatal(err)
	}
	stages := document["stages"].([]any)
	targetAccess := stages[6].(map[string]any)
	targetAccess["inputs"] = []any{map[string]any{"name": "stage.target-access", "digest": digest.SHA256(artifact)}}
	planPath := writeBundleFile(t, root, "staged-plan.json", mustJSON(t, document))
	plan, err := stageplan.Load(planPath, expected)
	if err != nil {
		t.Fatal(err)
	}

	receipts := make([]StageReceiptSource, 0, 6)
	predecessors := []stagereceipt.Verified{}
	type stageResult struct{ id, mutation, operation, evidence string }
	results := []stageResult{
		{"provider-prerequisites", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2")},
		{"cluster-lifecycle", "ATTEMPTED", runnerStageSHA("3"), runnerStageSHA("4")},
		{"lifecycle-observation", "NOT_APPLICABLE", "", runnerStageSHA("5")},
		{"enablement", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7")},
		{"network-observation", "NOT_APPLICABLE", "", runnerStageSHA("9")},
		{"runtime-binding", "NOT_APPLICABLE", "", runnerStageSHA("0")},
	}
	for index, result := range results {
		var receipt stagereceipt.Verified
		if result.id == "cluster-lifecycle" {
			receipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, runnerStageSHA("8"), at.Add(time.Duration(index-6)*time.Minute))
		} else {
			receipt, err = stagereceipt.New(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, at.Add(time.Duration(index-6)*time.Minute))
		}
		if err != nil {
			t.Fatal(err)
		}
		receipts = appendStageReceipt(t, root, receipts, receipt, result.id+".json")
		predecessors = []stagereceipt.Verified{receipt}
	}
	grantPath, keyPath := writeSubmissionStageGrant(t, root, plan, "target-access", predecessors, at)
	return targetAccessBundleTestFixture{
		config: TargetAccessStageBundleConfig{
			PlanPath: planPath, PlanExpected: expected, Receipts: receipts,
			GrantPath: grantPath, GrantPublicKeyPath: keyPath, EvaluationTime: at,
			ArtifactPath: writeBundleFile(t, root, "target-access.yaml", artifact), ExpectedObjects: runnerTargetAccessIdentities(),
		},
		plan: plan,
	}
}

func runnerTargetAccessIdentities() []projection.ResourceIdentity {
	return []projection.ResourceIdentity{
		{APIVersion: "v1", Kind: "Namespace", Name: "ok-observability"},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "kube-system", Name: "ok147-argocd-manager"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "ok147-argocd-platform-cluster"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: "ok147-argocd-platform-cluster"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "ok-observability", Name: "ok147-argocd-platform"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "ok-observability", Name: "ok147-argocd-platform"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "kube-system", Name: "ok147-argocd-kube-system"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "kube-system", Name: "ok147-argocd-kube-system"},
	}
}

func runnerTargetAccessYAML() []byte {
	return []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: ok-observability
  labels: {pod-security.kubernetes.io/enforce: privileged, pod-security.kubernetes.io/audit: privileged, pod-security.kubernetes.io/warn: privileged}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ok147-argocd-manager, namespace: kube-system}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: ok147-argocd-platform-cluster}
rules:
  - {apiGroups: [apiextensions.k8s.io], resources: [customresourcedefinitions], verbs: [get, list, watch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ok147-argocd-platform-cluster}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ok147-argocd-platform-cluster}
subjects: [{kind: ServiceAccount, name: ok147-argocd-manager, namespace: kube-system}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ok147-argocd-platform, namespace: ok-observability}
rules:
  - {apiGroups: [""], resources: [configmaps, services], verbs: [get, list, watch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ok147-argocd-platform, namespace: ok-observability}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ok147-argocd-platform}
subjects: [{kind: ServiceAccount, name: ok147-argocd-manager, namespace: kube-system}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ok147-argocd-kube-system, namespace: kube-system}
rules:
  - {apiGroups: [""], resources: [services], verbs: [get, list, watch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ok147-argocd-kube-system, namespace: kube-system}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ok147-argocd-kube-system}
subjects: [{kind: ServiceAccount, name: ok147-argocd-manager, namespace: kube-system}]
`)
}
