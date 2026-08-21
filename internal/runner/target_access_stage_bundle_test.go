package runner

import (
	"context"
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
	if err != nil || receipt.Format != TargetAccessStageBundleReceiptFormat || receipt.State != "VERIFIED" || receipt.PlanDigest != fixture.plan.PlanDigest || receipt.TargetIdentityDigest != digest.SHA256([]byte(targetAccessRuntimeUID)) || receipt.AuthorizationDigest == "" || len(receipt.ObjectDigests) != 11 || receipt.MutationAllowed {
		t.Fatalf("unexpected target-access bundle receipt: %#v %v", receipt, err)
	}
	if bundle.projection.Workload.Identity != digest.SHA256([]byte(targetAccessRuntimeUID)) || len(bundle.projection.Workload.Objects) != 11 {
		t.Fatalf("target-access projection differs: %#v", bundle.projection)
	}
}

func TestTargetAccessStageBundleOpensRuntimeBoundWorkloadAuthority(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	bundle, err := LoadTargetAccessStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := targetAccessRuntime(t, fixture.plan)
	bound, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.verified || bound.operation.Ledger == nil || bound.operation.Mutator == nil || bound.operation.Clock == nil || bound.operation.Mutator.Binding().StageID != "target-access" {
		t.Fatalf("incomplete target-access stage runtime: %#v", bound)
	}

	foreign := targetAccessRuntime(t, fixture.plan)
	binding, err := loadWorkloadAuthorityBinding(foreign.Workload.Path, foreign.Workload.ExpectedBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding.TargetClusterUID = "foreign-runtime-uid"
	raw, _ := json.Marshal(binding)
	if err := os.WriteFile(foreign.Workload.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	foreign.Workload.ExpectedBindingDigest, _ = WorkloadAuthorityBindingDigest(binding)
	if _, err := bundle.Open(foreign); err == nil {
		t.Fatal("foreign runtime target was accepted")
	}

	aliased := targetAccessRuntime(t, fixture.plan)
	ledgerToken, _ := os.ReadFile(aliased.Ledger.TokenFile)
	if err := os.WriteFile(aliased.Workload.TokenFile, ledgerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(aliased); err == nil {
		t.Fatal("shared ledger and workload credential was accepted")
	}

	if _, err := (VerifiedTargetAccessStageBundle{}).Open(TargetAccessStageRuntimeConfig{}); err == nil {
		t.Fatal("unverified target-access bundle opened a runtime")
	}
	if _, err := (BoundTargetAccessStage{}).Run(context.Background()); err == nil {
		t.Fatal("unverified target-access runtime executed")
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

const targetAccessRuntimeUID = "cluster-runtime-uid-147"

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
			receipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, digest.SHA256([]byte(targetAccessRuntimeUID)), at.Add(time.Duration(index-6)*time.Minute))
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

func targetAccessRuntime(t *testing.T, plan stageplan.Binding) TargetAccessStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ca := testCA(t)
	caPath := writeBundleFile(t, root, "workload-ca.crt", ca)
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: plan.IntentRevision,
		TargetClusterUID: targetAccessRuntimeUID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: "https://192.0.2.147:6443", CABundleDigest: digest.SHA256(ca),
	}
	bindingRaw, _ := json.Marshal(binding)
	bindingPath := writeBundleFile(t, root, "runtime-binding.json", bindingRaw)
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	return TargetAccessStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: "https://192.0.2.12:6443", Namespace: "openkubes-execution-system",
			TokenFile: writeBundleFile(t, root, "ledger-token", []byte("target-access-ledger-token")), CAFile: caPath,
		},
		Workload: WorkloadAuthorityFileResolverConfig{
			Path: bindingPath, ExpectedBindingDigest: bindingDigest,
			TokenFile: writeBundleFile(t, root, "workload-token", []byte("target-access-workload-token")), CAFile: caPath,
		},
		Clock: func() time.Time { return time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC) },
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
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "ok-observability", Name: "ok147-observability-autonomy"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "ok-observability", Name: "ok147-observability-autonomy"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "ok-observability", Name: "ok147-observability-autonomy"},
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
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ok147-observability-autonomy, namespace: ok-observability}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ok147-observability-autonomy, namespace: ok-observability}
rules:
  - {apiGroups: [""], resources: [services], verbs: [get]}
  - {apiGroups: [discovery.k8s.io], resources: [endpointslices], verbs: [list]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ok147-observability-autonomy, namespace: ok-observability}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ok147-observability-autonomy}
subjects: [{kind: ServiceAccount, name: ok147-observability-autonomy, namespace: ok-observability}]
`)
}
