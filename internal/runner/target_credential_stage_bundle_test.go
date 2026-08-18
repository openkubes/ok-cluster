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
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestLoadTargetCredentialStageBundleBindsPrefixPolicyGrantAndAccessIdentity(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "target-credential" || decision.Kind != "Credential" || decision.Operation != "IssueTargetCredential" || decision.Authority != "workload" || !decision.RequiresAuthorization {
		t.Fatalf("unexpected target-credential decision: %#v %v", decision, err)
	}
	receipt, err := bundle.Receipt()
	if err != nil || receipt.Format != TargetCredentialStageBundleReceiptFormat || receipt.State != "VERIFIED" || receipt.PlanDigest != fixture.plan.PlanDigest || receipt.PolicyDigest != fixture.policyDigest || receipt.TargetAccessArtifactDigest != fixture.accessDigest || receipt.TargetIdentityDigest != digest.SHA256([]byte(targetAccessRuntimeUID)) || receipt.AuthorizationDigest == "" || receipt.ServiceAccountIdentityDigest == "" || receipt.AudienceMode != "server-default" || receipt.ExpirationSeconds != 10800 || receipt.CredentialRetention != "memory-only" || receipt.NativeRotationClaimed || receipt.ProductionSuitableClaimed || receipt.MutationAllowed {
		t.Fatalf("unexpected target-credential receipt: %#v %v", receipt, err)
	}
	if bundle.policy.TargetIdentityDigest != receipt.TargetIdentityDigest {
		t.Fatal("verified lifecycle target was not materialized into the private in-memory policy")
	}
}

func TestLoadTargetCredentialStageBundleFailsClosed(t *testing.T) {
	tests := map[string]func(*targetCredentialBundleTestFixture){
		"implicit prefix":   func(f *targetCredentialBundleTestFixture) { f.config.Receipts = nil },
		"incomplete prefix": func(f *targetCredentialBundleTestFixture) { f.config.Receipts = f.config.Receipts[:6] },
		"changed policy": func(f *targetCredentialBundleTestFixture) {
			raw, _ := os.ReadFile(f.config.PolicyPath)
			_ = os.WriteFile(f.config.PolicyPath, append(raw, '\n'), 0o600)
		},
		"changed target access": func(f *targetCredentialBundleTestFixture) {
			raw, _ := os.ReadFile(f.config.TargetAccessArtifactPath)
			_ = os.WriteFile(f.config.TargetAccessArtifactPath, append(raw, '\n'), 0o600)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := targetCredentialBundleFixture(t)
			mutate(&fixture)
			if _, err := LoadTargetCredentialStageBundle(fixture.config); err == nil {
				t.Fatal("changed target-credential input was accepted")
			}
		})
	}

	if _, err := (VerifiedTargetCredentialStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified target-credential bundle exposed a decision")
	}
	if _, err := (VerifiedTargetCredentialStageBundle{}).Receipt(); err == nil {
		t.Fatal("unverified target-credential bundle exposed a receipt")
	}
}

func TestValidateTargetCredentialPolicyFailsClosed(t *testing.T) {
	target := digest.SHA256([]byte(targetAccessRuntimeUID))
	serviceAccount := projection.ResourceIdentity{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "kube-system", Name: "ok147-argocd-manager"}
	valid := func() targetCredentialPolicyDocument {
		return targetCredentialPolicyDocument{
			Format: TargetCredentialPolicyFormat, TargetIdentityDigest: submission.RuntimeTargetIdentityDigestPlaceholder,
			ServiceAccount:     targetCredentialServiceAccount{Namespace: serviceAccount.Namespace, Name: serviceAccount.Name},
			RequestedAudiences: []string{}, ExpirationSeconds: 10800,
			CredentialUse: "argocd-target-registration", Retention: "memory-only",
		}
	}
	if err := validateTargetCredentialPolicy(valid(), target, serviceAccount); err != nil {
		t.Fatal(err)
	}
	policyTests := map[string]func(*targetCredentialPolicyDocument){
		"prefilled target":        func(p *targetCredentialPolicyDocument) { p.TargetIdentityDigest = target },
		"foreign service account": func(p *targetCredentialPolicyDocument) { p.ServiceAccount.Name = "foreign-manager" },
		"guessed audience":        func(p *targetCredentialPolicyDocument) { p.RequestedAudiences = []string{"https://guessed.invalid"} },
		"long lifetime":           func(p *targetCredentialPolicyDocument) { p.ExpirationSeconds++ },
		"disk retention":          func(p *targetCredentialPolicyDocument) { p.Retention = "file" },
		"rotation claim":          func(p *targetCredentialPolicyDocument) { p.NativeRotation = true },
		"production claim":        func(p *targetCredentialPolicyDocument) { p.ProductionSuitable = true },
	}
	for name, mutate := range policyTests {
		t.Run(name, func(t *testing.T) {
			policy := valid()
			mutate(&policy)
			if err := validateTargetCredentialPolicy(policy, target, serviceAccount); err == nil {
				t.Fatal("invalid target-credential policy was accepted")
			}
		})
	}
}

type targetCredentialBundleTestFixture struct {
	config       TargetCredentialStageBundleConfig
	plan         stageplan.Binding
	policyDigest string
	accessDigest string
}

func targetCredentialBundleFixture(t *testing.T) targetCredentialBundleTestFixture {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC)
	expected := stageplan.Expected{
		ContractIdentity: runnerStagedPlan(t).ContractIdentity,
		IntentRevision:   runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	access := runnerTargetAccessYAML()
	accessDigest := digest.SHA256(access)
	policy := targetCredentialPolicyDocument{
		Format: TargetCredentialPolicyFormat, TargetIdentityDigest: submission.RuntimeTargetIdentityDigestPlaceholder,
		ServiceAccount:     targetCredentialServiceAccount{Namespace: "kube-system", Name: "ok147-argocd-manager"},
		RequestedAudiences: []string{}, ExpirationSeconds: 10800, CredentialUse: "argocd-target-registration",
		Retention: "memory-only", NativeRotation: false, ProductionSuitable: false,
	}
	policyRaw, _ := json.Marshal(policy)
	policyDigest := digest.SHA256(policyRaw)
	planRaw := submissionBundlePlan(t, expected, runnerStageSHA("1"), runnerStageSHA("2"))
	var document map[string]any
	if err := json.Unmarshal(planRaw, &document); err != nil {
		t.Fatal(err)
	}
	stages := document["stages"].([]any)
	stages[6].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-access", "digest": accessDigest}}
	stages[7].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-credential", "digest": policyDigest}}
	planPath := writeBundleFile(t, root, "staged-plan.json", mustJSON(t, document))
	plan, err := stageplan.Load(planPath, expected)
	if err != nil {
		t.Fatal(err)
	}

	receipts := make([]StageReceiptSource, 0, 7)
	predecessors := []stagereceipt.Verified{}
	results := []struct{ id, mutation, operation, evidence string }{
		{"provider-prerequisites", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2")},
		{"cluster-lifecycle", "ATTEMPTED", runnerStageSHA("3"), runnerStageSHA("4")},
		{"lifecycle-observation", "NOT_APPLICABLE", "", runnerStageSHA("5")},
		{"enablement", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7")},
		{"network-observation", "NOT_APPLICABLE", "", runnerStageSHA("9")},
		{"runtime-binding", "NOT_APPLICABLE", "", runnerStageSHA("0")},
		{"target-access", "ATTEMPTED", runnerStageSHA("e"), runnerStageSHA("f")},
	}
	for index, result := range results {
		var receipt stagereceipt.Verified
		if result.id == "cluster-lifecycle" {
			receipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, digest.SHA256([]byte(targetAccessRuntimeUID)), at.Add(time.Duration(index-7)*time.Minute))
		} else {
			receipt, err = stagereceipt.New(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, at.Add(time.Duration(index-7)*time.Minute))
		}
		if err != nil {
			t.Fatal(err)
		}
		receipts = appendStageReceipt(t, root, receipts, receipt, result.id+".json")
		predecessors = []stagereceipt.Verified{receipt}
	}
	grantPath, keyPath := writeSubmissionStageGrant(t, root, plan, "target-credential", predecessors, at)
	return targetCredentialBundleTestFixture{
		config: TargetCredentialStageBundleConfig{
			PlanPath: planPath, PlanExpected: expected, Receipts: receipts,
			GrantPath: grantPath, GrantPublicKeyPath: keyPath, EvaluationTime: at,
			PolicyPath:                  writeBundleFile(t, root, "target-credential.json", policyRaw),
			TargetAccessArtifactPath:    writeBundleFile(t, root, "target-access.yaml", access),
			TargetAccessExpectedObjects: runnerTargetAccessIdentities(),
		},
		plan: plan, policyDigest: policyDigest, accessDigest: accessDigest,
	}
}
