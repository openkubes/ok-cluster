package stageauthority

import (
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestRecoveryPolicyCanOnlyAuthorizeTargetAccess(t *testing.T) {
	base := verifiedPlan(t)
	doc := map[string]any{
		"format": stageplan.FormatRecovery, "recoverySourcePlanDigest": base.PlanDigest,
		"authorizationState": "NO-GO", "completionMode": stageplan.CompletionModeBareClusterMVP,
		"contractIdentity": base.ContractIdentity, "intentRevision": base.IntentRevision,
		"enablementRevision": base.EnablementRevision, "platformRevision": base.PlatformRevision,
		"executionFixture": base.ExecutionFixture, "authorities": base.Authorities, "stages": base.Stages[:7],
	}
	raw, _ := json.Marshal(doc)
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: base.ContractIdentity, IntentRevision: base.IntentRevision, EnablementRevision: base.EnablementRevision,
		PlatformRevision: base.PlatformRevision, ExecutionFixture: base.ExecutionFixture,
		InfrastructureAuthority: base.Authorities.Infrastructure, ManagementAuthority: base.Authorities.Management,
		GitOpsAuthority: base.Authorities.GitOps, CompletionMode: stageplan.CompletionModeBareClusterMVP,
		RecoverySourcePlanDigest: base.PlanDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, receipt, err := FromPlan(plan)
	if err != nil || receipt.StageCount != 1 || receipt.MutationAllowed {
		t.Fatalf("unsafe recovery policy: %#v %v", receipt, err)
	}
	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Stages) != 1 || policy.Stages[0].StageID != "target-access" || policy.Stages[0].StageOrder != 7 || policy.Stages[0].Operation != "CreateTargetAccess" {
		t.Fatalf("recovery authorizes replay: %#v", policy)
	}
}
