package stageauthority

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestRecoveryPolicyDisabledWithoutAtomicSourceReservation(t *testing.T) {
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
	if !errors.Is(err, stageplan.ErrRecoveryExecutionDisabled) || raw != nil || receipt.StageCount != 0 {
		t.Fatalf("recovery policy enabled without atomic reservation: %#v %v", receipt, err)
	}
}
