package stagecursor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestCursorSelectsEveryExactNextStageAndCompletes(t *testing.T) {
	plan := cursorPlan(t, "e")
	chain := successfulReceiptChain(t, plan)
	for completed := 0; completed <= len(chain); completed++ {
		cursor, err := Evaluate(plan, append([]stagereceipt.Verified{}, chain[:completed]...))
		if err != nil {
			t.Fatalf("completed=%d: %v", completed, err)
		}
		decision, err := cursor.Decision()
		if err != nil {
			t.Fatal(err)
		}
		if decision.CompletedStages != completed || decision.PlanDigest != plan.PlanDigest {
			t.Fatalf("completed=%d decision=%#v", completed, decision)
		}
		if completed == len(chain) {
			if decision.State != "COMPLETED" || decision.StageID != "" || decision.RequiresAuthorization || decision.Predecessors == nil {
				t.Fatalf("unexpected final decision: %#v", decision)
			}
			continue
		}
		expected := plan.Stages[completed]
		if decision.State != "NEXT" || decision.StageID != expected.ID || decision.StageOrder != expected.Order || decision.RequiresAuthorization != stageplan.IsMutating(expected) {
			t.Fatalf("unexpected next decision: %#v", decision)
		}
		predecessors, err := cursor.Predecessors()
		if err != nil {
			t.Fatal(err)
		}
		if completed == 0 && (predecessors == nil || len(predecessors) != 0) {
			t.Fatal("first stage lacks an explicit empty predecessor set")
		}
		if completed > 0 {
			digest, _ := chain[completed-1].Digest()
			if len(predecessors) != 1 || len(decision.Predecessors) != 1 || decision.Predecessors[0].ReceiptDigest != digest {
				t.Fatalf("next stage does not bind direct predecessor: %#v", decision)
			}
		}
	}
}

func TestCursorStopsPermanentlyAtTerminalReceipt(t *testing.T) {
	plan := cursorPlan(t, "e")
	at := time.Date(2026, 8, 16, 19, 0, 0, 0, time.UTC)
	failed, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "FAILED", "ATTEMPTED", cursorSHA("1"), cursorSHA("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := Evaluate(plan, []stagereceipt.Verified{failed})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := cursor.Decision()
	failedDigest, _ := failed.Digest()
	if decision.State != "STOPPED" || decision.TerminalOutcome != "FAILED" || decision.TerminalReceiptDigest != failedDigest || decision.CompletedStages != 0 {
		t.Fatalf("unexpected terminal decision: %#v", decision)
	}
	success := successfulReceiptChain(t, plan)
	if _, err := Evaluate(plan, []stagereceipt.Verified{failed, success[1]}); err == nil {
		t.Fatal("receipt prefix continued after terminal outcome")
	}
}

func TestCursorRejectsNilGapAndForeignPlan(t *testing.T) {
	plan := cursorPlan(t, "e")
	chain := successfulReceiptChain(t, plan)
	if _, err := Evaluate(plan, nil); err == nil {
		t.Fatal("nil receipt prefix was accepted")
	}
	if _, err := Evaluate(plan, []stagereceipt.Verified{chain[0], chain[2]}); err == nil {
		t.Fatal("gapped receipt prefix was accepted")
	}
	foreign := cursorPlan(t, "f")
	if _, err := Evaluate(foreign, []stagereceipt.Verified{chain[0]}); err == nil {
		t.Fatal("receipt from a different plan was accepted")
	}
	if _, err := (Cursor{}).Decision(); err == nil {
		t.Fatal("unverified zero-value cursor exposed a decision")
	}
}

func successfulReceiptChain(t *testing.T, plan stageplan.Binding) []stagereceipt.Verified {
	t.Helper()
	at := time.Date(2026, 8, 16, 19, 0, 0, 0, time.UTC)
	result := make([]stagereceipt.Verified, 0, len(plan.Stages))
	predecessors := []stagereceipt.Verified{}
	for index, stage := range plan.Stages {
		mutationState := "NOT_APPLICABLE"
		operationOutcome := ""
		if stageplan.IsMutating(stage) {
			mutationState = "ATTEMPTED"
			operationOutcome = cursorSHA(string("123456789abc"[index]))
		}
		receipt, err := stagereceipt.New(plan, stage.ID, predecessors, "SUCCEEDED", mutationState, operationOutcome, cursorSHA(string("abcdef012345"[index])), at.Add(time.Duration(index)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, receipt)
		predecessors = []stagereceipt.Verified{receipt}
	}
	return result
}

func cursorPlan(t *testing.T, firstInput string) stageplan.Binding {
	t.Helper()
	identity := contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
	ids := []string{"provider-prerequisites", "cluster-lifecycle", "lifecycle-observation", "enablement", "network-observation", "runtime-binding", "target-access", "target-credential", "target-registration", "platform-applications", "platform-observation", "aggregate-evidence"}
	kinds := []string{"Submission", "Submission", "Observation", "Submission", "Observation", "Binding", "Submission", "Credential", "Submission", "Submission", "Observation", "Evaluation"}
	authorities := []string{"infrastructure", "management", "management", "management", "workload", "runner", "workload", "workload", "gitops", "gitops", "gitops", "runner"}
	operations := []string{"CreateProviderPrerequisites", "CreateCluster", "", "CreateEnablement", "", "", "CreateTargetAccess", "IssueTargetCredential", "RegisterTarget", "CreatePlatformApplications", "", ""}
	stages := make([]map[string]any, len(ids))
	for index := range ids {
		requires := []string{}
		if index > 0 {
			requires = []string{ids[index-1]}
		}
		inputDigest := cursorSHA(string("abcdef012345"[index]))
		if index == 0 {
			inputDigest = cursorSHA(firstInput)
		}
		stages[index] = map[string]any{
			"id": ids[index], "order": index + 1, "kind": kinds[index], "authority": authorities[index], "requires": requires,
			"inputs": []map[string]any{{"name": "stage." + ids[index], "digest": inputDigest}},
		}
		if operations[index] != "" {
			stages[index]["grantOperation"] = operations[index]
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"format": stageplan.Format, "contractIdentity": identity,
		"intentRevision": cursorSHA("a"), "enablementRevision": cursorSHA("b"), "platformRevision": cursorSHA("c"), "executionFixture": cursorSHA("d"),
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	})
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: cursorSHA("a"), EnablementRevision: cursorSHA("b"), PlatformRevision: cursorSHA("c"), ExecutionFixture: cursorSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func cursorSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
