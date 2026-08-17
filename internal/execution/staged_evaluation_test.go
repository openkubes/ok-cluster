package execution

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestEvaluationStagePersistsAndResumesWithoutReevaluation(t *testing.T) {
	plan, cursor, at := aggregateEvaluationCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	evaluator := &fakeStageEvaluator{binding: evaluationBinding(t, plan), result: StageEvaluationResult{Outcome: "SUCCEEDED", EvidenceDigest: stagedSHA("e"), CompletedAt: at}}
	operation := EvaluationStageOperation{Ledger: store, Evaluator: evaluator}
	first, err := operation.Run(context.Background(), plan, cursor)
	if err != nil || first.State != "COMPLETED_SUCCEEDED" || first.StageReceiptDigest == "" || evaluator.calls != 1 {
		t.Fatalf("unexpected evaluation run: %#v calls=%d err=%v", first, evaluator.calls, err)
	}
	replayed, err := operation.Run(context.Background(), plan, cursor)
	if err != nil || replayed != first || evaluator.calls != 1 {
		t.Fatalf("persisted evaluation was executed again: %#v calls=%d err=%v", replayed, evaluator.calls, err)
	}
}

func TestEvaluationStagePersistsTerminalResultWithoutRawError(t *testing.T) {
	plan, cursor, at := aggregateEvaluationCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	evaluator := &fakeStageEvaluator{binding: evaluationBinding(t, plan), result: StageEvaluationResult{Outcome: "FAILED", EvidenceDigest: stagedSHA("f"), CompletedAt: at}}
	receipt, err := (EvaluationStageOperation{Ledger: store, Evaluator: evaluator}).Run(context.Background(), plan, cursor)
	var resultErr *EvaluationStageResultError
	if !errors.As(err, &resultErr) || receipt.State != "COMPLETED_FAILED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("terminal evaluation was not retained: %#v %v", receipt, err)
	}
}

func TestEvaluationStageFailsClosedBeforePersistence(t *testing.T) {
	plan, cursor, at := aggregateEvaluationCursor(t)
	for name, mutate := range map[string]func(*fakeStageEvaluator){
		"foreign binding": func(evaluator *fakeStageEvaluator) { evaluator.binding.Authority = "gitops" },
		"raw failure":     func(evaluator *fakeStageEvaluator) { evaluator.err = errors.New("sensitive endpoint detail") },
		"bad result":      func(evaluator *fakeStageEvaluator) { evaluator.result.EvidenceDigest = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
			evaluator := &fakeStageEvaluator{binding: evaluationBinding(t, plan), result: StageEvaluationResult{Outcome: "SUCCEEDED", EvidenceDigest: stagedSHA("e"), CompletedAt: at}}
			mutate(evaluator)
			receipt, err := (EvaluationStageOperation{Ledger: store, Evaluator: evaluator}).Run(context.Background(), plan, cursor)
			if err == nil || strings.Contains(err.Error(), "sensitive") || receipt.StageReceiptDigest != "" {
				t.Fatalf("unsafe evaluation result was accepted: %#v %v", receipt, err)
			}
		})
	}
}

func TestEvaluationStageRejectsObservationCursor(t *testing.T) {
	plan, cursor, _ := lifecycleObservationCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	evaluator := &fakeStageEvaluator{}
	if _, err := (EvaluationStageOperation{Ledger: store, Evaluator: evaluator}).Run(context.Background(), plan, cursor); err == nil || evaluator.calls != 0 {
		t.Fatalf("observation cursor reached evaluator: calls=%d err=%v", evaluator.calls, err)
	}
}

type fakeStageEvaluator struct {
	binding StageEvaluationBinding
	result  StageEvaluationResult
	err     error
	calls   int
}

func (evaluator *fakeStageEvaluator) Binding() StageEvaluationBinding { return evaluator.binding }
func (evaluator *fakeStageEvaluator) Evaluate(context.Context) (StageEvaluationResult, error) {
	evaluator.calls++
	return evaluator.result, evaluator.err
}

func aggregateEvaluationCursor(t *testing.T) (stageplan.Binding, stagecursor.Cursor, time.Time) {
	t.Helper()
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 17, 22, 0, 0, 0, time.UTC)
	predecessors := []stagereceipt.Verified{}
	prefix := []stagereceipt.Verified{}
	for index, stageID := range []string{"provider-prerequisites", "cluster-lifecycle", "lifecycle-observation", "enablement", "network-observation", "runtime-binding", "target-access", "target-credential", "target-registration", "platform-applications", "platform-observation"} {
		mutation := "ATTEMPTED"
		operationDigest := stagedSHA(string("123456789ab"[index]))
		if stageID == "lifecycle-observation" || stageID == "network-observation" || stageID == "runtime-binding" || stageID == "platform-observation" {
			mutation, operationDigest = "NOT_APPLICABLE", ""
		}
		var receipt stagereceipt.Verified
		var err error
		if stageID == "cluster-lifecycle" {
			receipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, stageID, predecessors, "SUCCEEDED", mutation, operationDigest, stagedSHA("e"), stagedSHA("7"), at.Add(time.Duration(index-11)*time.Second))
		} else {
			receipt, err = stagereceipt.New(plan, stageID, predecessors, "SUCCEEDED", mutation, operationDigest, stagedSHA("e"), at.Add(time.Duration(index-11)*time.Second))
		}
		if err != nil {
			t.Fatal(err)
		}
		prefix = append(prefix, receipt)
		predecessors = []stagereceipt.Verified{receipt}
	}
	cursor, err := stagecursor.Evaluate(plan, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return plan, cursor, at
}

func evaluationBinding(t *testing.T, plan stageplan.Binding) StageEvaluationBinding {
	t.Helper()
	stage, stageDigest, err := plan.Stage("aggregate-evidence")
	if err != nil {
		t.Fatal(err)
	}
	return StageEvaluationBinding{PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest, Authority: stage.Authority, ContractRevision: plan.IntentRevision}
}
