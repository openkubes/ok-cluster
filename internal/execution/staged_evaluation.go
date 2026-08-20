package execution

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const EvaluationStageReceiptFormat = "ok147-evaluation-stage-run-receipt/v1"

type StageEvaluationBinding struct {
	PlanDigest       string
	StageID          string
	StageDigest      string
	Authority        string
	ContractRevision string
}

type StageEvaluationResult struct {
	Outcome        string
	EvidenceDigest string
	CompletedAt    time.Time
}

// StageEvaluator is preconstructed for exactly one bounded, read-only
// evaluation stage. It has no mutation, authorization, retry or status-write
// method.
type StageEvaluator interface {
	Binding() StageEvaluationBinding
	Evaluate(context.Context) (StageEvaluationResult, error)
}

type EvaluationStageOperation struct {
	Ledger    *ledger.Ledger
	Evaluator StageEvaluator
}

type EvaluationStageRunReceipt struct {
	Format             string `json:"format"`
	State              string `json:"state"`
	PlanDigest         string `json:"planDigest,omitempty"`
	StageID            string `json:"stageId,omitempty"`
	StageReceiptDigest string `json:"stageReceiptDigest,omitempty"`
}

type EvaluationStageResultError struct{ State string }

func (err *EvaluationStageResultError) Error() string {
	return "evaluation stage completed with " + err.State
}

// Run invokes at most one prebound evaluator. Once its receipt is durable,
// replay returns that receipt without re-reading any authoritative source.
func (operation EvaluationStageOperation) Run(ctx context.Context, plan stageplan.Binding, cursor stagecursor.Cursor) (EvaluationStageRunReceipt, error) {
	return operation.run(ctx, plan, cursor, "")
}

// Retry invokes the evaluator again only when the caller binds the exact
// immutable digest of an already persisted FAILED receipt. The deterministic
// first receipt remains untouched; the retry is stored as a digest-addressed
// attempt.
func (operation EvaluationStageOperation) Retry(ctx context.Context, plan stageplan.Binding, cursor stagecursor.Cursor, failedReceiptDigest string) (EvaluationStageRunReceipt, error) {
	if !stagedDigestPattern.MatchString(failedReceiptDigest) {
		return EvaluationStageRunReceipt{Format: EvaluationStageReceiptFormat, State: "PREEVALUATION"}, errors.New("failed evaluation receipt digest is invalid")
	}
	return operation.run(ctx, plan, cursor, failedReceiptDigest)
}

func (operation EvaluationStageOperation) run(ctx context.Context, plan stageplan.Binding, cursor stagecursor.Cursor, failedReceiptDigest string) (EvaluationStageRunReceipt, error) {
	receipt := EvaluationStageRunReceipt{Format: EvaluationStageReceiptFormat, State: "PREEVALUATION"}
	if operation.Ledger == nil || operation.Evaluator == nil {
		return receipt, errors.New("evaluation stage ledger and evaluator are required")
	}
	decision, err := cursor.Decision()
	if err != nil {
		return receipt, err
	}
	if decision.State != "NEXT" || decision.Kind != "Evaluation" || decision.RequiresAuthorization || decision.Operation != "" {
		return receipt, errors.New("stage cursor does not select a read-only evaluation stage")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return receipt, err
	}
	want := StageEvaluationBinding{
		PlanDigest: plan.PlanDigest, StageID: decision.StageID, StageDigest: decision.StageDigest,
		Authority: decision.Authority, ContractRevision: plan.IntentRevision,
	}
	if operation.Evaluator.Binding() != want {
		return receipt, errors.New("preconstructed evaluator differs from the selected stage")
	}
	receipt.PlanDigest, receipt.StageID = plan.PlanDigest, decision.StageID
	if existing, found, err := operation.Ledger.InspectStageReceipt(ctx, plan, decision.StageID, predecessors); err != nil {
		return receipt, err
	} else if found {
		if failedReceiptDigest == "" {
			return finalizeEvaluationRunReceipt(receipt, existing)
		}
		failed, loadErr := operation.Ledger.LoadStageReceipt(ctx, plan, decision.StageID, failedReceiptDigest, predecessors)
		if loadErr != nil {
			return receipt, errors.New("evaluation retry does not bind an existing FAILED receipt")
		}
		failedReceipt, receiptErr := failed.Receipt()
		if receiptErr != nil || failedReceipt.State != "FAILED" {
			return receipt, errors.New("evaluation retry does not bind an existing FAILED receipt")
		}
	} else if failedReceiptDigest != "" {
		return receipt, errors.New("evaluation retry requires an existing FAILED receipt")
	}

	result, evaluateErr := operation.Evaluator.Evaluate(ctx)
	if evaluateErr != nil {
		return receipt, errors.New("bounded stage evaluation failed")
	}
	if !oneOf(result.Outcome, "SUCCEEDED", "FAILED", "STOPPED") || !stagedDigestPattern.MatchString(result.EvidenceDigest) || result.CompletedAt.IsZero() {
		return receipt, errors.New("stage evaluator returned an invalid redaction-safe result")
	}
	verified, err := stagereceipt.New(plan, decision.StageID, predecessors, result.Outcome, "NOT_APPLICABLE", "", result.EvidenceDigest, result.CompletedAt)
	if err != nil {
		return receipt, err
	}
	if _, err := operation.Ledger.StoreStageReceipt(ctx, plan, verified, predecessors); err != nil {
		return receipt, err
	}
	return finalizeEvaluationRunReceipt(receipt, verified)
}

func finalizeEvaluationRunReceipt(receipt EvaluationStageRunReceipt, verified stagereceipt.Verified) (EvaluationStageRunReceipt, error) {
	stageReceipt, err := verified.Receipt()
	if err != nil {
		return receipt, err
	}
	digest, err := verified.Digest()
	if err != nil {
		return receipt, err
	}
	receipt.StageReceiptDigest = digest
	receipt.State = "COMPLETED_" + stageReceipt.State
	if stageReceipt.State != "SUCCEEDED" {
		return receipt, &EvaluationStageResultError{State: receipt.State}
	}
	return receipt, nil
}
