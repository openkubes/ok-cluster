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

const ObservationStageReceiptFormat = "ok147-observation-stage-run-receipt/v1"

type StageObservationBinding struct {
	PlanDigest       string
	StageID          string
	StageDigest      string
	Authority        string
	ContractRevision string
}

type StageObservationResult struct {
	Outcome        string
	EvidenceDigest string
	CompletedAt    time.Time
}

// StageObserver is preconstructed for exactly one read-only observation
// stage. It has no mutation, authorization or dispatcher method.
type StageObserver interface {
	Binding() StageObservationBinding
	Observe(context.Context) (StageObservationResult, error)
}

type ObservationStageOperation struct {
	Ledger   *ledger.Ledger
	Observer StageObserver
}

type ObservationStageRunReceipt struct {
	Format             string `json:"format"`
	State              string `json:"state"`
	PlanDigest         string `json:"planDigest,omitempty"`
	StageID            string `json:"stageId,omitempty"`
	StageReceiptDigest string `json:"stageReceiptDigest,omitempty"`
}

type ObservationStageResultError struct{ State string }

func (err *ObservationStageResultError) Error() string {
	return "observation stage completed with " + err.State
}

// Run invokes at most one prebound read-only observer. An already persisted
// receipt is returned without observing again, making process termination
// after receipt persistence safe to resume.
func (operation ObservationStageOperation) Run(ctx context.Context, plan stageplan.Binding, cursor stagecursor.Cursor) (ObservationStageRunReceipt, error) {
	receipt := ObservationStageRunReceipt{Format: ObservationStageReceiptFormat, State: "PREOBSERVATION"}
	if operation.Ledger == nil || operation.Observer == nil {
		return receipt, errors.New("observation stage ledger and observer are required")
	}
	decision, err := cursor.Decision()
	if err != nil {
		return receipt, err
	}
	if decision.State != "NEXT" || decision.Kind != "Observation" || decision.RequiresAuthorization || decision.Operation != "" {
		return receipt, errors.New("stage cursor does not select a read-only observation stage")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return receipt, err
	}
	want := StageObservationBinding{
		PlanDigest: plan.PlanDigest, StageID: decision.StageID, StageDigest: decision.StageDigest,
		Authority: decision.Authority, ContractRevision: plan.IntentRevision,
	}
	if operation.Observer.Binding() != want {
		return receipt, errors.New("preconstructed observer differs from the selected stage")
	}
	receipt.PlanDigest, receipt.StageID = plan.PlanDigest, decision.StageID
	if existing, found, err := operation.Ledger.InspectStageReceipt(ctx, plan, decision.StageID, predecessors); err != nil {
		return receipt, err
	} else if found {
		return finalizeObservationRunReceipt(receipt, existing)
	}

	result, observeErr := operation.Observer.Observe(ctx)
	if observeErr != nil {
		return receipt, errors.New("bounded stage observation failed")
	}
	if !oneOf(result.Outcome, "SUCCEEDED", "FAILED", "STOPPED") || !stagedDigestPattern.MatchString(result.EvidenceDigest) || result.CompletedAt.IsZero() {
		return receipt, errors.New("stage observer returned an invalid redaction-safe result")
	}
	verified, err := stagereceipt.New(plan, decision.StageID, predecessors, result.Outcome, "NOT_APPLICABLE", "", result.EvidenceDigest, result.CompletedAt)
	if err != nil {
		return receipt, err
	}
	if _, err := operation.Ledger.StoreStageReceipt(ctx, plan, verified, predecessors); err != nil {
		return receipt, err
	}
	return finalizeObservationRunReceipt(receipt, verified)
}

func finalizeObservationRunReceipt(receipt ObservationStageRunReceipt, verified stagereceipt.Verified) (ObservationStageRunReceipt, error) {
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
		return receipt, &ObservationStageResultError{State: receipt.State}
	}
	return receipt, nil
}
