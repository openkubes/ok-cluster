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

const BindingStageReceiptFormat = "ok147-binding-stage-run-receipt/v1"

// StageBinderBinding makes one preconstructed local binder specific to one
// verified plan stage. It is not a dynamic operation dispatcher.
type StageBinderBinding struct {
	PlanDigest       string
	StageID          string
	StageDigest      string
	Authority        string
	ContractRevision string
}

// StageBindingResult is the redaction-safe result of producing one private,
// digest-bound runtime correlation artifact.
type StageBindingResult struct {
	Outcome        string
	EvidenceDigest string
	CompletedAt    time.Time
}

// StageBinder is preconstructed for exactly one local binding stage. It has no
// grant, Kubernetes mutation or general dispatcher method.
type StageBinder interface {
	Binding() StageBinderBinding
	Bind(context.Context) (StageBindingResult, error)
}

// BindingStageOperation composes cursor verification, one local binding call
// and immutable stage-receipt persistence.
type BindingStageOperation struct {
	Ledger *ledger.Ledger
	Binder StageBinder
}

type BindingStageRunReceipt struct {
	Format             string `json:"format"`
	State              string `json:"state"`
	PlanDigest         string `json:"planDigest,omitempty"`
	StageID            string `json:"stageId,omitempty"`
	StageReceiptDigest string `json:"stageReceiptDigest,omitempty"`
}

type BindingStageResultError struct{ State string }

func (err *BindingStageResultError) Error() string {
	return "binding stage completed with " + err.State
}

// Run invokes at most one prebound local binder. An already persisted receipt
// is returned without opening the binder again, so a process restart cannot
// silently regenerate a different runtime identity.
func (operation BindingStageOperation) Run(ctx context.Context, plan stageplan.Binding, cursor stagecursor.Cursor) (BindingStageRunReceipt, error) {
	receipt := BindingStageRunReceipt{Format: BindingStageReceiptFormat, State: "PREBINDING"}
	if operation.Ledger == nil || operation.Binder == nil {
		return receipt, errors.New("binding stage ledger and binder are required")
	}
	decision, err := cursor.Decision()
	if err != nil {
		return receipt, err
	}
	if decision.State != "NEXT" || decision.Kind != "Binding" || decision.Authority != "runner" || decision.RequiresAuthorization || decision.Operation != "" {
		return receipt, errors.New("stage cursor does not select a local binding stage")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return receipt, err
	}
	want := StageBinderBinding{
		PlanDigest: plan.PlanDigest, StageID: decision.StageID, StageDigest: decision.StageDigest,
		Authority: decision.Authority, ContractRevision: plan.IntentRevision,
	}
	if operation.Binder.Binding() != want {
		return receipt, errors.New("preconstructed binder differs from the selected stage")
	}
	receipt.PlanDigest, receipt.StageID = plan.PlanDigest, decision.StageID
	if existing, found, err := operation.Ledger.InspectStageReceipt(ctx, plan, decision.StageID, predecessors); err != nil {
		return receipt, err
	} else if found {
		return finalizeBindingRunReceipt(receipt, existing)
	}

	result, bindErr := operation.Binder.Bind(ctx)
	if bindErr != nil {
		return receipt, errors.New("bounded runtime binding failed")
	}
	if !oneOf(result.Outcome, "SUCCEEDED", "FAILED", "STOPPED") || !stagedDigestPattern.MatchString(result.EvidenceDigest) || result.CompletedAt.IsZero() {
		return receipt, errors.New("stage binder returned an invalid redaction-safe result")
	}
	verified, err := stagereceipt.New(plan, decision.StageID, predecessors, result.Outcome, "NOT_APPLICABLE", "", result.EvidenceDigest, result.CompletedAt)
	if err != nil {
		return receipt, err
	}
	if _, err := operation.Ledger.StoreStageReceipt(ctx, plan, verified, predecessors); err != nil {
		return receipt, err
	}
	return finalizeBindingRunReceipt(receipt, verified)
}

func finalizeBindingRunReceipt(receipt BindingStageRunReceipt, verified stagereceipt.Verified) (BindingStageRunReceipt, error) {
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
		return receipt, &BindingStageResultError{State: receipt.State}
	}
	return receipt, nil
}
