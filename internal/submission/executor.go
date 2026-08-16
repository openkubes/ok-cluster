package submission

import (
	"context"
	"errors"
	"fmt"
)

const RunReceiptFormat = "ok147-bounded-submission-run-receipt/v2"

// Executor preserves the projection's authority order: provider prerequisites
// first, then management-plane lifecycle objects. It has no retry or rollback
// capability.
type Executor struct {
	Infrastructure *KubernetesClient
	Management     *KubernetesClient
}

// Receipt exposes the exact completed prefix if execution stops. It is
// submission evidence only; it is never lifecycle-success evidence.
type Receipt struct {
	Format         string        `json:"format"`
	IntentRevision string        `json:"intentRevision"`
	State          string        `json:"state"`
	MutationState  string        `json:"mutationState"`
	Infrastructure *PlaneReceipt `json:"infrastructure,omitempty"`
	Management     *PlaneReceipt `json:"management,omitempty"`
}

// Execute performs one bounded pass and never retries. A successful receipt
// means the desired objects were accepted or already matched; reconciliation
// and Ready remain separate observation responsibilities.
func (executor Executor) Execute(ctx context.Context, plan Plan) (Receipt, error) {
	receipt := Receipt{
		Format:         RunReceiptFormat,
		IntentRevision: plan.IntentRevision,
		State:          "IN_PROGRESS",
		MutationState:  "NOT_ATTEMPTED",
	}
	if plan.Format != PlanFormat {
		return receipt, errors.New("submission plan format is not supported")
	}
	if executor.Infrastructure == nil || executor.Management == nil {
		return receipt, errors.New("both authority-plane submission clients are required")
	}
	infrastructure, err := executor.Infrastructure.Submit(ctx, plan.Infrastructure)
	receipt.Infrastructure = &infrastructure
	receipt.MutationState = combinedMutationState(receipt.MutationState, infrastructure.MutationState)
	if err != nil {
		receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
		return receipt, fmt.Errorf("infrastructure authority submission: %w", err)
	}
	management, err := executor.Management.Submit(ctx, plan.Management)
	receipt.Management = &management
	receipt.MutationState = combinedMutationState(receipt.MutationState, management.MutationState)
	if err != nil {
		receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
		return receipt, fmt.Errorf("management authority submission: %w", err)
	}
	receipt.State = "SUBMITTED_OBSERVATION_PENDING"
	return receipt, nil
}

func combinedMutationState(current, next string) string {
	if current == "ATTEMPTED" || next == "ATTEMPTED" {
		return "ATTEMPTED"
	}
	return "NOT_ATTEMPTED"
}
