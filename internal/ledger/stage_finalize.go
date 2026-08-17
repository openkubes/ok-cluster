package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

// FinalizeStageReceipt derives and persists the common stage receipt from an
// already durable mutating-stage outcome. It performs no stage work itself.
func (ledger *Ledger) FinalizeStageReceipt(ctx context.Context, plan stageplan.Binding, grant authorization.VerifiedStageGrant, predecessors []stagereceipt.Verified) (stagereceipt.Verified, error) {
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	stage, stageDigest, err := plan.Stage(binding.StageID)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	if !stageplan.IsMutating(stage) || binding.PlanDigest != plan.PlanDigest || binding.StageDigest != stageDigest || binding.Operation != stage.GrantOperation || binding.Authority != stage.Authority || binding.ContractRevision != plan.IntentRevision {
		return stagereceipt.Verified{}, errors.New("stage grant does not bind the mutating stage plan")
	}
	predecessorDigest, err := finalizedPredecessorDigest(predecessors)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	if predecessorDigest != binding.PredecessorDigest {
		return stagereceipt.Verified{}, errors.New("stage finalization predecessor receipts differ from authorization")
	}
	inspection, err := ledger.InspectStage(ctx, grant)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	if inspection.State != "COMPLETED" || inspection.Outcome == nil || inspection.OutcomeDigest == "" {
		return stagereceipt.Verified{}, errors.New("mutating stage has no durable completed outcome")
	}
	completedAt, err := time.Parse(time.RFC3339Nano, inspection.Outcome.CompletedAt)
	if err != nil {
		return stagereceipt.Verified{}, errors.New("mutating stage completion time is invalid")
	}
	verified, err := stagereceipt.NewWithTargetClusterUIDDigest(
		plan,
		stage.ID,
		predecessors,
		inspection.Outcome.Outcome,
		inspection.Outcome.MutationState,
		inspection.OutcomeDigest,
		inspection.Outcome.EvidenceDigest,
		inspection.Outcome.TargetClusterUIDDigest,
		completedAt,
	)
	if err != nil {
		return stagereceipt.Verified{}, fmt.Errorf("derive stage receipt from durable outcome: %w", err)
	}
	if _, err := ledger.StoreStageReceipt(ctx, plan, verified, predecessors); err != nil {
		return stagereceipt.Verified{}, err
	}
	return verified, nil
}

func finalizedPredecessorDigest(predecessors []stagereceipt.Verified) (string, error) {
	if predecessors == nil {
		return "", errors.New("stage finalization predecessor set must be explicit")
	}
	bindings := make([]authorization.StagePredecessor, len(predecessors))
	for index, predecessor := range predecessors {
		receipt, err := predecessor.Receipt()
		if err != nil {
			return "", err
		}
		receiptDigest, err := predecessor.Digest()
		if err != nil {
			return "", err
		}
		bindings[index] = authorization.StagePredecessor{StageID: receipt.StageID, OutcomeDigest: receiptDigest}
	}
	_, predecessorDigest, err := canonicalRecord(bindings)
	return predecessorDigest, err
}
