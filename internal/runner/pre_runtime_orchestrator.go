package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkubes/ok-cluster/internal/execution"
)

const PreRuntimeOrchestrationReceiptFormat = "ok147-pre-runtime-orchestration-receipt/v1"

var preRuntimeStageOrder = []string{
	"provider-prerequisites",
	"cluster-lifecycle",
	"lifecycle-observation",
	"enablement",
	"network-observation",
	"runtime-binding",
	"target-access",
}

type PreRuntimeStageCheckpoint struct {
	StageID            string `json:"stageId"`
	State              string `json:"state"`
	StageReceiptDigest string `json:"stageReceiptDigest"`
}

// PreRuntimeOrchestrationReceipt is a redaction-safe summary. It contains no
// credential, endpoint, target UID, CA, raw object or local path.
type PreRuntimeOrchestrationReceipt struct {
	Format      string                      `json:"format"`
	State       string                      `json:"state"`
	PlanDigest  string                      `json:"planDigest,omitempty"`
	StoppedAt   string                      `json:"stoppedAt,omitempty"`
	Checkpoints []PreRuntimeStageCheckpoint `json:"checkpoints"`
}

// PreRuntimeOrchestration composes only the already bounded Stage 1-7
// operations. Each callback may perform exactly one stage invocation and
// receives only the redaction-safe receipt of its direct predecessor.
type PreRuntimeOrchestration struct {
	RunProviderPrerequisites func(context.Context) (execution.StagedOperationReceipt, error)
	RunClusterLifecycle      func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error)
	RunLifecycleObservation  func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error)
	RunEnablement            func(context.Context, execution.ObservationStageRunReceipt) (execution.StagedOperationReceipt, error)
	RunNetworkObservation    func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error)
	RunRuntimeBinding        func(context.Context, execution.ObservationStageRunReceipt) (execution.BindingStageRunReceipt, error)
	RunTargetAccess          func(context.Context, execution.BindingStageRunReceipt) (execution.StagedOperationReceipt, error)
}

// Run executes the seven-stage prefix once, in order, and stops on the first
// malformed receipt or error. It has no retry, rollback or cleanup path.
func (orchestration PreRuntimeOrchestration) Run(ctx context.Context) (PreRuntimeOrchestrationReceipt, error) {
	receipt := PreRuntimeOrchestrationReceipt{
		Format: PreRuntimeOrchestrationReceiptFormat, State: "RUNNING",
		Checkpoints: []PreRuntimeStageCheckpoint{},
	}
	if orchestration.RunProviderPrerequisites == nil || orchestration.RunClusterLifecycle == nil ||
		orchestration.RunLifecycleObservation == nil || orchestration.RunEnablement == nil ||
		orchestration.RunNetworkObservation == nil || orchestration.RunRuntimeBinding == nil ||
		orchestration.RunTargetAccess == nil {
		receipt.State, receipt.StoppedAt = "STOPPED", preRuntimeStageOrder[0]
		return receipt, errors.New("pre-runtime orchestration is incomplete")
	}
	if err := ctx.Err(); err != nil {
		receipt.State, receipt.StoppedAt = "STOPPED", preRuntimeStageOrder[0]
		return receipt, errors.New("pre-runtime orchestration context is unavailable")
	}

	providerReceipt, runErr := orchestration.RunProviderPrerequisites(ctx)
	appendErr := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[0], execution.StagedReceiptFormat, providerReceipt.Format, providerReceipt.State, providerReceipt.PlanDigest, providerReceipt.StageID, providerReceipt.StageReceiptDigest)
	if runErr != nil {
		if appendErr == nil || providerReceipt == (execution.StagedOperationReceipt{}) {
			return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[0], runErr)
		}
		return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[0], appendErr)
	}
	if appendErr != nil {
		return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[0], appendErr)
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[1])
	}

	lifecycleReceipt, runErr := orchestration.RunClusterLifecycle(ctx, providerReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[1], execution.StagedReceiptFormat, lifecycleReceipt.Format, lifecycleReceipt.State, lifecycleReceipt.PlanDigest, lifecycleReceipt.StageID, lifecycleReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[1])
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[2])
	}

	lifecycleObservationReceipt, runErr := orchestration.RunLifecycleObservation(ctx, lifecycleReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[2], execution.ObservationStageReceiptFormat, lifecycleObservationReceipt.Format, lifecycleObservationReceipt.State, lifecycleObservationReceipt.PlanDigest, lifecycleObservationReceipt.StageID, lifecycleObservationReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[2])
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[3])
	}

	enablementReceipt, runErr := orchestration.RunEnablement(ctx, lifecycleObservationReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[3], execution.StagedReceiptFormat, enablementReceipt.Format, enablementReceipt.State, enablementReceipt.PlanDigest, enablementReceipt.StageID, enablementReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[3])
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[4])
	}

	networkObservationReceipt, runErr := orchestration.RunNetworkObservation(ctx, enablementReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[4], execution.ObservationStageReceiptFormat, networkObservationReceipt.Format, networkObservationReceipt.State, networkObservationReceipt.PlanDigest, networkObservationReceipt.StageID, networkObservationReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[4])
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[5])
	}

	runtimeBindingReceipt, runErr := orchestration.RunRuntimeBinding(ctx, networkObservationReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[5], execution.BindingStageReceiptFormat, runtimeBindingReceipt.Format, runtimeBindingReceipt.State, runtimeBindingReceipt.PlanDigest, runtimeBindingReceipt.StageID, runtimeBindingReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[5])
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[6])
	}

	targetAccessReceipt, runErr := orchestration.RunTargetAccess(ctx, runtimeBindingReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[6], execution.StagedReceiptFormat, targetAccessReceipt.Format, targetAccessReceipt.State, targetAccessReceipt.PlanDigest, targetAccessReceipt.StageID, targetAccessReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[6])
	}
	receipt.State = "SUCCEEDED"
	return receipt, nil
}

func appendPreRuntimeCheckpoint(receipt *PreRuntimeOrchestrationReceipt, expectedStage, expectedFormat, format, state, planDigest, stageID, stageReceiptDigest string) error {
	if receipt == nil || format != expectedFormat || state != "COMPLETED_SUCCEEDED" || stageID != expectedStage ||
		!stageReceiptPrefixDigestPattern.MatchString(planDigest) || !stageReceiptPrefixDigestPattern.MatchString(stageReceiptDigest) {
		return errors.New("pre-runtime stage receipt is invalid")
	}
	if receipt.PlanDigest == "" {
		receipt.PlanDigest = planDigest
	} else if receipt.PlanDigest != planDigest {
		return errors.New("pre-runtime stage plan identity changed")
	}
	receipt.Checkpoints = append(receipt.Checkpoints, PreRuntimeStageCheckpoint{
		StageID: stageID, State: state, StageReceiptDigest: stageReceiptDigest,
	})
	return nil
}

func stopPreRuntimeOrchestration(receipt PreRuntimeOrchestrationReceipt, stageID string) (PreRuntimeOrchestrationReceipt, error) {
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	return receipt, errors.New("pre-runtime orchestration stopped at " + stageID)
}

func stopPreRuntimeOrchestrationWithCause(receipt PreRuntimeOrchestrationReceipt, stageID string, cause error) (PreRuntimeOrchestrationReceipt, error) {
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	if cause == nil {
		return receipt, errors.New("pre-runtime orchestration stopped at " + stageID)
	}
	return receipt, fmt.Errorf("pre-runtime orchestration stopped at %s: %w", stageID, cause)
}
