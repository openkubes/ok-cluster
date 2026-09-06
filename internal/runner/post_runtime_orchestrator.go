package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkubes/ok-cluster/internal/execution"
)

const PostRuntimeOrchestrationReceiptFormat = "ok147-post-runtime-orchestration-receipt/v1"

var postRuntimeStageOrder = []string{
	"target-credential",
	"target-registration",
	"platform-applications",
	"platform-observation",
	"aggregate-evidence",
}

type PostRuntimeStageCheckpoint struct {
	StageID            string `json:"stageId"`
	State              string `json:"state"`
	StageReceiptDigest string `json:"stageReceiptDigest"`
}

// PostRuntimeOrchestrationReceipt is a redaction-safe summary. It contains no
// credential, endpoint, target UID, CA or local path.
type PostRuntimeOrchestrationReceipt struct {
	Format       string                       `json:"format"`
	State        string                       `json:"state"`
	PlanDigest   string                       `json:"planDigest,omitempty"`
	StoppedAt    string                       `json:"stoppedAt,omitempty"`
	StopCategory string                       `json:"stopCategory,omitempty"`
	Checkpoints  []PostRuntimeStageCheckpoint `json:"checkpoints"`
}

// PostRuntimeOrchestration composes only the already bounded Stage 8-12
// operations. Each callback may perform exactly one stage invocation. The
// Stage-8 credential is passed only to Stage 9 and is never exposed in the
// public receipt or to a later callback.
type PostRuntimeOrchestration struct {
	RunTargetCredential     func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error)
	RunTargetRegistration   func(context.Context, *VerifiedTargetCredentialStageHandoff, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error)
	RunPlatformApplications func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error)
	RunPlatformObservation  func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error)
	RunAggregateEvidence    func(context.Context, execution.ObservationStageRunReceipt) (execution.EvaluationStageRunReceipt, error)
}

// Run executes the five-stage suffix once, in order, and stops on the first
// malformed receipt or error. It has no retry, rollback or cleanup path.
func (orchestration PostRuntimeOrchestration) Run(ctx context.Context) (PostRuntimeOrchestrationReceipt, error) {
	receipt := PostRuntimeOrchestrationReceipt{
		Format: PostRuntimeOrchestrationReceiptFormat, State: "RUNNING",
		Checkpoints: []PostRuntimeStageCheckpoint{},
	}
	if orchestration.RunTargetCredential == nil || orchestration.RunTargetRegistration == nil ||
		orchestration.RunPlatformApplications == nil || orchestration.RunPlatformObservation == nil ||
		orchestration.RunAggregateEvidence == nil {
		receipt.State, receipt.StoppedAt = "STOPPED", postRuntimeStageOrder[0]
		return receipt, errors.New("post-runtime orchestration is incomplete")
	}
	if err := ctx.Err(); err != nil {
		receipt.State, receipt.StoppedAt = "STOPPED", postRuntimeStageOrder[0]
		return receipt, errors.New("post-runtime orchestration context is unavailable")
	}

	credentialReceipt, handoff, runErr := orchestration.RunTargetCredential(ctx)
	if err := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[0], execution.StagedReceiptFormat, credentialReceipt.Format, credentialReceipt.State, credentialReceipt.PlanDigest, credentialReceipt.StageID, credentialReceipt.StageReceiptDigest); err != nil || runErr != nil || handoff == nil {
		discardTargetCredentialHandoff(handoff)
		if runErr != nil {
			return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[0], runErr)
		}
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[0], err)
	}
	defer discardTargetCredentialHandoff(handoff)

	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[1], err)
	}
	registrationReceipt, runErr := orchestration.RunTargetRegistration(ctx, handoff, credentialReceipt)
	if appendErr := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[1], execution.StagedReceiptFormat, registrationReceipt.Format, registrationReceipt.State, registrationReceipt.PlanDigest, registrationReceipt.StageID, registrationReceipt.StageReceiptDigest); appendErr != nil || runErr != nil {
		if runErr != nil {
			return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[1], runErr)
		}
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[1], appendErr)
	}
	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[2], err)
	}
	applicationReceipt, runErr := orchestration.RunPlatformApplications(ctx, registrationReceipt)
	if appendErr := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[2], execution.StagedReceiptFormat, applicationReceipt.Format, applicationReceipt.State, applicationReceipt.PlanDigest, applicationReceipt.StageID, applicationReceipt.StageReceiptDigest); appendErr != nil || runErr != nil {
		if runErr != nil {
			return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[2], runErr)
		}
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[2], appendErr)
	}
	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[3], err)
	}
	observationReceipt, runErr := orchestration.RunPlatformObservation(ctx, applicationReceipt)
	if appendErr := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[3], execution.ObservationStageReceiptFormat, observationReceipt.Format, observationReceipt.State, observationReceipt.PlanDigest, observationReceipt.StageID, observationReceipt.StageReceiptDigest); appendErr != nil || runErr != nil {
		if runErr != nil {
			return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[3], runErr)
		}
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[3], appendErr)
	}
	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[4], err)
	}
	evaluationReceipt, runErr := orchestration.RunAggregateEvidence(ctx, observationReceipt)
	if appendErr := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[4], execution.EvaluationStageReceiptFormat, evaluationReceipt.Format, evaluationReceipt.State, evaluationReceipt.PlanDigest, evaluationReceipt.StageID, evaluationReceipt.StageReceiptDigest); appendErr != nil || runErr != nil {
		if runErr != nil {
			return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[4], runErr)
		}
		return stopPostRuntimeOrchestrationWithCause(receipt, postRuntimeStageOrder[4], appendErr)
	}
	receipt.State = "SUCCEEDED"
	return receipt, nil
}

func appendPostRuntimeCheckpoint(receipt *PostRuntimeOrchestrationReceipt, expectedStage, expectedFormat, format, state, planDigest, stageID, stageReceiptDigest string) error {
	if receipt == nil || format != expectedFormat || state != "COMPLETED_SUCCEEDED" || stageID != expectedStage ||
		!stageReceiptPrefixDigestPattern.MatchString(planDigest) || !stageReceiptPrefixDigestPattern.MatchString(stageReceiptDigest) {
		return errors.New("post-runtime stage receipt is invalid")
	}
	if receipt.PlanDigest == "" {
		receipt.PlanDigest = planDigest
	} else if receipt.PlanDigest != planDigest {
		return errors.New("post-runtime stage plan identity changed")
	}
	receipt.Checkpoints = append(receipt.Checkpoints, PostRuntimeStageCheckpoint{
		StageID: stageID, State: state, StageReceiptDigest: stageReceiptDigest,
	})
	return nil
}

func stopPostRuntimeOrchestration(receipt PostRuntimeOrchestrationReceipt, stageID string) (PostRuntimeOrchestrationReceipt, error) {
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	receipt.StopCategory = "ORCHESTRATION_STOPPED"
	return receipt, errors.New("post-runtime orchestration stopped at " + stageID)
}

func stopPostRuntimeOrchestrationWithCause(receipt PostRuntimeOrchestrationReceipt, stageID string, cause error) (PostRuntimeOrchestrationReceipt, error) {
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	receipt.StopCategory = redactedStopCategory(cause)
	if cause == nil {
		return receipt, errors.New("post-runtime orchestration stopped at " + stageID)
	}
	return receipt, fmt.Errorf("post-runtime orchestration stopped at %s: %w", stageID, cause)
}

func discardTargetCredentialHandoff(handoff *VerifiedTargetCredentialStageHandoff) {
	if handoff == nil {
		return
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.consumed {
		return
	}
	handoff.consumed = true
	handoff.credential = VerifiedTargetCredentialMaterial{}
}
