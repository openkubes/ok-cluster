package runner

import (
	"context"
	"errors"

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
	Format      string                       `json:"format"`
	State       string                       `json:"state"`
	PlanDigest  string                       `json:"planDigest,omitempty"`
	StoppedAt   string                       `json:"stoppedAt,omitempty"`
	Checkpoints []PostRuntimeStageCheckpoint `json:"checkpoints"`
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
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[0])
	}
	defer discardTargetCredentialHandoff(handoff)

	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[1])
	}
	registrationReceipt, runErr := orchestration.RunTargetRegistration(ctx, handoff, credentialReceipt)
	if err := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[1], execution.StagedReceiptFormat, registrationReceipt.Format, registrationReceipt.State, registrationReceipt.PlanDigest, registrationReceipt.StageID, registrationReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[1])
	}
	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[2])
	}
	applicationReceipt, runErr := orchestration.RunPlatformApplications(ctx, registrationReceipt)
	if err := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[2], execution.StagedReceiptFormat, applicationReceipt.Format, applicationReceipt.State, applicationReceipt.PlanDigest, applicationReceipt.StageID, applicationReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[2])
	}
	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[3])
	}
	observationReceipt, runErr := orchestration.RunPlatformObservation(ctx, applicationReceipt)
	if err := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[3], execution.ObservationStageReceiptFormat, observationReceipt.Format, observationReceipt.State, observationReceipt.PlanDigest, observationReceipt.StageID, observationReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[3])
	}
	if err := ctx.Err(); err != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[4])
	}
	evaluationReceipt, runErr := orchestration.RunAggregateEvidence(ctx, observationReceipt)
	if err := appendPostRuntimeCheckpoint(&receipt, postRuntimeStageOrder[4], execution.EvaluationStageReceiptFormat, evaluationReceipt.Format, evaluationReceipt.State, evaluationReceipt.PlanDigest, evaluationReceipt.StageID, evaluationReceipt.StageReceiptDigest); err != nil || runErr != nil {
		return stopPostRuntimeOrchestration(receipt, postRuntimeStageOrder[4])
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
	return receipt, errors.New("post-runtime orchestration stopped at " + stageID)
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
