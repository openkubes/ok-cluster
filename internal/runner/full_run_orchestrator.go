package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const (
	FullRunOrchestrationReceiptFormat       = "ok147-full-run-orchestration-receipt/v1"
	PostRuntimeContinuationBindingFormat    = "ok147-post-runtime-continuation-binding/v1"
	postRuntimeContinuationBindingState     = "VERIFIED"
	fullRunOrchestrationInitialStoppedStage = "provider-prerequisites"
)

type FullRunStageCheckpoint struct {
	StageID            string `json:"stageId"`
	State              string `json:"state"`
	StageReceiptDigest string `json:"stageReceiptDigest"`
}

// FullRunOrchestrationReceipt contains only redaction-safe stage identities.
// It does not contain authorization material, credentials, endpoints, target
// identities, raw objects or local paths.
type FullRunOrchestrationReceipt struct {
	Format       string                   `json:"format"`
	State        string                   `json:"state"`
	PlanDigest   string                   `json:"planDigest,omitempty"`
	StoppedAt    string                   `json:"stoppedAt,omitempty"`
	StopCategory string                   `json:"stopCategory,omitempty"`
	Checkpoints  []FullRunStageCheckpoint `json:"checkpoints"`
}

// PostRuntimeContinuationBinding proves that one already-opened Stage 8-12
// execution consumes the exact seven durable receipts produced by the prefix.
type PostRuntimeContinuationBinding struct {
	Format       string                      `json:"format"`
	State        string                      `json:"state"`
	PlanDigest   string                      `json:"planDigest"`
	Predecessors []PreRuntimeStageCheckpoint `json:"predecessors"`
}

// PostRuntimeContinuation is the narrow seam to the existing concrete
// PostRuntimeExecution. Binding is checked before Run can be invoked.
type PostRuntimeContinuation interface {
	ContinuationBinding() (PostRuntimeContinuationBinding, error)
	Run(context.Context) (PostRuntimeExecutionReceipt, error)
}

// PreRuntimeContinuation is the redaction-safe prefix seam. Both the typed
// orchestration and the concrete Stage 1-7 execution adapter can satisfy it.
type PreRuntimeContinuation interface {
	Run(context.Context) (PreRuntimeOrchestrationReceipt, error)
}

// FullRunOrchestration composes the exact Stage 1-7 prefix with one
// receipt-bound Stage 8-12 continuation. BindPostRuntime may open private
// runtime material but must not execute a stage; the returned binding is
// independently checked before Run.
type FullRunOrchestration struct {
	PreRuntime      PreRuntimeContinuation
	BindPostRuntime func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error)

	mu   sync.Mutex
	used bool
}

// Run is single-use and fail-closed. It has no retry, rollback or cleanup
// path, and never invokes the post-runtime continuation unless its exact seven
// predecessor receipt identities equal the completed prefix.
func (orchestration *FullRunOrchestration) Run(ctx context.Context) (FullRunOrchestrationReceipt, error) {
	receipt := FullRunOrchestrationReceipt{
		Format: FullRunOrchestrationReceiptFormat, State: "RUNNING",
		Checkpoints: []FullRunStageCheckpoint{},
	}
	if orchestration == nil {
		return stopFullRunOrchestration(receipt, fullRunOrchestrationInitialStoppedStage)
	}
	orchestration.mu.Lock()
	if orchestration.used {
		orchestration.mu.Unlock()
		return stopFullRunOrchestration(receipt, fullRunOrchestrationInitialStoppedStage)
	}
	orchestration.used = true
	orchestration.mu.Unlock()
	if orchestration.PreRuntime == nil || orchestration.BindPostRuntime == nil {
		return stopFullRunOrchestration(receipt, fullRunOrchestrationInitialStoppedStage)
	}
	if err := ctx.Err(); err != nil {
		return stopFullRunOrchestration(receipt, fullRunOrchestrationInitialStoppedStage)
	}

	prefix, prefixErr := orchestration.PreRuntime.Run(ctx)
	if prefixErr != nil && prefix.State == "STOPPED" && prefix.StoppedAt == preRuntimeStageOrder[0] &&
		prefix.PlanDigest == "" && len(prefix.Checkpoints) == 0 {
		return stopFullRunOrchestrationWithCategory(receipt, prefix.StoppedAt, prefix.StopCategory, prefixErr)
	}
	if err := appendFullRunPrefix(&receipt, prefix); err != nil {
		return stopFullRunOrchestration(receipt, nextFullRunStage(receipt.Checkpoints))
	}
	if prefixErr != nil || prefix.State != "SUCCEEDED" {
		return stopFullRunOrchestrationWithCategory(receipt, prefix.StoppedAt, prefix.StopCategory, prefixErr)
	}
	if err := ctx.Err(); err != nil {
		return stopFullRunOrchestration(receipt, postRuntimeStageOrder[0])
	}

	continuation, err := orchestration.BindPostRuntime(ctx, prefix)
	if err != nil || continuation == nil {
		return stopFullRunOrchestration(receipt, postRuntimeStageOrder[0])
	}
	binding, err := continuation.ContinuationBinding()
	if err != nil || validatePostRuntimeContinuationBinding(prefix, binding) != nil {
		return stopFullRunOrchestration(receipt, postRuntimeStageOrder[0])
	}
	if err := ctx.Err(); err != nil {
		return stopFullRunOrchestration(receipt, postRuntimeStageOrder[0])
	}

	suffix, suffixErr := continuation.Run(ctx)
	if err := appendFullRunSuffix(&receipt, suffix); err != nil {
		return stopFullRunOrchestration(receipt, nextFullRunStage(receipt.Checkpoints))
	}
	if suffixErr != nil || suffix.State != "SUCCEEDED" {
		return stopFullRunOrchestration(receipt, suffix.StoppedAt)
	}
	receipt.State = "SUCCEEDED"
	return receipt, nil
}

func appendFullRunPrefix(receipt *FullRunOrchestrationReceipt, prefix PreRuntimeOrchestrationReceipt) error {
	if receipt == nil || prefix.Format != PreRuntimeOrchestrationReceiptFormat ||
		!oneOfString(prefix.State, "SUCCEEDED", "STOPPED") ||
		!stageReceiptPrefixDigestPattern.MatchString(prefix.PlanDigest) || len(prefix.Checkpoints) > len(preRuntimeStageOrder) {
		return errors.New("full-run pre-runtime receipt is invalid")
	}
	if prefix.State == "SUCCEEDED" && (len(prefix.Checkpoints) != len(preRuntimeStageOrder) || prefix.StoppedAt != "") {
		return errors.New("successful full-run prefix is incomplete")
	}
	if prefix.State == "STOPPED" {
		if !validStoppedStage(preRuntimeStageOrder, len(prefix.Checkpoints), prefix.StoppedAt) {
			return errors.New("stopped full-run prefix is inconsistent")
		}
		if prefix.StopCategory != "" && !validRedactedStopCategory(prefix.StopCategory) {
			return errors.New("stopped full-run prefix category is invalid")
		}
	}
	receipt.PlanDigest = prefix.PlanDigest
	for index, checkpoint := range prefix.Checkpoints {
		if checkpoint.StageID != preRuntimeStageOrder[index] || checkpoint.State != "COMPLETED_SUCCEEDED" ||
			!stageReceiptPrefixDigestPattern.MatchString(checkpoint.StageReceiptDigest) {
			return errors.New("full-run pre-runtime checkpoint is invalid")
		}
		receipt.Checkpoints = append(receipt.Checkpoints, FullRunStageCheckpoint(checkpoint))
	}
	return nil
}

func appendFullRunSuffix(receipt *FullRunOrchestrationReceipt, suffix PostRuntimeExecutionReceipt) error {
	if receipt == nil || suffix.Format != PostRuntimeExecutionReceiptFormat ||
		!oneOfString(suffix.State, "SUCCEEDED", "STOPPED") || suffix.PlanDigest != receipt.PlanDigest ||
		len(receipt.Checkpoints) != len(preRuntimeStageOrder) || len(suffix.Checkpoints) > len(postRuntimeStageOrder) {
		return errors.New("full-run post-runtime receipt is invalid")
	}
	if suffix.State == "SUCCEEDED" && (len(suffix.Checkpoints) != len(postRuntimeStageOrder) || suffix.StoppedAt != "") {
		return errors.New("successful full-run suffix is incomplete")
	}
	if suffix.State == "STOPPED" {
		if !validStoppedStage(postRuntimeStageOrder, len(suffix.Checkpoints), suffix.StoppedAt) {
			return errors.New("stopped full-run suffix is inconsistent")
		}
	}
	for index, checkpoint := range suffix.Checkpoints {
		if checkpoint.StageID != postRuntimeStageOrder[index] || checkpoint.State != "COMPLETED_SUCCEEDED" ||
			!stageReceiptPrefixDigestPattern.MatchString(checkpoint.StageReceiptDigest) {
			return errors.New("full-run post-runtime checkpoint is invalid")
		}
		receipt.Checkpoints = append(receipt.Checkpoints, FullRunStageCheckpoint(checkpoint))
	}
	return nil
}

func newPostRuntimeContinuationBinding(planDigest string, prefix []stagereceipt.Verified) (PostRuntimeContinuationBinding, error) {
	binding := PostRuntimeContinuationBinding{
		Format: PostRuntimeContinuationBindingFormat, State: postRuntimeContinuationBindingState,
		PlanDigest: planDigest, Predecessors: []PreRuntimeStageCheckpoint{},
	}
	if !stageReceiptPrefixDigestPattern.MatchString(planDigest) || len(prefix) != len(preRuntimeStageOrder) {
		return PostRuntimeContinuationBinding{}, errors.New("post-runtime continuation prefix is invalid")
	}
	for index, verified := range prefix {
		stage, err := verified.Receipt()
		if err != nil || stage.StageID != preRuntimeStageOrder[index] || stage.State != "SUCCEEDED" {
			return PostRuntimeContinuationBinding{}, errors.New("post-runtime continuation stage is invalid")
		}
		digest, err := verified.Digest()
		if err != nil || !stageReceiptPrefixDigestPattern.MatchString(digest) {
			return PostRuntimeContinuationBinding{}, errors.New("post-runtime continuation digest is invalid")
		}
		binding.Predecessors = append(binding.Predecessors, PreRuntimeStageCheckpoint{
			StageID: stage.StageID, State: "COMPLETED_SUCCEEDED", StageReceiptDigest: digest,
		})
	}
	return binding, nil
}

func validatePostRuntimeContinuationBinding(prefix PreRuntimeOrchestrationReceipt, binding PostRuntimeContinuationBinding) error {
	if binding.Format != PostRuntimeContinuationBindingFormat || binding.State != postRuntimeContinuationBindingState ||
		binding.PlanDigest != prefix.PlanDigest || len(binding.Predecessors) != len(prefix.Checkpoints) {
		return errors.New("post-runtime continuation binding differs from completed prefix")
	}
	for index := range prefix.Checkpoints {
		if binding.Predecessors[index] != prefix.Checkpoints[index] {
			return errors.New("post-runtime continuation predecessor differs from completed prefix")
		}
	}
	return nil
}

func (binding PostRuntimeContinuationBinding) clone() PostRuntimeContinuationBinding {
	binding.Predecessors = append([]PreRuntimeStageCheckpoint(nil), binding.Predecessors...)
	return binding
}

func nextFullRunStage(checkpoints []FullRunStageCheckpoint) string {
	index := len(checkpoints)
	if index < len(preRuntimeStageOrder) {
		return preRuntimeStageOrder[index]
	}
	index -= len(preRuntimeStageOrder)
	if index < len(postRuntimeStageOrder) {
		return postRuntimeStageOrder[index]
	}
	return postRuntimeStageOrder[len(postRuntimeStageOrder)-1]
}

func validStoppedStage(order []string, completed int, stoppedAt string) bool {
	if completed < len(order) && stoppedAt == order[completed] {
		return true
	}
	return completed > 0 && completed <= len(order) && stoppedAt == order[completed-1]
}

func stopFullRunOrchestration(receipt FullRunOrchestrationReceipt, stageID string) (FullRunOrchestrationReceipt, error) {
	if stageID == "" {
		stageID = nextFullRunStage(receipt.Checkpoints)
	}
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	receipt.StopCategory = "ORCHESTRATION_STOPPED"
	return receipt, errors.New("full-run orchestration stopped at " + stageID)
}

func stopFullRunOrchestrationWithCause(receipt FullRunOrchestrationReceipt, stageID string, cause error) (FullRunOrchestrationReceipt, error) {
	return stopFullRunOrchestrationWithCategory(receipt, stageID, "", cause)
}

func stopFullRunOrchestrationWithCategory(receipt FullRunOrchestrationReceipt, stageID, category string, cause error) (FullRunOrchestrationReceipt, error) {
	if stageID == "" {
		stageID = nextFullRunStage(receipt.Checkpoints)
	}
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	if category == "" {
		category = redactedStopCategory(cause)
	}
	receipt.StopCategory = category
	if cause == nil {
		return receipt, errors.New("full-run orchestration stopped at " + stageID)
	}
	return receipt, fmt.Errorf("full-run orchestration stopped at %s: %w", stageID, cause)
}

func oneOfString(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
