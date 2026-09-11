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
	Format       string                      `json:"format"`
	State        string                      `json:"state"`
	PlanDigest   string                      `json:"planDigest,omitempty"`
	StoppedAt    string                      `json:"stoppedAt,omitempty"`
	StopCategory string                      `json:"stopCategory,omitempty"`
	Checkpoints  []PreRuntimeStageCheckpoint `json:"checkpoints"`
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
	if appendErr := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[4], execution.ObservationStageReceiptFormat, networkObservationReceipt.Format, networkObservationReceipt.State, networkObservationReceipt.PlanDigest, networkObservationReceipt.StageID, networkObservationReceipt.StageReceiptDigest); appendErr != nil || runErr != nil {
		if runErr != nil {
			return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[4], runErr)
		}
		return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[4], appendErr)
	}
	if err := ctx.Err(); err != nil {
		return stopPreRuntimeOrchestration(receipt, preRuntimeStageOrder[5])
	}

	runtimeBindingReceipt, runErr := orchestration.RunRuntimeBinding(ctx, networkObservationReceipt)
	if err := appendPreRuntimeCheckpoint(&receipt, preRuntimeStageOrder[5], execution.BindingStageReceiptFormat, runtimeBindingReceipt.Format, runtimeBindingReceipt.State, runtimeBindingReceipt.PlanDigest, runtimeBindingReceipt.StageID, runtimeBindingReceipt.StageReceiptDigest); err != nil || runErr != nil {
		if runErr != nil {
			return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[5], runErr)
		}
		return stopPreRuntimeOrchestrationWithCause(receipt, preRuntimeStageOrder[5], err)
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
	receipt.StopCategory = "ORCHESTRATION_STOPPED"
	return receipt, errors.New("pre-runtime orchestration stopped at " + stageID)
}

func stopPreRuntimeOrchestrationWithCause(receipt PreRuntimeOrchestrationReceipt, stageID string, cause error) (PreRuntimeOrchestrationReceipt, error) {
	receipt.State, receipt.StoppedAt = "STOPPED", stageID
	receipt.StopCategory = redactedStopCategory(cause)
	if cause == nil {
		return receipt, errors.New("pre-runtime orchestration stopped at " + stageID)
	}
	return receipt, fmt.Errorf("pre-runtime orchestration stopped at %s: %w", stageID, cause)
}

type redactedStopCategorizer interface {
	RedactedStopCategory() string
}

type fixedRedactedStopError struct {
	category string
	cause    error
}

func (err *fixedRedactedStopError) Error() string { return "stage orchestration stopped" }
func (err *fixedRedactedStopError) Unwrap() error { return err.cause }
func (err *fixedRedactedStopError) RedactedStopCategory() string {
	return err.category
}

func newFixedRedactedStop(category string, cause error) error {
	return &fixedRedactedStopError{category: category, cause: cause}
}

func redactedStopOrFallback(fallback string, cause error) error {
	var categorized redactedStopCategorizer
	if errors.As(cause, &categorized) {
		category := categorized.RedactedStopCategory()
		if validPostRuntimeBindStopCategory(category) || validPostPrefixActivationStopCategory(category) {
			return cause
		}
	}
	return newFixedRedactedStop(fallback, cause)
}

func validPostRuntimeBindStopCategory(category string) bool {
	switch category {
	case "POST_RUNTIME_PREFIX_UNAVAILABLE", "POST_RUNTIME_PREFIX_MISMATCH", "POST_RUNTIME_TARGET_IDENTITY_UNAVAILABLE",
		"POST_RUNTIME_WORKLOAD_AUTHORITY_UNAVAILABLE", "POST_RUNTIME_WORKLOAD_AUTHORITY_BIND_STOPPED", "POST_RUNTIME_EVIDENCE_IDENTITY_BIND_STOPPED",
		"POST_RUNTIME_ACTIVATION_STOPPED", "POST_RUNTIME_EXECUTION_OPEN_STOPPED":
		return true
	default:
		return false
	}
}

func postPrefixActivationStopOrFallback(cause error) error {
	var categorized redactedStopCategorizer
	if errors.As(cause, &categorized) && validPostPrefixActivationStopCategory(categorized.RedactedStopCategory()) {
		return cause
	}
	return newFixedRedactedStop("POST_RUNTIME_ACTIVATION_STOPPED", cause)
}

func validPostPrefixActivationStopCategory(category string) bool {
	switch category {
	case "POST_PREFIX_BINDING_INVALID", "POST_PREFIX_WORKLOAD_AUTHORITY_INVALID",
		"POST_PREFIX_RUNTIME_AUTHORITY_BUILD_STOPPED", "POST_PREFIX_RUNTIME_AUTHORITY_INSTALL_STOPPED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_STOPPED", "POST_PREFIX_OBSERVER_CREDENTIAL_TRANSPORT_STOPPED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CONVERGENCE_EXHAUSTED", "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_INVALID",
		"POST_PREFIX_OBSERVER_AUTHORITY_CONVERGENCE_EXHAUSTED", "POST_PREFIX_OBSERVER_AUTHORITY_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_HTTP_REJECTED", "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_ENVELOPE_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH", "POST_PREFIX_OBSERVER_CREDENTIAL_MATERIALIZATION_STOPPED", "POST_PREFIX_PACKAGE_BUILD_STOPPED",
		"POST_PREFIX_PACKAGE_CONSTRUCTION_STOPPED", "POST_PREFIX_PACKAGE_RECEIPT_INVALID", "POST_PREFIX_PACKAGE_PREFIX_MISMATCH",
		"POST_PREFIX_PACKAGE_CONFIG_INVALID", "POST_PREFIX_ACTIVATION_PACKAGE_BUILD_STOPPED", "POST_PREFIX_JOB_ENVELOPE_BUILD_STOPPED", "POST_PREFIX_PACKAGE_VERIFICATION_STOPPED",
		"POST_PREFIX_ACTIVATION_IDENTITY_INVALID", "POST_PREFIX_ACTIVATION_MANIFEST_BINDING_INVALID", "POST_PREFIX_ACTIVATION_RUNTIME_BINDING_INVALID", "POST_PREFIX_ACTIVATION_OBSERVER_CREDENTIAL_INVALID",
		"POST_PREFIX_ACTIVATION_WORKLOAD_CA_INVALID", "POST_PREFIX_ACTIVATION_AUTHORITIES_INVALID", "POST_PREFIX_ACTIVATION_TLS_NETWORK_INVALID", "POST_PREFIX_ACTIVATION_POLICY_OR_SIZE_INVALID",
		"POST_PREFIX_INSTALLER_CREDENTIAL_STOPPED", "POST_PREFIX_INSTALLER_CREDENTIAL_ISSUANCE_STOPPED",
		"POST_PREFIX_INSTALLER_CREDENTIAL_RECEIPT_INVALID", "POST_PREFIX_INSTALLER_CREDENTIAL_RECEIPT_ENCODING_STOPPED",
		"POST_PREFIX_INSTALLER_CREDENTIAL_MATERIALIZATION_STOPPED", "POST_PREFIX_LAUNCH_STOPPED":
		return true
	default:
		return false
	}
}

func postPrefixObserverCredentialStopOrFallback(cause error) error {
	var categorized redactedStopCategorizer
	if errors.As(cause, &categorized) && validPostPrefixObserverCredentialStopCategory(categorized.RedactedStopCategory()) {
		return cause
	}
	return newFixedRedactedStop("POST_PREFIX_OBSERVER_CREDENTIAL_STOPPED", cause)
}

func validPostPrefixObserverCredentialStopCategory(category string) bool {
	switch category {
	case "POST_PREFIX_OBSERVER_CREDENTIAL_TRANSPORT_STOPPED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CONVERGENCE_EXHAUSTED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_INVALID",
		"POST_PREFIX_OBSERVER_AUTHORITY_CONVERGENCE_EXHAUSTED",
		"POST_PREFIX_OBSERVER_AUTHORITY_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_HTTP_REJECTED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_ENVELOPE_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH",
		"POST_PREFIX_OBSERVER_CREDENTIAL_MATERIALIZATION_STOPPED":
		return true
	default:
		return false
	}
}

func redactedStopCategory(cause error) string {
	if cause == nil {
		return "ORCHESTRATION_STOPPED"
	}
	var categorized redactedStopCategorizer
	if errors.As(cause, &categorized) {
		switch category := categorized.RedactedStopCategory(); category {
		case "OBSERVATION_SOURCE_ERROR", "OBSERVATION_RESULT_INVALID", "OBSERVATION_INTERRUPTED",
			"RUNTIME_BINDING_SOURCE_STOPPED", "RUNTIME_BINDING_MATERIALIZATION_STOPPED", "RUNTIME_BINDING_MATERIAL_VERIFICATION_STOPPED", "RUNTIME_BINDING_PERSISTENCE_STOPPED", "RUNTIME_BINDING_WRITER_OPEN_STOPPED",
			"AUTHORIZATION_TRANSPORT_STOPPED", "AUTHORIZATION_HTTP_REJECTED", "AUTHORIZATION_RESPONSE_INVALID", "AUTHORIZATION_PERSISTENCE_STOPPED", "AUTHORIZATION_INTERRUPTED",
			"POST_RUNTIME_BIND_STOPPED", "POST_RUNTIME_PREFIX_UNAVAILABLE", "POST_RUNTIME_PREFIX_MISMATCH", "POST_RUNTIME_TARGET_IDENTITY_UNAVAILABLE",
			"POST_RUNTIME_WORKLOAD_AUTHORITY_UNAVAILABLE", "POST_RUNTIME_WORKLOAD_AUTHORITY_BIND_STOPPED", "POST_RUNTIME_EVIDENCE_IDENTITY_BIND_STOPPED",
			"POST_RUNTIME_ACTIVATION_STOPPED", "POST_RUNTIME_EXECUTION_OPEN_STOPPED",
			"POST_PREFIX_BINDING_INVALID", "POST_PREFIX_WORKLOAD_AUTHORITY_INVALID", "POST_PREFIX_RUNTIME_AUTHORITY_BUILD_STOPPED", "POST_PREFIX_RUNTIME_AUTHORITY_INSTALL_STOPPED",
			"POST_PREFIX_OBSERVER_CREDENTIAL_STOPPED", "POST_PREFIX_OBSERVER_CREDENTIAL_TRANSPORT_STOPPED",
			"POST_PREFIX_OBSERVER_CREDENTIAL_CONVERGENCE_EXHAUSTED", "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_INVALID",
			"POST_PREFIX_OBSERVER_AUTHORITY_CONVERGENCE_EXHAUSTED", "POST_PREFIX_OBSERVER_AUTHORITY_INVALID",
			"POST_PREFIX_OBSERVER_CREDENTIAL_HTTP_REJECTED", "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_ENVELOPE_INVALID",
			"POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH", "POST_PREFIX_OBSERVER_CREDENTIAL_MATERIALIZATION_STOPPED",
			"POST_PREFIX_PACKAGE_BUILD_STOPPED", "POST_PREFIX_PACKAGE_CONSTRUCTION_STOPPED", "POST_PREFIX_PACKAGE_RECEIPT_INVALID", "POST_PREFIX_PACKAGE_PREFIX_MISMATCH",
			"POST_PREFIX_PACKAGE_CONFIG_INVALID", "POST_PREFIX_ACTIVATION_PACKAGE_BUILD_STOPPED", "POST_PREFIX_JOB_ENVELOPE_BUILD_STOPPED", "POST_PREFIX_PACKAGE_VERIFICATION_STOPPED",
			"POST_PREFIX_ACTIVATION_IDENTITY_INVALID", "POST_PREFIX_ACTIVATION_MANIFEST_BINDING_INVALID", "POST_PREFIX_ACTIVATION_RUNTIME_BINDING_INVALID", "POST_PREFIX_ACTIVATION_OBSERVER_CREDENTIAL_INVALID",
			"POST_PREFIX_ACTIVATION_WORKLOAD_CA_INVALID", "POST_PREFIX_ACTIVATION_AUTHORITIES_INVALID", "POST_PREFIX_ACTIVATION_TLS_NETWORK_INVALID", "POST_PREFIX_ACTIVATION_POLICY_OR_SIZE_INVALID",
			"POST_PREFIX_INSTALLER_CREDENTIAL_STOPPED", "POST_PREFIX_INSTALLER_CREDENTIAL_ISSUANCE_STOPPED",
			"POST_PREFIX_INSTALLER_CREDENTIAL_RECEIPT_INVALID", "POST_PREFIX_INSTALLER_CREDENTIAL_RECEIPT_ENCODING_STOPPED",
			"POST_PREFIX_INSTALLER_CREDENTIAL_MATERIALIZATION_STOPPED", "POST_PREFIX_LAUNCH_STOPPED",
			"CONTINUATION_BINDING_UNAVAILABLE", "CONTINUATION_BINDING_INVALID", "TARGET_CREDENTIAL_HANDOFF_MISSING":
			return category
		}
	}
	var observationResult *execution.ObservationStageResultError
	if errors.As(cause, &observationResult) {
		return "OBSERVATION_" + observationResult.State
	}
	return "STAGE_EXECUTION_ERROR"
}

func validRedactedStopCategory(category string) bool {
	switch category {
	case "ORCHESTRATION_STOPPED", "STAGE_EXECUTION_ERROR", "OBSERVATION_SOURCE_ERROR",
		"OBSERVATION_RESULT_INVALID", "OBSERVATION_INTERRUPTED", "OBSERVATION_COMPLETED_FAILED",
		"OBSERVATION_COMPLETED_STOPPED", "RUNTIME_BINDING_SOURCE_STOPPED", "RUNTIME_BINDING_MATERIALIZATION_STOPPED",
		"RUNTIME_BINDING_MATERIAL_VERIFICATION_STOPPED", "RUNTIME_BINDING_PERSISTENCE_STOPPED", "RUNTIME_BINDING_WRITER_OPEN_STOPPED",
		"AUTHORIZATION_TRANSPORT_STOPPED", "AUTHORIZATION_HTTP_REJECTED", "AUTHORIZATION_RESPONSE_INVALID", "AUTHORIZATION_PERSISTENCE_STOPPED", "AUTHORIZATION_INTERRUPTED",
		"POST_RUNTIME_BIND_STOPPED", "POST_RUNTIME_PREFIX_UNAVAILABLE", "POST_RUNTIME_PREFIX_MISMATCH", "POST_RUNTIME_TARGET_IDENTITY_UNAVAILABLE",
		"POST_RUNTIME_WORKLOAD_AUTHORITY_UNAVAILABLE", "POST_RUNTIME_WORKLOAD_AUTHORITY_BIND_STOPPED", "POST_RUNTIME_EVIDENCE_IDENTITY_BIND_STOPPED",
		"POST_RUNTIME_ACTIVATION_STOPPED", "POST_RUNTIME_EXECUTION_OPEN_STOPPED",
		"POST_PREFIX_BINDING_INVALID", "POST_PREFIX_WORKLOAD_AUTHORITY_INVALID", "POST_PREFIX_RUNTIME_AUTHORITY_BUILD_STOPPED", "POST_PREFIX_RUNTIME_AUTHORITY_INSTALL_STOPPED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_STOPPED", "POST_PREFIX_OBSERVER_CREDENTIAL_TRANSPORT_STOPPED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CONVERGENCE_EXHAUSTED", "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_INVALID",
		"POST_PREFIX_OBSERVER_AUTHORITY_CONVERGENCE_EXHAUSTED", "POST_PREFIX_OBSERVER_AUTHORITY_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_HTTP_REJECTED", "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_ENVELOPE_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH", "POST_PREFIX_OBSERVER_CREDENTIAL_MATERIALIZATION_STOPPED",
		"POST_PREFIX_PACKAGE_BUILD_STOPPED", "POST_PREFIX_PACKAGE_CONSTRUCTION_STOPPED", "POST_PREFIX_PACKAGE_RECEIPT_INVALID", "POST_PREFIX_PACKAGE_PREFIX_MISMATCH",
		"POST_PREFIX_PACKAGE_CONFIG_INVALID", "POST_PREFIX_ACTIVATION_PACKAGE_BUILD_STOPPED", "POST_PREFIX_JOB_ENVELOPE_BUILD_STOPPED", "POST_PREFIX_PACKAGE_VERIFICATION_STOPPED",
		"POST_PREFIX_ACTIVATION_IDENTITY_INVALID", "POST_PREFIX_ACTIVATION_MANIFEST_BINDING_INVALID", "POST_PREFIX_ACTIVATION_RUNTIME_BINDING_INVALID", "POST_PREFIX_ACTIVATION_OBSERVER_CREDENTIAL_INVALID",
		"POST_PREFIX_ACTIVATION_WORKLOAD_CA_INVALID", "POST_PREFIX_ACTIVATION_AUTHORITIES_INVALID", "POST_PREFIX_ACTIVATION_TLS_NETWORK_INVALID", "POST_PREFIX_ACTIVATION_POLICY_OR_SIZE_INVALID",
		"POST_PREFIX_INSTALLER_CREDENTIAL_STOPPED", "POST_PREFIX_INSTALLER_CREDENTIAL_ISSUANCE_STOPPED",
		"POST_PREFIX_INSTALLER_CREDENTIAL_RECEIPT_INVALID", "POST_PREFIX_INSTALLER_CREDENTIAL_RECEIPT_ENCODING_STOPPED",
		"POST_PREFIX_INSTALLER_CREDENTIAL_MATERIALIZATION_STOPPED", "POST_PREFIX_LAUNCH_STOPPED",
		"CONTINUATION_BINDING_UNAVAILABLE", "CONTINUATION_BINDING_INVALID", "TARGET_CREDENTIAL_HANDOFF_MISSING":
		return true
	default:
		return false
	}
}
