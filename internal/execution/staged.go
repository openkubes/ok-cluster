package execution

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const StagedReceiptFormat = "ok147-staged-operation-run-receipt/v1"

var stagedDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// StageMutationBinding makes one preconstructed mutator specific to one
// verified plan stage. The mutator is not a dynamic operation dispatcher.
type StageMutationBinding struct {
	PlanDigest       string
	StageID          string
	StageDigest      string
	Operation        string
	Authority        string
	ContractRevision string
}

// StageMutationRequest contains only verified identities. Implementation
// inputs and credentials remain inside the preconstructed mutator.
type StageMutationRequest struct {
	StageMutationBinding
	ContractIdentity  contract.Identity
	GrantID           string
	PredecessorDigest string
}

// StageMutationResult is the complete redaction-safe result of one call.
type StageMutationResult struct {
	Outcome                string
	MutationState          string
	EvidenceDigest         string
	TargetClusterUIDDigest string
	FailureCategory        string
}

// StageMutator is a single, preconstructed mutation capability.
type StageMutator interface {
	Binding() StageMutationBinding
	Mutate(context.Context, StageMutationRequest) (StageMutationResult, error)
}

// StagedOperation composes cursor verification, authorization binding,
// single-use claim, one mutator call, durable outcome and receipt finalization.
type StagedOperation struct {
	Ledger  *ledger.Ledger
	Mutator StageMutator
	Clock   func() time.Time
}

// StagedOperationReceipt is redaction-safe orchestration evidence. The
// immutable stage receipt remains authoritative for chain continuation.
type StagedOperationReceipt struct {
	Format             string                      `json:"format"`
	State              string                      `json:"state"`
	PlanDigest         string                      `json:"planDigest,omitempty"`
	StageID            string                      `json:"stageId,omitempty"`
	Claim              *ledger.StageClaimReceipt   `json:"claim,omitempty"`
	Outcome            *ledger.StageOutcomeReceipt `json:"outcome,omitempty"`
	StageReceiptDigest string                      `json:"stageReceiptDigest,omitempty"`
	FailureCategory    string                      `json:"failureCategory,omitempty"`
}

// StageResultError means the operation reached a durable non-success outcome.
// It never exposes a mutator's raw error.
type StageResultError struct {
	State           string
	FailureCategory string
}

func (err *StageResultError) Error() string                { return "staged operation completed with " + err.State }
func (err *StageResultError) RedactedStopCategory() string { return err.FailureCategory }

// Run invokes at most one mutator. A pre-existing claim without outcome is an
// indeterminate terminal stop; a durable outcome is finalized without replay.
func (operation StagedOperation) Run(ctx context.Context, plan stageplan.Binding, cursor stagecursor.Cursor, grant authorization.VerifiedStageGrant) (StagedOperationReceipt, error) {
	receipt := StagedOperationReceipt{Format: StagedReceiptFormat, State: "PRECLAIM"}
	if operation.Ledger == nil || operation.Mutator == nil || operation.Clock == nil {
		return receipt, errors.New("staged operation ledger, mutator, and clock are required")
	}
	decision, err := cursor.Decision()
	if err != nil {
		return receipt, err
	}
	if decision.State != "NEXT" || !decision.RequiresAuthorization || decision.Operation == "" {
		return receipt, errors.New("stage cursor does not select an authorized mutating stage")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return receipt, err
	}
	binding, err := authorization.BindStageGrant(grant, plan, decision.StageID, predecessors)
	if err != nil {
		return receipt, err
	}
	receipt.PlanDigest = binding.PlanDigest
	receipt.StageID = binding.StageID
	wantMutation := StageMutationBinding{
		PlanDigest: binding.PlanDigest, StageID: binding.StageID, StageDigest: binding.StageDigest,
		Operation: binding.Operation, Authority: binding.Authority, ContractRevision: binding.ContractRevision,
	}
	if operation.Mutator.Binding() != wantMutation {
		return receipt, errors.New("preconstructed mutator differs from the selected authorized stage")
	}
	inspection, err := operation.Ledger.InspectStage(ctx, grant)
	if err != nil {
		return receipt, err
	}
	switch inspection.State {
	case "COMPLETED":
		return operation.finalize(ctx, receipt, plan, grant, predecessors, inspection.Outcome, "")
	case "AVAILABLE":
		if !inspection.ClaimAllowed {
			return receipt, errors.New("available stage grant is not claimable")
		}
	case "CLAIMED_INDETERMINATE_STOP":
		receipt.State = "CLAIMED_INDETERMINATE_STOP"
		return receipt, errors.New("mutating stage was claimed without a durable outcome")
	default:
		return receipt, errors.New("stage ledger returned an unsupported inspection state")
	}
	claim, err := operation.Ledger.ClaimStage(ctx, grant, operation.Clock())
	if err != nil {
		return receipt, err
	}
	receipt.Claim = &claim
	receipt.State = "CLAIMED_INDETERMINATE_STOP"
	result, mutationErr := operation.Mutator.Mutate(ctx, StageMutationRequest{
		StageMutationBinding: wantMutation,
		ContractIdentity:     plan.ContractIdentity,
		GrantID:              binding.GrantID,
		PredecessorDigest:    binding.PredecessorDigest,
	})
	if err := validateStageMutationResult(decision.StageID, result, mutationErr); err != nil {
		return receipt, err
	}
	receipt.FailureCategory = result.FailureCategory
	outcome, err := operation.Ledger.CompleteStageWithTarget(ctx, claim, result.Outcome, result.MutationState, result.EvidenceDigest, result.TargetClusterUIDDigest, operation.Clock())
	if err != nil {
		return receipt, err
	}
	receipt.Outcome = &outcome
	return operation.finalize(ctx, receipt, plan, grant, predecessors, &outcome, result.FailureCategory)
}

func (operation StagedOperation) finalize(ctx context.Context, receipt StagedOperationReceipt, plan stageplan.Binding, grant authorization.VerifiedStageGrant, predecessors []stagereceipt.Verified, outcome *ledger.StageOutcomeReceipt, failureCategory string) (StagedOperationReceipt, error) {
	if outcome == nil {
		return receipt, errors.New("completed stage inspection has no durable outcome")
	}
	verified, err := operation.Ledger.FinalizeStageReceipt(ctx, plan, grant, predecessors)
	if err != nil {
		return receipt, err
	}
	receiptDigest, err := verified.Digest()
	if err != nil {
		return receipt, err
	}
	receipt.Outcome = outcome
	receipt.StageReceiptDigest = receiptDigest
	receipt.State = "COMPLETED_" + outcome.Outcome
	if outcome.Outcome != "SUCCEEDED" {
		return receipt, &StageResultError{State: receipt.State, FailureCategory: failureCategory}
	}
	return receipt, nil
}

func validateStageMutationResult(stageID string, result StageMutationResult, mutationErr error) error {
	if !oneOf(result.Outcome, "SUCCEEDED", "FAILED", "STOPPED") || !oneOf(result.MutationState, "NOT_ATTEMPTED", "ATTEMPTED", "UNKNOWN") || !stagedDigestPattern.MatchString(result.EvidenceDigest) {
		return errors.New("stage mutator returned an invalid redaction-safe result")
	}
	if result.Outcome == "SUCCEEDED" {
		providerEnsureWithoutWrite := stageID == "provider-prerequisites" && result.MutationState == "NOT_ATTEMPTED"
		if mutationErr != nil || (result.MutationState != "ATTEMPTED" && !providerEnsureWithoutWrite) {
			return errors.New("stage mutator reported an inconsistent successful result")
		}
	}
	if result.FailureCategory != "" && (result.Outcome == "SUCCEEDED" || !validStageFailureCategory(result.FailureCategory)) {
		return errors.New("stage mutator returned an invalid redacted failure category")
	}
	if stageID == "cluster-lifecycle" && result.Outcome == "SUCCEEDED" {
		if !stagedDigestPattern.MatchString(result.TargetClusterUIDDigest) {
			return errors.New("successful Cluster lifecycle mutation lacks a runtime identity digest")
		}
	} else if result.TargetClusterUIDDigest != "" {
		return errors.New("stage mutation returned runtime identity outside successful Cluster lifecycle")
	}
	return nil
}

func validStageFailureCategory(category string) bool {
	switch category {
	case "SUBMISSION_DNS_STOPPED", "SUBMISSION_CONNECT_STOPPED", "SUBMISSION_TLS_STOPPED", "SUBMISSION_TIMEOUT_STOPPED", "SUBMISSION_TRANSPORT_STOPPED",
		"SUBMISSION_HTTP_REJECTED", "SUBMISSION_RESPONSE_INVALID", "SUBMISSION_OBJECT_MISMATCH", "SUBMISSION_CONFLICT_STOPPED":
		return true
	default:
		return false
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
