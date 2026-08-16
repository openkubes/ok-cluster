package execution

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// PlaneSubmitter is the exact-create capability already implemented by the
// bounded Kubernetes submission client.
type PlaneSubmitter interface {
	Submit(context.Context, submission.Plane) (submission.PlaneReceipt, error)
}

// SubmissionPlaneMutator is preconstructed for exactly one of the two
// Contract-to-CAPI projection planes. It cannot select another stage at run
// time and does not combine authority domains.
type SubmissionPlaneMutator struct {
	binding   StageMutationBinding
	identity  contract.Identity
	plane     submission.Plane
	submitter PlaneSubmitter
}

var _ StageMutator = (*SubmissionPlaneMutator)(nil)

// NewSubmissionPlaneMutator accepts only the provider-prerequisites or
// cluster-lifecycle stage. Enablement and later writes require their own typed
// adapters rather than a generic Kubernetes dispatcher.
func NewSubmissionPlaneMutator(plan stageplan.Binding, stageID string, projected submission.Plan, submitter PlaneSubmitter) (*SubmissionPlaneMutator, error) {
	if submitter == nil {
		return nil, errors.New("submission stage requires a bounded plane submitter")
	}
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		return nil, err
	}
	if projected.Format != submission.PlanFormat || projected.IntentRevision != plan.IntentRevision {
		return nil, errors.New("submission plan differs from the verified staged plan")
	}
	var plane submission.Plane
	var expectedAuthority string
	switch stage.ID {
	case "provider-prerequisites":
		plane = projected.Infrastructure
		expectedAuthority = plan.Authorities.Infrastructure
	case "cluster-lifecycle":
		plane = projected.Management
		expectedAuthority = plan.Authorities.Management
	default:
		return nil, errors.New("stage has no Contract-to-CAPI submission-plane adapter")
	}
	if plane.Identity != expectedAuthority || plane.Role == "" || len(plane.Objects) == 0 {
		return nil, errors.New("submission plane authority or content differs from the selected stage")
	}
	return &SubmissionPlaneMutator{
		binding: StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity:  plan.ContractIdentity,
		plane:     cloneSubmissionPlane(plane),
		submitter: submitter,
	}, nil
}

func (mutator *SubmissionPlaneMutator) Binding() StageMutationBinding {
	if mutator == nil {
		return StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *SubmissionPlaneMutator) Mutate(ctx context.Context, request StageMutationRequest) (StageMutationResult, error) {
	if mutator == nil || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity || request.GrantID == "" || !stagedDigestPattern.MatchString(request.PredecessorDigest) {
		return StageMutationResult{}, errors.New("submission mutation request differs from the preconstructed stage")
	}
	receipt, submitErr := mutator.submitter.Submit(ctx, cloneSubmissionPlane(mutator.plane))
	mutationState, err := validateSubmissionPlaneOutcome(receipt, mutator.plane, submitErr != nil)
	if err != nil {
		return StageMutationResult{}, err
	}
	evidenceDigest, err := canonicalDigest(receipt)
	if err != nil {
		return StageMutationResult{}, errors.New("derive bounded submission evidence")
	}
	if submitErr != nil {
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, errors.New("bounded submission stopped")
	}
	if mutationState != "ATTEMPTED" {
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
	}
	return StageMutationResult{Outcome: "SUCCEEDED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
}

func validateSubmissionPlaneOutcome(receipt submission.PlaneReceipt, plane submission.Plane, stopped bool) (string, error) {
	wantState := "SUBMITTED"
	if stopped {
		wantState = "STOPPED_PARTIAL_OR_UNKNOWN"
	}
	if receipt.Format != submission.PlaneReceiptFormat || receipt.Authority != plane.Identity || receipt.Role != plane.Role || receipt.State != wantState || len(receipt.Results) > len(plane.Objects) || (!stopped && len(receipt.Results) != len(plane.Objects)) {
		return "", errors.New("submission receipt differs from the preconstructed plane")
	}
	wantMutation := "NOT_ATTEMPTED"
	for index, result := range receipt.Results {
		expected := plane.Objects[index]
		if result.Identity.APIVersion != expected.Identity.APIVersion || result.Identity.Kind != expected.Identity.Kind || result.Identity.Name != expected.Identity.Name || result.Identity.Namespace != expected.Identity.Namespace || result.Digest != expected.Digest || result.UID == "" || len(result.UID) > 128 {
			return "", errors.New("submission receipt object differs from the preconstructed plane")
		}
		switch result.State {
		case "CREATED":
			wantMutation = "ATTEMPTED"
		case "UNCHANGED":
		default:
			return "", errors.New("submission receipt object state is invalid")
		}
	}
	if receipt.MutationState != wantMutation {
		return "", errors.New("submission receipt mutation state is inconsistent")
	}
	return wantMutation, nil
}

func cloneSubmissionPlane(source submission.Plane) submission.Plane {
	clone := submission.Plane{Identity: source.Identity, Role: source.Role, Objects: make([]submission.Object, len(source.Objects))}
	for index, object := range source.Objects {
		clone.Objects[index] = object
		clone.Objects[index].Raw = append([]byte(nil), object.Raw...)
	}
	return clone
}
