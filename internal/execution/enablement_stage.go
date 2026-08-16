package execution

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// EnablementMutator is bound to one externally rendered HelmChartProxy and the
// management writer. It never renders Helm content or writes HelmReleaseProxy.
type EnablementMutator struct {
	binding   StageMutationBinding
	identity  contract.Identity
	plane     submission.Plane
	submitter PlaneSubmitter
}

var _ StageMutator = (*EnablementMutator)(nil)

// NewEnablementMutator binds the fourth stage to its exact non-authorizing
// projection. Authorization and durable single-use claim remain owned by the
// surrounding StagedOperation.
func NewEnablementMutator(plan stageplan.Binding, projected submission.EnablementPlan, submitter PlaneSubmitter) (*EnablementMutator, error) {
	if submitter == nil {
		return nil, errors.New("enablement stage requires a bounded plane submitter")
	}
	stage, stageDigest, err := plan.Stage("enablement")
	if err != nil {
		return nil, err
	}
	if projected.Format != submission.EnablementPlanFormat || projected.MutationAllowed || projected.IntentRevision != plan.IntentRevision || projected.EnablementRevision != plan.EnablementRevision || projected.ExecutionFixture != plan.ExecutionFixture {
		return nil, errors.New("enablement projection differs from the verified staged plan")
	}
	if err := plan.RequireInput(stage.ID, "stage.enablement", projected.ArtifactDigest); err != nil {
		return nil, err
	}
	plane := projected.Management
	if plane.Identity != plan.Authorities.Management || plane.Role != "enablement-desired-state-writer" || len(plane.Objects) != 1 {
		return nil, errors.New("enablement projection authority or content differs from the selected stage")
	}
	object := plane.Objects[0]
	if object.Identity.APIVersion != "addons.cluster.x-k8s.io/v1alpha1" || object.Identity.Kind != "HelmChartProxy" || object.Identity.Namespace != plan.ContractIdentity.Namespace || len(object.Raw) == 0 {
		return nil, errors.New("enablement projection lacks the exact HelmChartProxy")
	}
	return &EnablementMutator{
		binding: StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity: plan.ContractIdentity, plane: cloneSubmissionPlane(plane), submitter: submitter,
	}, nil
}

func (mutator *EnablementMutator) Binding() StageMutationBinding {
	if mutator == nil {
		return StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *EnablementMutator) Mutate(ctx context.Context, request StageMutationRequest) (StageMutationResult, error) {
	if mutator == nil || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity || request.GrantID == "" || !stagedDigestPattern.MatchString(request.PredecessorDigest) {
		return StageMutationResult{}, errors.New("enablement mutation request differs from the preconstructed stage")
	}
	receipt, submitErr := mutator.submitter.Submit(ctx, cloneSubmissionPlane(mutator.plane))
	mutationState, err := validateSubmissionPlaneOutcome(receipt, mutator.plane, submitErr != nil)
	if err != nil {
		return StageMutationResult{}, err
	}
	evidenceDigest, err := canonicalDigest(receipt)
	if err != nil {
		return StageMutationResult{}, errors.New("derive bounded enablement evidence")
	}
	if submitErr != nil {
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, errors.New("bounded enablement submission stopped")
	}
	if mutationState != "ATTEMPTED" {
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
	}
	return StageMutationResult{Outcome: "SUCCEEDED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
}
