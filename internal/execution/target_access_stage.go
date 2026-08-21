package execution

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// TargetAccessMutator is bound to the exact eleven-object workload access set.
// It neither issues credentials nor registers the target with GitOps.
type TargetAccessMutator struct {
	binding   StageMutationBinding
	identity  contract.Identity
	plane     submission.Plane
	submitter PlaneSubmitter
}

var _ StageMutator = (*TargetAccessMutator)(nil)

// NewTargetAccessMutator accepts only the verified target-access projection.
// Authorization and the durable single-use claim remain with StagedOperation.
func NewTargetAccessMutator(plan stageplan.Binding, projected submission.TargetAccessPlan, submitter PlaneSubmitter) (*TargetAccessMutator, error) {
	if submitter == nil {
		return nil, errors.New("target-access stage requires a bounded plane submitter")
	}
	stage, stageDigest, err := plan.Stage("target-access")
	if err != nil {
		return nil, err
	}
	if projected.Format != submission.TargetAccessPlanFormat || projected.MutationAllowed || projected.IntentRevision != plan.IntentRevision || projected.PlatformRevision != plan.PlatformRevision || projected.ExecutionFixture != plan.ExecutionFixture {
		return nil, errors.New("target-access projection differs from the verified staged plan")
	}
	if err := plan.RequireInput(stage.ID, "stage.target-access", projected.ArtifactDigest); err != nil {
		return nil, err
	}
	plane := projected.Workload
	if !stagedDigestPattern.MatchString(projected.TargetIdentityDigest) || plane.Identity != projected.TargetIdentityDigest || plane.Role != "target-access-writer" || len(plane.Objects) != 11 {
		return nil, errors.New("target-access projection authority or content differs from the selected stage")
	}
	expectedKinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding"}
	for index, object := range plane.Objects {
		if object.Identity.Kind != expectedKinds[index] || !stagedDigestPattern.MatchString(object.Digest) || object.CollectionPath == "" || object.ObjectPath == "" || len(object.Raw) == 0 {
			return nil, errors.New("target-access projection lacks the exact eleven-object set")
		}
	}
	return &TargetAccessMutator{
		binding: StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity: plan.ContractIdentity, plane: cloneSubmissionPlane(plane), submitter: submitter,
	}, nil
}

func (mutator *TargetAccessMutator) Binding() StageMutationBinding {
	if mutator == nil {
		return StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *TargetAccessMutator) Mutate(ctx context.Context, request StageMutationRequest) (StageMutationResult, error) {
	if mutator == nil || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity || request.GrantID == "" || !stagedDigestPattern.MatchString(request.PredecessorDigest) {
		return StageMutationResult{}, errors.New("target-access mutation request differs from the preconstructed stage")
	}
	receipt, submitErr := mutator.submitter.Submit(ctx, cloneSubmissionPlane(mutator.plane))
	mutationState, err := validateSubmissionPlaneOutcome(receipt, mutator.plane, submitErr != nil)
	if err != nil {
		return StageMutationResult{}, err
	}
	evidenceDigest, err := canonicalDigest(receipt)
	if err != nil {
		return StageMutationResult{}, errors.New("derive bounded target-access evidence")
	}
	if submitErr != nil {
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, errors.New("bounded target-access submission stopped")
	}
	if mutationState != "ATTEMPTED" {
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
	}
	return StageMutationResult{Outcome: "SUCCEEDED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
}
