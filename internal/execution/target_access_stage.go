package execution

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// TargetAccessMutator is bound to the exact sixteen-object workload access set.
// It neither issues credentials nor registers the target with GitOps.
type TargetAccessMutator struct {
	binding                StageMutationBinding
	identity               contract.Identity
	enablementRevision     string
	platformRevision       string
	executionFixture       string
	stageOrder             int
	executionAttemptDigest string
	artifactDigest         string
	plane                  submission.Plane
	submitter              TargetAccessSubmitter
}

var _ StageMutator = (*TargetAccessMutator)(nil)

// TargetAccessSubmitter receives the already-validated stage mutation binding
// as well as the immutable target-access plane. A future fixed-purpose remote
// executor must bind its durable request/result to these values. DispatchID is
// deterministic from the single-use grant-bound request and verified artifact;
// it is not a nonce or permission to replay. A remote protocol must durably
// fence it before any potentially mutating handoff.
type TargetAccessSubmitter interface {
	SubmitTargetAccess(context.Context, TargetAccessDispatch) (submission.PlaneReceipt, error)
}

// TargetAccessDispatch is the complete immutable handoff envelope for one
// verified stage operation. It is an in-process contract, not yet a serialized
// Job API or permission to retry.
type TargetAccessDispatch struct {
	Mutation             StageMutationRequest
	DispatchID           string
	ArtifactDigest       string
	TargetIdentityDigest string
	Plane                submission.Plane
}

// DirectTargetAccessSubmitter preserves the current in-process Kubernetes
// submission path. It intentionally ignores the stage request because no
// remote handoff is made; it does not add Job, policy, or credential behavior.
type DirectTargetAccessSubmitter struct {
	Submitter PlaneSubmitter
}

func (submitter DirectTargetAccessSubmitter) SubmitTargetAccess(ctx context.Context, dispatch TargetAccessDispatch) (submission.PlaneReceipt, error) {
	if submitter.Submitter == nil {
		return submission.PlaneReceipt{}, errors.New("bounded target-access plane submitter is required")
	}
	return submitter.Submitter.Submit(ctx, dispatch.Plane)
}

// NewTargetAccessMutator accepts only the verified target-access projection.
// Authorization and the durable single-use claim remain with StagedOperation.
func NewTargetAccessMutator(plan stageplan.Binding, projected submission.TargetAccessPlan, submitter TargetAccessSubmitter) (*TargetAccessMutator, error) {
	if submitter == nil {
		return nil, errors.New("target-access stage requires a bounded target-access submitter")
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
	if !stagedDigestPattern.MatchString(projected.TargetIdentityDigest) || plane.Identity != projected.TargetIdentityDigest || plane.Role != "target-access-writer" || len(plane.Objects) != submission.TargetAccessObjectCount {
		return nil, errors.New("target-access projection authority or content differs from the selected stage")
	}
	expectedKinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole"}
	for index, object := range plane.Objects {
		if object.Identity.Kind != expectedKinds[index] || !stagedDigestPattern.MatchString(object.Digest) || object.CollectionPath == "" || object.ObjectPath == "" || len(object.Raw) == 0 {
			return nil, errors.New("target-access projection lacks the exact sixteen-object set")
		}
	}
	return &TargetAccessMutator{
		binding: StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity: plan.ContractIdentity, enablementRevision: plan.EnablementRevision,
		platformRevision: plan.PlatformRevision, executionFixture: plan.ExecutionFixture,
		stageOrder: stage.Order, executionAttemptDigest: plan.ExecutionAttempt,
		artifactDigest: projected.ArtifactDigest, plane: cloneSubmissionPlane(plane), submitter: submitter,
	}, nil
}

func (mutator *TargetAccessMutator) Binding() StageMutationBinding {
	if mutator == nil {
		return StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *TargetAccessMutator) Mutate(ctx context.Context, request StageMutationRequest) (StageMutationResult, error) {
	if mutator == nil || !request.verifiedStageGrant || !stageClaimMatchesMutation(request) || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity || request.EnablementRevision != mutator.enablementRevision || request.PlatformRevision != mutator.platformRevision || request.ExecutionFixture != mutator.executionFixture || request.StageOrder != mutator.stageOrder || request.ExecutionAttemptDigest != mutator.executionAttemptDigest || request.GrantID == "" || !stagedDigestPattern.MatchString(request.PredecessorDigest) || !stagedDigestPattern.MatchString(request.AuthorizationDigest) || !stagedDigestPattern.MatchString(request.AuthorizationKeyID) || len(request.AuthorizationEnvelope) == 0 || len(request.AuthorizationEnvelope) > 128*1024 || digest.SHA256(request.AuthorizationEnvelope) != request.AuthorizationDigest {
		return StageMutationResult{}, errors.New("target-access mutation request differs from the preconstructed stage")
	}
	request.AuthorizationEnvelope = append([]byte(nil), request.AuthorizationEnvelope...)
	dispatchID, err := targetAccessDispatchID(request, mutator.artifactDigest, mutator.plane.Identity)
	if err != nil {
		return StageMutationResult{}, errors.New("derive bounded target-access dispatch identity")
	}
	dispatch := TargetAccessDispatch{
		Mutation: request, DispatchID: dispatchID, ArtifactDigest: mutator.artifactDigest,
		TargetIdentityDigest: mutator.plane.Identity, Plane: cloneSubmissionPlane(mutator.plane),
	}
	receipt, submitErr := mutator.submitter.SubmitTargetAccess(ctx, dispatch)
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

func targetAccessDispatchID(request StageMutationRequest, artifactDigest, targetIdentityDigest string) (string, error) {
	claimDigest, err := canonicalDigest(request.StageClaim)
	if err != nil {
		return "", err
	}
	return canonicalDigest(struct {
		Format                 string               `json:"format"`
		Binding                StageMutationBinding `json:"binding"`
		ContractIdentity       contract.Identity    `json:"contractIdentity"`
		EnablementRevision     string               `json:"enablementRevision"`
		PlatformRevision       string               `json:"platformRevision"`
		ExecutionFixture       string               `json:"executionFixture"`
		StageOrder             int                  `json:"stageOrder"`
		ExecutionAttemptDigest string               `json:"executionAttemptDigest"`
		AuthorizationDigest    string               `json:"authorizationDigest"`
		AuthorizationKeyID     string               `json:"authorizationKeyId"`
		GrantID                string               `json:"grantId"`
		PredecessorDigest      string               `json:"predecessorDigest"`
		StageClaimDigest       string               `json:"stageClaimDigest"`
		ArtifactDigest         string               `json:"artifactDigest"`
		TargetIdentityDigest   string               `json:"targetIdentityDigest"`
	}{"ok147-target-access-dispatch/v1", request.StageMutationBinding, request.ContractIdentity,
		request.EnablementRevision, request.PlatformRevision, request.ExecutionFixture, request.StageOrder,
		request.ExecutionAttemptDigest, request.AuthorizationDigest, request.AuthorizationKeyID,
		request.GrantID, request.PredecessorDigest, claimDigest, artifactDigest, targetIdentityDigest})
}
