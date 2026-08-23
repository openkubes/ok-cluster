package execution

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
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
		// Provider prerequisites are intentionally durable across disposable
		// Cluster attempts. An exact all-UNCHANGED plane is therefore a
		// successful idempotent ensure, while Cluster lifecycle and every other
		// mutating stage still require an actual write.
		if mutator.binding.StageID == "provider-prerequisites" && mutationState == "NOT_ATTEMPTED" {
			return StageMutationResult{Outcome: "SUCCEEDED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
		}
		return StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: evidenceDigest}, nil
	}
	result := StageMutationResult{Outcome: "SUCCEEDED", MutationState: mutationState, EvidenceDigest: evidenceDigest}
	if mutator.binding.StageID == "cluster-lifecycle" {
		uid, err := submittedLifecycleClusterUID(receipt, mutator.plane, mutator.identity)
		if err != nil {
			return StageMutationResult{}, err
		}
		result.TargetClusterUIDDigest = digest.SHA256([]byte(uid))
	}
	return result, nil
}

func submittedLifecycleClusterUID(receipt submission.PlaneReceipt, plane submission.Plane, identity contract.Identity) (string, error) {
	var uid string
	for index, object := range plane.Objects {
		if object.Identity.APIVersion != "cluster.x-k8s.io/v1beta2" || object.Identity.Kind != "Cluster" || object.Identity.Namespace != identity.Namespace || object.Identity.Name != identity.Name {
			continue
		}
		if uid != "" || index >= len(receipt.Results) || receipt.Results[index].UID == "" {
			return "", errors.New("Cluster lifecycle submission has ambiguous runtime identity")
		}
		uid = receipt.Results[index].UID
	}
	if uid == "" {
		return "", errors.New("Cluster lifecycle submission lacks exact runtime identity")
	}
	return uid, nil
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
	if stopped {
		// A failed POST is an attempted mutation even when no object result can
		// be appended. Completed results therefore provide only a lower bound
		// for a stopped receipt's mutation state.
		if receipt.MutationState != "NOT_ATTEMPTED" && receipt.MutationState != "ATTEMPTED" {
			return "", errors.New("submission receipt mutation state is invalid")
		}
		if wantMutation == "ATTEMPTED" && receipt.MutationState != "ATTEMPTED" {
			return "", errors.New("submission receipt mutation state loses a completed create")
		}
		return receipt.MutationState, nil
	} else if receipt.MutationState != wantMutation {
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
