package runner

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// TargetRegistrationStageMutator adapts exactly one already prepared
// create-only launcher to the durable staged-operation protocol. It adds no
// API route and cannot select another stage or authority at runtime.
type TargetRegistrationStageMutator struct {
	binding   execution.StageMutationBinding
	identity  contract.Identity
	material  TargetRegistrationMaterialReceipt
	authority string
	launcher  *KubernetesTargetRegistrationLauncher
}

var _ execution.StageMutator = (*TargetRegistrationStageMutator)(nil)

func NewTargetRegistrationStageMutator(plan stageplan.Binding, material VerifiedTargetRegistrationMaterial, launcher *KubernetesTargetRegistrationLauncher) (*TargetRegistrationStageMutator, error) {
	receipt, err := material.Receipt()
	if err != nil || launcher == nil || launcher.receipt != receipt || launcher.authority != plan.Authorities.GitOps {
		return nil, errors.New("target-registration mutator requires exact verified material and launcher")
	}
	stage, stageDigest, err := plan.Stage("target-registration")
	if err != nil {
		return nil, err
	}
	if receipt.PlanDigest != plan.PlanDigest || receipt.TargetIdentityDigest != material.targetIdentityDigest ||
		stage.Authority != "gitops" || material.authority != plan.Authorities.GitOps || stage.GrantOperation != "RegisterTarget" || len(stage.Inputs) != 1 ||
		stage.Inputs[0].Name != "stage.target-registration" {
		return nil, errors.New("target-registration material differs from selected staged plan")
	}
	return &TargetRegistrationStageMutator{
		binding: execution.StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity: plan.ContractIdentity, material: receipt, authority: plan.Authorities.GitOps, launcher: launcher,
	}, nil
}

func (mutator *TargetRegistrationStageMutator) Binding() execution.StageMutationBinding {
	if mutator == nil {
		return execution.StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *TargetRegistrationStageMutator) Mutate(ctx context.Context, request execution.StageMutationRequest) (execution.StageMutationResult, error) {
	if mutator == nil || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity ||
		request.GrantID == "" || !stageReceiptPrefixDigestPattern.MatchString(request.PredecessorDigest) {
		return execution.StageMutationResult{}, errors.New("target-registration mutation request differs from the preconstructed stage")
	}
	receipt, launchErr := mutator.launcher.Install(ctx)
	mutationState, err := validateTargetRegistrationLaunchOutcome(receipt, mutator.material, mutator.authority, launchErr != nil)
	if err != nil {
		return execution.StageMutationResult{}, err
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return execution.StageMutationResult{}, errors.New("derive bounded target-registration evidence")
	}
	result := execution.StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: digest.SHA256(receiptRaw)}
	if launchErr != nil {
		return result, errors.New("bounded target-registration launch stopped")
	}
	if receipt.State == "INSTALLED" && mutationState == "ATTEMPTED" {
		result.Outcome = "SUCCEEDED"
	}
	return result, nil
}

func validateTargetRegistrationLaunchOutcome(receipt TargetRegistrationLaunchReceipt, material TargetRegistrationMaterialReceipt, authority string, stopped bool) (string, error) {
	wantState := "INSTALLED"
	if stopped {
		if receipt.State != "STOPPED_ZERO_WRITE" && receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" {
			return "", errors.New("target-registration stopped receipt has invalid state")
		}
		wantState = receipt.State
	}
	if receipt.Format != TargetRegistrationLaunchReceiptFormat || receipt.StageID != "target-registration" ||
		receipt.PlanDigest != material.PlanDigest || receipt.TargetIdentityDigest != material.TargetIdentityDigest ||
		receipt.MaterializationBindingDigest != material.MaterializationBindingDigest || receipt.Authority != authority || receipt.State != wantState ||
		receipt.CredentialBytesInReceipt || len(receipt.Results) > 2 || (!stopped && len(receipt.Results) != 2) {
		return "", errors.New("target-registration launch receipt differs from verified material")
	}
	expectedRoles := []string{"project", "registration"}
	expectedDigests := []string{material.ProjectDigest, material.RegistrationTemplateDigest}
	for index, result := range receipt.Results {
		if result.Order != index+1 || result.Role != expectedRoles[index] || result.BoundDigest != expectedDigests[index] ||
			result.Namespace == "" || result.Name == "" || result.State != "CREATED" || result.MaterializedObjectDigestRetained ||
			!stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			return "", errors.New("target-registration launch result differs from exact object order")
		}
	}
	switch receipt.MutationState {
	case "NOT_ATTEMPTED":
		if len(receipt.Results) != 0 || !stopped {
			return "", errors.New("target-registration no-write outcome is inconsistent")
		}
		return "NOT_ATTEMPTED", nil
	case "ATTEMPTED":
		if len(receipt.Results) == 0 && !stopped {
			return "", errors.New("target-registration attempted outcome lacks results")
		}
		return "ATTEMPTED", nil
	case "ATTEMPTED_UNKNOWN":
		if !stopped {
			return "", errors.New("target-registration unknown outcome is not stopped")
		}
		return "UNKNOWN", nil
	default:
		return "", errors.New("target-registration mutation state is invalid")
	}
}
