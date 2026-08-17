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

// PlatformApplicationsStageMutator adapts one already verified create-only
// launcher to the durable staged-operation protocol. It cannot select another
// stage, authority, Application set or operation at runtime.
type PlatformApplicationsStageMutator struct {
	binding   execution.StageMutationBinding
	identity  contract.Identity
	bundle    PlatformApplicationsStageBundleReceipt
	authority string
	objects   []platformApplicationLaunchObject
	launcher  *KubernetesPlatformApplicationsLauncher
}

var _ execution.StageMutator = (*PlatformApplicationsStageMutator)(nil)

func NewPlatformApplicationsStageMutator(plan stageplan.Binding, bundle VerifiedPlatformApplicationsStageBundle, launcher *KubernetesPlatformApplicationsLauncher) (*PlatformApplicationsStageMutator, error) {
	if err := verifyPlatformApplicationsStageBundle(bundle); err != nil || launcher == nil || !samePlatformApplicationsBundleReceipt(launcher.receipt, bundle.receipt) || launcher.authority != plan.Authorities.GitOps || verifyPlatformApplicationLaunchObjects(launcher.objects) != nil {
		return nil, errors.New("platform-applications mutator requires exact verified bundle and launcher")
	}
	stage, stageDigest, err := plan.Stage("platform-applications")
	if err != nil {
		return nil, err
	}
	if bundle.receipt.PlanDigest != plan.PlanDigest || stage.Authority != "gitops" || bundle.receipt.Authority != plan.Authorities.GitOps || stage.GrantOperation != "CreatePlatformApplications" || len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.platform-applications" || stage.Inputs[0].Digest != bundle.receipt.ArtifactDigest {
		return nil, errors.New("platform-applications bundle differs from selected staged plan")
	}
	objects := make([]platformApplicationLaunchObject, len(launcher.objects))
	for index, object := range launcher.objects {
		objects[index] = object
		objects[index].raw = append([]byte(nil), object.raw...)
	}
	return &PlatformApplicationsStageMutator{
		binding: execution.StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity: plan.ContractIdentity, bundle: bundle.receipt, authority: plan.Authorities.GitOps,
		objects: objects, launcher: launcher,
	}, nil
}

func samePlatformApplicationsBundleReceipt(left, right PlatformApplicationsStageBundleReceipt) bool {
	if left.Format != right.Format || left.State != right.State || left.PlanDigest != right.PlanDigest || left.StageID != right.StageID || left.AuthorizationDigest != right.AuthorizationDigest || left.ArtifactDigest != right.ArtifactDigest || left.TargetIdentityDigest != right.TargetIdentityDigest || left.ProfileDigest != right.ProfileDigest || left.Authority != right.Authority || left.MutationAllowed != right.MutationAllowed || len(left.ApplicationDigests) != len(right.ApplicationDigests) {
		return false
	}
	for index := range left.ApplicationDigests {
		if left.ApplicationDigests[index] != right.ApplicationDigests[index] {
			return false
		}
	}
	return true
}

func (mutator *PlatformApplicationsStageMutator) Binding() execution.StageMutationBinding {
	if mutator == nil {
		return execution.StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *PlatformApplicationsStageMutator) Mutate(ctx context.Context, request execution.StageMutationRequest) (execution.StageMutationResult, error) {
	if mutator == nil || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity || request.GrantID == "" || !stageReceiptPrefixDigestPattern.MatchString(request.PredecessorDigest) {
		return execution.StageMutationResult{}, errors.New("platform-applications mutation request differs from the preconstructed stage")
	}
	receipt, launchErr := mutator.launcher.Install(ctx)
	mutationState, err := validatePlatformApplicationsLaunchOutcome(receipt, mutator.bundle, mutator.objects, mutator.authority, launchErr != nil)
	if err != nil {
		return execution.StageMutationResult{}, err
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return execution.StageMutationResult{}, errors.New("derive bounded platform-applications evidence")
	}
	result := execution.StageMutationResult{Outcome: "STOPPED", MutationState: mutationState, EvidenceDigest: digest.SHA256(receiptRaw)}
	if launchErr != nil {
		return result, errors.New("bounded platform-applications launch stopped")
	}
	if receipt.State == "INSTALLED" && mutationState == "ATTEMPTED" {
		result.Outcome = "SUCCEEDED"
	}
	return result, nil
}

func validatePlatformApplicationsLaunchOutcome(receipt PlatformApplicationsLaunchReceipt, bundle PlatformApplicationsStageBundleReceipt, objects []platformApplicationLaunchObject, authority string, stopped bool) (string, error) {
	wantState := "INSTALLED"
	if stopped {
		if receipt.State != "STOPPED_ZERO_WRITE" && receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" {
			return "", errors.New("platform-applications stopped receipt has invalid state")
		}
		wantState = receipt.State
	}
	if receipt.Format != PlatformApplicationsLaunchReceiptFormat || receipt.StageID != "platform-applications" ||
		receipt.PlanDigest != bundle.PlanDigest || receipt.ArtifactDigest != bundle.ArtifactDigest ||
		receipt.TargetIdentityDigest != bundle.TargetIdentityDigest || receipt.ProfileDigest != bundle.ProfileDigest ||
		receipt.Authority != authority || receipt.State != wantState || len(receipt.Results) > len(objects) || (!stopped && len(receipt.Results) != len(objects)) {
		return "", errors.New("platform-applications launch receipt differs from verified bundle")
	}
	for index, result := range receipt.Results {
		object := objects[index]
		if result.Order != index+1 || result.Phase != "platform-application" || result.APIVersion != object.apiVersion || result.Kind != object.kind || result.Namespace != object.namespace || result.Name != object.name || result.ObjectDigest != object.digest || result.ObjectState != "CREATED" || !stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			return "", errors.New("platform-applications launch result differs from exact object order")
		}
	}
	switch receipt.MutationState {
	case "NOT_ATTEMPTED":
		if len(receipt.Results) != 0 || !stopped {
			return "", errors.New("platform-applications no-write outcome is inconsistent")
		}
		return "NOT_ATTEMPTED", nil
	case "ATTEMPTED":
		if len(receipt.Results) == 0 && !stopped {
			return "", errors.New("platform-applications attempted outcome lacks results")
		}
		return "ATTEMPTED", nil
	case "ATTEMPTED_UNKNOWN":
		if !stopped {
			return "", errors.New("platform-applications unknown outcome is not stopped")
		}
		return "UNKNOWN", nil
	default:
		return "", errors.New("platform-applications mutation state is invalid")
	}
}
