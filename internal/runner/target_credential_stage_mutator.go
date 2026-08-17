package runner

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

type targetCredentialStoppedEvidence struct {
	Format               string `json:"format"`
	StageID              string `json:"stageId"`
	PlanDigest           string `json:"planDigest"`
	PolicyDigest         string `json:"policyDigest"`
	TargetIdentityDigest string `json:"targetIdentityDigest"`
	State                string `json:"state"`
	CredentialRetained   bool   `json:"credentialRetained"`
}

// TargetCredentialStageMutator adapts one TokenRequest issuer to the durable
// staged-operation protocol while retaining successful credential bytes only
// for one in-process handoff.
type TargetCredentialStageMutator struct {
	mu       sync.Mutex
	binding  execution.StageMutationBinding
	identity contract.Identity
	bundle   TargetCredentialStageBundleReceipt
	issuer   *KubernetesTargetCredentialIssuer
	material VerifiedTargetCredentialMaterial
	ready    bool
}

var _ execution.StageMutator = (*TargetCredentialStageMutator)(nil)

func NewTargetCredentialStageMutator(plan stageplan.Binding, bundle TargetCredentialStageBundleReceipt, issuer *KubernetesTargetCredentialIssuer) (*TargetCredentialStageMutator, error) {
	stage, stageDigest, err := plan.Stage("target-credential")
	if err != nil {
		return nil, err
	}
	if issuer == nil || bundle.Format != TargetCredentialStageBundleReceiptFormat || bundle.State != "VERIFIED" ||
		bundle.PlanDigest != plan.PlanDigest || bundle.StageID != stage.ID || bundle.TargetIdentityDigest != issuer.targetIdentity ||
		stage.Kind != "Credential" || stage.Authority != "workload" || stage.GrantOperation != "IssueTargetCredential" {
		return nil, errors.New("target-credential mutator requires the exact verified stage and issuer")
	}
	return &TargetCredentialStageMutator{
		binding: execution.StageMutationBinding{
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
		},
		identity: plan.ContractIdentity, bundle: bundle, issuer: issuer,
	}, nil
}

func (mutator *TargetCredentialStageMutator) Binding() execution.StageMutationBinding {
	if mutator == nil {
		return execution.StageMutationBinding{}
	}
	return mutator.binding
}

func (mutator *TargetCredentialStageMutator) Mutate(ctx context.Context, request execution.StageMutationRequest) (execution.StageMutationResult, error) {
	if mutator == nil || request.StageMutationBinding != mutator.binding || request.ContractIdentity != mutator.identity ||
		request.GrantID == "" || !stageReceiptPrefixDigestPattern.MatchString(request.PredecessorDigest) {
		return execution.StageMutationResult{}, errors.New("target-credential mutation request differs from the preconstructed stage")
	}
	material, issueErr := mutator.issuer.Issue(ctx)
	if issueErr != nil {
		evidence, _ := json.Marshal(targetCredentialStoppedEvidence{
			Format: "ok147-target-credential-stopped-evidence/v1", StageID: "target-credential",
			PlanDigest: mutator.bundle.PlanDigest, PolicyDigest: mutator.bundle.PolicyDigest,
			TargetIdentityDigest: mutator.bundle.TargetIdentityDigest, State: "STOPPED", CredentialRetained: false,
		})
		return execution.StageMutationResult{Outcome: "STOPPED", MutationState: "UNKNOWN", EvidenceDigest: digest.SHA256(evidence)}, errors.New("bounded target-credential issuance stopped")
	}
	receipt, err := material.Receipt()
	if err != nil || receipt.PolicyDigest != mutator.bundle.PolicyDigest || receipt.TargetIdentityDigest != mutator.bundle.TargetIdentityDigest || receipt.ServiceAccountIdentityDigest != mutator.bundle.ServiceAccountIdentityDigest {
		return execution.StageMutationResult{}, errors.New("issued target credential differs from verified stage")
	}
	evidence, err := json.Marshal(receipt)
	if err != nil {
		return execution.StageMutationResult{}, errors.New("derive bounded target-credential evidence")
	}
	mutator.mu.Lock()
	mutator.material = material
	mutator.ready = true
	mutator.mu.Unlock()
	return execution.StageMutationResult{Outcome: "SUCCEEDED", MutationState: "ATTEMPTED", EvidenceDigest: digest.SHA256(evidence)}, nil
}

func (mutator *TargetCredentialStageMutator) TakeMaterial() (VerifiedTargetCredentialMaterial, error) {
	if mutator == nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential mutator is required")
	}
	mutator.mu.Lock()
	defer mutator.mu.Unlock()
	if !mutator.ready {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential material is unavailable")
	}
	material := mutator.material
	mutator.material = VerifiedTargetCredentialMaterial{}
	mutator.ready = false
	if _, err := material.Receipt(); err != nil {
		return VerifiedTargetCredentialMaterial{}, err
	}
	return material, nil
}
