package runner

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

// VerifiedTargetCredentialStageHandoff binds the canonical public Stage-8
// receipt to one private, memory-only credential. Only the redacted receipts
// are publicly readable; the credential can be consumed once inside runner.
type VerifiedTargetCredentialStageHandoff struct {
	mu         sync.Mutex
	receipt    stagereceipt.Verified
	credential VerifiedTargetCredentialMaterial
	consumed   bool
	verified   bool
}

func newVerifiedTargetCredentialStageHandoff(receipt stagereceipt.Verified, credential VerifiedTargetCredentialMaterial) (*VerifiedTargetCredentialStageHandoff, error) {
	stage, err := receipt.Receipt()
	if err != nil {
		return nil, err
	}
	issued, err := credential.Receipt()
	if err != nil {
		return nil, err
	}
	issuedRaw, err := json.Marshal(issued)
	if err != nil {
		return nil, errors.New("encode target-credential handoff evidence")
	}
	if stage.StageID != "target-credential" || stage.State != "SUCCEEDED" || stage.MutationState != "ATTEMPTED" ||
		stage.EvidenceDigest != digest.SHA256(issuedRaw) || stage.TargetClusterUIDDigest != "" ||
		issued.StageID != stage.StageID || issued.TargetIdentityDigest != credential.targetIdentity {
		return nil, errors.New("target-credential handoff differs from durable Stage-8 receipt")
	}
	return &VerifiedTargetCredentialStageHandoff{receipt: receipt, credential: credential, verified: true}, nil
}

func (handoff *VerifiedTargetCredentialStageHandoff) StageReceipt() (stagereceipt.Receipt, error) {
	if handoff == nil || !handoff.verified {
		return stagereceipt.Receipt{}, errors.New("target-credential handoff was not produced by verification")
	}
	return handoff.receipt.Receipt()
}

func (handoff *VerifiedTargetCredentialStageHandoff) StageReceiptBytes() ([]byte, error) {
	if handoff == nil || !handoff.verified {
		return nil, errors.New("target-credential handoff was not produced by verification")
	}
	return handoff.receipt.Bytes()
}

func (handoff *VerifiedTargetCredentialStageHandoff) StageReceiptDigest() (string, error) {
	if handoff == nil || !handoff.verified {
		return "", errors.New("target-credential handoff was not produced by verification")
	}
	return handoff.receipt.Digest()
}

func (handoff *VerifiedTargetCredentialStageHandoff) CredentialReceipt() (TargetCredentialIssueReceipt, error) {
	if handoff == nil || !handoff.verified {
		return TargetCredentialIssueReceipt{}, errors.New("target-credential handoff was not produced by verification")
	}
	return handoff.credential.Receipt()
}

func (handoff *VerifiedTargetCredentialStageHandoff) takeCredential() (VerifiedTargetCredentialMaterial, error) {
	if handoff == nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential handoff is required")
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if !handoff.verified || handoff.consumed {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential handoff is unavailable or already consumed")
	}
	if _, err := handoff.credential.Receipt(); err != nil {
		return VerifiedTargetCredentialMaterial{}, err
	}
	handoff.consumed = true
	credential := handoff.credential
	handoff.credential = VerifiedTargetCredentialMaterial{}
	return credential, nil
}
