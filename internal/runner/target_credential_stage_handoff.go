package runner

import (
	"errors"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

// VerifiedTargetCredentialStageHandoff binds the canonical public Stage-8
// receipt to one private, memory-only credential. Only the redacted receipts
// are publicly readable; the credential can be consumed once inside runner.
type VerifiedTargetCredentialStageHandoff struct {
	mu                       sync.Mutex
	plan                     stageplan.Binding
	prefix                   []stagereceipt.Verified
	receipt                  stagereceipt.Verified
	credential               VerifiedTargetCredentialMaterial
	credentialEvidenceDigest string
	recoveryRequestDigest    string
	consumed                 bool
	verified                 bool
}

func newVerifiedTargetCredentialStageHandoff(plan stageplan.Binding, prefix []stagereceipt.Verified, receipt stagereceipt.Verified, credential VerifiedTargetCredentialMaterial) (*VerifiedTargetCredentialStageHandoff, error) {
	if len(prefix) != 7 {
		return nil, errors.New("target-credential handoff requires the exact seven-stage prefix")
	}
	stage, err := receipt.Receipt()
	if err != nil {
		return nil, err
	}
	issued, err := credential.Receipt()
	if err != nil {
		return nil, err
	}
	issuedRaw, err := canonicalTargetRegistrationValue(issued)
	if err != nil {
		return nil, errors.New("encode target-credential handoff evidence")
	}
	if stage.StageID != "target-credential" || stage.State != "SUCCEEDED" || stage.MutationState != "ATTEMPTED" ||
		stage.PlanDigest != plan.PlanDigest || stage.EvidenceDigest != digest.SHA256(issuedRaw) || stage.TargetClusterUIDDigest != "" ||
		issued.StageID != stage.StageID || issued.TargetIdentityDigest != credential.targetIdentity {
		return nil, errors.New("target-credential handoff differs from durable Stage-8 receipt")
	}
	combined := append(append([]stagereceipt.Verified(nil), prefix...), receipt)
	cursor, err := stagecursor.Evaluate(plan, combined)
	if err != nil {
		return nil, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-registration" {
		return nil, errors.New("target-credential handoff does not select target registration")
	}
	return &VerifiedTargetCredentialStageHandoff{
		plan: plan, prefix: combined, receipt: receipt, credential: credential,
		credentialEvidenceDigest: digest.SHA256(issuedRaw), verified: true,
	}, nil
}

func newVerifiedRecoveredTargetCredentialStageHandoff(plan stageplan.Binding, prefix []stagereceipt.Verified, prior stagereceipt.Verified, credential VerifiedTargetCredentialMaterial, recovery TargetCredentialRecoveryReceipt) (*VerifiedTargetCredentialStageHandoff, error) {
	if len(prefix) != 7 || recovery.Format != TargetCredentialRecoveryReceiptFormat || recovery.State != "REISSUED" ||
		recovery.Outcome == nil || recovery.Outcome.Outcome != "SUCCEEDED" || recovery.Outcome.MutationState != "ATTEMPTED" ||
		recovery.CredentialBytesInReceipt || recovery.StageReceiptRewritten || recovery.PlanDigest != plan.PlanDigest {
		return nil, errors.New("recovered target-credential handoff requires exact successful recovery evidence")
	}
	priorDigest, err := prior.Digest()
	if err != nil || priorDigest != recovery.PriorStageReceiptDigest {
		return nil, errors.New("recovered target-credential handoff prior receipt differs")
	}
	stage, err := prior.Receipt()
	if err != nil || stage.StageID != "target-credential" || stage.State != "SUCCEEDED" || stage.MutationState != "ATTEMPTED" || stage.PlanDigest != plan.PlanDigest {
		return nil, errors.New("recovered target-credential handoff lacks successful Stage-8 receipt")
	}
	issued, err := credential.Receipt()
	if err != nil || issued.TargetIdentityDigest != recovery.TargetIdentityDigest {
		return nil, errors.New("recovered target-credential handoff target differs")
	}
	issuedRaw, err := canonicalTargetRegistrationValue(issued)
	if err != nil || digest.SHA256(issuedRaw) != recovery.CredentialIssueReceiptDigest || recovery.Outcome.EvidenceDigest != recovery.CredentialIssueReceiptDigest {
		return nil, errors.New("recovered target-credential handoff evidence differs")
	}
	combined := append(append([]stagereceipt.Verified(nil), prefix...), prior)
	cursor, err := stagecursor.Evaluate(plan, combined)
	if err != nil {
		return nil, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-registration" {
		return nil, errors.New("recovered target-credential handoff does not select target registration")
	}
	return &VerifiedTargetCredentialStageHandoff{
		plan: plan, prefix: combined, receipt: prior, credential: credential,
		credentialEvidenceDigest: recovery.CredentialIssueReceiptDigest,
		recoveryRequestDigest:    recovery.RecoveryRequestDigest, verified: true,
	}, nil
}

func (handoff *VerifiedTargetCredentialStageHandoff) credentialEvidence() (string, string, error) {
	if handoff == nil {
		return "", "", errors.New("target-credential handoff is required")
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if !handoff.verified || handoff.consumed || !stageReceiptPrefixDigestPattern.MatchString(handoff.credentialEvidenceDigest) {
		return "", "", errors.New("target-credential handoff evidence is unavailable")
	}
	if handoff.recoveryRequestDigest != "" && !stageReceiptPrefixDigestPattern.MatchString(handoff.recoveryRequestDigest) {
		return "", "", errors.New("target-credential recovery request identity is invalid")
	}
	return handoff.credentialEvidenceDigest, handoff.recoveryRequestDigest, nil
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
	if handoff == nil {
		return TargetCredentialIssueReceipt{}, errors.New("target-credential handoff was not produced by verification")
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if !handoff.verified || handoff.consumed {
		return TargetCredentialIssueReceipt{}, errors.New("target-credential handoff is unavailable or already consumed")
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

func (handoff *VerifiedTargetCredentialStageHandoff) registrationContext() (stageplan.Binding, stagecursor.Cursor, []stagereceipt.Verified, error) {
	if handoff == nil {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, errors.New("target-credential handoff is required")
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if !handoff.verified || handoff.consumed || len(handoff.prefix) != 8 {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, errors.New("target-credential handoff is unavailable or already consumed")
	}
	prefix := append([]stagereceipt.Verified(nil), handoff.prefix...)
	cursor, err := stagecursor.Evaluate(handoff.plan, prefix)
	if err != nil {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, err
	}
	return handoff.plan, cursor, prefix, nil
}
