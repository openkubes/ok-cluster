package runner

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const AggregateEvidenceStageLaunchCandidateFormat = "ok147-aggregate-evidence-stage-launch-candidate/v1"

type AggregateEvidenceStageLaunchCandidateReceipt struct {
	Format                            string `json:"format"`
	State                             string `json:"state"`
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	EvidencePackageDigest             string `json:"evidencePackageDigest"`
	CredentialPackageDigest           string `json:"credentialPackageDigest"`
	PrivateInputPackageDigest         string `json:"privateInputPackageDigest"`
	RuntimeManifestDigest             string `json:"runtimeManifestDigest"`
	LaunchPlanDigest                  string `json:"launchPlanDigest"`
	AuthorityEndpointDigest           string `json:"authorityEndpointDigest"`
	CABundleDigest                    string `json:"caBundleDigest"`
	InstallerCredentialBindingDigest  string `json:"installerCredentialBindingDigest"`
	InstallerCredentialEvidenceDigest string `json:"installerCredentialEvidenceDigest"`
	PreparedAt                        string `json:"preparedAt"`
	ValidUntil                        string `json:"validUntil"`
	CandidateDigest                   string `json:"candidateDigest"`
	MutationAllowed                   bool   `json:"mutationAllowed"`
}

type aggregateEvidenceStageLaunchCandidateIdentity struct {
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	EvidencePackageDigest             string `json:"evidencePackageDigest"`
	CredentialPackageDigest           string `json:"credentialPackageDigest"`
	PrivateInputPackageDigest         string `json:"privateInputPackageDigest"`
	RuntimeManifestDigest             string `json:"runtimeManifestDigest"`
	LaunchPlanDigest                  string `json:"launchPlanDigest"`
	AuthorityEndpointDigest           string `json:"authorityEndpointDigest"`
	CABundleDigest                    string `json:"caBundleDigest"`
	InstallerCredentialBindingDigest  string `json:"installerCredentialBindingDigest"`
	InstallerCredentialEvidenceDigest string `json:"installerCredentialEvidenceDigest"`
	PreparedAt                        string `json:"preparedAt"`
	ValidUntil                        string `json:"validUntil"`
}

type VerifiedAggregateEvidenceStageLaunchCandidate struct {
	receipt              AggregateEvidenceStageLaunchCandidateReceipt
	authorityEndpoint    string
	installerTokenDigest string
	verified             bool
}

// PrepareAggregateEvidenceStageLaunchCandidate binds the coherent launch plan
// to one API, CA and evidenced installer credential without reading a secret
// or performing an API request.
func PrepareAggregateEvidenceStageLaunchCandidate(config SubmissionStageLaunchCandidateConfig, packaged VerifiedAggregateEvidenceStagePackage, credentials VerifiedAggregateEvidenceStageCredentialPackage, privateInputs VerifiedAggregateEvidenceStagePrivateInputPackage, runtime VerifiedAggregateEvidenceStageRuntimePrerequisite) (VerifiedAggregateEvidenceStageLaunchCandidate, error) {
	plan, err := PlanAggregateEvidenceStageLaunch(packaged, credentials, privateInputs, runtime)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, err
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.AuthorityEndpoint)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, err
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerTokenDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerCredentialEvidenceDigest) {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("aggregate evidence launch candidate credential identities are invalid")
	}
	if config.PreparedAt.IsZero() || !config.PreparedAt.Equal(config.PreparedAt.Truncate(time.Second)) {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("aggregate evidence launch candidate preparation time is required")
	}
	materializedAt, err := time.Parse(time.RFC3339, credentials.receipt.MaterializedAt)
	if err != nil || config.PreparedAt.Before(materializedAt) {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("aggregate evidence launch candidate predates credential materialization")
	}
	validUntil := time.Time{}
	for _, credential := range credentials.receipt.Credentials {
		expiresAt, err := time.Parse(time.RFC3339, credential.ExpiresAt)
		if err != nil {
			return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("aggregate evidence credential expiration is invalid")
		}
		candidate := expiresAt.Add(-minimumStageCredentialRemaining)
		if validUntil.IsZero() || candidate.Before(validUntil) {
			validUntil = candidate
		}
	}
	if validUntil.IsZero() || config.PreparedAt.After(validUntil) {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("aggregate evidence credentials cannot retain minimum lifetime")
	}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("encode aggregate evidence launch plan identity")
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: config.InstallerTokenDigest, EvidenceDigest: config.InstallerCredentialEvidenceDigest})
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("encode aggregate evidence installer credential identity")
	}
	identity := aggregateEvidenceStageLaunchCandidateIdentity{
		StageID: plan.StageID, Authority: plan.Authority, EvidencePackageDigest: plan.EvidencePackageDigest,
		CredentialPackageDigest: plan.CredentialPackageDigest, PrivateInputPackageDigest: plan.PrivateInputPackageDigest,
		RuntimeManifestDigest: plan.RuntimeManifestDigest, LaunchPlanDigest: digest.SHA256(planRaw),
		AuthorityEndpointDigest: digest.SHA256([]byte(endpoint)), CABundleDigest: config.CABundleDigest,
		InstallerCredentialBindingDigest: digest.SHA256(credentialBindingRaw), InstallerCredentialEvidenceDigest: config.InstallerCredentialEvidenceDigest,
		PreparedAt: config.PreparedAt.UTC().Format(time.RFC3339), ValidUntil: validUntil.UTC().Format(time.RFC3339),
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchCandidate{}, errors.New("encode aggregate evidence launch candidate identity")
	}
	receipt := AggregateEvidenceStageLaunchCandidateReceipt{
		Format: AggregateEvidenceStageLaunchCandidateFormat, State: "PREPARED", StageID: identity.StageID, Authority: identity.Authority,
		EvidencePackageDigest: identity.EvidencePackageDigest, CredentialPackageDigest: identity.CredentialPackageDigest,
		PrivateInputPackageDigest: identity.PrivateInputPackageDigest, RuntimeManifestDigest: identity.RuntimeManifestDigest,
		LaunchPlanDigest: identity.LaunchPlanDigest, AuthorityEndpointDigest: identity.AuthorityEndpointDigest,
		CABundleDigest: identity.CABundleDigest, InstallerCredentialBindingDigest: identity.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: identity.InstallerCredentialEvidenceDigest, PreparedAt: identity.PreparedAt,
		ValidUntil: identity.ValidUntil, CandidateDigest: digest.SHA256(identityRaw), MutationAllowed: false,
	}
	return VerifiedAggregateEvidenceStageLaunchCandidate{receipt: receipt, authorityEndpoint: endpoint, installerTokenDigest: config.InstallerTokenDigest, verified: true}, nil
}

func (candidate VerifiedAggregateEvidenceStageLaunchCandidate) Receipt() (AggregateEvidenceStageLaunchCandidateReceipt, error) {
	if err := verifyAggregateEvidenceStageLaunchCandidate(candidate); err != nil {
		return AggregateEvidenceStageLaunchCandidateReceipt{}, err
	}
	return candidate.receipt, nil
}

func verifyAggregateEvidenceStageLaunchCandidate(candidate VerifiedAggregateEvidenceStageLaunchCandidate) error {
	if !candidate.verified || candidate.receipt.Format != AggregateEvidenceStageLaunchCandidateFormat || candidate.receipt.State != "PREPARED" || candidate.receipt.StageID != "aggregate-evidence" || candidate.receipt.Authority == "" || candidate.receipt.MutationAllowed || candidate.authorityEndpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(candidate.installerTokenDigest) {
		return errors.New("aggregate evidence launch candidate was not produced by verification")
	}
	for _, value := range []string{candidate.receipt.EvidencePackageDigest, candidate.receipt.CredentialPackageDigest, candidate.receipt.PrivateInputPackageDigest, candidate.receipt.RuntimeManifestDigest, candidate.receipt.LaunchPlanDigest, candidate.receipt.AuthorityEndpointDigest, candidate.receipt.CABundleDigest, candidate.receipt.InstallerCredentialBindingDigest, candidate.receipt.InstallerCredentialEvidenceDigest, candidate.receipt.CandidateDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("aggregate evidence launch candidate contains an invalid digest")
		}
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: candidate.installerTokenDigest, EvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest})
	if err != nil || digest.SHA256(credentialBindingRaw) != candidate.receipt.InstallerCredentialBindingDigest {
		return errors.New("aggregate evidence installer credential identity changed")
	}
	identity := aggregateEvidenceStageLaunchCandidateIdentity{
		StageID: candidate.receipt.StageID, Authority: candidate.receipt.Authority,
		EvidencePackageDigest: candidate.receipt.EvidencePackageDigest, CredentialPackageDigest: candidate.receipt.CredentialPackageDigest,
		PrivateInputPackageDigest: candidate.receipt.PrivateInputPackageDigest, RuntimeManifestDigest: candidate.receipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidate.receipt.LaunchPlanDigest, AuthorityEndpointDigest: candidate.receipt.AuthorityEndpointDigest,
		CABundleDigest: candidate.receipt.CABundleDigest, InstallerCredentialBindingDigest: candidate.receipt.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest,
		PreparedAt:                        candidate.receipt.PreparedAt, ValidUntil: candidate.receipt.ValidUntil,
	}
	raw, err := json.Marshal(identity)
	if err != nil || digest.SHA256(raw) != candidate.receipt.CandidateDigest || digest.SHA256([]byte(candidate.authorityEndpoint)) != candidate.receipt.AuthorityEndpointDigest {
		return errors.New("aggregate evidence launch candidate identity changed")
	}
	preparedAt, err := time.Parse(time.RFC3339, candidate.receipt.PreparedAt)
	if err != nil {
		return errors.New("aggregate evidence launch candidate preparation time is invalid")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.receipt.ValidUntil)
	if err != nil || validUntil.Before(preparedAt) {
		return errors.New("aggregate evidence launch candidate validity is invalid")
	}
	return nil
}
