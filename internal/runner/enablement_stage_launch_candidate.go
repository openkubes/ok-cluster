package runner

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const EnablementStageLaunchCandidateFormat = "ok147-enablement-stage-launch-candidate/v1"

type EnablementStageLaunchCandidateReceipt struct {
	Format                            string `json:"format"`
	State                             string `json:"state"`
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	EnablementPackageDigest           string `json:"enablementPackageDigest"`
	CredentialPackageDigest           string `json:"credentialPackageDigest"`
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

type enablementStageLaunchCandidateIdentity struct {
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	EnablementPackageDigest           string `json:"enablementPackageDigest"`
	CredentialPackageDigest           string `json:"credentialPackageDigest"`
	RuntimeManifestDigest             string `json:"runtimeManifestDigest"`
	LaunchPlanDigest                  string `json:"launchPlanDigest"`
	AuthorityEndpointDigest           string `json:"authorityEndpointDigest"`
	CABundleDigest                    string `json:"caBundleDigest"`
	InstallerCredentialBindingDigest  string `json:"installerCredentialBindingDigest"`
	InstallerCredentialEvidenceDigest string `json:"installerCredentialEvidenceDigest"`
	PreparedAt                        string `json:"preparedAt"`
	ValidUntil                        string `json:"validUntil"`
}

// VerifiedEnablementStageLaunchCandidate retains the exact endpoint and
// installer-token identity that are absent from its redaction-safe receipt.
type VerifiedEnablementStageLaunchCandidate struct {
	receipt              EnablementStageLaunchCandidateReceipt
	authorityEndpoint    string
	installerTokenDigest string
	verified             bool
}

// PrepareEnablementStageLaunchCandidate binds one coherent launch plan to one
// API destination, CA and independently evidenced installer credential. It
// opens no credential and performs no API request.
func PrepareEnablementStageLaunchCandidate(config SubmissionStageLaunchCandidateConfig, packaged VerifiedEnablementStagePackage, credentials VerifiedEnablementStageCredentialPackage, runtime VerifiedEnablementStageRuntimePrerequisite) (VerifiedEnablementStageLaunchCandidate, error) {
	plan, err := PlanEnablementStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return VerifiedEnablementStageLaunchCandidate{}, err
	}
	if err := verifyEnablementStageCredentialPackage(credentials); err != nil {
		return VerifiedEnablementStageLaunchCandidate{}, err
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.AuthorityEndpoint)
	if err != nil {
		return VerifiedEnablementStageLaunchCandidate{}, err
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerTokenDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerCredentialEvidenceDigest) {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("enablement launch candidate credential identities are invalid")
	}
	if config.PreparedAt.IsZero() || !config.PreparedAt.Equal(config.PreparedAt.Truncate(time.Second)) {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("enablement launch candidate preparation time is required")
	}
	materializedAt, err := time.Parse(time.RFC3339, credentials.receipt.MaterializedAt)
	if err != nil || config.PreparedAt.Before(materializedAt) {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("enablement launch candidate predates credential materialization")
	}
	validUntil := time.Time{}
	for _, credential := range credentials.receipt.Credentials {
		expiresAt, err := time.Parse(time.RFC3339, credential.ExpiresAt)
		if err != nil {
			return VerifiedEnablementStageLaunchCandidate{}, errors.New("enablement credential expiration is invalid")
		}
		candidate := expiresAt.Add(-minimumStageCredentialRemaining)
		if validUntil.IsZero() || candidate.Before(validUntil) {
			validUntil = candidate
		}
	}
	if validUntil.IsZero() || config.PreparedAt.After(validUntil) {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("enablement credentials cannot retain minimum lifetime")
	}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("encode enablement launch plan identity")
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: config.InstallerTokenDigest, EvidenceDigest: config.InstallerCredentialEvidenceDigest})
	if err != nil {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("encode enablement installer credential identity")
	}
	identity := enablementStageLaunchCandidateIdentity{
		StageID: plan.StageID, Authority: plan.Authority, EnablementPackageDigest: plan.EnablementPackageDigest,
		CredentialPackageDigest: plan.CredentialPackageDigest, RuntimeManifestDigest: plan.RuntimeManifestDigest,
		LaunchPlanDigest: digest.SHA256(planRaw), AuthorityEndpointDigest: digest.SHA256([]byte(endpoint)),
		CABundleDigest: config.CABundleDigest, InstallerCredentialBindingDigest: digest.SHA256(credentialBindingRaw),
		InstallerCredentialEvidenceDigest: config.InstallerCredentialEvidenceDigest,
		PreparedAt:                        config.PreparedAt.UTC().Format(time.RFC3339), ValidUntil: validUntil.UTC().Format(time.RFC3339),
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return VerifiedEnablementStageLaunchCandidate{}, errors.New("encode enablement launch candidate identity")
	}
	receipt := EnablementStageLaunchCandidateReceipt{
		Format: EnablementStageLaunchCandidateFormat, State: "PREPARED", StageID: identity.StageID, Authority: identity.Authority,
		EnablementPackageDigest: identity.EnablementPackageDigest, CredentialPackageDigest: identity.CredentialPackageDigest,
		RuntimeManifestDigest: identity.RuntimeManifestDigest, LaunchPlanDigest: identity.LaunchPlanDigest,
		AuthorityEndpointDigest: identity.AuthorityEndpointDigest, CABundleDigest: identity.CABundleDigest,
		InstallerCredentialBindingDigest:  identity.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: identity.InstallerCredentialEvidenceDigest,
		PreparedAt:                        identity.PreparedAt, ValidUntil: identity.ValidUntil, CandidateDigest: digest.SHA256(identityRaw), MutationAllowed: false,
	}
	return VerifiedEnablementStageLaunchCandidate{receipt: receipt, authorityEndpoint: endpoint, installerTokenDigest: config.InstallerTokenDigest, verified: true}, nil
}

func (candidate VerifiedEnablementStageLaunchCandidate) Receipt() (EnablementStageLaunchCandidateReceipt, error) {
	if err := verifyEnablementStageLaunchCandidate(candidate); err != nil {
		return EnablementStageLaunchCandidateReceipt{}, err
	}
	return candidate.receipt, nil
}

func verifyEnablementStageLaunchCandidate(candidate VerifiedEnablementStageLaunchCandidate) error {
	if !candidate.verified || candidate.receipt.Format != EnablementStageLaunchCandidateFormat || candidate.receipt.State != "PREPARED" || candidate.receipt.StageID != "enablement" || candidate.receipt.Authority == "" || candidate.receipt.MutationAllowed || candidate.authorityEndpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(candidate.installerTokenDigest) {
		return errors.New("enablement launch candidate was not produced by verification")
	}
	for _, value := range []string{
		candidate.receipt.EnablementPackageDigest, candidate.receipt.CredentialPackageDigest, candidate.receipt.RuntimeManifestDigest,
		candidate.receipt.LaunchPlanDigest, candidate.receipt.AuthorityEndpointDigest, candidate.receipt.CABundleDigest,
		candidate.receipt.InstallerCredentialBindingDigest, candidate.receipt.InstallerCredentialEvidenceDigest, candidate.receipt.CandidateDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("enablement launch candidate contains an invalid digest")
		}
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: candidate.installerTokenDigest, EvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest})
	if err != nil || digest.SHA256(credentialBindingRaw) != candidate.receipt.InstallerCredentialBindingDigest {
		return errors.New("enablement installer credential identity changed after verification")
	}
	identity := enablementStageLaunchCandidateIdentity{
		StageID: candidate.receipt.StageID, Authority: candidate.receipt.Authority,
		EnablementPackageDigest: candidate.receipt.EnablementPackageDigest, CredentialPackageDigest: candidate.receipt.CredentialPackageDigest,
		RuntimeManifestDigest: candidate.receipt.RuntimeManifestDigest, LaunchPlanDigest: candidate.receipt.LaunchPlanDigest,
		AuthorityEndpointDigest: candidate.receipt.AuthorityEndpointDigest, CABundleDigest: candidate.receipt.CABundleDigest,
		InstallerCredentialBindingDigest:  candidate.receipt.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest,
		PreparedAt:                        candidate.receipt.PreparedAt, ValidUntil: candidate.receipt.ValidUntil,
	}
	raw, err := json.Marshal(identity)
	if err != nil || digest.SHA256(raw) != candidate.receipt.CandidateDigest || digest.SHA256([]byte(candidate.authorityEndpoint)) != candidate.receipt.AuthorityEndpointDigest {
		return errors.New("enablement launch candidate identity changed after verification")
	}
	preparedAt, err := time.Parse(time.RFC3339, candidate.receipt.PreparedAt)
	if err != nil {
		return errors.New("enablement launch candidate preparation time is invalid")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.receipt.ValidUntil)
	if err != nil || validUntil.Before(preparedAt) {
		return errors.New("enablement launch candidate validity is invalid")
	}
	return nil
}
