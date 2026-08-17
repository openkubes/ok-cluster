package runner

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const SubmissionStageLaunchCandidateFormat = "ok147-submission-stage-launch-candidate/v1"

type SubmissionStageLaunchCandidateConfig struct {
	AuthorityEndpoint                 string
	CABundleDigest                    string
	InstallerTokenDigest              string
	InstallerCredentialEvidenceDigest string
	PreparedAt                        time.Time
}

type SubmissionStageLaunchCandidateReceipt struct {
	Format                            string `json:"format"`
	State                             string `json:"state"`
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	StagePackageDigest                string `json:"stagePackageDigest"`
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

type submissionStageLaunchCandidateIdentity struct {
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	StagePackageDigest                string `json:"stagePackageDigest"`
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

type submissionStageInstallerCredentialIdentity struct {
	TokenDigest    string `json:"tokenDigest"`
	EvidenceDigest string `json:"evidenceDigest"`
}

// VerifiedSubmissionStageLaunchCandidate retains the private endpoint and
// token identity that are deliberately absent from its public receipt.
type VerifiedSubmissionStageLaunchCandidate struct {
	receipt              SubmissionStageLaunchCandidateReceipt
	authorityEndpoint    string
	installerTokenDigest string
	verified             bool
}

// PrepareSubmissionStageLaunchCandidate binds one coherent launch to one API
// destination, CA and independently evidenced installer credential. It reads
// no credential and performs no API request.
func PrepareSubmissionStageLaunchCandidate(config SubmissionStageLaunchCandidateConfig, packaged VerifiedSubmissionStagePackage, credentials VerifiedSubmissionStageCredentialPackage, runtime VerifiedSubmissionStageRuntimePrerequisite) (VerifiedSubmissionStageLaunchCandidate, error) {
	plan, err := PlanSubmissionStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return VerifiedSubmissionStageLaunchCandidate{}, err
	}
	credentialReceipt, secrets, err := prepareSubmissionStageCredentialInstallation(credentials)
	if err != nil {
		return VerifiedSubmissionStageLaunchCandidate{}, err
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.AuthorityEndpoint)
	if err != nil {
		return VerifiedSubmissionStageLaunchCandidate{}, err
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerTokenDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerCredentialEvidenceDigest) {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("stage launch candidate credential identities are invalid")
	}
	if config.PreparedAt.IsZero() || !config.PreparedAt.Equal(config.PreparedAt.Truncate(time.Second)) {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("stage launch candidate preparation time is required")
	}
	materializedAt, err := time.Parse(time.RFC3339, credentialReceipt.MaterializedAt)
	if err != nil || config.PreparedAt.Before(materializedAt) {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("stage launch candidate predates credential materialization")
	}
	validUntil := secrets[0].expiresAt.Add(-minimumStageCredentialRemaining)
	for _, secret := range secrets[1:] {
		candidate := secret.expiresAt.Add(-minimumStageCredentialRemaining)
		if candidate.Before(validUntil) {
			validUntil = candidate
		}
	}
	if config.PreparedAt.After(validUntil) {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("stage launch candidate credentials cannot retain minimum lifetime")
	}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("encode stage launch plan identity")
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: config.InstallerTokenDigest, EvidenceDigest: config.InstallerCredentialEvidenceDigest})
	if err != nil {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("encode stage launcher credential identity")
	}
	identity := submissionStageLaunchCandidateIdentity{
		StageID: plan.StageID, Authority: plan.Authority, StagePackageDigest: plan.StagePackageDigest,
		CredentialPackageDigest: plan.CredentialPackageDigest, RuntimeManifestDigest: plan.RuntimeManifestDigest,
		LaunchPlanDigest: digest.SHA256(planRaw), AuthorityEndpointDigest: digest.SHA256([]byte(endpoint)),
		CABundleDigest: config.CABundleDigest, InstallerCredentialBindingDigest: digest.SHA256(credentialBindingRaw),
		InstallerCredentialEvidenceDigest: config.InstallerCredentialEvidenceDigest,
		PreparedAt:                        config.PreparedAt.UTC().Format(time.RFC3339), ValidUntil: validUntil.UTC().Format(time.RFC3339),
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return VerifiedSubmissionStageLaunchCandidate{}, errors.New("encode stage launch candidate identity")
	}
	receipt := SubmissionStageLaunchCandidateReceipt{
		Format: SubmissionStageLaunchCandidateFormat, State: "PREPARED", StageID: identity.StageID, Authority: identity.Authority,
		StagePackageDigest: identity.StagePackageDigest, CredentialPackageDigest: identity.CredentialPackageDigest,
		RuntimeManifestDigest: identity.RuntimeManifestDigest, LaunchPlanDigest: identity.LaunchPlanDigest,
		AuthorityEndpointDigest: identity.AuthorityEndpointDigest, CABundleDigest: identity.CABundleDigest,
		InstallerCredentialBindingDigest:  identity.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: identity.InstallerCredentialEvidenceDigest,
		PreparedAt:                        identity.PreparedAt, ValidUntil: identity.ValidUntil, CandidateDigest: digest.SHA256(identityRaw), MutationAllowed: false,
	}
	return VerifiedSubmissionStageLaunchCandidate{receipt: receipt, authorityEndpoint: endpoint, installerTokenDigest: config.InstallerTokenDigest, verified: true}, nil
}

func (candidate VerifiedSubmissionStageLaunchCandidate) Receipt() (SubmissionStageLaunchCandidateReceipt, error) {
	if err := verifySubmissionStageLaunchCandidate(candidate); err != nil {
		return SubmissionStageLaunchCandidateReceipt{}, err
	}
	return candidate.receipt, nil
}

func verifySubmissionStageLaunchCandidate(candidate VerifiedSubmissionStageLaunchCandidate) error {
	if !candidate.verified || candidate.receipt.Format != SubmissionStageLaunchCandidateFormat || candidate.receipt.State != "PREPARED" || candidate.receipt.MutationAllowed || candidate.authorityEndpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(candidate.installerTokenDigest) {
		return errors.New("stage launch candidate was not produced by verification")
	}
	for _, value := range []string{
		candidate.receipt.StagePackageDigest, candidate.receipt.CredentialPackageDigest, candidate.receipt.RuntimeManifestDigest,
		candidate.receipt.LaunchPlanDigest, candidate.receipt.AuthorityEndpointDigest, candidate.receipt.CABundleDigest,
		candidate.receipt.InstallerCredentialBindingDigest, candidate.receipt.InstallerCredentialEvidenceDigest, candidate.receipt.CandidateDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("stage launch candidate contains an invalid digest")
		}
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: candidate.installerTokenDigest, EvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest})
	if err != nil || digest.SHA256(credentialBindingRaw) != candidate.receipt.InstallerCredentialBindingDigest {
		return errors.New("stage launch candidate credential identity changed after verification")
	}
	identity := submissionStageLaunchCandidateIdentity{
		StageID: candidate.receipt.StageID, Authority: candidate.receipt.Authority,
		StagePackageDigest: candidate.receipt.StagePackageDigest, CredentialPackageDigest: candidate.receipt.CredentialPackageDigest,
		RuntimeManifestDigest: candidate.receipt.RuntimeManifestDigest, LaunchPlanDigest: candidate.receipt.LaunchPlanDigest,
		AuthorityEndpointDigest: candidate.receipt.AuthorityEndpointDigest, CABundleDigest: candidate.receipt.CABundleDigest,
		InstallerCredentialBindingDigest:  candidate.receipt.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest,
		PreparedAt:                        candidate.receipt.PreparedAt, ValidUntil: candidate.receipt.ValidUntil,
	}
	raw, err := json.Marshal(identity)
	if err != nil || digest.SHA256(raw) != candidate.receipt.CandidateDigest || digest.SHA256([]byte(candidate.authorityEndpoint)) != candidate.receipt.AuthorityEndpointDigest {
		return errors.New("stage launch candidate identity changed after verification")
	}
	preparedAt, err := time.Parse(time.RFC3339, candidate.receipt.PreparedAt)
	if err != nil {
		return errors.New("stage launch candidate preparation time is invalid")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.receipt.ValidUntil)
	if err != nil || validUntil.Before(preparedAt) {
		return errors.New("stage launch candidate validity is invalid")
	}
	return nil
}

func normalizeSubmissionStageLaunchEndpoint(raw string) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil || endpoint.Scheme != "https" {
		return "", errors.New("stage launch candidate requires an exact IP-literal HTTPS endpoint")
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return endpoint.String(), nil
}
