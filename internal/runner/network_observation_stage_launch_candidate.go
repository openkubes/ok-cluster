package runner

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const NetworkObservationStageLaunchCandidateFormat = "ok147-network-observation-stage-launch-candidate/v1"

type NetworkObservationStageLaunchCandidateReceipt struct {
	Format                            string `json:"format"`
	State                             string `json:"state"`
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	ObservationPackageDigest          string `json:"observationPackageDigest"`
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

type networkObservationStageLaunchCandidateIdentity struct {
	StageID                           string `json:"stageId"`
	Authority                         string `json:"authority"`
	ObservationPackageDigest          string `json:"observationPackageDigest"`
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

// VerifiedNetworkObservationStageLaunchCandidate retains the exact API
// endpoint and installer token identity outside its redaction-safe receipt.
type VerifiedNetworkObservationStageLaunchCandidate struct {
	receipt              NetworkObservationStageLaunchCandidateReceipt
	authorityEndpoint    string
	installerTokenDigest string
	verified             bool
}

// PrepareNetworkObservationStageLaunchCandidate binds the coherent launch
// plan to one API, CA and evidenced installer credential without reading a
// credential or performing an API request.
func PrepareNetworkObservationStageLaunchCandidate(config SubmissionStageLaunchCandidateConfig, packaged VerifiedNetworkObservationStagePackage, credentials VerifiedNetworkObservationStageCredentialPackage, runtime VerifiedNetworkObservationStageRuntimePrerequisite) (VerifiedNetworkObservationStageLaunchCandidate, error) {
	plan, err := PlanNetworkObservationStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchCandidate{}, err
	}
	if err := verifyNetworkObservationStageCredentialPackage(credentials); err != nil {
		return VerifiedNetworkObservationStageLaunchCandidate{}, err
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.AuthorityEndpoint)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchCandidate{}, err
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerTokenDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerCredentialEvidenceDigest) {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("network observation launch candidate credential identities are invalid")
	}
	if config.PreparedAt.IsZero() || !config.PreparedAt.Equal(config.PreparedAt.Truncate(time.Second)) {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("network observation launch candidate preparation time is required")
	}
	materializedAt, err := time.Parse(time.RFC3339, credentials.receipt.MaterializedAt)
	if err != nil || config.PreparedAt.Before(materializedAt) {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("network observation launch candidate predates credential materialization")
	}
	validUntil := time.Time{}
	for _, credential := range credentials.receipt.Credentials {
		expiresAt, err := time.Parse(time.RFC3339, credential.ExpiresAt)
		if err != nil {
			return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("network observation credential expiration is invalid")
		}
		candidate := expiresAt.Add(-minimumStageCredentialRemaining)
		if validUntil.IsZero() || candidate.Before(validUntil) {
			validUntil = candidate
		}
	}
	if validUntil.IsZero() || config.PreparedAt.After(validUntil) {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("network observation credentials cannot retain minimum lifetime")
	}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("encode network observation launch plan identity")
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: config.InstallerTokenDigest, EvidenceDigest: config.InstallerCredentialEvidenceDigest})
	if err != nil {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("encode network observation installer credential identity")
	}
	identity := networkObservationStageLaunchCandidateIdentity{
		StageID: plan.StageID, Authority: plan.Authority, ObservationPackageDigest: plan.ObservationPackageDigest,
		CredentialPackageDigest: plan.CredentialPackageDigest, RuntimeManifestDigest: plan.RuntimeManifestDigest,
		LaunchPlanDigest: digest.SHA256(planRaw), AuthorityEndpointDigest: digest.SHA256([]byte(endpoint)),
		CABundleDigest: config.CABundleDigest, InstallerCredentialBindingDigest: digest.SHA256(credentialBindingRaw),
		InstallerCredentialEvidenceDigest: config.InstallerCredentialEvidenceDigest,
		PreparedAt:                        config.PreparedAt.UTC().Format(time.RFC3339), ValidUntil: validUntil.UTC().Format(time.RFC3339),
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchCandidate{}, errors.New("encode network observation launch candidate identity")
	}
	receipt := NetworkObservationStageLaunchCandidateReceipt{
		Format: NetworkObservationStageLaunchCandidateFormat, State: "PREPARED", StageID: identity.StageID, Authority: identity.Authority,
		ObservationPackageDigest: identity.ObservationPackageDigest, CredentialPackageDigest: identity.CredentialPackageDigest,
		RuntimeManifestDigest: identity.RuntimeManifestDigest, LaunchPlanDigest: identity.LaunchPlanDigest,
		AuthorityEndpointDigest: identity.AuthorityEndpointDigest, CABundleDigest: identity.CABundleDigest,
		InstallerCredentialBindingDigest: identity.InstallerCredentialBindingDigest, InstallerCredentialEvidenceDigest: identity.InstallerCredentialEvidenceDigest,
		PreparedAt: identity.PreparedAt, ValidUntil: identity.ValidUntil, CandidateDigest: digest.SHA256(identityRaw), MutationAllowed: false,
	}
	return VerifiedNetworkObservationStageLaunchCandidate{receipt: receipt, authorityEndpoint: endpoint, installerTokenDigest: config.InstallerTokenDigest, verified: true}, nil
}

func (candidate VerifiedNetworkObservationStageLaunchCandidate) Receipt() (NetworkObservationStageLaunchCandidateReceipt, error) {
	if err := verifyNetworkObservationStageLaunchCandidate(candidate); err != nil {
		return NetworkObservationStageLaunchCandidateReceipt{}, err
	}
	return candidate.receipt, nil
}

func verifyNetworkObservationStageLaunchCandidate(candidate VerifiedNetworkObservationStageLaunchCandidate) error {
	if !candidate.verified || candidate.receipt.Format != NetworkObservationStageLaunchCandidateFormat || candidate.receipt.State != "PREPARED" || candidate.receipt.StageID != "network-observation" || candidate.receipt.Authority == "" || candidate.receipt.MutationAllowed || candidate.authorityEndpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(candidate.installerTokenDigest) {
		return errors.New("network observation launch candidate was not produced by verification")
	}
	for _, value := range []string{
		candidate.receipt.ObservationPackageDigest, candidate.receipt.CredentialPackageDigest, candidate.receipt.RuntimeManifestDigest,
		candidate.receipt.LaunchPlanDigest, candidate.receipt.AuthorityEndpointDigest, candidate.receipt.CABundleDigest,
		candidate.receipt.InstallerCredentialBindingDigest, candidate.receipt.InstallerCredentialEvidenceDigest, candidate.receipt.CandidateDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("network observation launch candidate contains an invalid digest")
		}
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: candidate.installerTokenDigest, EvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest})
	if err != nil || digest.SHA256(credentialBindingRaw) != candidate.receipt.InstallerCredentialBindingDigest {
		return errors.New("network observation installer credential identity changed after verification")
	}
	identity := networkObservationStageLaunchCandidateIdentity{
		StageID: candidate.receipt.StageID, Authority: candidate.receipt.Authority,
		ObservationPackageDigest: candidate.receipt.ObservationPackageDigest, CredentialPackageDigest: candidate.receipt.CredentialPackageDigest,
		RuntimeManifestDigest: candidate.receipt.RuntimeManifestDigest, LaunchPlanDigest: candidate.receipt.LaunchPlanDigest,
		AuthorityEndpointDigest: candidate.receipt.AuthorityEndpointDigest, CABundleDigest: candidate.receipt.CABundleDigest,
		InstallerCredentialBindingDigest: candidate.receipt.InstallerCredentialBindingDigest, InstallerCredentialEvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest,
		PreparedAt: candidate.receipt.PreparedAt, ValidUntil: candidate.receipt.ValidUntil,
	}
	raw, err := json.Marshal(identity)
	if err != nil || digest.SHA256(raw) != candidate.receipt.CandidateDigest || digest.SHA256([]byte(candidate.authorityEndpoint)) != candidate.receipt.AuthorityEndpointDigest {
		return errors.New("network observation launch candidate identity changed after verification")
	}
	preparedAt, err := time.Parse(time.RFC3339, candidate.receipt.PreparedAt)
	if err != nil {
		return errors.New("network observation launch candidate preparation time is invalid")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.receipt.ValidUntil)
	if err != nil || validUntil.Before(preparedAt) {
		return errors.New("network observation launch candidate validity is invalid")
	}
	return nil
}
