package runner

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingStageLaunchCandidateFormat = "ok147-runtime-binding-stage-launch-candidate/v1"

type RuntimeBindingStageLaunchCandidateReceipt struct {
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

type runtimeBindingStageLaunchCandidateIdentity struct {
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

// VerifiedRuntimeBindingStageLaunchCandidate retains the exact API endpoint
// and installer token identity outside its redaction-safe receipt.
type VerifiedRuntimeBindingStageLaunchCandidate struct {
	receipt              RuntimeBindingStageLaunchCandidateReceipt
	authorityEndpoint    string
	installerTokenDigest string
	verified             bool
}

// PrepareRuntimeBindingStageLaunchCandidate binds the coherent launch plan to
// one API, CA and evidenced installer credential without reading a credential
// or performing an API request.
func PrepareRuntimeBindingStageLaunchCandidate(config SubmissionStageLaunchCandidateConfig, packaged VerifiedRuntimeBindingStagePackage, credentials VerifiedRuntimeBindingStageCredentialPackage, runtime VerifiedRuntimeBindingStageRuntimePrerequisite) (VerifiedRuntimeBindingStageLaunchCandidate, error) {
	plan, err := PlanRuntimeBindingStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, err
	}
	if err := verifyRuntimeBindingStageCredentialPackage(credentials); err != nil {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, err
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.AuthorityEndpoint)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, err
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerTokenDigest) || !stageReceiptPrefixDigestPattern.MatchString(config.InstallerCredentialEvidenceDigest) {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("runtime binding launch candidate credential identities are invalid")
	}
	if config.PreparedAt.IsZero() || !config.PreparedAt.Equal(config.PreparedAt.Truncate(time.Second)) {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("runtime binding launch candidate preparation time is required")
	}
	materializedAt, err := time.Parse(time.RFC3339, credentials.receipt.MaterializedAt)
	if err != nil || config.PreparedAt.Before(materializedAt) {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("runtime binding launch candidate predates credential materialization")
	}
	validUntil := time.Time{}
	for _, credential := range credentials.receipt.Credentials {
		expiresAt, err := time.Parse(time.RFC3339, credential.ExpiresAt)
		if err != nil {
			return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("runtime binding credential expiration is invalid")
		}
		candidate := expiresAt.Add(-minimumStageCredentialRemaining)
		if validUntil.IsZero() || candidate.Before(validUntil) {
			validUntil = candidate
		}
	}
	if validUntil.IsZero() || config.PreparedAt.After(validUntil) {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("runtime binding credentials cannot retain minimum lifetime")
	}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("encode runtime binding launch plan identity")
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: config.InstallerTokenDigest, EvidenceDigest: config.InstallerCredentialEvidenceDigest})
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("encode runtime binding installer credential identity")
	}
	identity := runtimeBindingStageLaunchCandidateIdentity{
		StageID: plan.StageID, Authority: plan.Authority, StagePackageDigest: plan.StagePackageDigest,
		CredentialPackageDigest: plan.CredentialPackageDigest, RuntimeManifestDigest: plan.RuntimeManifestDigest,
		LaunchPlanDigest: digest.SHA256(planRaw), AuthorityEndpointDigest: digest.SHA256([]byte(endpoint)),
		CABundleDigest: config.CABundleDigest, InstallerCredentialBindingDigest: digest.SHA256(credentialBindingRaw),
		InstallerCredentialEvidenceDigest: config.InstallerCredentialEvidenceDigest,
		PreparedAt:                        config.PreparedAt.UTC().Format(time.RFC3339), ValidUntil: validUntil.UTC().Format(time.RFC3339),
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchCandidate{}, errors.New("encode runtime binding launch candidate identity")
	}
	receipt := RuntimeBindingStageLaunchCandidateReceipt{
		Format: RuntimeBindingStageLaunchCandidateFormat, State: "PREPARED", StageID: identity.StageID, Authority: identity.Authority,
		StagePackageDigest: identity.StagePackageDigest, CredentialPackageDigest: identity.CredentialPackageDigest,
		RuntimeManifestDigest: identity.RuntimeManifestDigest, LaunchPlanDigest: identity.LaunchPlanDigest,
		AuthorityEndpointDigest: identity.AuthorityEndpointDigest, CABundleDigest: identity.CABundleDigest,
		InstallerCredentialBindingDigest: identity.InstallerCredentialBindingDigest, InstallerCredentialEvidenceDigest: identity.InstallerCredentialEvidenceDigest,
		PreparedAt: identity.PreparedAt, ValidUntil: identity.ValidUntil, CandidateDigest: digest.SHA256(identityRaw), MutationAllowed: false,
	}
	return VerifiedRuntimeBindingStageLaunchCandidate{receipt: receipt, authorityEndpoint: endpoint, installerTokenDigest: config.InstallerTokenDigest, verified: true}, nil
}

func (candidate VerifiedRuntimeBindingStageLaunchCandidate) Receipt() (RuntimeBindingStageLaunchCandidateReceipt, error) {
	if err := verifyRuntimeBindingStageLaunchCandidate(candidate); err != nil {
		return RuntimeBindingStageLaunchCandidateReceipt{}, err
	}
	return candidate.receipt, nil
}

func verifyRuntimeBindingStageLaunchCandidate(candidate VerifiedRuntimeBindingStageLaunchCandidate) error {
	if !candidate.verified || candidate.receipt.Format != RuntimeBindingStageLaunchCandidateFormat || candidate.receipt.State != "PREPARED" || candidate.receipt.StageID != "runtime-binding" || candidate.receipt.Authority == "" || candidate.receipt.MutationAllowed || candidate.authorityEndpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(candidate.installerTokenDigest) {
		return errors.New("runtime binding launch candidate was not produced by verification")
	}
	for _, value := range []string{
		candidate.receipt.StagePackageDigest, candidate.receipt.CredentialPackageDigest, candidate.receipt.RuntimeManifestDigest,
		candidate.receipt.LaunchPlanDigest, candidate.receipt.AuthorityEndpointDigest, candidate.receipt.CABundleDigest,
		candidate.receipt.InstallerCredentialBindingDigest, candidate.receipt.InstallerCredentialEvidenceDigest, candidate.receipt.CandidateDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("runtime binding launch candidate contains an invalid digest")
		}
	}
	credentialBindingRaw, err := json.Marshal(submissionStageInstallerCredentialIdentity{TokenDigest: candidate.installerTokenDigest, EvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest})
	if err != nil || digest.SHA256(credentialBindingRaw) != candidate.receipt.InstallerCredentialBindingDigest {
		return errors.New("runtime binding installer credential identity changed after verification")
	}
	identity := runtimeBindingStageLaunchCandidateIdentity{
		StageID: candidate.receipt.StageID, Authority: candidate.receipt.Authority,
		StagePackageDigest: candidate.receipt.StagePackageDigest, CredentialPackageDigest: candidate.receipt.CredentialPackageDigest,
		RuntimeManifestDigest: candidate.receipt.RuntimeManifestDigest, LaunchPlanDigest: candidate.receipt.LaunchPlanDigest,
		AuthorityEndpointDigest: candidate.receipt.AuthorityEndpointDigest, CABundleDigest: candidate.receipt.CABundleDigest,
		InstallerCredentialBindingDigest: candidate.receipt.InstallerCredentialBindingDigest, InstallerCredentialEvidenceDigest: candidate.receipt.InstallerCredentialEvidenceDigest,
		PreparedAt: candidate.receipt.PreparedAt, ValidUntil: candidate.receipt.ValidUntil,
	}
	raw, err := json.Marshal(identity)
	if err != nil || digest.SHA256(raw) != candidate.receipt.CandidateDigest || digest.SHA256([]byte(candidate.authorityEndpoint)) != candidate.receipt.AuthorityEndpointDigest {
		return errors.New("runtime binding launch candidate identity changed after verification")
	}
	preparedAt, err := time.Parse(time.RFC3339, candidate.receipt.PreparedAt)
	if err != nil {
		return errors.New("runtime binding launch candidate preparation time is invalid")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.receipt.ValidUntil)
	if err != nil || validUntil.Before(preparedAt) {
		return errors.New("runtime binding launch candidate validity is invalid")
	}
	return nil
}
