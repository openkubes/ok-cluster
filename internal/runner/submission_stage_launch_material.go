package runner

import (
	"errors"
	"time"
)

const SubmissionStageLaunchMaterialFormat = "ok147-submission-stage-launch-material/v1"

type SubmissionStageLaunchMaterialConfig struct {
	Package               SubmissionStagePackageConfig
	MaterializationTime   time.Time
	Ledger                SubmissionStageCredentialSource
	SelectedAuthority     SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type SubmissionStageLaunchMaterialReceipt struct {
	Format                  string `json:"format"`
	State                   string `json:"state"`
	StageID                 string `json:"stageId"`
	Authority               string `json:"authority"`
	StagePackageDigest      string `json:"stagePackageDigest"`
	CredentialPackageDigest string `json:"credentialPackageDigest"`
	RuntimeManifestDigest   string `json:"runtimeManifestDigest"`
	LaunchPlanDigest        string `json:"launchPlanDigest"`
	CandidateDigest         string `json:"candidateDigest"`
	ValidUntil              string `json:"validUntil"`
	MutationAllowed         bool   `json:"mutationAllowed"`
}

type VerifiedSubmissionStageLaunchMaterial struct {
	packaged    VerifiedSubmissionStagePackage
	credentials VerifiedSubmissionStageCredentialPackage
	runtime     VerifiedSubmissionStageRuntimePrerequisite
	candidate   VerifiedSubmissionStageLaunchCandidate
	receipt     SubmissionStageLaunchMaterialReceipt
	verified    bool
}

type SubmissionStageLaunchOpenConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	ExpectedCandidateDigest string
}

// BuildSubmissionStageLaunchMaterial constructs the complete private launch
// input from independently bound sources. It opens only bounded local source
// files and performs no Kubernetes request.
func BuildSubmissionStageLaunchMaterial(config SubmissionStageLaunchMaterialConfig) (VerifiedSubmissionStageLaunchMaterial, error) {
	packaged, err := BuildSubmissionStagePackage(config.Package)
	if err != nil {
		return VerifiedSubmissionStageLaunchMaterial{}, err
	}
	credentials, err := BuildSubmissionStageCredentialPackage(SubmissionStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		Ledger: config.Ledger, SelectedAuthority: config.SelectedAuthority,
	})
	if err != nil {
		return VerifiedSubmissionStageLaunchMaterial{}, err
	}
	runtime, err := BuildSubmissionStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedSubmissionStageLaunchMaterial{}, err
	}
	candidate, err := PrepareSubmissionStageLaunchCandidate(config.Candidate, packaged, credentials, runtime)
	if err != nil {
		return VerifiedSubmissionStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedSubmissionStageLaunchMaterial{}, err
	}
	receipt := SubmissionStageLaunchMaterialReceipt{
		Format: SubmissionStageLaunchMaterialFormat, State: "VERIFIED", StageID: candidateReceipt.StageID,
		Authority: candidateReceipt.Authority, StagePackageDigest: candidateReceipt.StagePackageDigest,
		CredentialPackageDigest: candidateReceipt.CredentialPackageDigest, RuntimeManifestDigest: candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidateReceipt.LaunchPlanDigest, CandidateDigest: candidateReceipt.CandidateDigest,
		ValidUntil: candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedSubmissionStageLaunchMaterial{
		packaged: packaged, credentials: credentials, runtime: runtime, candidate: candidate, receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedSubmissionStageLaunchMaterial) Receipt() (SubmissionStageLaunchMaterialReceipt, error) {
	if err := verifySubmissionStageLaunchMaterial(material); err != nil {
		return SubmissionStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

// CandidateReceipt exposes only the redaction-safe exact approval identity.
// Private launch material remains inaccessible to the caller.
func (material VerifiedSubmissionStageLaunchMaterial) CandidateReceipt() (SubmissionStageLaunchCandidateReceipt, error) {
	if err := verifySubmissionStageLaunchMaterial(material); err != nil {
		return SubmissionStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

// Open requires the caller to repeat the exact candidate digest but does not
// allow it to replace any verified package or candidate component.
func (material VerifiedSubmissionStageLaunchMaterial) Open(config SubmissionStageLaunchOpenConfig) (*KubernetesSubmissionStageLauncher, error) {
	if err := verifySubmissionStageLaunchMaterial(material); err != nil {
		return nil, err
	}
	if config.ExpectedCandidateDigest == "" || config.ExpectedCandidateDigest != material.receipt.CandidateDigest {
		return nil, errors.New("stage launch open requires the exact candidate digest")
	}
	return OpenKubernetesSubmissionStageLauncher(SubmissionStageLauncherConfig{
		Authority: config.Authority, Clock: config.Clock, Candidate: material.candidate,
		ExpectedCandidateDigest: config.ExpectedCandidateDigest,
	}, material.packaged, material.credentials, material.runtime)
}

func verifySubmissionStageLaunchMaterial(material VerifiedSubmissionStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != SubmissionStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("stage launch material was not produced by verification")
	}
	plan, err := PlanSubmissionStageLaunch(material.packaged, material.credentials, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority || material.receipt.StagePackageDigest != plan.StagePackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest || material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority || material.receipt.StagePackageDigest != candidateReceipt.StagePackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest || material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest || material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("stage launch material identity changed after verification")
	}
	return nil
}
