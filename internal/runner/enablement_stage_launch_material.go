package runner

import (
	"errors"
	"time"
)

const EnablementStageLaunchMaterialFormat = "ok147-enablement-stage-launch-material/v1"

type EnablementStageLaunchMaterialConfig struct {
	Package               EnablementStagePackageConfig
	MaterializationTime   time.Time
	Ledger                SubmissionStageCredentialSource
	ManagementWriter      SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type EnablementStageLaunchMaterialReceipt struct {
	Format                  string `json:"format"`
	State                   string `json:"state"`
	StageID                 string `json:"stageId"`
	Authority               string `json:"authority"`
	EnablementPackageDigest string `json:"enablementPackageDigest"`
	CredentialPackageDigest string `json:"credentialPackageDigest"`
	RuntimeManifestDigest   string `json:"runtimeManifestDigest"`
	LaunchPlanDigest        string `json:"launchPlanDigest"`
	CandidateDigest         string `json:"candidateDigest"`
	ValidUntil              string `json:"validUntil"`
	MutationAllowed         bool   `json:"mutationAllowed"`
}

// VerifiedEnablementStageLaunchMaterial retains every private component but
// deliberately provides no Open or execution method at this checkpoint.
type VerifiedEnablementStageLaunchMaterial struct {
	packaged    VerifiedEnablementStagePackage
	credentials VerifiedEnablementStageCredentialPackage
	runtime     VerifiedEnablementStageRuntimePrerequisite
	candidate   VerifiedEnablementStageLaunchCandidate
	receipt     EnablementStageLaunchMaterialReceipt
	verified    bool
}

// BuildEnablementStageLaunchMaterial constructs the complete private launch
// input from independently bound sources. It opens only bounded local files,
// performs no API request and grants no launch authority.
func BuildEnablementStageLaunchMaterial(config EnablementStageLaunchMaterialConfig) (VerifiedEnablementStageLaunchMaterial, error) {
	packaged, err := BuildEnablementStagePackage(config.Package)
	if err != nil {
		return VerifiedEnablementStageLaunchMaterial{}, err
	}
	credentials, err := BuildEnablementStageCredentialPackage(EnablementStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		Ledger: config.Ledger, ManagementWriter: config.ManagementWriter,
	})
	if err != nil {
		return VerifiedEnablementStageLaunchMaterial{}, err
	}
	runtime, err := BuildEnablementStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedEnablementStageLaunchMaterial{}, err
	}
	candidate, err := PrepareEnablementStageLaunchCandidate(config.Candidate, packaged, credentials, runtime)
	if err != nil {
		return VerifiedEnablementStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedEnablementStageLaunchMaterial{}, err
	}
	receipt := EnablementStageLaunchMaterialReceipt{
		Format: EnablementStageLaunchMaterialFormat, State: "VERIFIED", StageID: candidateReceipt.StageID,
		Authority: candidateReceipt.Authority, EnablementPackageDigest: candidateReceipt.EnablementPackageDigest,
		CredentialPackageDigest: candidateReceipt.CredentialPackageDigest, RuntimeManifestDigest: candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidateReceipt.LaunchPlanDigest, CandidateDigest: candidateReceipt.CandidateDigest,
		ValidUntil: candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedEnablementStageLaunchMaterial{
		packaged: packaged, credentials: credentials, runtime: runtime, candidate: candidate,
		receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedEnablementStageLaunchMaterial) Receipt() (EnablementStageLaunchMaterialReceipt, error) {
	if err := verifyEnablementStageLaunchMaterial(material); err != nil {
		return EnablementStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func (material VerifiedEnablementStageLaunchMaterial) CandidateReceipt() (EnablementStageLaunchCandidateReceipt, error) {
	if err := verifyEnablementStageLaunchMaterial(material); err != nil {
		return EnablementStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

func verifyEnablementStageLaunchMaterial(material VerifiedEnablementStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != EnablementStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("enablement launch material was not produced by verification")
	}
	plan, err := PlanEnablementStageLaunch(material.packaged, material.credentials, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority || material.receipt.EnablementPackageDigest != plan.EnablementPackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest || material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority || material.receipt.EnablementPackageDigest != candidateReceipt.EnablementPackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest || material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest || material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("enablement launch material identity changed after verification")
	}
	return nil
}
