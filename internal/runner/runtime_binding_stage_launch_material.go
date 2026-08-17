package runner

import (
	"errors"
	"time"
)

const RuntimeBindingStageLaunchMaterialFormat = "ok147-runtime-binding-stage-launch-material/v1"

type RuntimeBindingStageLaunchMaterialConfig struct {
	Package               RuntimeBindingStagePackageConfig
	MaterializationTime   time.Time
	LedgerWriter          SubmissionStageCredentialSource
	PersistenceWriter     SubmissionStageCredentialSource
	WorkloadObserver      SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type RuntimeBindingStageLaunchMaterialReceipt struct {
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

// VerifiedRuntimeBindingStageLaunchMaterial retains every exact private
// object, credential and candidate needed by a later launcher while exposing
// only redaction-safe receipts.
type VerifiedRuntimeBindingStageLaunchMaterial struct {
	packaged    VerifiedRuntimeBindingStagePackage
	credentials VerifiedRuntimeBindingStageCredentialPackage
	runtime     VerifiedRuntimeBindingStageRuntimePrerequisite
	candidate   VerifiedRuntimeBindingStageLaunchCandidate
	receipt     RuntimeBindingStageLaunchMaterialReceipt
	verified    bool
}

// BuildRuntimeBindingStageLaunchMaterial reconstructs and re-verifies the
// complete private launch input from bounded local sources. It performs no API
// request and grants no launch authority.
func BuildRuntimeBindingStageLaunchMaterial(config RuntimeBindingStageLaunchMaterialConfig) (VerifiedRuntimeBindingStageLaunchMaterial, error) {
	packaged, err := BuildRuntimeBindingStagePackage(config.Package)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchMaterial{}, err
	}
	credentials, err := BuildRuntimeBindingStageCredentialPackage(RuntimeBindingStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		WorkloadBindingPath: config.Package.WorkloadBindingPath,
		LedgerWriter:        config.LedgerWriter, PersistenceWriter: config.PersistenceWriter, WorkloadObserver: config.WorkloadObserver,
	})
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchMaterial{}, err
	}
	runtime, err := BuildRuntimeBindingStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchMaterial{}, err
	}
	candidate, err := PrepareRuntimeBindingStageLaunchCandidate(config.Candidate, packaged, credentials, runtime)
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedRuntimeBindingStageLaunchMaterial{}, err
	}
	receipt := RuntimeBindingStageLaunchMaterialReceipt{
		Format: RuntimeBindingStageLaunchMaterialFormat, State: "VERIFIED", StageID: candidateReceipt.StageID,
		Authority: candidateReceipt.Authority, StagePackageDigest: candidateReceipt.StagePackageDigest,
		CredentialPackageDigest: candidateReceipt.CredentialPackageDigest, RuntimeManifestDigest: candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidateReceipt.LaunchPlanDigest, CandidateDigest: candidateReceipt.CandidateDigest,
		ValidUntil: candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedRuntimeBindingStageLaunchMaterial{
		packaged: packaged, credentials: credentials, runtime: runtime, candidate: candidate,
		receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedRuntimeBindingStageLaunchMaterial) Receipt() (RuntimeBindingStageLaunchMaterialReceipt, error) {
	if err := verifyRuntimeBindingStageLaunchMaterial(material); err != nil {
		return RuntimeBindingStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func (material VerifiedRuntimeBindingStageLaunchMaterial) CandidateReceipt() (RuntimeBindingStageLaunchCandidateReceipt, error) {
	if err := verifyRuntimeBindingStageLaunchMaterial(material); err != nil {
		return RuntimeBindingStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

func verifyRuntimeBindingStageLaunchMaterial(material VerifiedRuntimeBindingStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != RuntimeBindingStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("runtime binding launch material was not produced by verification")
	}
	plan, err := PlanRuntimeBindingStageLaunch(material.packaged, material.credentials, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority || material.receipt.StagePackageDigest != plan.StagePackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest || material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority || material.receipt.StagePackageDigest != candidateReceipt.StagePackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest || material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest || material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("runtime binding launch material identity changed after verification")
	}
	return nil
}
