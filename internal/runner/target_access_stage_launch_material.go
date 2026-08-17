package runner

import (
	"errors"
	"time"
)

const TargetAccessStageLaunchMaterialFormat = "ok147-target-access-stage-launch-material/v1"

type TargetAccessStageLaunchMaterialConfig struct {
	Package               TargetAccessStagePackageConfig
	MaterializationTime   time.Time
	LedgerWriter          SubmissionStageCredentialSource
	WorkloadWriter        SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type TargetAccessStageLaunchMaterialReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	StageID                   string `json:"stageId"`
	Authority                 string `json:"authority"`
	TargetAccessPackageDigest string `json:"targetAccessPackageDigest"`
	CredentialPackageDigest   string `json:"credentialPackageDigest"`
	RuntimeManifestDigest     string `json:"runtimeManifestDigest"`
	LaunchPlanDigest          string `json:"launchPlanDigest"`
	CandidateDigest           string `json:"candidateDigest"`
	ValidUntil                string `json:"validUntil"`
	MutationAllowed           bool   `json:"mutationAllowed"`
}

// VerifiedTargetAccessStageLaunchMaterial retains all exact public and
// private components needed by a later single-use launcher while exposing
// only redaction-safe receipts.
type VerifiedTargetAccessStageLaunchMaterial struct {
	packaged    VerifiedTargetAccessStagePackage
	credentials VerifiedTargetAccessStageCredentialPackage
	runtime     VerifiedTargetAccessStageRuntimePrerequisite
	candidate   VerifiedTargetAccessStageLaunchCandidate
	receipt     TargetAccessStageLaunchMaterialReceipt
	verified    bool
}

type TargetAccessStageLaunchOpenConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	ExpectedCandidateDigest string
}

// BuildTargetAccessStageLaunchMaterial reconstructs and re-verifies the
// complete private launch input from bounded local sources. It performs no API
// request and grants no launch authority.
func BuildTargetAccessStageLaunchMaterial(config TargetAccessStageLaunchMaterialConfig) (VerifiedTargetAccessStageLaunchMaterial, error) {
	packaged, err := BuildTargetAccessStagePackage(config.Package)
	if err != nil {
		return VerifiedTargetAccessStageLaunchMaterial{}, err
	}
	credentials, err := BuildTargetAccessStageCredentialPackage(TargetAccessStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		WorkloadBindingPath: config.Package.WorkloadBindingPath,
		LedgerWriter:        config.LedgerWriter, WorkloadWriter: config.WorkloadWriter,
	})
	if err != nil {
		return VerifiedTargetAccessStageLaunchMaterial{}, err
	}
	runtime, err := BuildTargetAccessStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedTargetAccessStageLaunchMaterial{}, err
	}
	candidate, err := PrepareTargetAccessStageLaunchCandidate(config.Candidate, packaged, credentials, runtime)
	if err != nil {
		return VerifiedTargetAccessStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedTargetAccessStageLaunchMaterial{}, err
	}
	receipt := TargetAccessStageLaunchMaterialReceipt{
		Format: TargetAccessStageLaunchMaterialFormat, State: "VERIFIED", StageID: candidateReceipt.StageID,
		Authority: candidateReceipt.Authority, TargetAccessPackageDigest: candidateReceipt.TargetAccessPackageDigest,
		CredentialPackageDigest: candidateReceipt.CredentialPackageDigest, RuntimeManifestDigest: candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidateReceipt.LaunchPlanDigest, CandidateDigest: candidateReceipt.CandidateDigest,
		ValidUntil: candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedTargetAccessStageLaunchMaterial{
		packaged: packaged, credentials: credentials, runtime: runtime, candidate: candidate,
		receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedTargetAccessStageLaunchMaterial) Receipt() (TargetAccessStageLaunchMaterialReceipt, error) {
	if err := verifyTargetAccessStageLaunchMaterial(material); err != nil {
		return TargetAccessStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func (material VerifiedTargetAccessStageLaunchMaterial) CandidateReceipt() (TargetAccessStageLaunchCandidateReceipt, error) {
	if err := verifyTargetAccessStageLaunchMaterial(material); err != nil {
		return TargetAccessStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

// Open requires the exact retained candidate and validates local installer
// material without contacting Kubernetes.
func (material VerifiedTargetAccessStageLaunchMaterial) Open(config TargetAccessStageLaunchOpenConfig) (*KubernetesTargetAccessStageLauncher, error) {
	if err := verifyTargetAccessStageLaunchMaterial(material); err != nil {
		return nil, err
	}
	if config.ExpectedCandidateDigest == "" || config.ExpectedCandidateDigest != material.receipt.CandidateDigest {
		return nil, errors.New("target-access launch open requires the exact candidate digest")
	}
	return OpenKubernetesTargetAccessStageLauncher(TargetAccessStageLauncherConfig{
		Authority: config.Authority, Clock: config.Clock, Candidate: material.candidate,
		ExpectedCandidateDigest: config.ExpectedCandidateDigest,
	}, material.packaged, material.credentials, material.runtime)
}

func verifyTargetAccessStageLaunchMaterial(material VerifiedTargetAccessStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != TargetAccessStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("target-access launch material was not produced by verification")
	}
	plan, err := PlanTargetAccessStageLaunch(material.packaged, material.credentials, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority || material.receipt.TargetAccessPackageDigest != plan.TargetAccessPackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest || material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority || material.receipt.TargetAccessPackageDigest != candidateReceipt.TargetAccessPackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest || material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest || material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("target-access launch material identity changed after verification")
	}
	return nil
}
