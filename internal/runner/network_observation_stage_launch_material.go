package runner

import (
	"errors"
	"time"
)

const NetworkObservationStageLaunchMaterialFormat = "ok147-network-observation-stage-launch-material/v1"

type NetworkObservationStageLaunchMaterialConfig struct {
	Package               NetworkObservationStagePackageConfig
	MaterializationTime   time.Time
	Ledger                SubmissionStageCredentialSource
	ManagementObserver    SubmissionStageCredentialSource
	WorkloadObserver      SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type NetworkObservationStageLaunchMaterialReceipt struct {
	Format                   string `json:"format"`
	State                    string `json:"state"`
	StageID                  string `json:"stageId"`
	Authority                string `json:"authority"`
	ObservationPackageDigest string `json:"observationPackageDigest"`
	CredentialPackageDigest  string `json:"credentialPackageDigest"`
	RuntimeManifestDigest    string `json:"runtimeManifestDigest"`
	LaunchPlanDigest         string `json:"launchPlanDigest"`
	CandidateDigest          string `json:"candidateDigest"`
	ValidUntil               string `json:"validUntil"`
	MutationAllowed          bool   `json:"mutationAllowed"`
}

// VerifiedNetworkObservationStageLaunchMaterial retains every exact private
// object, credential and candidate needed by a later launcher while exposing
// only redaction-safe receipts.
type VerifiedNetworkObservationStageLaunchMaterial struct {
	packaged    VerifiedNetworkObservationStagePackage
	credentials VerifiedNetworkObservationStageCredentialPackage
	runtime     VerifiedNetworkObservationStageRuntimePrerequisite
	candidate   VerifiedNetworkObservationStageLaunchCandidate
	receipt     NetworkObservationStageLaunchMaterialReceipt
	verified    bool
}

// BuildNetworkObservationStageLaunchMaterial reconstructs and re-verifies the
// complete private launch input from bounded local sources. It performs no API
// request and grants no launch authority.
func BuildNetworkObservationStageLaunchMaterial(config NetworkObservationStageLaunchMaterialConfig) (VerifiedNetworkObservationStageLaunchMaterial, error) {
	packaged, err := BuildNetworkObservationStagePackage(config.Package)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchMaterial{}, err
	}
	credentials, err := BuildNetworkObservationStageCredentialPackage(NetworkObservationStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		WorkloadBindingPath: config.Package.WorkloadBindingPath,
		Ledger:              config.Ledger, ManagementObserver: config.ManagementObserver, WorkloadObserver: config.WorkloadObserver,
	})
	if err != nil {
		return VerifiedNetworkObservationStageLaunchMaterial{}, err
	}
	runtime, err := BuildNetworkObservationStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchMaterial{}, err
	}
	candidate, err := PrepareNetworkObservationStageLaunchCandidate(config.Candidate, packaged, credentials, runtime)
	if err != nil {
		return VerifiedNetworkObservationStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedNetworkObservationStageLaunchMaterial{}, err
	}
	receipt := NetworkObservationStageLaunchMaterialReceipt{
		Format: NetworkObservationStageLaunchMaterialFormat, State: "VERIFIED", StageID: candidateReceipt.StageID,
		Authority: candidateReceipt.Authority, ObservationPackageDigest: candidateReceipt.ObservationPackageDigest,
		CredentialPackageDigest: candidateReceipt.CredentialPackageDigest, RuntimeManifestDigest: candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidateReceipt.LaunchPlanDigest, CandidateDigest: candidateReceipt.CandidateDigest,
		ValidUntil: candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedNetworkObservationStageLaunchMaterial{
		packaged: packaged, credentials: credentials, runtime: runtime, candidate: candidate,
		receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedNetworkObservationStageLaunchMaterial) Receipt() (NetworkObservationStageLaunchMaterialReceipt, error) {
	if err := verifyNetworkObservationStageLaunchMaterial(material); err != nil {
		return NetworkObservationStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func (material VerifiedNetworkObservationStageLaunchMaterial) CandidateReceipt() (NetworkObservationStageLaunchCandidateReceipt, error) {
	if err := verifyNetworkObservationStageLaunchMaterial(material); err != nil {
		return NetworkObservationStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

func verifyNetworkObservationStageLaunchMaterial(material VerifiedNetworkObservationStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != NetworkObservationStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("network observation launch material was not produced by verification")
	}
	plan, err := PlanNetworkObservationStageLaunch(material.packaged, material.credentials, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority || material.receipt.ObservationPackageDigest != plan.ObservationPackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest || material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority || material.receipt.ObservationPackageDigest != candidateReceipt.ObservationPackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest || material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest || material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("network observation launch material identity changed after verification")
	}
	return nil
}
