package runner

import (
	"errors"
	"time"
)

const LifecycleObservationStageLaunchMaterialFormat = "ok147-lifecycle-observation-stage-launch-material/v1"

type LifecycleObservationStageLaunchMaterialConfig struct {
	Package               LifecycleObservationStagePackageConfig
	MaterializationTime   time.Time
	Ledger                SubmissionStageCredentialSource
	ManagementObserver    SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type LifecycleObservationStageLaunchMaterialReceipt struct {
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

type VerifiedLifecycleObservationStageLaunchMaterial struct {
	packaged    VerifiedLifecycleObservationStagePackage
	credentials VerifiedLifecycleObservationStageCredentialPackage
	runtime     VerifiedLifecycleObservationStageRuntimePrerequisite
	candidate   VerifiedLifecycleObservationStageLaunchCandidate
	receipt     LifecycleObservationStageLaunchMaterialReceipt
	verified    bool
}

type LifecycleObservationStageLaunchOpenConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	ExpectedCandidateDigest string
}

// BuildLifecycleObservationStageLaunchMaterial constructs one sealed private
// launch input from independently bound sources. It opens only bounded local
// files and performs no Kubernetes request.
func BuildLifecycleObservationStageLaunchMaterial(config LifecycleObservationStageLaunchMaterialConfig) (VerifiedLifecycleObservationStageLaunchMaterial, error) {
	packaged, err := BuildLifecycleObservationStagePackage(config.Package)
	if err != nil {
		return VerifiedLifecycleObservationStageLaunchMaterial{}, err
	}
	credentials, err := BuildLifecycleObservationStageCredentialPackage(LifecycleObservationStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		Ledger: config.Ledger, ManagementObserver: config.ManagementObserver,
	})
	if err != nil {
		return VerifiedLifecycleObservationStageLaunchMaterial{}, err
	}
	runtime, err := BuildLifecycleObservationStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedLifecycleObservationStageLaunchMaterial{}, err
	}
	candidate, err := PrepareLifecycleObservationStageLaunchCandidate(config.Candidate, packaged, credentials, runtime)
	if err != nil {
		return VerifiedLifecycleObservationStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedLifecycleObservationStageLaunchMaterial{}, err
	}
	receipt := LifecycleObservationStageLaunchMaterialReceipt{
		Format: LifecycleObservationStageLaunchMaterialFormat, State: "VERIFIED", StageID: candidateReceipt.StageID,
		Authority: candidateReceipt.Authority, ObservationPackageDigest: candidateReceipt.ObservationPackageDigest,
		CredentialPackageDigest: candidateReceipt.CredentialPackageDigest, RuntimeManifestDigest: candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest: candidateReceipt.LaunchPlanDigest, CandidateDigest: candidateReceipt.CandidateDigest,
		ValidUntil: candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedLifecycleObservationStageLaunchMaterial{
		packaged: packaged, credentials: credentials, runtime: runtime, candidate: candidate, receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedLifecycleObservationStageLaunchMaterial) Receipt() (LifecycleObservationStageLaunchMaterialReceipt, error) {
	if err := verifyLifecycleObservationStageLaunchMaterial(material); err != nil {
		return LifecycleObservationStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func (material VerifiedLifecycleObservationStageLaunchMaterial) CandidateReceipt() (LifecycleObservationStageLaunchCandidateReceipt, error) {
	if err := verifyLifecycleObservationStageLaunchMaterial(material); err != nil {
		return LifecycleObservationStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

// Open requires the exact prepared candidate digest and never permits callers
// to replace any private verified component retained by the material.
func (material VerifiedLifecycleObservationStageLaunchMaterial) Open(config LifecycleObservationStageLaunchOpenConfig) (*KubernetesLifecycleObservationStageLauncher, error) {
	if err := verifyLifecycleObservationStageLaunchMaterial(material); err != nil {
		return nil, err
	}
	if config.ExpectedCandidateDigest == "" || config.ExpectedCandidateDigest != material.receipt.CandidateDigest {
		return nil, errors.New("lifecycle observation launch open requires the exact candidate digest")
	}
	return OpenKubernetesLifecycleObservationStageLauncher(LifecycleObservationStageLauncherConfig{
		Authority: config.Authority, Clock: config.Clock, Candidate: material.candidate,
		ExpectedCandidateDigest: config.ExpectedCandidateDigest,
	}, material.packaged, material.credentials, material.runtime)
}

func verifyLifecycleObservationStageLaunchMaterial(material VerifiedLifecycleObservationStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != LifecycleObservationStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("lifecycle observation launch material was not produced by verification")
	}
	plan, err := PlanLifecycleObservationStageLaunch(material.packaged, material.credentials, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority || material.receipt.ObservationPackageDigest != plan.ObservationPackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest || material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority || material.receipt.ObservationPackageDigest != candidateReceipt.ObservationPackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest || material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest || material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("lifecycle observation launch material identity changed after verification")
	}
	return nil
}
