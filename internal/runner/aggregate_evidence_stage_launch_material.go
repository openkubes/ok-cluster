package runner

import (
	"errors"
	"time"
)

const AggregateEvidenceStageLaunchMaterialFormat = "ok147-aggregate-evidence-stage-launch-material/v1"

type AggregateEvidenceStageLaunchMaterialConfig struct {
	Package               AggregateEvidenceStagePackageConfig
	MaterializationTime   time.Time
	Ledger                SubmissionStageCredentialSource
	ManagementObserver    SubmissionStageCredentialSource
	WorkloadObserver      SubmissionStageCredentialSource
	ArgoObserver          SubmissionStageCredentialSource
	RuntimeManifest       []byte
	RuntimeManifestDigest string
	Candidate             SubmissionStageLaunchCandidateConfig
}

type AggregateEvidenceStageLaunchMaterialReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	StageID                   string `json:"stageId"`
	Authority                 string `json:"authority"`
	EvidencePackageDigest     string `json:"evidencePackageDigest"`
	CredentialPackageDigest   string `json:"credentialPackageDigest"`
	PrivateInputPackageDigest string `json:"privateInputPackageDigest"`
	RuntimeManifestDigest     string `json:"runtimeManifestDigest"`
	LaunchPlanDigest          string `json:"launchPlanDigest"`
	CandidateDigest           string `json:"candidateDigest"`
	ValidUntil                string `json:"validUntil"`
	MutationAllowed           bool   `json:"mutationAllowed"`
}

// VerifiedAggregateEvidenceStageLaunchMaterial retains every exact public
// object, private object, credential and launch candidate required by a later
// launcher. Only redaction-safe identities are exposed through its receipt.
type VerifiedAggregateEvidenceStageLaunchMaterial struct {
	packaged      VerifiedAggregateEvidenceStagePackage
	credentials   VerifiedAggregateEvidenceStageCredentialPackage
	privateInputs VerifiedAggregateEvidenceStagePrivateInputPackage
	runtime       VerifiedAggregateEvidenceStageRuntimePrerequisite
	candidate     VerifiedAggregateEvidenceStageLaunchCandidate
	receipt       AggregateEvidenceStageLaunchMaterialReceipt
	verified      bool
}

type AggregateEvidenceStageLaunchOpenConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	ExpectedCandidateDigest string
}

// BuildAggregateEvidenceStageLaunchMaterial reconstructs and re-verifies the
// complete private Stage 12 launch input from bounded local sources. It makes
// no Kubernetes API request and grants no launch authority.
func BuildAggregateEvidenceStageLaunchMaterial(config AggregateEvidenceStageLaunchMaterialConfig) (VerifiedAggregateEvidenceStageLaunchMaterial, error) {
	packaged, err := BuildAggregateEvidenceStagePackage(config.Package)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchMaterial{}, err
	}
	credentials, err := BuildAggregateEvidenceStageCredentialPackage(AggregateEvidenceStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: config.MaterializationTime,
		Ledger: config.Ledger, ManagementObserver: config.ManagementObserver,
		WorkloadObserver: config.WorkloadObserver, ArgoObserver: config.ArgoObserver,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchMaterial{}, err
	}
	privateInputs, err := BuildAggregateEvidenceStagePrivateInputPackage(packaged)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchMaterial{}, err
	}
	runtime, err := BuildAggregateEvidenceStageRuntimePrerequisite(packaged, config.RuntimeManifest, config.RuntimeManifestDigest)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchMaterial{}, err
	}
	candidate, err := PrepareAggregateEvidenceStageLaunchCandidate(config.Candidate, packaged, credentials, privateInputs, runtime)
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchMaterial{}, err
	}
	candidateReceipt, err := candidate.Receipt()
	if err != nil {
		return VerifiedAggregateEvidenceStageLaunchMaterial{}, err
	}
	receipt := AggregateEvidenceStageLaunchMaterialReceipt{
		Format: AggregateEvidenceStageLaunchMaterialFormat, State: "VERIFIED",
		StageID: candidateReceipt.StageID, Authority: candidateReceipt.Authority,
		EvidencePackageDigest:     candidateReceipt.EvidencePackageDigest,
		CredentialPackageDigest:   candidateReceipt.CredentialPackageDigest,
		PrivateInputPackageDigest: candidateReceipt.PrivateInputPackageDigest,
		RuntimeManifestDigest:     candidateReceipt.RuntimeManifestDigest,
		LaunchPlanDigest:          candidateReceipt.LaunchPlanDigest,
		CandidateDigest:           candidateReceipt.CandidateDigest,
		ValidUntil:                candidateReceipt.ValidUntil, MutationAllowed: false,
	}
	return VerifiedAggregateEvidenceStageLaunchMaterial{
		packaged: packaged, credentials: credentials, privateInputs: privateInputs,
		runtime: runtime, candidate: candidate, receipt: receipt, verified: true,
	}, nil
}

func (material VerifiedAggregateEvidenceStageLaunchMaterial) Receipt() (AggregateEvidenceStageLaunchMaterialReceipt, error) {
	if err := verifyAggregateEvidenceStageLaunchMaterial(material); err != nil {
		return AggregateEvidenceStageLaunchMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func (material VerifiedAggregateEvidenceStageLaunchMaterial) CandidateReceipt() (AggregateEvidenceStageLaunchCandidateReceipt, error) {
	if err := verifyAggregateEvidenceStageLaunchMaterial(material); err != nil {
		return AggregateEvidenceStageLaunchCandidateReceipt{}, err
	}
	return material.candidate.Receipt()
}

// Open requires the exact retained candidate and validates local installer
// material without contacting Kubernetes.
func (material VerifiedAggregateEvidenceStageLaunchMaterial) Open(config AggregateEvidenceStageLaunchOpenConfig) (*KubernetesAggregateEvidenceStageLauncher, error) {
	if err := verifyAggregateEvidenceStageLaunchMaterial(material); err != nil {
		return nil, err
	}
	if config.ExpectedCandidateDigest == "" || config.ExpectedCandidateDigest != material.receipt.CandidateDigest {
		return nil, errors.New("aggregate evidence launch open requires the exact candidate digest")
	}
	return OpenKubernetesAggregateEvidenceStageLauncher(AggregateEvidenceStageLauncherConfig{
		Authority: config.Authority, Clock: config.Clock, Candidate: material.candidate,
		ExpectedCandidateDigest: config.ExpectedCandidateDigest,
	}, material.packaged, material.credentials, material.privateInputs, material.runtime)
}

func verifyAggregateEvidenceStageLaunchMaterial(material VerifiedAggregateEvidenceStageLaunchMaterial) error {
	if !material.verified || material.receipt.Format != AggregateEvidenceStageLaunchMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.MutationAllowed {
		return errors.New("aggregate evidence launch material was not produced by verification")
	}
	plan, err := PlanAggregateEvidenceStageLaunch(material.packaged, material.credentials, material.privateInputs, material.runtime)
	if err != nil {
		return err
	}
	candidateReceipt, err := material.candidate.Receipt()
	if err != nil {
		return err
	}
	if material.receipt.StageID != plan.StageID || material.receipt.Authority != plan.Authority ||
		material.receipt.EvidencePackageDigest != plan.EvidencePackageDigest || material.receipt.CredentialPackageDigest != plan.CredentialPackageDigest ||
		material.receipt.PrivateInputPackageDigest != plan.PrivateInputPackageDigest || material.receipt.RuntimeManifestDigest != plan.RuntimeManifestDigest ||
		material.receipt.StageID != candidateReceipt.StageID || material.receipt.Authority != candidateReceipt.Authority ||
		material.receipt.EvidencePackageDigest != candidateReceipt.EvidencePackageDigest || material.receipt.CredentialPackageDigest != candidateReceipt.CredentialPackageDigest ||
		material.receipt.PrivateInputPackageDigest != candidateReceipt.PrivateInputPackageDigest || material.receipt.RuntimeManifestDigest != candidateReceipt.RuntimeManifestDigest ||
		material.receipt.LaunchPlanDigest != candidateReceipt.LaunchPlanDigest || material.receipt.CandidateDigest != candidateReceipt.CandidateDigest ||
		material.receipt.ValidUntil != candidateReceipt.ValidUntil {
		return errors.New("aggregate evidence launch material identity changed after verification")
	}
	return nil
}
