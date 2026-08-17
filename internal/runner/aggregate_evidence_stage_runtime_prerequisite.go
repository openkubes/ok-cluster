package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const AggregateEvidenceStageRuntimePrerequisiteFormat = "ok147-aggregate-evidence-stage-runtime-prerequisite/v1"

type AggregateEvidenceStageRuntimePrerequisiteReceipt struct {
	Format                string `json:"format"`
	State                 string `json:"state"`
	EvidencePackageDigest string `json:"evidencePackageDigest"`
	ManifestDigest        string `json:"manifestDigest"`
	ObjectDigest          string `json:"objectDigest"`
	Authority             string `json:"authority"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	MutationAllowed       bool   `json:"mutationAllowed"`
}

type VerifiedAggregateEvidenceStageRuntimePrerequisite struct {
	raw      []byte
	receipt  AggregateEvidenceStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildAggregateEvidenceStageRuntimePrerequisite binds the shared tokenless
// runtime ServiceAccount to one exact aggregate-evidence package offline.
func BuildAggregateEvidenceStageRuntimePrerequisite(packaged VerifiedAggregateEvidenceStagePackage, manifest []byte, expectedDigest string) (VerifiedAggregateEvidenceStageRuntimePrerequisite, error) {
	plan, err := PlanAggregateEvidenceStageInstallation(packaged)
	if err != nil {
		return VerifiedAggregateEvidenceStageRuntimePrerequisite{}, err
	}
	raw, objectDigest, err := buildStageRuntimePrerequisiteObject(manifest, expectedDigest)
	if err != nil {
		return VerifiedAggregateEvidenceStageRuntimePrerequisite{}, err
	}
	receipt := AggregateEvidenceStageRuntimePrerequisiteReceipt{
		Format: AggregateEvidenceStageRuntimePrerequisiteFormat, State: "VERIFIED",
		EvidencePackageDigest: plan.EvidencePackageDigest, ManifestDigest: expectedDigest,
		ObjectDigest: objectDigest, Authority: plan.Authority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedAggregateEvidenceStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedAggregateEvidenceStageRuntimePrerequisite) Receipt() (AggregateEvidenceStageRuntimePrerequisiteReceipt, error) {
	if err := verifyAggregateEvidenceStageRuntimePrerequisite(runtime); err != nil {
		return AggregateEvidenceStageRuntimePrerequisiteReceipt{}, err
	}
	return runtime.receipt, nil
}

func verifyAggregateEvidenceStageRuntimePrerequisite(runtime VerifiedAggregateEvidenceStageRuntimePrerequisite) error {
	if !runtime.verified || runtime.receipt.Format != AggregateEvidenceStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || runtime.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.EvidencePackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return errors.New("aggregate evidence runtime prerequisite was not produced by verification")
	}
	return nil
}
