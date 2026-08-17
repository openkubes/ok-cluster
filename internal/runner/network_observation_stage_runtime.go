package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const NetworkObservationStageRuntimePrerequisiteFormat = "ok147-network-observation-stage-runtime-prerequisite/v1"

type NetworkObservationStageRuntimePrerequisiteReceipt struct {
	Format                   string `json:"format"`
	State                    string `json:"state"`
	ObservationPackageDigest string `json:"observationPackageDigest"`
	ManifestDigest           string `json:"manifestDigest"`
	ObjectDigest             string `json:"objectDigest"`
	Authority                string `json:"authority"`
	Namespace                string `json:"namespace"`
	Name                     string `json:"name"`
	MutationAllowed          bool   `json:"mutationAllowed"`
}

type VerifiedNetworkObservationStageRuntimePrerequisite struct {
	raw      []byte
	receipt  NetworkObservationStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildNetworkObservationStageRuntimePrerequisite binds the shared tokenless
// runtime ServiceAccount to one exact network-observation package offline.
func BuildNetworkObservationStageRuntimePrerequisite(packaged VerifiedNetworkObservationStagePackage, manifest []byte, expectedDigest string) (VerifiedNetworkObservationStageRuntimePrerequisite, error) {
	plan, err := PlanNetworkObservationStageInstallation(packaged)
	if err != nil {
		return VerifiedNetworkObservationStageRuntimePrerequisite{}, err
	}
	raw, objectDigest, err := buildStageRuntimePrerequisiteObject(manifest, expectedDigest)
	if err != nil {
		return VerifiedNetworkObservationStageRuntimePrerequisite{}, err
	}
	receipt := NetworkObservationStageRuntimePrerequisiteReceipt{
		Format: NetworkObservationStageRuntimePrerequisiteFormat, State: "VERIFIED",
		ObservationPackageDigest: plan.ObservationPackageDigest, ManifestDigest: expectedDigest,
		ObjectDigest: objectDigest, Authority: plan.Authority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedNetworkObservationStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedNetworkObservationStageRuntimePrerequisite) Receipt() (NetworkObservationStageRuntimePrerequisiteReceipt, error) {
	if err := verifyNetworkObservationStageRuntimePrerequisite(runtime); err != nil {
		return NetworkObservationStageRuntimePrerequisiteReceipt{}, err
	}
	return runtime.receipt, nil
}

func verifyNetworkObservationStageRuntimePrerequisite(runtime VerifiedNetworkObservationStageRuntimePrerequisite) error {
	if !runtime.verified || runtime.receipt.Format != NetworkObservationStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || runtime.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ObservationPackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return errors.New("network observation runtime prerequisite was not produced by verification")
	}
	return nil
}
