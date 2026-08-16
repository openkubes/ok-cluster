package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const EnablementStageRuntimePrerequisiteFormat = "ok147-enablement-stage-runtime-prerequisite/v1"

type EnablementStageRuntimePrerequisiteReceipt struct {
	Format                  string `json:"format"`
	State                   string `json:"state"`
	EnablementPackageDigest string `json:"enablementPackageDigest"`
	ManifestDigest          string `json:"manifestDigest"`
	ObjectDigest            string `json:"objectDigest"`
	Authority               string `json:"authority"`
	Namespace               string `json:"namespace"`
	Name                    string `json:"name"`
	MutationAllowed         bool   `json:"mutationAllowed"`
}

type VerifiedEnablementStageRuntimePrerequisite struct {
	raw      []byte
	receipt  EnablementStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildEnablementStageRuntimePrerequisite binds the shared tokenless runtime
// ServiceAccount to one exact Enablement package entirely offline.
func BuildEnablementStageRuntimePrerequisite(packaged VerifiedEnablementStagePackage, manifest []byte, expectedDigest string) (VerifiedEnablementStageRuntimePrerequisite, error) {
	packageReceipt, err := packaged.Receipt()
	if err != nil || packaged.managementAuthority == "" {
		return VerifiedEnablementStageRuntimePrerequisite{}, errors.New("verified enablement package is required")
	}
	raw, objectDigest, err := buildStageRuntimePrerequisiteObject(manifest, expectedDigest)
	if err != nil {
		return VerifiedEnablementStageRuntimePrerequisite{}, err
	}
	receipt := EnablementStageRuntimePrerequisiteReceipt{
		Format: EnablementStageRuntimePrerequisiteFormat, State: "VERIFIED",
		EnablementPackageDigest: packageReceipt.PackageDigest, ManifestDigest: expectedDigest,
		ObjectDigest: objectDigest, Authority: packaged.managementAuthority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedEnablementStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedEnablementStageRuntimePrerequisite) Receipt() (EnablementStageRuntimePrerequisiteReceipt, error) {
	if err := verifyEnablementStageRuntimePrerequisite(runtime); err != nil {
		return EnablementStageRuntimePrerequisiteReceipt{}, err
	}
	return runtime.receipt, nil
}

func verifyEnablementStageRuntimePrerequisite(runtime VerifiedEnablementStageRuntimePrerequisite) error {
	if !runtime.verified || runtime.receipt.Format != EnablementStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || runtime.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.EnablementPackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return errors.New("enablement runtime prerequisite was not produced by verification")
	}
	return nil
}
