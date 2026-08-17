package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const TargetAccessStageRuntimePrerequisiteFormat = "ok147-target-access-stage-runtime-prerequisite/v1"

type TargetAccessStageRuntimePrerequisiteReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	TargetAccessPackageDigest string `json:"targetAccessPackageDigest"`
	ManifestDigest            string `json:"manifestDigest"`
	ObjectDigest              string `json:"objectDigest"`
	Authority                 string `json:"authority"`
	Namespace                 string `json:"namespace"`
	Name                      string `json:"name"`
	MutationAllowed           bool   `json:"mutationAllowed"`
}

type VerifiedTargetAccessStageRuntimePrerequisite struct {
	raw      []byte
	receipt  TargetAccessStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildTargetAccessStageRuntimePrerequisite binds the shared tokenless runner
// ServiceAccount on the central execution plane entirely offline.
func BuildTargetAccessStageRuntimePrerequisite(packaged VerifiedTargetAccessStagePackage, manifest []byte, expectedDigest string) (VerifiedTargetAccessStageRuntimePrerequisite, error) {
	packageReceipt, err := packaged.Receipt()
	if err != nil || packaged.installationAuthority == "" {
		return VerifiedTargetAccessStageRuntimePrerequisite{}, errors.New("verified target-access package is required")
	}
	raw, objectDigest, err := buildStageRuntimePrerequisiteObject(manifest, expectedDigest)
	if err != nil {
		return VerifiedTargetAccessStageRuntimePrerequisite{}, err
	}
	receipt := TargetAccessStageRuntimePrerequisiteReceipt{
		Format: TargetAccessStageRuntimePrerequisiteFormat, State: "VERIFIED",
		TargetAccessPackageDigest: packageReceipt.PackageDigest, ManifestDigest: expectedDigest,
		ObjectDigest: objectDigest, Authority: packaged.installationAuthority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedTargetAccessStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedTargetAccessStageRuntimePrerequisite) Receipt() (TargetAccessStageRuntimePrerequisiteReceipt, error) {
	if err := verifyTargetAccessStageRuntimePrerequisite(runtime); err != nil {
		return TargetAccessStageRuntimePrerequisiteReceipt{}, err
	}
	return runtime.receipt, nil
}

func verifyTargetAccessStageRuntimePrerequisite(runtime VerifiedTargetAccessStageRuntimePrerequisite) error {
	if !runtime.verified || runtime.receipt.Format != TargetAccessStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || runtime.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.TargetAccessPackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return errors.New("target-access runtime prerequisite was not produced by verification")
	}
	return nil
}
