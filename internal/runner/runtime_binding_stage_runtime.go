package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingStageRuntimePrerequisiteFormat = "ok147-runtime-binding-stage-runtime-prerequisite/v1"

type RuntimeBindingStageRuntimePrerequisiteReceipt struct {
	Format               string `json:"format"`
	State                string `json:"state"`
	BindingPackageDigest string `json:"bindingPackageDigest"`
	ManifestDigest       string `json:"manifestDigest"`
	ObjectDigest         string `json:"objectDigest"`
	Authority            string `json:"authority"`
	Namespace            string `json:"namespace"`
	Name                 string `json:"name"`
	MutationAllowed      bool   `json:"mutationAllowed"`
}

type VerifiedRuntimeBindingStageRuntimePrerequisite struct {
	raw      []byte
	receipt  RuntimeBindingStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildRuntimeBindingStageRuntimePrerequisite binds the shared tokenless
// runtime ServiceAccount to one exact runtime-binding package offline.
func BuildRuntimeBindingStageRuntimePrerequisite(packaged VerifiedRuntimeBindingStagePackage, manifest []byte, expectedDigest string) (VerifiedRuntimeBindingStageRuntimePrerequisite, error) {
	packageReceipt, err := packaged.Receipt()
	if err != nil {
		return VerifiedRuntimeBindingStageRuntimePrerequisite{}, err
	}
	raw, objectDigest, err := buildStageRuntimePrerequisiteObject(manifest, expectedDigest)
	if err != nil {
		return VerifiedRuntimeBindingStageRuntimePrerequisite{}, err
	}
	receipt := RuntimeBindingStageRuntimePrerequisiteReceipt{
		Format: RuntimeBindingStageRuntimePrerequisiteFormat, State: "VERIFIED",
		BindingPackageDigest: packageReceipt.PackageDigest, ManifestDigest: expectedDigest,
		ObjectDigest: objectDigest, Authority: packaged.managementAuthority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedRuntimeBindingStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedRuntimeBindingStageRuntimePrerequisite) Receipt() (RuntimeBindingStageRuntimePrerequisiteReceipt, error) {
	if !runtime.verified || runtime.receipt.Format != RuntimeBindingStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || runtime.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.BindingPackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return RuntimeBindingStageRuntimePrerequisiteReceipt{}, errors.New("runtime binding runtime prerequisite was not produced by verification")
	}
	return runtime.receipt, nil
}
