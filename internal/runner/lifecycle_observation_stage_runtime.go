package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const LifecycleObservationStageRuntimePrerequisiteFormat = "ok147-lifecycle-observation-stage-runtime-prerequisite/v1"

type LifecycleObservationStageRuntimePrerequisiteReceipt struct {
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

type VerifiedLifecycleObservationStageRuntimePrerequisite struct {
	raw      []byte
	receipt  LifecycleObservationStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildLifecycleObservationStageRuntimePrerequisite binds the shared,
// tokenless runtime ServiceAccount to this exact observation package. It
// neither reads a credential nor contacts Kubernetes.
func BuildLifecycleObservationStageRuntimePrerequisite(packaged VerifiedLifecycleObservationStagePackage, manifest []byte, expectedDigest string) (VerifiedLifecycleObservationStageRuntimePrerequisite, error) {
	plan, err := PlanLifecycleObservationStageInstallation(packaged)
	if err != nil {
		return VerifiedLifecycleObservationStageRuntimePrerequisite{}, err
	}
	raw, objectDigest, err := buildStageRuntimePrerequisiteObject(manifest, expectedDigest)
	if err != nil {
		return VerifiedLifecycleObservationStageRuntimePrerequisite{}, err
	}
	receipt := LifecycleObservationStageRuntimePrerequisiteReceipt{
		Format: LifecycleObservationStageRuntimePrerequisiteFormat, State: "VERIFIED",
		ObservationPackageDigest: plan.ObservationPackageDigest, ManifestDigest: expectedDigest,
		ObjectDigest: objectDigest, Authority: plan.Authority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedLifecycleObservationStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedLifecycleObservationStageRuntimePrerequisite) Receipt() (LifecycleObservationStageRuntimePrerequisiteReceipt, error) {
	if err := verifyLifecycleObservationStageRuntimePrerequisite(runtime); err != nil {
		return LifecycleObservationStageRuntimePrerequisiteReceipt{}, err
	}
	return runtime.receipt, nil
}

func verifyLifecycleObservationStageRuntimePrerequisite(runtime VerifiedLifecycleObservationStageRuntimePrerequisite) error {
	if !runtime.verified || runtime.receipt.Format != LifecycleObservationStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || runtime.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ObservationPackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return errors.New("lifecycle observation runtime prerequisite was not produced by verification")
	}
	return nil
}
