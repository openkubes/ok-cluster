package runner

import (
	"bytes"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const maximumRuntimeBindingMaterialFileBytes = 64 * 1024

type RuntimeBindingMaterialFileConfig struct {
	Bundle       StageResumeConfig
	MaterialPath string
	ReceiptPath  string
}

// LoadRuntimeBindingMaterialFiles reconstructs a verified private runtime
// binding after executor restart. Both files are mounted from the same
// immutable management-plane Secret; no API request is performed here.
func LoadRuntimeBindingMaterialFiles(config RuntimeBindingMaterialFileConfig) (VerifiedRuntimeBindingMaterial, error) {
	plan, _, prefix, err := loadStageResumeWithPrefix(config.Bundle)
	if err != nil {
		return VerifiedRuntimeBindingMaterial{}, err
	}
	if len(prefix) < 6 {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding replay requires the successful six-stage prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || lifecycle.State != "SUCCEEDED" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding replay lacks durable lifecycle identity")
	}
	network, err := prefix[4].Receipt()
	if err != nil || network.StageID != "network-observation" || network.State != "SUCCEEDED" || !stageReceiptPrefixDigestPattern.MatchString(network.EvidenceDigest) {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding replay lacks successful network evidence")
	}
	runtimeStage, err := prefix[5].Receipt()
	if err != nil || runtimeStage.StageID != "runtime-binding" || runtimeStage.State != "SUCCEEDED" || !stageReceiptPrefixDigestPattern.MatchString(runtimeStage.EvidenceDigest) {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding replay lacks successful persistence evidence")
	}
	materialRaw, err := readBoundedRegular(config.MaterialPath, maximumRuntimeBindingMaterialFileBytes)
	if err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("read bounded runtime binding material")
	}
	receiptRaw, err := readBoundedRegular(config.ReceiptPath, maximumRuntimeBindingMaterialFileBytes)
	if err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("read bounded runtime binding material receipt")
	}
	var material RuntimeBindingMaterial
	if err := jsonstrict.Decode(materialRaw, &material); err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("decode strict runtime binding material")
	}
	var receipt RuntimeBindingMaterialReceipt
	if err := jsonstrict.Decode(receiptRaw, &receipt); err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("decode strict runtime binding material receipt")
	}
	canonical, err := canonicalRuntimeBinding(material)
	if err != nil || !bytes.Equal(canonical, materialRaw) {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding material is not canonical")
	}
	if receipt.Format != RuntimeBindingMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "runtime-binding" || receipt.PersistentMutationAllowed ||
		receipt.PlanDigest != plan.PlanDigest || receipt.IntentRevision != plan.IntentRevision || receipt.PrivateMaterialDigest != digest.SHA256(materialRaw) ||
		receipt.TargetClusterUIDDigest != lifecycle.TargetClusterUIDDigest || receipt.LifecycleEvidenceDigest != lifecycle.EvidenceDigest || receipt.NetworkEvidenceDigest != network.EvidenceDigest {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding material receipt differs from durable execution history")
	}
	if material.Format != RuntimeBindingMaterialFormat || material.State != "CURRENT_RUNTIME_BOUND" || material.PlanDigest != plan.PlanDigest ||
		material.IntentRevision != plan.IntentRevision || material.EnablementRevision != plan.EnablementRevision ||
		material.PlatformRevision != plan.PlatformRevision || material.ExecutionFixture != plan.ExecutionFixture ||
		material.Target.Name != plan.ContractIdentity.Name {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding material differs from verified stage plan")
	}
	verified := VerifiedRuntimeBindingMaterial{material: material, raw: append([]byte(nil), materialRaw...), receipt: receipt, verified: true}
	if err := verifyRuntimeBindingMaterial(verified); err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("verify replayed runtime binding material")
	}
	return verified, nil
}
