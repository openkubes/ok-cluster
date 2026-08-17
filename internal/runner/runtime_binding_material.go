package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingMaterialFormat = "ok147-runtime-binding-material/v1"

type RuntimeBindingObservation struct {
	KubeSystemUID            string
	LocalPathStorageClassUID string
	LocalPathProvisioner     string
}

type RuntimeBindingMaterialConfig struct {
	Bundle                        StageResumeConfig
	WorkloadBindingPath           string
	ExpectedWorkloadBindingDigest string
	WorkloadCAFile                string
	Observation                   RuntimeBindingObservation
}

type RuntimeBindingTarget struct {
	Name                 string `json:"name"`
	CAPIClusterUID       string `json:"capiClusterUid"`
	TargetIdentityScheme string `json:"targetIdentityScheme"`
	WorkloadAPIEndpoint  string `json:"workloadApiEndpoint"`
	WorkloadAPICAData    string `json:"workloadApiCaData"`
	WorkloadAPICADigest  string `json:"workloadApiCaDigest"`
	KubeSystemUID        string `json:"kubeSystemUid"`
}

type RuntimeBindingStorage struct {
	Name        string `json:"name"`
	UID         string `json:"uid"`
	Provisioner string `json:"provisioner"`
}

type RuntimeBindingEvidence struct {
	LifecycleEvidenceDigest string `json:"lifecycleEvidenceDigest"`
	NetworkEvidenceDigest   string `json:"networkEvidenceDigest"`
}

// RuntimeBindingMaterial is private runtime data. Its endpoint, raw UIDs and
// public CA payload must not be copied into public evidence.
type RuntimeBindingMaterial struct {
	Format             string                 `json:"format"`
	State              string                 `json:"state"`
	PlanDigest         string                 `json:"planDigest"`
	IntentRevision     string                 `json:"intentRevision"`
	EnablementRevision string                 `json:"enablementRevision"`
	PlatformRevision   string                 `json:"platformRevision"`
	ExecutionFixture   string                 `json:"executionFixture"`
	Target             RuntimeBindingTarget   `json:"target"`
	Storage            RuntimeBindingStorage  `json:"storage"`
	Evidence           RuntimeBindingEvidence `json:"evidence"`
}

type RuntimeBindingMaterialReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	StageID                   string `json:"stageId"`
	PlanDigest                string `json:"planDigest"`
	IntentRevision            string `json:"intentRevision"`
	TargetClusterUIDDigest    string `json:"targetClusterUidDigest"`
	WorkloadAPICADigest       string `json:"workloadApiCaDigest"`
	KubeSystemUIDDigest       string `json:"kubeSystemUidDigest"`
	LocalPathStorageUIDDigest string `json:"localPathStorageUidDigest"`
	LifecycleEvidenceDigest   string `json:"lifecycleEvidenceDigest"`
	NetworkEvidenceDigest     string `json:"networkEvidenceDigest"`
	PrivateMaterialDigest     string `json:"privateMaterialDigest"`
	PersistentMutationAllowed bool   `json:"persistentMutationAllowed"`
}

type VerifiedRuntimeBindingMaterial struct {
	material RuntimeBindingMaterial
	raw      []byte
	receipt  RuntimeBindingMaterialReceipt
	verified bool
}

// BuildRuntimeBindingMaterial correlates the exact successful five-receipt
// prefix with the already verified workload authority, current read-only
// workload observations and the actual CA bytes. It performs no API request
// and writes no file.
func BuildRuntimeBindingMaterial(config RuntimeBindingMaterialConfig) (VerifiedRuntimeBindingMaterial, error) {
	plan, cursor, prefix, err := loadStageResumeWithPrefix(config.Bundle)
	if err != nil {
		return VerifiedRuntimeBindingMaterial{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "runtime-binding" || decision.Kind != "Binding" || decision.Authority != "runner" || decision.RequiresAuthorization || decision.Operation != "" {
		return VerifiedRuntimeBindingMaterial{}, errors.New("verified prefix does not select runtime binding")
	}
	if len(prefix) != 5 {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding requires the exact five-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding history lacks durable target correlation")
	}
	network, err := prefix[4].Receipt()
	if err != nil || network.StageID != "network-observation" || network.State != "SUCCEEDED" {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime binding history lacks successful NetworkReady evidence")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, config.ExpectedWorkloadBindingDigest)
	if err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("load verified workload authority binding")
	}
	if binding.IntentRevision != plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return VerifiedRuntimeBindingMaterial{}, errors.New("workload authority differs from durable lifecycle target")
	}
	ca, err := readBoundedRegular(config.WorkloadCAFile, maximumCABytes)
	if err != nil || digest.SHA256(ca) != binding.CABundleDigest {
		return VerifiedRuntimeBindingMaterial{}, errors.New("workload API CA differs from runtime authority")
	}
	if !runtimeInputUIDPattern.MatchString(config.Observation.KubeSystemUID) || !runtimeInputUIDPattern.MatchString(config.Observation.LocalPathStorageClassUID) || config.Observation.LocalPathProvisioner != "rancher.io/local-path" {
		return VerifiedRuntimeBindingMaterial{}, errors.New("runtime workload observation is invalid")
	}
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND",
		PlanDigest: plan.PlanDigest, IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		Target: RuntimeBindingTarget{
			Name: plan.ContractIdentity.Name, CAPIClusterUID: binding.TargetClusterUID, TargetIdentityScheme: binding.TargetIdentityScheme,
			WorkloadAPIEndpoint: binding.Endpoint, WorkloadAPICAData: base64.StdEncoding.EncodeToString(ca),
			WorkloadAPICADigest: binding.CABundleDigest, KubeSystemUID: config.Observation.KubeSystemUID,
		},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: config.Observation.LocalPathStorageClassUID, Provisioner: config.Observation.LocalPathProvisioner},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: lifecycle.EvidenceDigest, NetworkEvidenceDigest: network.EvidenceDigest},
	}
	raw, err := canonicalRuntimeBinding(material)
	if err != nil {
		return VerifiedRuntimeBindingMaterial{}, errors.New("encode private runtime binding material")
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding", PlanDigest: plan.PlanDigest,
		IntentRevision: plan.IntentRevision, TargetClusterUIDDigest: lifecycle.TargetClusterUIDDigest,
		WorkloadAPICADigest: binding.CABundleDigest, KubeSystemUIDDigest: digest.SHA256([]byte(config.Observation.KubeSystemUID)),
		LocalPathStorageUIDDigest: digest.SHA256([]byte(config.Observation.LocalPathStorageClassUID)),
		LifecycleEvidenceDigest:   lifecycle.EvidenceDigest, NetworkEvidenceDigest: network.EvidenceDigest,
		PrivateMaterialDigest: digest.SHA256(raw), PersistentMutationAllowed: false,
	}
	return VerifiedRuntimeBindingMaterial{material: material, raw: raw, receipt: receipt, verified: true}, nil
}

func (material VerifiedRuntimeBindingMaterial) Bytes() ([]byte, error) {
	if err := verifyRuntimeBindingMaterial(material); err != nil {
		return nil, err
	}
	return append([]byte(nil), material.raw...), nil
}

func (material VerifiedRuntimeBindingMaterial) Receipt() (RuntimeBindingMaterialReceipt, error) {
	if err := verifyRuntimeBindingMaterial(material); err != nil {
		return RuntimeBindingMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func verifyRuntimeBindingMaterial(material VerifiedRuntimeBindingMaterial) error {
	if !material.verified || material.receipt.Format != RuntimeBindingMaterialFormat || material.receipt.State != "VERIFIED" || material.receipt.StageID != "runtime-binding" || material.receipt.PersistentMutationAllowed {
		return errors.New("runtime binding material was not produced by verification")
	}
	raw, err := canonicalRuntimeBinding(material.material)
	if err != nil || !bytes.Equal(raw, material.raw) || digest.SHA256(raw) != material.receipt.PrivateMaterialDigest {
		return errors.New("runtime binding material changed after verification")
	}
	if digest.SHA256([]byte(material.material.Target.CAPIClusterUID)) != material.receipt.TargetClusterUIDDigest || material.material.Target.WorkloadAPICADigest != material.receipt.WorkloadAPICADigest || digest.SHA256([]byte(material.material.Target.KubeSystemUID)) != material.receipt.KubeSystemUIDDigest || digest.SHA256([]byte(material.material.Storage.UID)) != material.receipt.LocalPathStorageUIDDigest || material.material.Evidence.LifecycleEvidenceDigest != material.receipt.LifecycleEvidenceDigest || material.material.Evidence.NetworkEvidenceDigest != material.receipt.NetworkEvidenceDigest {
		return errors.New("runtime binding receipt differs from private material")
	}
	return nil
}

func canonicalRuntimeBinding(binding RuntimeBindingMaterial) ([]byte, error) {
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}
