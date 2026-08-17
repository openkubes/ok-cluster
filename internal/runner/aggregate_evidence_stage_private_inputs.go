package runner

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
)

const AggregateEvidenceStagePrivateInputPackageFormat = "ok147-aggregate-evidence-stage-private-input-package/v1"

type AggregateEvidenceStagePrivateInputObjectReceipt struct {
	Role           string `json:"role"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	ContentDigest  string `json:"contentDigest"`
	ObjectDigest   string `json:"objectDigest"`
	ExistingPolicy string `json:"existingPolicy"`
	CreatePolicy   string `json:"createPolicy"`
}

type AggregateEvidenceStagePrivateInputPackageReceipt struct {
	Format                string                                            `json:"format"`
	State                 string                                            `json:"state"`
	StageID               string                                            `json:"stageId"`
	EvidencePackageDigest string                                            `json:"evidencePackageDigest"`
	Authority             string                                            `json:"authority"`
	PackageDigest         string                                            `json:"packageDigest"`
	Objects               []AggregateEvidenceStagePrivateInputObjectReceipt `json:"objects"`
	MutationAllowed       bool                                              `json:"mutationAllowed"`
}

type aggregateEvidenceStagePrivateInputPackageIdentity struct {
	EvidencePackageDigest string                                            `json:"evidencePackageDigest"`
	Authority             string                                            `json:"authority"`
	Objects               []AggregateEvidenceStagePrivateInputObjectReceipt `json:"objects"`
}

type aggregateEvidenceStagePrivateInputObject struct {
	role string
	name string
	raw  []byte
}

// VerifiedAggregateEvidenceStagePrivateInputPackage retains the exact two
// private Secret bodies. Runtime binding is required-existing; capability is
// create-if-absent-or-exact. Neither payload is exposed by the receipt.
type VerifiedAggregateEvidenceStagePrivateInputPackage struct {
	objects   []aggregateEvidenceStagePrivateInputObject
	receipt   AggregateEvidenceStagePrivateInputPackageReceipt
	authority string
	verified  bool
}

// BuildAggregateEvidenceStagePrivateInputPackage materializes both private
// Secret expectations entirely offline and assigns their distinct policies.
func BuildAggregateEvidenceStagePrivateInputPackage(packaged VerifiedAggregateEvidenceStagePackage) (VerifiedAggregateEvidenceStagePrivateInputPackage, error) {
	stageReceipt, err := packaged.Receipt()
	if err != nil {
		return VerifiedAggregateEvidenceStagePrivateInputPackage{}, err
	}
	var runtimeReceipt RuntimeBindingMaterialReceipt
	if err := jsonstrict.Decode(packaged.runtimeReceiptRaw, &runtimeReceipt); err != nil {
		return VerifiedAggregateEvidenceStagePrivateInputPackage{}, errors.New("decode aggregate private runtime receipt")
	}
	runtimeSecret := runtimeBindingSecret{
		APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque",
		Metadata: runtimeBindingSecretObjectMeta{
			Name: packaged.runtimeSecret, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "ok-cluster-contract-executor", "openkubes.io/stage-id": "runtime-binding",
			},
			Annotations: map[string]string{
				"openkubes.io/content-digest": packaged.runtimeDigest, "openkubes.io/plan-digest": runtimeReceipt.PlanDigest,
			},
		},
		Data: map[string][]byte{
			runtimeBindingSecretDataKey:        append([]byte(nil), packaged.runtimeMaterialRaw...),
			runtimeBindingReceiptSecretDataKey: append([]byte(nil), packaged.runtimeReceiptRaw...),
		},
	}
	runtimeRaw, err := json.Marshal(runtimeSecret)
	if err != nil {
		return VerifiedAggregateEvidenceStagePrivateInputPackage{}, errors.New("encode aggregate private runtime Secret")
	}
	capabilitySecret := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "immutable": true, "type": "Opaque",
		"metadata": map[string]any{
			"name": packaged.capabilitySecret, "namespace": submissionStageInputNamespace,
			"labels": map[string]any{
				"app.kubernetes.io/managed-by": "ok-cluster-contract-executor", "openkubes.io/stage-id": stageReceipt.StageID,
			},
			"annotations": map[string]any{"openkubes.io/content-digest": packaged.capabilityDigest},
		},
		"data": map[string]any{"platform-capability.json": base64.StdEncoding.EncodeToString(packaged.capabilityRaw)},
	}
	capabilityRaw, err := json.Marshal(capabilitySecret)
	if err != nil {
		return VerifiedAggregateEvidenceStagePrivateInputPackage{}, errors.New("encode aggregate private capability Secret")
	}
	objects := []aggregateEvidenceStagePrivateInputObject{
		{role: "runtime-binding", name: packaged.runtimeSecret, raw: runtimeRaw},
		{role: "platform-capability", name: packaged.capabilitySecret, raw: capabilityRaw},
	}
	receipts := []AggregateEvidenceStagePrivateInputObjectReceipt{
		{Role: objects[0].role, Namespace: submissionStageInputNamespace, Name: objects[0].name, ContentDigest: packaged.runtimeDigest, ObjectDigest: digest.SHA256(runtimeRaw), ExistingPolicy: "REQUIRE_EXACT_EXISTING", CreatePolicy: "DO_NOT_CREATE"},
		{Role: objects[1].role, Namespace: submissionStageInputNamespace, Name: objects[1].name, ContentDigest: packaged.capabilityDigest, ObjectDigest: digest.SHA256(capabilityRaw), ExistingPolicy: "VERIFY_EXACT_GLOBAL_STATE", CreatePolicy: "CREATE_ONLY_AFTER_GLOBAL_ABSENCE"},
	}
	identity, err := json.Marshal(aggregateEvidenceStagePrivateInputPackageIdentity{EvidencePackageDigest: stageReceipt.PackageDigest, Authority: packaged.managementAuthority, Objects: receipts})
	if err != nil {
		return VerifiedAggregateEvidenceStagePrivateInputPackage{}, errors.New("encode aggregate private input package identity")
	}
	receipt := AggregateEvidenceStagePrivateInputPackageReceipt{
		Format: AggregateEvidenceStagePrivateInputPackageFormat, State: "VERIFIED", StageID: stageReceipt.StageID,
		EvidencePackageDigest: stageReceipt.PackageDigest, Authority: packaged.managementAuthority,
		PackageDigest: digest.SHA256(identity), Objects: receipts, MutationAllowed: false,
	}
	return VerifiedAggregateEvidenceStagePrivateInputPackage{objects: cloneAggregateEvidencePrivateInputObjects(objects), receipt: receipt, authority: packaged.managementAuthority, verified: true}, nil
}

func (packaged VerifiedAggregateEvidenceStagePrivateInputPackage) Receipt() (AggregateEvidenceStagePrivateInputPackageReceipt, error) {
	if err := verifyAggregateEvidenceStagePrivateInputPackage(packaged); err != nil {
		return AggregateEvidenceStagePrivateInputPackageReceipt{}, errors.New("aggregate evidence private input package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Objects = append([]AggregateEvidenceStagePrivateInputObjectReceipt(nil), packaged.receipt.Objects...)
	return receipt, nil
}

func verifyAggregateEvidenceStagePrivateInputPackage(packaged VerifiedAggregateEvidenceStagePrivateInputPackage) error {
	if !packaged.verified || packaged.receipt.Format != AggregateEvidenceStagePrivateInputPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "aggregate-evidence" || packaged.receipt.MutationAllowed || packaged.authority == "" || packaged.receipt.Authority != packaged.authority || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.EvidencePackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.PackageDigest) || len(packaged.objects) != 2 || len(packaged.receipt.Objects) != 2 {
		return errors.New("aggregate evidence private input package identity is incomplete")
	}
	identity, err := json.Marshal(aggregateEvidenceStagePrivateInputPackageIdentity{EvidencePackageDigest: packaged.receipt.EvidencePackageDigest, Authority: packaged.receipt.Authority, Objects: packaged.receipt.Objects})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("aggregate evidence private input package identity changed")
	}
	wantRoles := []string{"runtime-binding", "platform-capability"}
	wantExisting := []string{"REQUIRE_EXACT_EXISTING", "VERIFY_EXACT_GLOBAL_STATE"}
	wantCreate := []string{"DO_NOT_CREATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE"}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Objects[index]
		if object.role != wantRoles[index] || receipt.Role != wantRoles[index] || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || receipt.ExistingPolicy != wantExisting[index] || receipt.CreatePolicy != wantCreate[index] || !stageReceiptPrefixDigestPattern.MatchString(receipt.ContentDigest) || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("aggregate evidence private input object identity changed")
		}
	}
	if err := verifyAggregateEvidenceRuntimeInput(packaged.objects[0].raw, packaged.receipt.Objects[0]); err != nil {
		return err
	}
	return verifyAggregateEvidenceCapabilityInput(packaged.objects[1].raw, packaged.receipt.Objects[1])
}

func verifyAggregateEvidenceRuntimeInput(raw []byte, receipt AggregateEvidenceStagePrivateInputObjectReceipt) error {
	var secret runtimeBindingSecret
	if err := jsonstrict.Decode(raw, &secret); err != nil || secret.APIVersion != "v1" || secret.Kind != "Secret" || !secret.Immutable || secret.Type != "Opaque" || secret.Metadata.Name != receipt.Name || secret.Metadata.Namespace != receipt.Namespace || len(secret.Data) != 2 || digest.SHA256(secret.Data[runtimeBindingSecretDataKey]) != receipt.ContentDigest {
		return errors.New("aggregate evidence runtime input semantics changed")
	}
	var materialReceipt RuntimeBindingMaterialReceipt
	if jsonstrict.Decode(secret.Data[runtimeBindingReceiptSecretDataKey], &materialReceipt) != nil || materialReceipt.PrivateMaterialDigest != receipt.ContentDigest || len(secret.Metadata.Labels) != 2 || secret.Metadata.Labels["app.kubernetes.io/managed-by"] != "ok-cluster-contract-executor" || secret.Metadata.Labels["openkubes.io/stage-id"] != "runtime-binding" || len(secret.Metadata.Annotations) != 2 || secret.Metadata.Annotations["openkubes.io/content-digest"] != receipt.ContentDigest || secret.Metadata.Annotations["openkubes.io/plan-digest"] != materialReceipt.PlanDigest {
		return errors.New("aggregate evidence runtime receipt semantics changed")
	}
	return nil
}

func verifyAggregateEvidenceCapabilityInput(raw []byte, receipt AggregateEvidenceStagePrivateInputObjectReceipt) error {
	var secret map[string]any
	if err := jsonstrict.Decode(raw, &secret); err != nil {
		return errors.New("aggregate evidence capability input is invalid")
	}
	metadata, _ := secret["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	data, _ := secret["data"].(map[string]any)
	encoded, ok := data["platform-capability.json"].(string)
	capabilityRaw, err := base64.StdEncoding.DecodeString(encoded)
	if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != receipt.Name || metadata["namespace"] != receipt.Namespace || len(labels) != 2 || labels["app.kubernetes.io/managed-by"] != "ok-cluster-contract-executor" || labels["openkubes.io/stage-id"] != "aggregate-evidence" || len(annotations) != 1 || annotations["openkubes.io/content-digest"] != receipt.ContentDigest || len(data) != 1 || !ok || err != nil {
		return errors.New("aggregate evidence capability input semantics changed")
	}
	var capability observation.PlatformCapabilityState
	if jsonstrict.Decode(capabilityRaw, &capability) != nil || observation.ValidatePlatformCapabilityState(capability) != nil || capability.EvidenceDigest != receipt.ContentDigest {
		return errors.New("aggregate evidence capability assertion changed")
	}
	return nil
}

func cloneAggregateEvidencePrivateInputObjects(objects []aggregateEvidenceStagePrivateInputObject) []aggregateEvidenceStagePrivateInputObject {
	result := append([]aggregateEvidenceStagePrivateInputObject(nil), objects...)
	for index := range result {
		result[index].raw = append([]byte(nil), objects[index].raw...)
	}
	return result
}
