package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const EnablementStageInputFormat = "ok147-enablement-stage-input/v1"

// EnablementStageInputReceipt exposes only the immutable public input
// identities. The ConfigMap contains no credential or authorization decision.
type EnablementStageInputReceipt struct {
	Format              string   `json:"format"`
	State               string   `json:"state"`
	StageID             string   `json:"stageId"`
	ConfigMapName       string   `json:"configMapName"`
	ConfigMapDigest     string   `json:"configMapDigest"`
	ReceiptPrefixDigest string   `json:"receiptPrefixDigest"`
	EnablementDigest    string   `json:"enablementDigest"`
	DataKeys            []string `json:"dataKeys"`
}

type VerifiedEnablementStageInput struct {
	raw      []byte
	receipt  EnablementStageInputReceipt
	verified bool
}

// BuildEnablementStageInput snapshots the already verified fourth-stage
// artifact chain into one immutable ConfigMap. It performs no API request.
func BuildEnablementStageInput(config EnablementStageBundleConfig, configMapName string) (VerifiedEnablementStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(configMapName) || len(configMapName) > 63 || len(configMapName) < len("ok147-") || configMapName[:len("ok147-")] != "ok147-" {
		return VerifiedEnablementStageInput{}, errors.New("enablement stage input ConfigMap name is invalid")
	}
	if len(config.Receipts) != 3 {
		return VerifiedEnablementStageInput{}, errors.New("enablement stage input requires exactly three predecessor receipts")
	}
	if _, err := LoadEnablementStageBundle(config); err != nil {
		return VerifiedEnablementStageInput{}, err
	}

	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: []stageReceiptPrefixEntry{
		{File: "provider-receipt.json", Digest: config.Receipts[0].Digest},
		{File: "lifecycle-receipt.json", Digest: config.Receipts[1].Digest},
		{File: "lifecycle-observation-receipt.json", Digest: config.Receipts[2].Digest},
	}}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedEnablementStageInput{}, errors.New("encode enablement receipt prefix")
	}
	paths := map[string]string{
		"staged-plan.json": config.PlanPath, "stage-grant.json": config.GrantPath,
		"stage-authority.pub": config.GrantPublicKeyPath, "enablement.yaml": config.ArtifactPath,
		"provider-receipt.json": config.Receipts[0].Path, "lifecycle-receipt.json": config.Receipts[1].Path,
		"lifecycle-observation-receipt.json": config.Receipts[2].Path,
	}
	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedEnablementStageInput{}, errors.New("read bounded enablement stage input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedEnablementStageInput{}, errors.New("enablement stage input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}
	if _, err := LoadEnablementStageBundle(config); err != nil {
		return VerifiedEnablementStageInput{}, errors.New("enablement stage inputs changed during materialization")
	}

	configMap := submissionStageInputConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name: configMapName, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "enablement"},
			Annotations: map[string]string{
				"openkubes.io/input-format": EnablementStageInputFormat, "openkubes.io/receipt-prefix-digest": digest.SHA256(prefixRaw),
			},
		},
		Immutable: true, Data: data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedEnablementStageInput{}, errors.New("encode enablement stage input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedEnablementStageInput{}, errors.New("enablement stage input ConfigMap exceeds size limit")
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return VerifiedEnablementStageInput{
		raw: raw,
		receipt: EnablementStageInputReceipt{
			Format: EnablementStageInputFormat, State: "VERIFIED", StageID: "enablement", ConfigMapName: configMapName,
			ConfigMapDigest: digest.SHA256(raw), ReceiptPrefixDigest: digest.SHA256(prefixRaw), EnablementDigest: digest.SHA256([]byte(data["enablement.yaml"])), DataKeys: keys,
		},
		verified: true,
	}, nil
}

func (input VerifiedEnablementStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("enablement stage input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedEnablementStageInput) Receipt() (EnablementStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" {
		return EnablementStageInputReceipt{}, errors.New("enablement stage input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
