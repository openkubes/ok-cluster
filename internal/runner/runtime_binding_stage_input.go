package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingStageInputFormat = "ok147-runtime-binding-stage-input/v1"

type RuntimeBindingStageInputReceipt struct {
	Format              string   `json:"format"`
	State               string   `json:"state"`
	StageID             string   `json:"stageId"`
	ConfigMapName       string   `json:"configMapName"`
	ConfigMapDigest     string   `json:"configMapDigest"`
	ReceiptPrefixDigest string   `json:"receiptPrefixDigest"`
	DataKeys            []string `json:"dataKeys"`
}

type VerifiedRuntimeBindingStageInput struct {
	raw      []byte
	receipt  RuntimeBindingStageInputReceipt
	verified bool
}

// BuildRuntimeBindingStageInput packages only the immutable public plan and
// exact five-receipt prefix. Workload authority, credentials, endpoint, CA and
// private runtime material remain outside the ConfigMap.
func BuildRuntimeBindingStageInput(config StageResumeConfig, configMapName string) (VerifiedRuntimeBindingStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(configMapName) || len(configMapName) > 63 || !strings.HasPrefix(configMapName, "ok147-") {
		return VerifiedRuntimeBindingStageInput{}, errors.New("runtime binding input ConfigMap name is invalid")
	}
	if _, err := LoadRuntimeBindingStageBundle(config); err != nil {
		return VerifiedRuntimeBindingStageInput{}, err
	}
	if len(config.Receipts) != 5 {
		return VerifiedRuntimeBindingStageInput{}, errors.New("runtime binding input requires the exact five-receipt prefix")
	}
	keys := []string{
		"provider-receipt.json", "lifecycle-receipt.json", "lifecycle-observation-receipt.json",
		"enablement-receipt.json", "network-observation-receipt.json",
	}
	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: make([]stageReceiptPrefixEntry, len(keys))}
	paths := map[string]string{"staged-plan.json": config.PlanPath}
	for index, key := range keys {
		paths[key] = config.Receipts[index].Path
		prefix.Receipts[index] = stageReceiptPrefixEntry{File: key, Digest: config.Receipts[index].Digest}
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedRuntimeBindingStageInput{}, errors.New("encode runtime binding receipt prefix")
	}
	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedRuntimeBindingStageInput{}, errors.New("read bounded runtime binding input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedRuntimeBindingStageInput{}, errors.New("runtime binding input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}
	if _, err := LoadRuntimeBindingStageBundle(config); err != nil {
		return VerifiedRuntimeBindingStageInput{}, errors.New("runtime binding inputs changed during materialization")
	}
	configMap := submissionStageInputConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name: configMapName, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "runtime-binding",
			},
			Annotations: map[string]string{
				"openkubes.io/input-format": RuntimeBindingStageInputFormat, "openkubes.io/receipt-prefix-digest": digest.SHA256(prefixRaw),
			},
		},
		Immutable: true, Data: data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedRuntimeBindingStageInput{}, errors.New("encode runtime binding input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedRuntimeBindingStageInput{}, errors.New("runtime binding input ConfigMap exceeds size limit")
	}
	dataKeys := make([]string, 0, len(data))
	for key := range data {
		dataKeys = append(dataKeys, key)
	}
	sort.Strings(dataKeys)
	receipt := RuntimeBindingStageInputReceipt{
		Format: RuntimeBindingStageInputFormat, State: "VERIFIED", StageID: "runtime-binding",
		ConfigMapName: configMapName, ConfigMapDigest: digest.SHA256(raw),
		ReceiptPrefixDigest: digest.SHA256(prefixRaw), DataKeys: dataKeys,
	}
	return VerifiedRuntimeBindingStageInput{raw: raw, receipt: receipt, verified: true}, nil
}

func (input VerifiedRuntimeBindingStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("runtime binding input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedRuntimeBindingStageInput) Receipt() (RuntimeBindingStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" || digest.SHA256(input.raw) != input.receipt.ConfigMapDigest {
		return RuntimeBindingStageInputReceipt{}, errors.New("runtime binding input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
