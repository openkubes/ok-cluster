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

const LifecycleObservationStageInputFormat = "ok147-lifecycle-observation-stage-input/v1"

type LifecycleObservationStageInputReceipt struct {
	Format              string   `json:"format"`
	State               string   `json:"state"`
	StageID             string   `json:"stageId"`
	ConfigMapName       string   `json:"configMapName"`
	ConfigMapDigest     string   `json:"configMapDigest"`
	ReceiptPrefixDigest string   `json:"receiptPrefixDigest"`
	DataKeys            []string `json:"dataKeys"`
}

type VerifiedLifecycleObservationStageInput struct {
	raw      []byte
	receipt  LifecycleObservationStageInputReceipt
	verified bool
}

// BuildLifecycleObservationStageInput packages only the plan and the exact
// provider/lifecycle receipt prefix. It contains no grant, projection or
// credential material and performs no Kubernetes request.
func BuildLifecycleObservationStageInput(config StageResumeConfig, configMapName string) (VerifiedLifecycleObservationStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(configMapName) || len(configMapName) > 63 || !strings.HasPrefix(configMapName, "ok147-") {
		return VerifiedLifecycleObservationStageInput{}, errors.New("lifecycle observation input ConfigMap name is invalid")
	}
	if _, err := LoadLifecycleObservationStageBundle(config); err != nil {
		return VerifiedLifecycleObservationStageInput{}, err
	}
	if len(config.Receipts) != 2 {
		return VerifiedLifecycleObservationStageInput{}, errors.New("lifecycle observation input requires provider and lifecycle receipts")
	}
	keys := []string{"provider-receipt.json", "lifecycle-receipt.json"}
	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: make([]stageReceiptPrefixEntry, 2)}
	paths := map[string]string{"staged-plan.json": config.PlanPath}
	for index, key := range keys {
		paths[key] = config.Receipts[index].Path
		prefix.Receipts[index] = stageReceiptPrefixEntry{File: key, Digest: config.Receipts[index].Digest}
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedLifecycleObservationStageInput{}, errors.New("encode lifecycle observation receipt prefix")
	}
	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedLifecycleObservationStageInput{}, errors.New("read bounded lifecycle observation input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedLifecycleObservationStageInput{}, errors.New("lifecycle observation input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}
	if _, err := LoadLifecycleObservationStageBundle(config); err != nil {
		return VerifiedLifecycleObservationStageInput{}, errors.New("lifecycle observation inputs changed during materialization")
	}
	configMap := submissionStageInputConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name: configMapName, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "lifecycle-observation",
			},
			Annotations: map[string]string{
				"openkubes.io/input-format": LifecycleObservationStageInputFormat, "openkubes.io/receipt-prefix-digest": digest.SHA256(prefixRaw),
			},
		},
		Immutable: true, Data: data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedLifecycleObservationStageInput{}, errors.New("encode lifecycle observation input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedLifecycleObservationStageInput{}, errors.New("lifecycle observation input ConfigMap exceeds size limit")
	}
	dataKeys := make([]string, 0, len(data))
	for key := range data {
		dataKeys = append(dataKeys, key)
	}
	sort.Strings(dataKeys)
	receipt := LifecycleObservationStageInputReceipt{
		Format: LifecycleObservationStageInputFormat, State: "VERIFIED", StageID: "lifecycle-observation",
		ConfigMapName: configMapName, ConfigMapDigest: digest.SHA256(raw),
		ReceiptPrefixDigest: digest.SHA256(prefixRaw), DataKeys: dataKeys,
	}
	return VerifiedLifecycleObservationStageInput{raw: raw, receipt: receipt, verified: true}, nil
}

func (input VerifiedLifecycleObservationStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("lifecycle observation input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedLifecycleObservationStageInput) Receipt() (LifecycleObservationStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" {
		return LifecycleObservationStageInputReceipt{}, errors.New("lifecycle observation input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
