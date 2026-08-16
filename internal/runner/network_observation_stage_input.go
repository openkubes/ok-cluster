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

const NetworkObservationStageInputFormat = "ok147-network-observation-stage-input/v1"

type NetworkObservationStageInputConfig struct {
	Bundle                       StageResumeConfig
	NetworkProfilePath           string
	ExpectedNetworkProfileDigest string
	ConfigMapName                string
}

type NetworkObservationStageInputReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	StageID              string   `json:"stageId"`
	ConfigMapName        string   `json:"configMapName"`
	ConfigMapDigest      string   `json:"configMapDigest"`
	ReceiptPrefixDigest  string   `json:"receiptPrefixDigest"`
	NetworkProfileDigest string   `json:"networkProfileDigest"`
	DataKeys             []string `json:"dataKeys"`
}

type VerifiedNetworkObservationStageInput struct {
	raw      []byte
	receipt  NetworkObservationStageInputReceipt
	verified bool
}

// BuildNetworkObservationStageInput packages only public immutable semantic
// inputs. The private workload binding, endpoint, credentials and CA material
// are deliberately excluded.
func BuildNetworkObservationStageInput(config NetworkObservationStageInputConfig) (VerifiedNetworkObservationStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(config.ConfigMapName) || len(config.ConfigMapName) > 63 || !strings.HasPrefix(config.ConfigMapName, "ok147-") {
		return VerifiedNetworkObservationStageInput{}, errors.New("network observation input ConfigMap name is invalid")
	}
	bundle, err := LoadNetworkObservationStageBundle(config.Bundle)
	if err != nil {
		return VerifiedNetworkObservationStageInput{}, err
	}
	if len(config.Bundle.Receipts) != 4 {
		return VerifiedNetworkObservationStageInput{}, errors.New("network observation input requires the exact four-receipt prefix")
	}
	profile, err := LoadNetworkProfileFile(NetworkProfileFileConfig{
		Path: config.NetworkProfilePath, ExpectedProfileDigest: config.ExpectedNetworkProfileDigest,
		ExpectedIntentRevision: bundle.plan.IntentRevision, ExpectedEnablementRevision: bundle.plan.EnablementRevision,
	})
	if err != nil {
		return VerifiedNetworkObservationStageInput{}, errors.New("load public network observation profile")
	}
	keys := []string{"provider-receipt.json", "lifecycle-receipt.json", "lifecycle-observation-receipt.json", "enablement-receipt.json"}
	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: make([]stageReceiptPrefixEntry, len(keys))}
	paths := map[string]string{"staged-plan.json": config.Bundle.PlanPath, "network-profile.json": config.NetworkProfilePath}
	for index, key := range keys {
		paths[key] = config.Bundle.Receipts[index].Path
		prefix.Receipts[index] = stageReceiptPrefixEntry{File: key, Digest: config.Bundle.Receipts[index].Digest}
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedNetworkObservationStageInput{}, errors.New("encode network observation receipt prefix")
	}
	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedNetworkObservationStageInput{}, errors.New("read bounded network observation input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedNetworkObservationStageInput{}, errors.New("network observation input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}
	if _, err := LoadNetworkObservationStageBundle(config.Bundle); err != nil {
		return VerifiedNetworkObservationStageInput{}, errors.New("network observation receipts changed during materialization")
	}
	if _, err := LoadNetworkProfileFile(NetworkProfileFileConfig{
		Path: config.NetworkProfilePath, ExpectedProfileDigest: profile.Digest,
		ExpectedIntentRevision: bundle.plan.IntentRevision, ExpectedEnablementRevision: bundle.plan.EnablementRevision,
	}); err != nil {
		return VerifiedNetworkObservationStageInput{}, errors.New("network observation profile changed during materialization")
	}
	configMap := submissionStageInputConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name: config.ConfigMapName, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "network-observation",
			},
			Annotations: map[string]string{
				"openkubes.io/input-format":           NetworkObservationStageInputFormat,
				"openkubes.io/receipt-prefix-digest":  digest.SHA256(prefixRaw),
				"openkubes.io/network-profile-digest": profile.Digest,
			},
		},
		Immutable: true, Data: data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedNetworkObservationStageInput{}, errors.New("encode network observation input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedNetworkObservationStageInput{}, errors.New("network observation input ConfigMap exceeds size limit")
	}
	dataKeys := make([]string, 0, len(data))
	for key := range data {
		dataKeys = append(dataKeys, key)
	}
	sort.Strings(dataKeys)
	return VerifiedNetworkObservationStageInput{
		raw: raw,
		receipt: NetworkObservationStageInputReceipt{
			Format: NetworkObservationStageInputFormat, State: "VERIFIED", StageID: "network-observation",
			ConfigMapName: config.ConfigMapName, ConfigMapDigest: digest.SHA256(raw),
			ReceiptPrefixDigest: digest.SHA256(prefixRaw), NetworkProfileDigest: profile.Digest, DataKeys: dataKeys,
		},
		verified: true,
	}, nil
}

func (input VerifiedNetworkObservationStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("network observation input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedNetworkObservationStageInput) Receipt() (NetworkObservationStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" || digest.SHA256(input.raw) != input.receipt.ConfigMapDigest {
		return NetworkObservationStageInputReceipt{}, errors.New("network observation input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
