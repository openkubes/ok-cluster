package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const TargetAccessStageInputFormat = "ok147-target-access-stage-input/v1"

// TargetAccessStageInputReceipt exposes only immutable public artifact and
// target-digest identities. The ConfigMap contains no runtime binding or token.
type TargetAccessStageInputReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	StageID              string   `json:"stageId"`
	ConfigMapName        string   `json:"configMapName"`
	ConfigMapDigest      string   `json:"configMapDigest"`
	ReceiptPrefixDigest  string   `json:"receiptPrefixDigest"`
	TargetAccessDigest   string   `json:"targetAccessDigest"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	DataKeys             []string `json:"dataKeys"`
}

type VerifiedTargetAccessStageInput struct {
	raw      []byte
	receipt  TargetAccessStageInputReceipt
	verified bool
}

// BuildTargetAccessStageInput snapshots the verified seventh-stage public
// chain into one immutable ConfigMap without reading credentials or runtime
// binding material and without contacting an API.
func BuildTargetAccessStageInput(config TargetAccessStageBundleConfig, configMapName string) (VerifiedTargetAccessStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(configMapName) || len(configMapName) > 63 || len(configMapName) < len("ok147-") || configMapName[:len("ok147-")] != "ok147-" {
		return VerifiedTargetAccessStageInput{}, errors.New("target-access stage input ConfigMap name is invalid")
	}
	if len(config.Receipts) != 6 {
		return VerifiedTargetAccessStageInput{}, errors.New("target-access stage input requires exactly six predecessor receipts")
	}
	bundle, err := LoadTargetAccessStageBundle(config)
	if err != nil {
		return VerifiedTargetAccessStageInput{}, err
	}
	bundleReceipt, err := bundle.Receipt()
	if err != nil {
		return VerifiedTargetAccessStageInput{}, err
	}

	receiptFiles := []string{
		"provider-receipt.json", "lifecycle-receipt.json", "lifecycle-observation-receipt.json",
		"enablement-receipt.json", "network-observation-receipt.json", "runtime-binding-receipt.json",
	}
	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: make([]stageReceiptPrefixEntry, len(receiptFiles))}
	paths := map[string]string{
		"staged-plan.json": config.PlanPath, "stage-grant.json": config.GrantPath,
		"stage-authority.pub": config.GrantPublicKeyPath, "target-access.yaml": config.ArtifactPath,
	}
	for index, file := range receiptFiles {
		prefix.Receipts[index] = stageReceiptPrefixEntry{File: file, Digest: config.Receipts[index].Digest}
		paths[file] = config.Receipts[index].Path
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedTargetAccessStageInput{}, errors.New("encode target-access receipt prefix")
	}
	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedTargetAccessStageInput{}, errors.New("read bounded target-access stage input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedTargetAccessStageInput{}, errors.New("target-access stage input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}
	if _, err := LoadTargetAccessStageBundle(config); err != nil {
		return VerifiedTargetAccessStageInput{}, errors.New("target-access stage inputs changed during materialization")
	}

	configMap := submissionStageInputConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name: configMapName, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "target-access"},
			Annotations: map[string]string{
				"openkubes.io/input-format": TargetAccessStageInputFormat, "openkubes.io/receipt-prefix-digest": digest.SHA256(prefixRaw),
				"openkubes.io/target-identity-digest": bundleReceipt.TargetIdentityDigest,
			},
		},
		Immutable: true, Data: data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedTargetAccessStageInput{}, errors.New("encode target-access stage input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedTargetAccessStageInput{}, errors.New("target-access stage input ConfigMap exceeds size limit")
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return VerifiedTargetAccessStageInput{
		raw: raw,
		receipt: TargetAccessStageInputReceipt{
			Format: TargetAccessStageInputFormat, State: "VERIFIED", StageID: "target-access", ConfigMapName: configMapName,
			ConfigMapDigest: digest.SHA256(raw), ReceiptPrefixDigest: digest.SHA256(prefixRaw),
			TargetAccessDigest: digest.SHA256([]byte(data["target-access.yaml"])), TargetIdentityDigest: bundleReceipt.TargetIdentityDigest, DataKeys: keys,
		},
		verified: true,
	}, nil
}

func (input VerifiedTargetAccessStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("target-access stage input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedTargetAccessStageInput) Receipt() (TargetAccessStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" || !stageReceiptPrefixDigestPattern.MatchString(input.receipt.TargetIdentityDigest) {
		return TargetAccessStageInputReceipt{}, errors.New("target-access stage input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
