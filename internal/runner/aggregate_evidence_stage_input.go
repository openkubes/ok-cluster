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

const AggregateEvidenceStageInputFormat = "ok147-aggregate-evidence-stage-input/v1"

type AggregateEvidenceStageInputConfig struct {
	Bundle                         StageResumeConfig
	AggregateEvidenceProfilePath   string
	ExpectedAggregateProfileDigest string
	ConfigMapName                  string
}

type AggregateEvidenceStageInputReceipt struct {
	Format                 string   `json:"format"`
	State                  string   `json:"state"`
	StageID                string   `json:"stageId"`
	ConfigMapName          string   `json:"configMapName"`
	ConfigMapDigest        string   `json:"configMapDigest"`
	ReceiptPrefixDigest    string   `json:"receiptPrefixDigest"`
	AggregateProfileDigest string   `json:"aggregateProfileDigest"`
	DataKeys               []string `json:"dataKeys"`
}

type VerifiedAggregateEvidenceStageInput struct {
	raw      []byte
	receipt  AggregateEvidenceStageInputReceipt
	verified bool
}

var aggregateEvidenceReceiptFiles = []string{
	"provider-receipt.json",
	"lifecycle-receipt.json",
	"lifecycle-observation-receipt.json",
	"enablement-receipt.json",
	"network-observation-receipt.json",
	"runtime-binding-receipt.json",
	"target-access-receipt.json",
	"target-credential-receipt.json",
	"target-registration-receipt.json",
	"platform-applications-receipt.json",
	"platform-observation-receipt.json",
}

// BuildAggregateEvidenceStageInput snapshots the exact public Stage-12 input.
// Private runtime identity, credentials, endpoints, CA material and capability
// evidence remain outside this immutable ConfigMap.
func BuildAggregateEvidenceStageInput(config AggregateEvidenceStageInputConfig) (VerifiedAggregateEvidenceStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(config.ConfigMapName) || len(config.ConfigMapName) > 63 || !strings.HasPrefix(config.ConfigMapName, "ok147-") {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("aggregate evidence input ConfigMap name is invalid")
	}
	if len(config.Bundle.Receipts) != len(aggregateEvidenceReceiptFiles) {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("aggregate evidence input requires the exact eleven-receipt prefix")
	}
	plan, _, _, err := loadStageResumeWithPrefix(config.Bundle)
	if err != nil {
		return VerifiedAggregateEvidenceStageInput{}, err
	}
	profile, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: config.AggregateEvidenceProfilePath, ExpectedProfileDigest: config.ExpectedAggregateProfileDigest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
		ExpectedPlatformRevision: plan.PlatformRevision, ExpectedExecutionFixture: plan.ExecutionFixture,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("load public aggregate evidence profile")
	}
	if _, err := LoadAggregateEvidenceStageBundle(AggregateEvidenceStageBundleConfig{
		StageResumeConfig: config.Bundle, Profile: profile.Profile, ExpectedProfileDigest: profile.Digest,
	}); err != nil {
		return VerifiedAggregateEvidenceStageInput{}, err
	}

	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: make([]stageReceiptPrefixEntry, len(aggregateEvidenceReceiptFiles))}
	paths := map[string]string{
		"staged-plan.json":                config.Bundle.PlanPath,
		"aggregate-evidence-profile.json": config.AggregateEvidenceProfilePath,
	}
	for index, file := range aggregateEvidenceReceiptFiles {
		prefix.Receipts[index] = stageReceiptPrefixEntry{File: file, Digest: config.Bundle.Receipts[index].Digest}
		paths[file] = config.Bundle.Receipts[index].Path
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("encode aggregate evidence receipt prefix")
	}
	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedAggregateEvidenceStageInput{}, errors.New("read bounded aggregate evidence input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedAggregateEvidenceStageInput{}, errors.New("aggregate evidence input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}
	if _, err := LoadAggregateEvidenceStageBundle(AggregateEvidenceStageBundleConfig{
		StageResumeConfig: config.Bundle, Profile: profile.Profile, ExpectedProfileDigest: profile.Digest,
	}); err != nil {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("aggregate evidence receipts changed during materialization")
	}
	if _, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: config.AggregateEvidenceProfilePath, ExpectedProfileDigest: profile.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
		ExpectedPlatformRevision: plan.PlatformRevision, ExpectedExecutionFixture: plan.ExecutionFixture,
	}); err != nil {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("aggregate evidence profile changed during materialization")
	}

	configMap := submissionStageInputConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name: config.ConfigMapName, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "aggregate-evidence",
			},
			Annotations: map[string]string{
				"openkubes.io/input-format":             AggregateEvidenceStageInputFormat,
				"openkubes.io/receipt-prefix-digest":    digest.SHA256(prefixRaw),
				"openkubes.io/aggregate-profile-digest": profile.Digest,
			},
		},
		Immutable: true, Data: data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("encode aggregate evidence input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedAggregateEvidenceStageInput{}, errors.New("aggregate evidence input ConfigMap exceeds size limit")
	}
	dataKeys := make([]string, 0, len(data))
	for key := range data {
		dataKeys = append(dataKeys, key)
	}
	sort.Strings(dataKeys)
	return VerifiedAggregateEvidenceStageInput{
		raw: raw,
		receipt: AggregateEvidenceStageInputReceipt{
			Format: AggregateEvidenceStageInputFormat, State: "VERIFIED", StageID: "aggregate-evidence",
			ConfigMapName: config.ConfigMapName, ConfigMapDigest: digest.SHA256(raw),
			ReceiptPrefixDigest: digest.SHA256(prefixRaw), AggregateProfileDigest: profile.Digest, DataKeys: dataKeys,
		},
		verified: true,
	}, nil
}

func (input VerifiedAggregateEvidenceStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("aggregate evidence input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedAggregateEvidenceStageInput) Receipt() (AggregateEvidenceStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" || digest.SHA256(input.raw) != input.receipt.ConfigMapDigest {
		return AggregateEvidenceStageInputReceipt{}, errors.New("aggregate evidence input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
