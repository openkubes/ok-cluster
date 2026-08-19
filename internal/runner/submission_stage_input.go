package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	SubmissionStageInputFormat       = "ok147-submission-stage-input/v1"
	submissionStageInputNamespace    = "openkubes-execution-system"
	maximumSubmissionStageInputBytes = 900 * 1024
	providerReceiptInputKey          = "provider-receipt.json"
)

var submissionStageInputNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

// SubmissionStageInputReceipt contains only redaction-safe identities for an
// immutable, credential-free Job input ConfigMap.
type SubmissionStageInputReceipt struct {
	Format              string   `json:"format"`
	State               string   `json:"state"`
	StageID             string   `json:"stageId"`
	ConfigMapName       string   `json:"configMapName"`
	ConfigMapDigest     string   `json:"configMapDigest"`
	ReceiptPrefixDigest string   `json:"receiptPrefixDigest"`
	DataKeys            []string `json:"dataKeys"`
}

// VerifiedSubmissionStageInput retains the exact ConfigMap bytes produced by
// verification. Callers receive copies and cannot alter the verified value.
type VerifiedSubmissionStageInput struct {
	raw      []byte
	receipt  SubmissionStageInputReceipt
	verified bool
}

type submissionStageInputConfigMap struct {
	APIVersion string                         `json:"apiVersion"`
	Kind       string                         `json:"kind"`
	Metadata   submissionStageInputObjectMeta `json:"metadata"`
	Immutable  bool                           `json:"immutable"`
	Data       map[string]string              `json:"data"`
}

type submissionStageInputObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// BuildSubmissionStageInput materializes only the public artifacts consumed
// by the bounded submission-stage Job. It performs no Kubernetes request and
// cannot package tokens, CA material, kubeconfigs or private keys.
func BuildSubmissionStageInput(config SubmissionStageBundleConfig, configMapName string) (VerifiedSubmissionStageInput, error) {
	if !submissionStageInputNamePattern.MatchString(configMapName) || len(configMapName) > 63 || !strings.HasPrefix(configMapName, "ok147-") {
		return VerifiedSubmissionStageInput{}, errors.New("submission stage input ConfigMap name is invalid")
	}
	bundle, err := LoadSubmissionStageBundle(config)
	if err != nil {
		return VerifiedSubmissionStageInput{}, err
	}

	root := config.ProjectionRoot
	if root == "" && config.ProjectionManifestPath != "" {
		root = filepath.Dir(config.ProjectionManifestPath)
	}
	paths := map[string]string{
		"staged-plan.json":            config.PlanPath,
		"stage-grant.json":            config.GrantPath,
		"stage-authority.pub":         config.GrantPublicKeyPath,
		"projection-manifest.json":    config.ProjectionManifestPath,
		"authority-map.json":          filepath.Join(root, "authority-map.json"),
		"ok-infra-prerequisites.yaml": filepath.Join(root, "ok-infra-prerequisites.yaml"),
		"ok-mgmt-lifecycle.yaml":      filepath.Join(root, "ok-mgmt-lifecycle.yaml"),
	}
	projectionBaseKeys := map[string]bool{
		"authority-map.json": true, "ok-infra-prerequisites.yaml": true, "ok-mgmt-lifecycle.yaml": true,
	}
	for _, artifact := range bundle.projectionBinding.Artifacts {
		if _, exists := paths[artifact.Name]; exists {
			if !projectionBaseKeys[artifact.Name] {
				return VerifiedSubmissionStageInput{}, errors.New("projection artifact collides with reserved stage input key")
			}
			continue
		}
		paths[artifact.Name] = filepath.Join(root, artifact.Name)
	}
	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat, Receipts: []stageReceiptPrefixEntry{}}
	switch config.ExpectedStageID {
	case "provider-prerequisites":
		if len(config.Receipts) != 0 {
			return VerifiedSubmissionStageInput{}, errors.New("provider stage input must use an empty receipt prefix")
		}
	case "cluster-lifecycle":
		if len(config.Receipts) != 1 {
			return VerifiedSubmissionStageInput{}, errors.New("cluster lifecycle input requires exactly one provider receipt")
		}
		paths[providerReceiptInputKey] = config.Receipts[0].Path
		prefix.Receipts = append(prefix.Receipts, stageReceiptPrefixEntry{File: providerReceiptInputKey, Digest: config.Receipts[0].Digest})
	default:
		return VerifiedSubmissionStageInput{}, errors.New("submission stage input supports only Contract-to-CAPI stages")
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return VerifiedSubmissionStageInput{}, errors.New("encode stage receipt prefix")
	}

	data := make(map[string]string, len(paths)+1)
	data["receipt-prefix.json"] = string(prefixRaw)
	for key, path := range paths {
		raw, err := readBoundedRegular(path, maximumSubmissionStageInputBytes)
		if err != nil {
			return VerifiedSubmissionStageInput{}, errors.New("read bounded submission stage input " + key)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return VerifiedSubmissionStageInput{}, errors.New("submission stage input is not valid ConfigMap text")
		}
		data[key] = string(raw)
	}

	// Reverify the artifact chain after capturing every source. The Job repeats
	// the same verification before credentials are opened, so any residual
	// source-file race can only stop execution, never authorize changed input.
	if _, err := LoadSubmissionStageBundle(config); err != nil {
		return VerifiedSubmissionStageInput{}, errors.New("submission stage inputs changed during materialization")
	}

	configMap := submissionStageInputConfigMap{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: submissionStageInputObjectMeta{
			Name:      configMapName,
			Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-contract-executor",
				"openkubes.io/stage-id":  config.ExpectedStageID,
			},
			Annotations: map[string]string{
				"openkubes.io/input-format":          SubmissionStageInputFormat,
				"openkubes.io/receipt-prefix-digest": digest.SHA256(prefixRaw),
			},
		},
		Immutable: true,
		Data:      data,
	}
	raw, err := json.Marshal(configMap)
	if err != nil {
		return VerifiedSubmissionStageInput{}, errors.New("encode submission stage input ConfigMap")
	}
	if len(raw) > maximumSubmissionStageInputBytes {
		return VerifiedSubmissionStageInput{}, errors.New("submission stage input ConfigMap exceeds size limit")
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	receipt := SubmissionStageInputReceipt{
		Format: SubmissionStageInputFormat, State: "VERIFIED", StageID: config.ExpectedStageID,
		ConfigMapName: configMapName, ConfigMapDigest: digest.SHA256(raw),
		ReceiptPrefixDigest: digest.SHA256(prefixRaw), DataKeys: keys,
	}
	return VerifiedSubmissionStageInput{raw: raw, receipt: receipt, verified: true}, nil
}

func (input VerifiedSubmissionStageInput) Bytes() ([]byte, error) {
	if !input.verified || len(input.raw) == 0 {
		return nil, errors.New("submission stage input was not produced by verification")
	}
	return append([]byte(nil), input.raw...), nil
}

func (input VerifiedSubmissionStageInput) Receipt() (SubmissionStageInputReceipt, error) {
	if !input.verified || input.receipt.State != "VERIFIED" {
		return SubmissionStageInputReceipt{}, errors.New("submission stage input was not produced by verification")
	}
	receipt := input.receipt
	receipt.DataKeys = append([]string(nil), input.receipt.DataKeys...)
	return receipt, nil
}
