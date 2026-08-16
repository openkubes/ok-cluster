package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const SubmissionStageRuntimePrerequisiteFormat = "ok147-submission-stage-runtime-prerequisite/v1"

type SubmissionStageRuntimePrerequisiteReceipt struct {
	Format             string `json:"format"`
	State              string `json:"state"`
	StagePackageDigest string `json:"stagePackageDigest"`
	ManifestDigest     string `json:"manifestDigest"`
	ObjectDigest       string `json:"objectDigest"`
	Authority          string `json:"authority"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	MutationAllowed    bool   `json:"mutationAllowed"`
}

type VerifiedSubmissionStageRuntimePrerequisite struct {
	raw      []byte
	receipt  SubmissionStageRuntimePrerequisiteReceipt
	verified bool
}

// BuildSubmissionStageRuntimePrerequisite binds the exact shared tokenless
// ServiceAccount manifest to one verified stage package. It performs no API
// request and retains only canonical JSON for the later exact installer.
func BuildSubmissionStageRuntimePrerequisite(packaged VerifiedSubmissionStagePackage, manifest []byte, expectedDigest string) (VerifiedSubmissionStageRuntimePrerequisite, error) {
	plan, err := PlanSubmissionStageInstallation(packaged)
	if err != nil {
		return VerifiedSubmissionStageRuntimePrerequisite{}, err
	}
	if len(manifest) == 0 || !stageReceiptPrefixDigestPattern.MatchString(expectedDigest) || digest.SHA256(manifest) != expectedDigest {
		return VerifiedSubmissionStageRuntimePrerequisite{}, errors.New("submission stage runtime manifest differs from expected identity")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(manifest))
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || len(object) == 0 {
		return VerifiedSubmissionStageRuntimePrerequisite{}, errors.New("decode submission stage runtime manifest")
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return VerifiedSubmissionStageRuntimePrerequisite{}, errors.New("submission stage runtime manifest contains multiple objects")
	}
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	if object["apiVersion"] != "v1" || object["kind"] != "ServiceAccount" || object["automountServiceAccountToken"] != false || metadata["name"] != "ok147-contract-executor-runtime" || metadata["namespace"] != submissionStageInputNamespace || labels["app.kubernetes.io/name"] != "ok-cluster-contract-executor" || labels["openkubes.io/runtime-boundary"] != "submission-stage" {
		return VerifiedSubmissionStageRuntimePrerequisite{}, errors.New("submission stage runtime ServiceAccount semantics are invalid")
	}
	if len(object) != 4 || len(metadata) != 3 || len(labels) != 2 {
		return VerifiedSubmissionStageRuntimePrerequisite{}, errors.New("submission stage runtime ServiceAccount contains unbound fields")
	}
	raw, err := json.Marshal(object)
	if err != nil {
		return VerifiedSubmissionStageRuntimePrerequisite{}, errors.New("encode submission stage runtime ServiceAccount")
	}
	receipt := SubmissionStageRuntimePrerequisiteReceipt{
		Format: SubmissionStageRuntimePrerequisiteFormat, State: "VERIFIED", StagePackageDigest: plan.PackageDigest,
		ManifestDigest: expectedDigest, ObjectDigest: digest.SHA256(raw), Authority: packaged.installationAuthority,
		Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", MutationAllowed: false,
	}
	return VerifiedSubmissionStageRuntimePrerequisite{raw: raw, receipt: receipt, verified: true}, nil
}

func (runtime VerifiedSubmissionStageRuntimePrerequisite) Receipt() (SubmissionStageRuntimePrerequisiteReceipt, error) {
	if !runtime.verified || runtime.receipt.State != "VERIFIED" || len(runtime.raw) == 0 {
		return SubmissionStageRuntimePrerequisiteReceipt{}, errors.New("submission stage runtime prerequisite was not produced by verification")
	}
	return runtime.receipt, nil
}
