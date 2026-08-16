package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const SubmissionStagePackageFormat = "ok147-submission-stage-package/v1"

// SubmissionStagePackageConfig contains only operator-selected runtime object,
// image, endpoint and credential-Secret identities. Stage, Contract,
// evaluation-time and receipt-prefix values are derived from Bundle.
type SubmissionStagePackageConfig struct {
	Bundle                    SubmissionStageBundleConfig
	JobTemplate               []byte
	JobTemplateDigest         string
	RunID                     string
	ImageDigest               string
	InputConfigMap            string
	LedgerAPIURL              string
	LedgerAPICIDR             string
	LedgerCredentialSecret    string
	AuthorityAPIURL           string
	AuthorityAPICIDR          string
	AuthorityCredentialSecret string
}

// SubmissionStagePackageReceipt is a redaction-safe proof of offline
// composition. MutationAllowed is always false: producing a package is not a
// Kubernetes apply or an execution authorization.
type SubmissionStagePackageReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	StageID              string   `json:"stageId"`
	PackageDigest        string   `json:"packageDigest"`
	InputConfigMapDigest string   `json:"inputConfigMapDigest"`
	ReceiptPrefixDigest  string   `json:"receiptPrefixDigest"`
	JobTemplateDigest    string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest    string   `json:"jobEnvelopeDigest"`
	ObjectKinds          []string `json:"objectKinds"`
	AuthorizationState   string   `json:"authorizationState"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

type VerifiedSubmissionStagePackage struct {
	raw                   []byte
	receipt               SubmissionStagePackageReceipt
	installationAuthority string
	verified              bool
}

// BuildSubmissionStagePackage composes one immutable input ConfigMap with one
// bounded Job/NetworkPolicy envelope. It does not create Kubernetes objects,
// read credentials or contact an API server.
func BuildSubmissionStagePackage(config SubmissionStagePackageConfig) (VerifiedSubmissionStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedSubmissionStagePackage{}, errors.New("submission stage Job template digest differs from expected identity")
	}
	if config.InputConfigMap == config.LedgerCredentialSecret || config.InputConfigMap == config.AuthorityCredentialSecret {
		return VerifiedSubmissionStagePackage{}, errors.New("submission stage input and credential object names must be distinct")
	}
	input, err := BuildSubmissionStageInput(config.Bundle, config.InputConfigMap)
	if err != nil {
		return VerifiedSubmissionStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedSubmissionStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedSubmissionStagePackage{}, err
	}
	jobRaw, err := RenderSubmissionStageJobTemplate(config.JobTemplate, SubmissionStageJobValues{
		RunID: config.RunID, StageID: config.Bundle.ExpectedStageID,
		ImageDigest: config.ImageDigest, EvaluationTime: config.Bundle.EvaluationTime.UTC().Format(time.RFC3339),
		Expected: config.Bundle.PlanExpected, InputConfigMap: config.InputConfigMap,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		LedgerAPIURL:        config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR,
		LedgerCredentialSecret: config.LedgerCredentialSecret,
		AuthorityAPIURL:        config.AuthorityAPIURL, AuthorityAPICIDR: config.AuthorityAPICIDR,
		AuthorityCredentialSecret: config.AuthorityCredentialSecret,
	})
	if err != nil {
		return VerifiedSubmissionStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := SubmissionStagePackageReceipt{
		Format: SubmissionStagePackageFormat, State: "VERIFIED", StageID: config.Bundle.ExpectedStageID,
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, JobTemplateDigest: config.JobTemplateDigest,
		JobEnvelopeDigest:  digest.SHA256(jobRaw),
		ObjectKinds:        []string{"ConfigMap", "NetworkPolicy", "Job"},
		AuthorizationState: "VERIFIED", MutationAllowed: false,
	}
	return VerifiedSubmissionStagePackage{
		raw: packageRaw, receipt: receipt,
		installationAuthority: config.Bundle.PlanExpected.ManagementAuthority,
		verified:              true,
	}, nil
}

func (packaged VerifiedSubmissionStagePackage) Bytes() ([]byte, error) {
	if !packaged.verified || len(packaged.raw) == 0 {
		return nil, errors.New("submission stage package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedSubmissionStagePackage) Receipt() (SubmissionStagePackageReceipt, error) {
	if !packaged.verified || packaged.receipt.State != "VERIFIED" {
		return SubmissionStagePackageReceipt{}, errors.New("submission stage package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}
