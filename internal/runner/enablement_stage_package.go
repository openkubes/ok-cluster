package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const EnablementStagePackageFormat = "ok147-enablement-stage-package/v1"

// EnablementStagePackageConfig contains only public package identities and the
// names of separately materialized credential Secrets.
type EnablementStagePackageConfig struct {
	Bundle                     EnablementStageBundleConfig
	JobTemplate                []byte
	JobTemplateDigest          string
	RunID                      string
	ImageDigest                string
	InputConfigMap             string
	HelmChartProxyName         string
	LedgerAPIURL               string
	LedgerAPICIDR              string
	LedgerCredentialSecret     string
	ManagementAPIURL           string
	ManagementAPICIDR          string
	ManagementCredentialSecret string
}

// EnablementStagePackageReceipt is redaction-safe offline composition proof.
type EnablementStagePackageReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	StageID              string   `json:"stageId"`
	PackageDigest        string   `json:"packageDigest"`
	InputConfigMapDigest string   `json:"inputConfigMapDigest"`
	ReceiptPrefixDigest  string   `json:"receiptPrefixDigest"`
	EnablementDigest     string   `json:"enablementDigest"`
	JobTemplateDigest    string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest    string   `json:"jobEnvelopeDigest"`
	ObjectKinds          []string `json:"objectKinds"`
	AuthorizationState   string   `json:"authorizationState"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

type VerifiedEnablementStagePackage struct {
	raw      []byte
	receipt  EnablementStagePackageReceipt
	verified bool
}

// BuildEnablementStagePackage composes an immutable input ConfigMap with one
// bounded NetworkPolicy/Job envelope. It performs no API request.
func BuildEnablementStagePackage(config EnablementStagePackageConfig) (VerifiedEnablementStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedEnablementStagePackage{}, errors.New("enablement stage Job template digest differs from expected identity")
	}
	if config.InputConfigMap == config.LedgerCredentialSecret || config.InputConfigMap == config.ManagementCredentialSecret {
		return VerifiedEnablementStagePackage{}, errors.New("enablement stage input and credential object names must be distinct")
	}
	input, err := BuildEnablementStageInput(config.Bundle, config.InputConfigMap)
	if err != nil {
		return VerifiedEnablementStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedEnablementStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedEnablementStagePackage{}, err
	}
	jobRaw, err := RenderEnablementStageJobTemplate(config.JobTemplate, EnablementStageJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest,
		EvaluationTime: config.Bundle.EvaluationTime.UTC().Format(time.RFC3339), Expected: config.Bundle.PlanExpected,
		InputConfigMap: config.InputConfigMap, ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		HelmChartProxyName: config.HelmChartProxyName,
		LedgerAPIURL:       config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR, LedgerCredentialSecret: config.LedgerCredentialSecret,
		ManagementAPIURL: config.ManagementAPIURL, ManagementAPICIDR: config.ManagementAPICIDR, ManagementCredentialSecret: config.ManagementCredentialSecret,
	})
	if err != nil {
		return VerifiedEnablementStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := EnablementStagePackageReceipt{
		Format: EnablementStagePackageFormat, State: "VERIFIED", StageID: "enablement",
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, EnablementDigest: inputReceipt.EnablementDigest,
		JobTemplateDigest: config.JobTemplateDigest, JobEnvelopeDigest: digest.SHA256(jobRaw),
		ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"}, AuthorizationState: "VERIFIED", MutationAllowed: false,
	}
	return VerifiedEnablementStagePackage{raw: packageRaw, receipt: receipt, verified: true}, nil
}

func (packaged VerifiedEnablementStagePackage) Bytes() ([]byte, error) {
	if !packaged.verified || len(packaged.raw) == 0 {
		return nil, errors.New("enablement stage package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedEnablementStagePackage) Receipt() (EnablementStagePackageReceipt, error) {
	if !packaged.verified || packaged.receipt.State != "VERIFIED" {
		return EnablementStagePackageReceipt{}, errors.New("enablement stage package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}
