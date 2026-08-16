package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const LifecycleObservationStagePackageFormat = "ok147-lifecycle-observation-stage-package/v1"

type LifecycleObservationStagePackageConfig struct {
	Bundle                     StageResumeConfig
	JobTemplate                []byte
	JobTemplateDigest          string
	RunID                      string
	ImageDigest                string
	InputConfigMap             string
	LedgerAPIURL               string
	LedgerAPICIDR              string
	LedgerCredentialSecret     string
	ManagementAPIURL           string
	ManagementAPICIDR          string
	ManagementCredentialSecret string
	PollInterval               time.Duration
	PollTimeout                time.Duration
}

type LifecycleObservationStagePackageReceipt struct {
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

type VerifiedLifecycleObservationStagePackage struct {
	raw      []byte
	receipt  LifecycleObservationStagePackageReceipt
	verified bool
}

// BuildLifecycleObservationStagePackage composes one immutable public input
// ConfigMap and one bounded NetworkPolicy/Job envelope entirely offline.
func BuildLifecycleObservationStagePackage(config LifecycleObservationStagePackageConfig) (VerifiedLifecycleObservationStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedLifecycleObservationStagePackage{}, errors.New("lifecycle observation Job template digest differs from expected identity")
	}
	if config.InputConfigMap == config.LedgerCredentialSecret || config.InputConfigMap == config.ManagementCredentialSecret {
		return VerifiedLifecycleObservationStagePackage{}, errors.New("lifecycle observation input and credential object names must be distinct")
	}
	input, err := BuildLifecycleObservationStageInput(config.Bundle, config.InputConfigMap)
	if err != nil {
		return VerifiedLifecycleObservationStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedLifecycleObservationStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedLifecycleObservationStagePackage{}, err
	}
	jobRaw, err := RenderLifecycleObservationStageJobTemplate(config.JobTemplate, LifecycleObservationStageJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest, Expected: config.Bundle.PlanExpected,
		InputConfigMap: config.InputConfigMap, ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		LedgerAPIURL: config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR, LedgerCredentialSecret: config.LedgerCredentialSecret,
		ManagementAPIURL: config.ManagementAPIURL, ManagementAPICIDR: config.ManagementAPICIDR, ManagementCredentialSecret: config.ManagementCredentialSecret,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout,
	})
	if err != nil {
		return VerifiedLifecycleObservationStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := LifecycleObservationStagePackageReceipt{
		Format: LifecycleObservationStagePackageFormat, State: "VERIFIED", StageID: "lifecycle-observation",
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, JobTemplateDigest: config.JobTemplateDigest,
		JobEnvelopeDigest: digest.SHA256(jobRaw), ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"},
		AuthorizationState: "NOT_REQUIRED", MutationAllowed: false,
	}
	return VerifiedLifecycleObservationStagePackage{raw: packageRaw, receipt: receipt, verified: true}, nil
}

func (packaged VerifiedLifecycleObservationStagePackage) Bytes() ([]byte, error) {
	if !packaged.verified || len(packaged.raw) == 0 {
		return nil, errors.New("lifecycle observation package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedLifecycleObservationStagePackage) Receipt() (LifecycleObservationStagePackageReceipt, error) {
	if !packaged.verified || packaged.receipt.State != "VERIFIED" {
		return LifecycleObservationStagePackageReceipt{}, errors.New("lifecycle observation package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}
