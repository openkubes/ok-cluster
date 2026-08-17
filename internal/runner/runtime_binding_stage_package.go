package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingStagePackageFormat = "ok147-runtime-binding-stage-package/v1"

type RuntimeBindingStagePackageConfig struct {
	Bundle                        StageResumeConfig
	InputConfigMap                string
	JobTemplate                   []byte
	JobTemplateDigest             string
	RunID                         string
	ImageDigest                   string
	LedgerAPIURL                  string
	LedgerAPICIDR                 string
	LedgerCredentialSecret        string
	PersistenceCredentialSecret   string
	WorkloadAPIURL                string
	WorkloadAPICIDR               string
	WorkloadCredentialSecret      string
	WorkloadBindingPath           string
	ExpectedWorkloadBindingDigest string
}

type RuntimeBindingStagePackageReceipt struct {
	Format                string   `json:"format"`
	State                 string   `json:"state"`
	StageID               string   `json:"stageId"`
	PackageDigest         string   `json:"packageDigest"`
	InputConfigMapDigest  string   `json:"inputConfigMapDigest"`
	ReceiptPrefixDigest   string   `json:"receiptPrefixDigest"`
	WorkloadBindingDigest string   `json:"workloadBindingDigest"`
	JobTemplateDigest     string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest     string   `json:"jobEnvelopeDigest"`
	ObjectKinds           []string `json:"objectKinds"`
	AuthorizationState    string   `json:"authorizationState"`
	MutationAllowed       bool     `json:"mutationAllowed"`
}

type VerifiedRuntimeBindingStagePackage struct {
	raw                   []byte
	receipt               RuntimeBindingStagePackageReceipt
	ledgerCredential      string
	persistenceCredential string
	workloadCredential    string
	managementAuthority   string
	workloadAuthority     string
	verified              bool
}

// BuildRuntimeBindingStagePackage correlates the public ConfigMap, private
// workload binding and hardened Job envelope entirely offline.
func BuildRuntimeBindingStagePackage(config RuntimeBindingStagePackageConfig) (VerifiedRuntimeBindingStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedRuntimeBindingStagePackage{}, errors.New("runtime binding Job template digest differs from expected identity")
	}
	input, err := BuildRuntimeBindingStageInput(config.Bundle, config.InputConfigMap)
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, err
	}
	bundle, err := LoadRuntimeBindingStageBundle(config.Bundle)
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, err
	}
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, errors.New("read runtime binding package target correlation")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, config.ExpectedWorkloadBindingDigest)
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, errors.New("verify private runtime binding package authority")
	}
	if binding.IntentRevision != bundle.plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest || binding.Endpoint != config.WorkloadAPIURL {
		return VerifiedRuntimeBindingStagePackage{}, errors.New("private workload binding differs from runtime binding package target")
	}
	jobRaw, err := RenderRuntimeBindingStageJobTemplate(config.JobTemplate, RuntimeBindingStageJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest, Expected: config.Bundle.PlanExpected,
		InputConfigMap: config.InputConfigMap, ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		LedgerAPIURL: config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR, LedgerCredentialSecret: config.LedgerCredentialSecret,
		PersistenceCredentialSecret: config.PersistenceCredentialSecret,
		WorkloadAPIURL:              config.WorkloadAPIURL, WorkloadAPICIDR: config.WorkloadAPICIDR,
		WorkloadCredentialSecret: config.WorkloadCredentialSecret, WorkloadBindingDigest: config.ExpectedWorkloadBindingDigest,
	})
	if err != nil {
		return VerifiedRuntimeBindingStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := RuntimeBindingStagePackageReceipt{
		Format: RuntimeBindingStagePackageFormat, State: "VERIFIED", StageID: "runtime-binding",
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, WorkloadBindingDigest: config.ExpectedWorkloadBindingDigest,
		JobTemplateDigest: config.JobTemplateDigest, JobEnvelopeDigest: digest.SHA256(jobRaw),
		ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"}, AuthorizationState: "NOT_REQUIRED", MutationAllowed: false,
	}
	return VerifiedRuntimeBindingStagePackage{
		raw: packageRaw, receipt: receipt, ledgerCredential: config.LedgerCredentialSecret,
		persistenceCredential: config.PersistenceCredentialSecret, workloadCredential: config.WorkloadCredentialSecret,
		managementAuthority: bundle.plan.Authorities.Management, workloadAuthority: digest.SHA256([]byte(binding.TargetClusterUID)), verified: true,
	}, nil
}

func (packaged VerifiedRuntimeBindingStagePackage) Bytes() ([]byte, error) {
	if !packaged.verified || len(packaged.raw) == 0 {
		return nil, errors.New("runtime binding package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedRuntimeBindingStagePackage) Receipt() (RuntimeBindingStagePackageReceipt, error) {
	if !packaged.verified || packaged.receipt.State != "VERIFIED" || digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest || packaged.ledgerCredential == "" || packaged.persistenceCredential == "" || packaged.workloadCredential == "" || packaged.ledgerCredential == packaged.persistenceCredential || packaged.ledgerCredential == packaged.workloadCredential || packaged.persistenceCredential == packaged.workloadCredential || packaged.managementAuthority == "" || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) {
		return RuntimeBindingStagePackageReceipt{}, errors.New("runtime binding package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}
