package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const NetworkObservationStagePackageFormat = "ok147-network-observation-stage-package/v1"

type NetworkObservationStagePackageConfig struct {
	Input                         NetworkObservationStageInputConfig
	JobTemplate                   []byte
	JobTemplateDigest             string
	RunID                         string
	ImageDigest                   string
	LedgerAPIURL                  string
	LedgerAPICIDR                 string
	LedgerCredentialSecret        string
	ManagementAPIURL              string
	ManagementAPICIDR             string
	ManagementCredentialSecret    string
	WorkloadAPIURL                string
	WorkloadAPICIDR               string
	WorkloadCredentialSecret      string
	WorkloadBindingPath           string
	ExpectedWorkloadBindingDigest string
	PollInterval                  time.Duration
	PollTimeout                   time.Duration
}

type NetworkObservationStagePackageReceipt struct {
	Format                string   `json:"format"`
	State                 string   `json:"state"`
	StageID               string   `json:"stageId"`
	PackageDigest         string   `json:"packageDigest"`
	InputConfigMapDigest  string   `json:"inputConfigMapDigest"`
	ReceiptPrefixDigest   string   `json:"receiptPrefixDigest"`
	NetworkProfileDigest  string   `json:"networkProfileDigest"`
	WorkloadBindingDigest string   `json:"workloadBindingDigest"`
	JobTemplateDigest     string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest     string   `json:"jobEnvelopeDigest"`
	ObjectKinds           []string `json:"objectKinds"`
	AuthorizationState    string   `json:"authorizationState"`
	MutationAllowed       bool     `json:"mutationAllowed"`
}

type VerifiedNetworkObservationStagePackage struct {
	raw                  []byte
	receipt              NetworkObservationStagePackageReceipt
	ledgerCredential     string
	managementCredential string
	workloadCredential   string
	managementAuthority  string
	workloadAuthority    string
	intentRevision       string
	workloadEndpoint     string
	workloadCABundle     string
	verified             bool
}

// BuildNetworkObservationStagePackage verifies the public input, the private
// binding identity, and the two-endpoint Job envelope entirely offline. The
// private binding bytes are never copied into package output.
func BuildNetworkObservationStagePackage(config NetworkObservationStagePackageConfig) (VerifiedNetworkObservationStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedNetworkObservationStagePackage{}, errors.New("network observation Job template digest differs from expected identity")
	}
	input, err := BuildNetworkObservationStageInput(config.Input)
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, err
	}
	bundle, err := LoadNetworkObservationStageBundle(config.Input.Bundle)
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, err
	}
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, errors.New("read package target correlation")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, config.ExpectedWorkloadBindingDigest)
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, errors.New("verify private package workload binding")
	}
	if binding.IntentRevision != bundle.plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest || binding.Endpoint != config.WorkloadAPIURL {
		return VerifiedNetworkObservationStagePackage{}, errors.New("private workload binding differs from package target")
	}
	jobRaw, err := RenderNetworkObservationStageJobTemplate(config.JobTemplate, NetworkObservationStageJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest, Expected: config.Input.Bundle.PlanExpected,
		InputConfigMap: config.Input.ConfigMapName, ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		NetworkProfileDigest: inputReceipt.NetworkProfileDigest,
		LedgerAPIURL:         config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR, LedgerCredentialSecret: config.LedgerCredentialSecret,
		ManagementAPIURL: config.ManagementAPIURL, ManagementAPICIDR: config.ManagementAPICIDR, ManagementCredentialSecret: config.ManagementCredentialSecret,
		WorkloadAPIURL: config.WorkloadAPIURL, WorkloadAPICIDR: config.WorkloadAPICIDR,
		WorkloadCredentialSecret: config.WorkloadCredentialSecret, WorkloadBindingDigest: config.ExpectedWorkloadBindingDigest,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout,
	})
	if err != nil {
		return VerifiedNetworkObservationStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := NetworkObservationStagePackageReceipt{
		Format: NetworkObservationStagePackageFormat, State: "VERIFIED", StageID: "network-observation",
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, NetworkProfileDigest: inputReceipt.NetworkProfileDigest,
		WorkloadBindingDigest: config.ExpectedWorkloadBindingDigest, JobTemplateDigest: config.JobTemplateDigest,
		JobEnvelopeDigest: digest.SHA256(jobRaw), ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"},
		AuthorizationState: "NOT_REQUIRED", MutationAllowed: false,
	}
	return VerifiedNetworkObservationStagePackage{
		raw: packageRaw, receipt: receipt, ledgerCredential: config.LedgerCredentialSecret,
		managementCredential: config.ManagementCredentialSecret, workloadCredential: config.WorkloadCredentialSecret,
		managementAuthority: bundle.plan.Authorities.Management,
		workloadAuthority:   digest.SHA256([]byte(binding.TargetClusterUID)),
		intentRevision:      binding.IntentRevision, workloadEndpoint: binding.Endpoint,
		workloadCABundle: binding.CABundleDigest,
		verified:         true,
	}, nil
}

func (packaged VerifiedNetworkObservationStagePackage) Bytes() ([]byte, error) {
	if !packaged.verified || len(packaged.raw) == 0 {
		return nil, errors.New("network observation package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedNetworkObservationStagePackage) Receipt() (NetworkObservationStagePackageReceipt, error) {
	if !packaged.verified || packaged.receipt.State != "VERIFIED" || digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest || packaged.ledgerCredential == "" || packaged.managementCredential == "" || packaged.workloadCredential == "" || packaged.ledgerCredential == packaged.managementCredential || packaged.ledgerCredential == packaged.workloadCredential || packaged.managementCredential == packaged.workloadCredential || packaged.managementAuthority == "" || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) || !stageReceiptPrefixDigestPattern.MatchString(packaged.intentRevision) || packaged.workloadEndpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadCABundle) {
		return NetworkObservationStagePackageReceipt{}, errors.New("network observation package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}
