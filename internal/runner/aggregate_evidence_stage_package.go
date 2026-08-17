package runner

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
)

const AggregateEvidenceStagePackageFormat = "ok147-aggregate-evidence-stage-package/v1"

type AggregateEvidenceStagePackageConfig struct {
	Input                            AggregateEvidenceStageInputConfig
	JobTemplate                      []byte
	JobTemplateDigest                string
	RunID                            string
	ImageDigest                      string
	LedgerAPIURL                     string
	LedgerAPICIDR                    string
	LedgerCredentialSecret           string
	ManagementAPIURL                 string
	ManagementAPICIDR                string
	ManagementCredentialSecret       string
	WorkloadAPIURL                   string
	WorkloadAPICIDR                  string
	WorkloadCredentialSecret         string
	ArgoAPIURL                       string
	ArgoAPICIDR                      string
	ArgoCredentialSecret             string
	RuntimeBindingSecret             string
	RuntimeBindingMaterialPath       string
	RuntimeBindingReceiptPath        string
	PlatformCapabilitySecret         string
	PlatformCapabilityPath           string
	ExpectedPlatformCapabilityDigest string
}

type AggregateEvidenceStagePackageReceipt struct {
	Format                   string   `json:"format"`
	State                    string   `json:"state"`
	StageID                  string   `json:"stageId"`
	PackageDigest            string   `json:"packageDigest"`
	InputConfigMapDigest     string   `json:"inputConfigMapDigest"`
	ReceiptPrefixDigest      string   `json:"receiptPrefixDigest"`
	AggregateProfileDigest   string   `json:"aggregateProfileDigest"`
	NetworkProfileDigest     string   `json:"networkProfileDigest"`
	PlatformProfileDigest    string   `json:"platformProfileDigest"`
	RuntimeBindingDigest     string   `json:"runtimeBindingDigest"`
	PlatformCapabilityDigest string   `json:"platformCapabilityDigest"`
	JobTemplateDigest        string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest        string   `json:"jobEnvelopeDigest"`
	ObjectKinds              []string `json:"objectKinds"`
	AuthorizationState       string   `json:"authorizationState"`
	MutationAllowed          bool     `json:"mutationAllowed"`
}

type VerifiedAggregateEvidenceStagePackage struct {
	raw                  []byte
	receipt              AggregateEvidenceStagePackageReceipt
	ledgerCredential     string
	managementCredential string
	workloadCredential   string
	argoCredential       string
	runtimeSecret        string
	capabilitySecret     string
	managementAuthority  string
	workloadAuthority    string
	workloadCABundle     string
	gitOpsAuthority      string
	runtimeDigest        string
	capabilityDigest     string
	runtimeMaterialRaw   []byte
	runtimeReceiptRaw    []byte
	capabilityRaw        []byte
	verified             bool
}

// BuildAggregateEvidenceStagePackage correlates the public input, private
// runtime replay, private capability assertion and hardened Job envelope
// entirely offline. Private bytes are never copied into package output.
func BuildAggregateEvidenceStagePackage(config AggregateEvidenceStagePackageConfig) (VerifiedAggregateEvidenceStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("aggregate evidence Job template digest differs from expected identity")
	}
	input, err := BuildAggregateEvidenceStageInput(config.Input)
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, err
	}
	plan, _, _, err := loadStageResumeWithPrefix(config.Input.Bundle)
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, err
	}
	aggregateProfile, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: config.Input.AggregateEvidenceProfilePath, ExpectedProfileDigest: inputReceipt.AggregateProfileDigest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
		ExpectedPlatformRevision: plan.PlatformRevision, ExpectedExecutionFixture: plan.ExecutionFixture,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("verify aggregate evidence package profile")
	}
	bundle, err := LoadAggregateEvidenceStageBundle(AggregateEvidenceStageBundleConfig{
		StageResumeConfig: config.Input.Bundle, Profile: aggregateProfile.Profile, ExpectedProfileDigest: aggregateProfile.Digest,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("verify aggregate evidence package bundle")
	}
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle: config.Input.Bundle, MaterialPath: config.RuntimeBindingMaterialPath, ReceiptPath: config.RuntimeBindingReceiptPath,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("verify private aggregate runtime binding")
	}
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil || runtime.material.Target.WorkloadAPIEndpoint != config.WorkloadAPIURL || digest.SHA256([]byte(runtime.material.Target.CAPIClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("private aggregate runtime differs from package target")
	}
	platformProfile, err := LoadPlatformProfileFile(PlatformProfileFileConfig{
		Path: config.Input.PlatformProfilePath, ExpectedProfileDigest: inputReceipt.PlatformProfileDigest,
		ExpectedIntentRevision: bundle.plan.IntentRevision, ExpectedPlatformRevision: bundle.plan.PlatformRevision,
		ExpectedExecutionFixture: bundle.plan.ExecutionFixture,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("verify aggregate platform profile")
	}
	capability, err := LoadPlatformCapabilityFile(PlatformCapabilityFileConfig{
		Path: config.PlatformCapabilityPath, ExpectedEvidenceDigest: config.ExpectedPlatformCapabilityDigest,
		ExpectedIntentRevision: bundle.plan.IntentRevision, ExpectedPlatformRevision: bundle.plan.PlatformRevision,
		ExpectedExecutionFixture: bundle.plan.ExecutionFixture, ExpectedTargetClusterUID: runtime.material.Target.CAPIClusterUID,
		ExpectedContractDigest:   platformProfile.Profile.CapabilityContractDigest,
		ExpectedExecutableDigest: platformProfile.Profile.CapabilityExecutableDigest,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("verify private aggregate platform capability")
	}
	capabilityRaw, err := readBoundedRegular(config.PlatformCapabilityPath, maximumPlatformCapabilityBytes)
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("read private aggregate platform capability")
	}
	runtimeReceiptRaw, err := json.Marshal(runtime.receipt)
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, errors.New("encode private aggregate runtime receipt")
	}
	jobRaw, err := RenderAggregateEvidenceStageJobTemplate(config.JobTemplate, AggregateEvidenceStageJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest, Expected: config.Input.Bundle.PlanExpected,
		InputConfigMap: config.Input.ConfigMapName, ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		AggregateProfileDigest: inputReceipt.AggregateProfileDigest, NetworkProfileDigest: inputReceipt.NetworkProfileDigest,
		PlatformProfileDigest: inputReceipt.PlatformProfileDigest,
		LedgerAPIURL:          config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR, LedgerCredentialSecret: config.LedgerCredentialSecret,
		ManagementAPIURL: config.ManagementAPIURL, ManagementAPICIDR: config.ManagementAPICIDR, ManagementCredentialSecret: config.ManagementCredentialSecret,
		WorkloadAPIURL: config.WorkloadAPIURL, WorkloadAPICIDR: config.WorkloadAPICIDR, WorkloadCredentialSecret: config.WorkloadCredentialSecret,
		ArgoAPIURL: config.ArgoAPIURL, ArgoAPICIDR: config.ArgoAPICIDR, ArgoCredentialSecret: config.ArgoCredentialSecret,
		RuntimeBindingSecret: config.RuntimeBindingSecret, PlatformCapabilitySecret: config.PlatformCapabilitySecret,
		PlatformCapabilityDigest: config.ExpectedPlatformCapabilityDigest,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := AggregateEvidenceStagePackageReceipt{
		Format: AggregateEvidenceStagePackageFormat, State: "VERIFIED", StageID: "aggregate-evidence",
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, AggregateProfileDigest: inputReceipt.AggregateProfileDigest,
		NetworkProfileDigest: inputReceipt.NetworkProfileDigest, PlatformProfileDigest: inputReceipt.PlatformProfileDigest,
		RuntimeBindingDigest: runtime.receipt.PrivateMaterialDigest, PlatformCapabilityDigest: capability.EvidenceDigest(),
		JobTemplateDigest: config.JobTemplateDigest, JobEnvelopeDigest: digest.SHA256(jobRaw),
		ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"}, AuthorizationState: "NOT_REQUIRED", MutationAllowed: false,
	}
	return VerifiedAggregateEvidenceStagePackage{
		raw: packageRaw, receipt: receipt, ledgerCredential: config.LedgerCredentialSecret,
		managementCredential: config.ManagementCredentialSecret, workloadCredential: config.WorkloadCredentialSecret,
		argoCredential: config.ArgoCredentialSecret, runtimeSecret: config.RuntimeBindingSecret,
		capabilitySecret: config.PlatformCapabilitySecret, managementAuthority: bundle.plan.Authorities.Management,
		workloadAuthority: digest.SHA256([]byte(runtime.material.Target.CAPIClusterUID)), workloadCABundle: runtime.material.Target.WorkloadAPICADigest,
		gitOpsAuthority: bundle.plan.Authorities.GitOps,
		runtimeDigest:   runtime.receipt.PrivateMaterialDigest, capabilityDigest: capability.EvidenceDigest(),
		runtimeMaterialRaw: append([]byte(nil), runtime.raw...), runtimeReceiptRaw: runtimeReceiptRaw,
		capabilityRaw: append([]byte(nil), capabilityRaw...),
		verified:      true,
	}, nil
}

func (packaged VerifiedAggregateEvidenceStagePackage) Bytes() ([]byte, error) {
	if err := verifyAggregateEvidenceStagePackage(packaged); err != nil {
		return nil, errors.New("aggregate evidence package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedAggregateEvidenceStagePackage) Receipt() (AggregateEvidenceStagePackageReceipt, error) {
	if err := verifyAggregateEvidenceStagePackage(packaged); err != nil {
		return AggregateEvidenceStagePackageReceipt{}, errors.New("aggregate evidence package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyAggregateEvidenceStagePackage(packaged VerifiedAggregateEvidenceStagePackage) error {
	if !packaged.verified || packaged.receipt.Format != AggregateEvidenceStagePackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "aggregate-evidence" || packaged.receipt.MutationAllowed || digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest ||
		packaged.ledgerCredential == "" || packaged.managementCredential == "" || packaged.workloadCredential == "" || packaged.argoCredential == "" || packaged.runtimeSecret == "" || packaged.capabilitySecret == "" || packaged.managementAuthority == "" || packaged.gitOpsAuthority == "" || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadCABundle) {
		return errors.New("aggregate evidence package identity is incomplete")
	}
	parts := bytes.SplitN(packaged.raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || digest.SHA256(parts[0]) != packaged.receipt.InputConfigMapDigest || digest.SHA256(parts[1]) != packaged.receipt.JobEnvelopeDigest ||
		packaged.runtimeDigest != packaged.receipt.RuntimeBindingDigest || packaged.capabilityDigest != packaged.receipt.PlatformCapabilityDigest || digest.SHA256(packaged.runtimeMaterialRaw) != packaged.runtimeDigest {
		return errors.New("aggregate evidence package component identity changed")
	}
	var runtimeReceipt RuntimeBindingMaterialReceipt
	if jsonstrict.Decode(packaged.runtimeReceiptRaw, &runtimeReceipt) != nil || runtimeReceipt.PrivateMaterialDigest != packaged.runtimeDigest || runtimeReceipt.WorkloadAPICADigest != packaged.workloadCABundle {
		return errors.New("aggregate evidence private runtime receipt changed")
	}
	var capability observation.PlatformCapabilityState
	if jsonstrict.Decode(packaged.capabilityRaw, &capability) != nil || observation.ValidatePlatformCapabilityState(capability) != nil || capability.EvidenceDigest != packaged.capabilityDigest || digest.SHA256([]byte(capability.TargetClusterUID)) != packaged.workloadAuthority {
		return errors.New("aggregate evidence private capability changed")
	}
	for _, value := range []string{
		packaged.receipt.ReceiptPrefixDigest, packaged.receipt.AggregateProfileDigest, packaged.receipt.NetworkProfileDigest,
		packaged.receipt.PlatformProfileDigest, packaged.receipt.RuntimeBindingDigest, packaged.receipt.PlatformCapabilityDigest,
		packaged.receipt.JobTemplateDigest, packaged.receipt.JobEnvelopeDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("aggregate evidence package digest identity is invalid")
		}
	}
	names := []string{packaged.ledgerCredential, packaged.managementCredential, packaged.workloadCredential, packaged.argoCredential, packaged.runtimeSecret, packaged.capabilitySecret}
	seen := map[string]struct{}{}
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			return errors.New("aggregate evidence package private objects are not distinct")
		}
		seen[name] = struct{}{}
	}
	return nil
}
