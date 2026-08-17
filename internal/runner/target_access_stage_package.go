package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
)

const TargetAccessStagePackageFormat = "ok147-target-access-stage-package/v1"

// TargetAccessStagePackageConfig correlates the public input and Job envelope
// with a private runtime binding without embedding that binding or credentials.
type TargetAccessStagePackageConfig struct {
	Bundle                        TargetAccessStageBundleConfig
	JobTemplate                   []byte
	JobTemplateDigest             string
	RunID                         string
	ImageDigest                   string
	InputConfigMap                string
	ObservabilityNamespace        string
	ManagerServiceAccount         string
	ClusterRole                   string
	ClusterRoleBinding            string
	PlatformRole                  string
	PlatformRoleBinding           string
	KubeSystemRole                string
	KubeSystemRoleBinding         string
	LedgerAPIURL                  string
	LedgerAPICIDR                 string
	LedgerCredentialSecret        string
	WorkloadAPIURL                string
	WorkloadAPICIDR               string
	WorkloadCredentialSecret      string
	WorkloadBindingPath           string
	ExpectedWorkloadBindingDigest string
}

// TargetAccessStagePackageReceipt is a redaction-safe offline composition
// proof. TargetAccessDigest covers the eight rendered target objects while
// TargetIdentityDigest correlates the package to the CAPI-created workload.
type TargetAccessStagePackageReceipt struct {
	Format                string   `json:"format"`
	State                 string   `json:"state"`
	StageID               string   `json:"stageId"`
	PackageDigest         string   `json:"packageDigest"`
	InputConfigMapDigest  string   `json:"inputConfigMapDigest"`
	ReceiptPrefixDigest   string   `json:"receiptPrefixDigest"`
	TargetAccessDigest    string   `json:"targetAccessDigest"`
	TargetIdentityDigest  string   `json:"targetIdentityDigest"`
	WorkloadBindingDigest string   `json:"workloadBindingDigest"`
	InstallationAuthority string   `json:"installationAuthority"`
	JobTemplateDigest     string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest     string   `json:"jobEnvelopeDigest"`
	ObjectKinds           []string `json:"objectKinds"`
	AuthorizationState    string   `json:"authorizationState"`
	MutationAllowed       bool     `json:"mutationAllowed"`
}

type VerifiedTargetAccessStagePackage struct {
	raw                   []byte
	receipt               TargetAccessStagePackageReceipt
	ledgerCredential      string
	workloadCredential    string
	installationAuthority string
	managementAuthority   string
	workloadAuthority     string
	verified              bool
}

// BuildTargetAccessStagePackage composes one immutable public ConfigMap and
// one hardened NetworkPolicy/Job envelope. It performs no API request.
func BuildTargetAccessStagePackage(config TargetAccessStagePackageConfig) (VerifiedTargetAccessStagePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedTargetAccessStagePackage{}, errors.New("target-access stage Job template digest differs from expected identity")
	}
	jobObjects := []projection.ResourceIdentity{
		{APIVersion: "v1", Kind: "Namespace", Name: config.ObservabilityNamespace},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "kube-system", Name: config.ManagerServiceAccount},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: config.ClusterRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: config.ClusterRoleBinding},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: config.ObservabilityNamespace, Name: config.PlatformRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: config.ObservabilityNamespace, Name: config.PlatformRoleBinding},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "kube-system", Name: config.KubeSystemRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "kube-system", Name: config.KubeSystemRoleBinding},
	}
	if len(config.Bundle.ExpectedObjects) != len(jobObjects) {
		return VerifiedTargetAccessStagePackage{}, errors.New("target-access Job object identities differ from verified bundle")
	}
	for index := range jobObjects {
		if config.Bundle.ExpectedObjects[index] != jobObjects[index] {
			return VerifiedTargetAccessStagePackage{}, errors.New("target-access Job object identities differ from verified bundle")
		}
	}
	input, err := BuildTargetAccessStageInput(config.Bundle, config.InputConfigMap)
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, err
	}
	inputRaw, err := input.Bytes()
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, err
	}
	inputReceipt, err := input.Receipt()
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, err
	}
	bundle, err := LoadTargetAccessStageBundle(config.Bundle)
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, err
	}
	bundleReceipt, err := bundle.Receipt()
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, err
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, config.ExpectedWorkloadBindingDigest)
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, errors.New("verify private target-access runtime binding")
	}
	workloadAuthority := digest.SHA256([]byte(binding.TargetClusterUID))
	if binding.IntentRevision != bundle.plan.IntentRevision || workloadAuthority != bundleReceipt.TargetIdentityDigest || binding.Endpoint != config.WorkloadAPIURL {
		return VerifiedTargetAccessStagePackage{}, errors.New("private workload binding differs from target-access package target")
	}
	jobRaw, err := RenderTargetAccessStageJobTemplate(config.JobTemplate, TargetAccessStageJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest,
		EvaluationTime: config.Bundle.EvaluationTime.UTC().Format(time.RFC3339), Expected: config.Bundle.PlanExpected,
		InputConfigMap: config.InputConfigMap, ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest,
		ObservabilityNamespace: config.ObservabilityNamespace, ManagerServiceAccount: config.ManagerServiceAccount,
		ClusterRole: config.ClusterRole, ClusterRoleBinding: config.ClusterRoleBinding,
		PlatformRole: config.PlatformRole, PlatformRoleBinding: config.PlatformRoleBinding,
		KubeSystemRole: config.KubeSystemRole, KubeSystemRoleBinding: config.KubeSystemRoleBinding,
		LedgerAPIURL: config.LedgerAPIURL, LedgerAPICIDR: config.LedgerAPICIDR, LedgerCredentialSecret: config.LedgerCredentialSecret,
		WorkloadAPIURL: config.WorkloadAPIURL, WorkloadAPICIDR: config.WorkloadAPICIDR, WorkloadCredentialSecret: config.WorkloadCredentialSecret,
		WorkloadBindingDigest: config.ExpectedWorkloadBindingDigest,
	})
	if err != nil {
		return VerifiedTargetAccessStagePackage{}, err
	}
	packageRaw := make([]byte, 0, len(inputRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, inputRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := TargetAccessStagePackageReceipt{
		Format: TargetAccessStagePackageFormat, State: "VERIFIED", StageID: "target-access",
		PackageDigest: digest.SHA256(packageRaw), InputConfigMapDigest: inputReceipt.ConfigMapDigest,
		ReceiptPrefixDigest: inputReceipt.ReceiptPrefixDigest, TargetAccessDigest: inputReceipt.TargetAccessDigest,
		TargetIdentityDigest: inputReceipt.TargetIdentityDigest, WorkloadBindingDigest: config.ExpectedWorkloadBindingDigest,
		InstallationAuthority: bundle.plan.Authorities.GitOps,
		JobTemplateDigest:     config.JobTemplateDigest, JobEnvelopeDigest: digest.SHA256(jobRaw),
		ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"}, AuthorizationState: "VERIFIED", MutationAllowed: false,
	}
	return VerifiedTargetAccessStagePackage{
		raw: packageRaw, receipt: receipt, ledgerCredential: config.LedgerCredentialSecret,
		workloadCredential:    config.WorkloadCredentialSecret,
		installationAuthority: bundle.plan.Authorities.GitOps, managementAuthority: bundle.plan.Authorities.Management,
		workloadAuthority: workloadAuthority, verified: true,
	}, nil
}

func (packaged VerifiedTargetAccessStagePackage) Bytes() ([]byte, error) {
	if err := verifyTargetAccessStagePackage(packaged); err != nil {
		return nil, errors.New("target-access stage package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedTargetAccessStagePackage) Receipt() (TargetAccessStagePackageReceipt, error) {
	if err := verifyTargetAccessStagePackage(packaged); err != nil {
		return TargetAccessStagePackageReceipt{}, errors.New("target-access stage package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyTargetAccessStagePackage(packaged VerifiedTargetAccessStagePackage) error {
	if !packaged.verified || packaged.receipt.Format != TargetAccessStagePackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "target-access" || packaged.receipt.MutationAllowed || len(packaged.raw) == 0 || packaged.ledgerCredential == "" || packaged.workloadCredential == "" || packaged.ledgerCredential == packaged.workloadCredential || packaged.installationAuthority == "" || packaged.managementAuthority == "" || packaged.installationAuthority == packaged.managementAuthority || packaged.receipt.InstallationAuthority != packaged.installationAuthority || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) {
		return errors.New("target-access stage package identity is incomplete")
	}
	if digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest || packaged.workloadAuthority != packaged.receipt.TargetIdentityDigest {
		return errors.New("target-access stage package target identity changed after verification")
	}
	for _, value := range []string{
		packaged.receipt.InputConfigMapDigest, packaged.receipt.ReceiptPrefixDigest,
		packaged.receipt.TargetAccessDigest, packaged.receipt.TargetIdentityDigest,
		packaged.receipt.WorkloadBindingDigest, packaged.receipt.JobTemplateDigest,
		packaged.receipt.JobEnvelopeDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("target-access stage package digest identity changed after verification")
		}
	}
	if len(packaged.receipt.ObjectKinds) != 3 || packaged.receipt.ObjectKinds[0] != "ConfigMap" || packaged.receipt.ObjectKinds[1] != "NetworkPolicy" || packaged.receipt.ObjectKinds[2] != "Job" || packaged.receipt.AuthorizationState != "VERIFIED" {
		return errors.New("target-access stage package object inventory changed after verification")
	}
	return nil
}
