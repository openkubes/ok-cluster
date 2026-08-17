package runner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const AggregateEvidenceStageCredentialPackageFormat = "ok147-aggregate-evidence-stage-credential-package/v1"

type AggregateEvidenceStageCredentialPackageConfig struct {
	Package             VerifiedAggregateEvidenceStagePackage
	MaterializationTime time.Time
	Ledger              SubmissionStageCredentialSource
	ManagementObserver  SubmissionStageCredentialSource
	WorkloadObserver    SubmissionStageCredentialSource
	ArgoObserver        SubmissionStageCredentialSource
}

type AggregateEvidenceStageCredentialPackageReceipt struct {
	Format                string                                   `json:"format"`
	State                 string                                   `json:"state"`
	StageID               string                                   `json:"stageId"`
	StagePackageDigest    string                                   `json:"stagePackageDigest"`
	InstallationAuthority string                                   `json:"installationAuthority"`
	MaterializedAt        string                                   `json:"materializedAt"`
	PackageDigest         string                                   `json:"packageDigest"`
	Credentials           []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed       bool                                     `json:"mutationAllowed"`
}

type aggregateEvidenceStageCredentialPackageIdentity struct {
	StagePackageDigest    string                                   `json:"stagePackageDigest"`
	InstallationAuthority string                                   `json:"installationAuthority"`
	MaterializedAt        string                                   `json:"materializedAt"`
	Credentials           []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedAggregateEvidenceStageCredentialPackage retains four exact Secret
// objects privately. The receipt exposes only their identities and expiry.
type VerifiedAggregateEvidenceStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               AggregateEvidenceStageCredentialPackageReceipt
	installationAuthority string
	workloadAuthority     string
	workloadCABundle      string
	gitOpsAuthority       string
	verified              bool
}

// BuildAggregateEvidenceStageCredentialPackage verifies four independent,
// short-lived credentials entirely offline. It performs no TokenRequest and no
// Kubernetes API request.
func BuildAggregateEvidenceStageCredentialPackage(config AggregateEvidenceStageCredentialPackageConfig) (VerifiedAggregateEvidenceStageCredentialPackage, error) {
	packageReceipt, err := config.Package.Receipt()
	if err != nil || packageReceipt.StageID != "aggregate-evidence" {
		return VerifiedAggregateEvidenceStageCredentialPackage{}, errors.New("verified aggregate evidence package is required")
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedAggregateEvidenceStageCredentialPackage{}, errors.New("aggregate evidence credential materialization time is required")
	}
	if config.Ledger.CABundleDigest != config.ManagementObserver.CABundleDigest {
		return VerifiedAggregateEvidenceStageCredentialPackage{}, errors.New("aggregate evidence management credentials use different CA identities")
	}
	if config.WorkloadObserver.CABundleDigest != config.Package.workloadCABundle {
		return VerifiedAggregateEvidenceStageCredentialPackage{}, errors.New("aggregate evidence workload credential differs from runtime CA identity")
	}

	bindings := []struct {
		role      string
		name      string
		authority string
		source    SubmissionStageCredentialSource
	}{
		{role: "ledger", name: config.Package.ledgerCredential, authority: config.Package.managementAuthority, source: config.Ledger},
		{role: "management-observer", name: config.Package.managementCredential, authority: config.Package.managementAuthority, source: config.ManagementObserver},
		{role: "workload-observer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority, source: config.WorkloadObserver},
		{role: "argo-observer", name: config.Package.argoCredential, authority: config.Package.gitOpsAuthority, source: config.ArgoObserver},
	}
	objects := make([]submissionStageCredentialObject, 0, len(bindings))
	receipts := make([]SubmissionStageCredentialObjectReceipt, 0, len(bindings))
	tokens := make([][]byte, 0, len(bindings))
	for _, credential := range bindings {
		object, receipt, token, err := buildSubmissionStageCredentialObject(
			packageReceipt.StageID, config.MaterializationTime.UTC(), credential.role,
			credential.name, credential.authority, credential.source,
		)
		if err != nil {
			return VerifiedAggregateEvidenceStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, receipt)
		tokens = append(tokens, token)
	}
	for left := range tokens {
		for right := left + 1; right < len(tokens); right++ {
			if len(tokens[left]) == len(tokens[right]) && subtle.ConstantTimeCompare(tokens[left], tokens[right]) == 1 {
				return VerifiedAggregateEvidenceStageCredentialPackage{}, errors.New("aggregate evidence credentials must be pairwise distinct")
			}
		}
	}

	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	identity, err := json.Marshal(aggregateEvidenceStageCredentialPackageIdentity{
		StagePackageDigest: packageReceipt.PackageDigest, InstallationAuthority: config.Package.managementAuthority,
		MaterializedAt: materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedAggregateEvidenceStageCredentialPackage{}, errors.New("encode aggregate evidence credential package identity")
	}
	receipt := AggregateEvidenceStageCredentialPackageReceipt{
		Format: AggregateEvidenceStageCredentialPackageFormat, State: "VERIFIED", StageID: packageReceipt.StageID,
		StagePackageDigest: packageReceipt.PackageDigest, InstallationAuthority: config.Package.managementAuthority,
		MaterializedAt: materializedAt, PackageDigest: digest.SHA256(identity), Credentials: receipts,
		MutationAllowed: false,
	}
	return VerifiedAggregateEvidenceStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.managementAuthority,
		workloadAuthority:     config.Package.workloadAuthority, workloadCABundle: config.Package.workloadCABundle,
		gitOpsAuthority: config.Package.gitOpsAuthority, verified: true,
	}, nil
}

func (packaged VerifiedAggregateEvidenceStageCredentialPackage) Receipt() (AggregateEvidenceStageCredentialPackageReceipt, error) {
	if err := verifyAggregateEvidenceStageCredentialPackage(packaged); err != nil {
		return AggregateEvidenceStageCredentialPackageReceipt{}, errors.New("aggregate evidence credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func verifyAggregateEvidenceStageCredentialPackage(packaged VerifiedAggregateEvidenceStageCredentialPackage) error {
	if !packaged.verified || packaged.receipt.Format != AggregateEvidenceStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "aggregate-evidence" || packaged.receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.StagePackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.PackageDigest) || packaged.installationAuthority == "" || packaged.receipt.InstallationAuthority != packaged.installationAuthority || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadCABundle) || packaged.gitOpsAuthority == "" || len(packaged.objects) != 4 || len(packaged.receipt.Credentials) != 4 {
		return errors.New("aggregate evidence credential package identity is incomplete")
	}
	identity, err := json.Marshal(aggregateEvidenceStageCredentialPackageIdentity{
		StagePackageDigest:    packaged.receipt.StagePackageDigest,
		InstallationAuthority: packaged.receipt.InstallationAuthority,
		MaterializedAt:        packaged.receipt.MaterializedAt, Credentials: packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("aggregate evidence credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return errors.New("aggregate evidence credential materialization time is invalid")
	}
	expectedRoles := []string{"ledger", "management-observer", "workload-observer", "argo-observer"}
	expectedAuthorities := []string{packaged.installationAuthority, packaged.installationAuthority, packaged.workloadAuthority, packaged.gitOpsAuthority}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Credentials[index]
		if object.role != expectedRoles[index] || receipt.Role != expectedRoles[index] || object.authority != expectedAuthorities[index] || receipt.Authority != expectedAuthorities[index] || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("aggregate evidence credential object identity changed after verification")
		}
	}
	if packaged.receipt.Credentials[0].CABundleDigest != packaged.receipt.Credentials[1].CABundleDigest || packaged.receipt.Credentials[2].CABundleDigest != packaged.workloadCABundle {
		return errors.New("aggregate evidence credential CA identity changed after verification")
	}
	return nil
}
