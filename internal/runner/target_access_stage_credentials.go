package runner

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const TargetAccessStageCredentialPackageFormat = "ok147-target-access-stage-credential-package/v1"

type TargetAccessStageCredentialPackageConfig struct {
	Package             VerifiedTargetAccessStagePackage
	MaterializationTime time.Time
	WorkloadBindingPath string
	LedgerWriter        SubmissionStageCredentialSource
	WorkloadWriter      SubmissionStageCredentialSource
}

// TargetAccessStageCredentialPackageReceipt binds two private immutable
// Secrets without exposing token, CA, subject, endpoint, UID or source paths.
type TargetAccessStageCredentialPackageReceipt struct {
	Format                    string                                   `json:"format"`
	State                     string                                   `json:"state"`
	StageID                   string                                   `json:"stageId"`
	TargetAccessPackageDigest string                                   `json:"targetAccessPackageDigest"`
	WorkloadBindingDigest     string                                   `json:"workloadBindingDigest"`
	InstallationAuthority     string                                   `json:"installationAuthority"`
	MaterializedAt            string                                   `json:"materializedAt"`
	PackageDigest             string                                   `json:"packageDigest"`
	Credentials               []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed           bool                                     `json:"mutationAllowed"`
}

type targetAccessStageCredentialPackageIdentity struct {
	TargetAccessPackageDigest string                                   `json:"targetAccessPackageDigest"`
	WorkloadBindingDigest     string                                   `json:"workloadBindingDigest"`
	InstallationAuthority     string                                   `json:"installationAuthority"`
	MaterializedAt            string                                   `json:"materializedAt"`
	Credentials               []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedTargetAccessStageCredentialPackage keeps private Secret bytes
// inaccessible to callers; only the redaction-safe receipt is exposed.
type VerifiedTargetAccessStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               TargetAccessStageCredentialPackageReceipt
	installationAuthority string
	managementAuthority   string
	workloadAuthority     string
	verified              bool
}

// BuildTargetAccessStageCredentialPackage verifies two independent,
// short-lived TokenRequest results and the package-bound workload identity.
// It performs no Kubernetes request.
func BuildTargetAccessStageCredentialPackage(config TargetAccessStageCredentialPackageConfig) (VerifiedTargetAccessStageCredentialPackage, error) {
	packageReceipt, err := config.Package.Receipt()
	if err != nil || packageReceipt.StageID != "target-access" {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("verified target-access package is required")
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("target-access credential materialization time is required")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, packageReceipt.WorkloadBindingDigest)
	if err != nil {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("verify private target-access workload binding")
	}
	if digest.SHA256([]byte(binding.TargetClusterUID)) != config.Package.workloadAuthority || binding.CABundleDigest != config.WorkloadWriter.CABundleDigest {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("target-access workload authority differs from verified package")
	}
	bindings := []struct {
		role      string
		name      string
		authority string
		source    SubmissionStageCredentialSource
	}{
		{role: "ledger-writer", name: config.Package.ledgerCredential, authority: config.Package.managementAuthority, source: config.LedgerWriter},
		{role: "workload-writer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority, source: config.WorkloadWriter},
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
			return VerifiedTargetAccessStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, receipt)
		tokens = append(tokens, token)
	}
	if len(tokens[0]) == len(tokens[1]) && subtle.ConstantTimeCompare(tokens[0], tokens[1]) == 1 {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("target-access credentials must be distinct")
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("encode private target-access workload binding")
	}
	var workloadSecret map[string]any
	if err := jsonstrict.Decode(objects[1].raw, &workloadSecret); err != nil {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("decode private target-access workload credential")
	}
	data, ok := workloadSecret["data"].(map[string]any)
	if !ok {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("private target-access workload credential data is missing")
	}
	data["binding.json"] = base64.StdEncoding.EncodeToString(bindingRaw)
	objects[1].raw, err = json.Marshal(workloadSecret)
	if err != nil || len(objects[1].raw) > maximumStageCredentialObjectBytes {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("target-access workload credential Secret exceeds accepted size")
	}
	receipts[1].ObjectDigest = digest.SHA256(objects[1].raw)

	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	identity, err := json.Marshal(targetAccessStageCredentialPackageIdentity{
		TargetAccessPackageDigest: packageReceipt.PackageDigest, WorkloadBindingDigest: packageReceipt.WorkloadBindingDigest,
		InstallationAuthority: config.Package.installationAuthority, MaterializedAt: materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedTargetAccessStageCredentialPackage{}, errors.New("encode target-access credential package identity")
	}
	receipt := TargetAccessStageCredentialPackageReceipt{
		Format: TargetAccessStageCredentialPackageFormat, State: "VERIFIED", StageID: packageReceipt.StageID,
		TargetAccessPackageDigest: packageReceipt.PackageDigest, WorkloadBindingDigest: packageReceipt.WorkloadBindingDigest,
		InstallationAuthority: config.Package.installationAuthority, MaterializedAt: materializedAt,
		PackageDigest: digest.SHA256(identity), Credentials: receipts, MutationAllowed: false,
	}
	return VerifiedTargetAccessStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.installationAuthority, managementAuthority: config.Package.managementAuthority,
		workloadAuthority: config.Package.workloadAuthority, verified: true,
	}, nil
}

func (packaged VerifiedTargetAccessStageCredentialPackage) Receipt() (TargetAccessStageCredentialPackageReceipt, error) {
	if err := verifyTargetAccessStageCredentialPackage(packaged); err != nil {
		return TargetAccessStageCredentialPackageReceipt{}, errors.New("target-access credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func verifyTargetAccessStageCredentialPackage(packaged VerifiedTargetAccessStageCredentialPackage) error {
	if !packaged.verified || packaged.receipt.Format != TargetAccessStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "target-access" || packaged.receipt.MutationAllowed || packaged.installationAuthority == "" || packaged.managementAuthority == "" || packaged.installationAuthority == packaged.managementAuthority || packaged.receipt.InstallationAuthority != packaged.installationAuthority || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) || len(packaged.objects) != 2 || len(packaged.receipt.Credentials) != 2 {
		return errors.New("target-access credential package identity is incomplete")
	}
	identity, err := json.Marshal(targetAccessStageCredentialPackageIdentity{
		TargetAccessPackageDigest: packaged.receipt.TargetAccessPackageDigest,
		WorkloadBindingDigest:     packaged.receipt.WorkloadBindingDigest,
		InstallationAuthority:     packaged.receipt.InstallationAuthority,
		MaterializedAt:            packaged.receipt.MaterializedAt, Credentials: packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("target-access credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return errors.New("target-access credential materialization time is invalid")
	}
	expectedRoles := []string{"ledger-writer", "workload-writer"}
	expectedAuthorities := []string{packaged.managementAuthority, packaged.workloadAuthority}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Credentials[index]
		if object.role != expectedRoles[index] || receipt.Role != expectedRoles[index] || object.authority != expectedAuthorities[index] || receipt.Authority != expectedAuthorities[index] || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("target-access credential object identity changed after verification")
		}
	}
	var workloadSecret map[string]any
	if err := jsonstrict.Decode(packaged.objects[1].raw, &workloadSecret); err != nil {
		return errors.New("target-access workload credential is invalid")
	}
	data, ok := workloadSecret["data"].(map[string]any)
	if !ok {
		return errors.New("target-access workload credential data is missing")
	}
	bindingEncoded, ok := data["binding.json"].(string)
	if !ok {
		return errors.New("target-access workload binding is missing")
	}
	bindingRaw, err := base64.StdEncoding.DecodeString(bindingEncoded)
	if err != nil {
		return errors.New("target-access workload binding encoding is invalid")
	}
	var binding WorkloadAuthorityBinding
	if err := jsonstrict.Decode(bindingRaw, &binding); err != nil {
		return errors.New("target-access workload binding is invalid")
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil || bindingDigest != packaged.receipt.WorkloadBindingDigest || digest.SHA256([]byte(binding.TargetClusterUID)) != packaged.workloadAuthority {
		return errors.New("target-access workload authority identity changed after verification")
	}
	return nil
}
