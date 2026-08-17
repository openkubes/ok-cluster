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

const RuntimeBindingStageCredentialPackageFormat = "ok147-runtime-binding-stage-credential-package/v1"

type RuntimeBindingStageCredentialPackageConfig struct {
	Package             VerifiedRuntimeBindingStagePackage
	MaterializationTime time.Time
	WorkloadBindingPath string
	LedgerWriter        SubmissionStageCredentialSource
	PersistenceWriter   SubmissionStageCredentialSource
	WorkloadObserver    SubmissionStageCredentialSource
}

// RuntimeBindingStageCredentialPackageReceipt is safe to publish. It binds
// the three private immutable Secrets without exposing token, CA, subject,
// endpoint or source-path material.
type RuntimeBindingStageCredentialPackageReceipt struct {
	Format                string                                   `json:"format"`
	State                 string                                   `json:"state"`
	StageID               string                                   `json:"stageId"`
	StagePackageDigest    string                                   `json:"stagePackageDigest"`
	WorkloadBindingDigest string                                   `json:"workloadBindingDigest"`
	InstallationAuthority string                                   `json:"installationAuthority"`
	MaterializedAt        string                                   `json:"materializedAt"`
	PackageDigest         string                                   `json:"packageDigest"`
	Credentials           []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed       bool                                     `json:"mutationAllowed"`
}

type runtimeBindingStageCredentialPackageIdentity struct {
	StagePackageDigest    string                                   `json:"stagePackageDigest"`
	WorkloadBindingDigest string                                   `json:"workloadBindingDigest"`
	InstallationAuthority string                                   `json:"installationAuthority"`
	MaterializedAt        string                                   `json:"materializedAt"`
	Credentials           []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedRuntimeBindingStageCredentialPackage retains the three exact
// immutable Secrets privately. Only the workload observer Secret also carries
// the private workload binding required by the tokenless runtime Job.
type VerifiedRuntimeBindingStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               RuntimeBindingStageCredentialPackageReceipt
	installationAuthority string
	workloadAuthority     string
	verified              bool
}

// BuildRuntimeBindingStageCredentialPackage verifies three independently
// issued short-lived TokenRequest results and produces private Secret bytes.
// It is entirely offline and performs no Kubernetes request.
func BuildRuntimeBindingStageCredentialPackage(config RuntimeBindingStageCredentialPackageConfig) (VerifiedRuntimeBindingStageCredentialPackage, error) {
	packageReceipt, err := config.Package.Receipt()
	if err != nil || packageReceipt.StageID != "runtime-binding" {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("verified runtime binding package is required")
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("runtime binding credential materialization time is required")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, packageReceipt.WorkloadBindingDigest)
	if err != nil {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("verify private runtime binding workload authority")
	}
	if digest.SHA256([]byte(binding.TargetClusterUID)) != config.Package.workloadAuthority || binding.CABundleDigest != config.WorkloadObserver.CABundleDigest {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("runtime binding workload authority differs from verified package")
	}
	bindings := []struct {
		role      string
		name      string
		authority string
		source    SubmissionStageCredentialSource
	}{
		{role: "ledger-writer", name: config.Package.ledgerCredential, authority: config.Package.managementAuthority, source: config.LedgerWriter},
		{role: "persistence-writer", name: config.Package.persistenceCredential, authority: config.Package.managementAuthority, source: config.PersistenceWriter},
		{role: "workload-observer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority, source: config.WorkloadObserver},
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
			return VerifiedRuntimeBindingStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, receipt)
		tokens = append(tokens, token)
	}
	for left := range tokens {
		for right := left + 1; right < len(tokens); right++ {
			if len(tokens[left]) == len(tokens[right]) && subtle.ConstantTimeCompare(tokens[left], tokens[right]) == 1 {
				return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("runtime binding credentials must be pairwise distinct")
			}
		}
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("encode private runtime binding workload authority")
	}
	var workloadSecret map[string]any
	if err := jsonstrict.Decode(objects[2].raw, &workloadSecret); err != nil {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("decode private runtime binding workload credential")
	}
	data, ok := workloadSecret["data"].(map[string]any)
	if !ok {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("private runtime binding workload credential data is missing")
	}
	data["binding.json"] = base64.StdEncoding.EncodeToString(bindingRaw)
	objects[2].raw, err = json.Marshal(workloadSecret)
	if err != nil || len(objects[2].raw) > maximumStageCredentialObjectBytes {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("runtime binding workload credential Secret exceeds accepted size")
	}
	receipts[2].ObjectDigest = digest.SHA256(objects[2].raw)

	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	identity, err := json.Marshal(runtimeBindingStageCredentialPackageIdentity{
		StagePackageDigest: packageReceipt.PackageDigest, WorkloadBindingDigest: packageReceipt.WorkloadBindingDigest,
		InstallationAuthority: config.Package.managementAuthority, MaterializedAt: materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedRuntimeBindingStageCredentialPackage{}, errors.New("encode runtime binding credential package identity")
	}
	receipt := RuntimeBindingStageCredentialPackageReceipt{
		Format: RuntimeBindingStageCredentialPackageFormat, State: "VERIFIED", StageID: packageReceipt.StageID,
		StagePackageDigest: packageReceipt.PackageDigest, WorkloadBindingDigest: packageReceipt.WorkloadBindingDigest,
		InstallationAuthority: config.Package.managementAuthority, MaterializedAt: materializedAt,
		PackageDigest: digest.SHA256(identity), Credentials: receipts, MutationAllowed: false,
	}
	return VerifiedRuntimeBindingStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.managementAuthority,
		workloadAuthority:     config.Package.workloadAuthority, verified: true,
	}, nil
}

func (packaged VerifiedRuntimeBindingStageCredentialPackage) Receipt() (RuntimeBindingStageCredentialPackageReceipt, error) {
	if err := verifyRuntimeBindingStageCredentialPackage(packaged); err != nil {
		return RuntimeBindingStageCredentialPackageReceipt{}, errors.New("runtime binding credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func verifyRuntimeBindingStageCredentialPackage(packaged VerifiedRuntimeBindingStageCredentialPackage) error {
	if !packaged.verified || packaged.receipt.Format != RuntimeBindingStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "runtime-binding" || packaged.installationAuthority == "" || packaged.receipt.InstallationAuthority != packaged.installationAuthority || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) || len(packaged.objects) != 3 || len(packaged.receipt.Credentials) != 3 {
		return errors.New("runtime binding credential package identity is incomplete")
	}
	identity, err := json.Marshal(runtimeBindingStageCredentialPackageIdentity{
		StagePackageDigest: packaged.receipt.StagePackageDigest, WorkloadBindingDigest: packaged.receipt.WorkloadBindingDigest,
		InstallationAuthority: packaged.receipt.InstallationAuthority,
		MaterializedAt:        packaged.receipt.MaterializedAt, Credentials: packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("runtime binding credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return errors.New("runtime binding credential materialization time is invalid")
	}
	expectedRoles := []string{"ledger-writer", "persistence-writer", "workload-observer"}
	expectedAuthorities := []string{packaged.installationAuthority, packaged.installationAuthority, packaged.workloadAuthority}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Credentials[index]
		if object.role != expectedRoles[index] || receipt.Role != expectedRoles[index] || object.authority != expectedAuthorities[index] || receipt.Authority != expectedAuthorities[index] || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("runtime binding credential object identity changed after verification")
		}
	}
	var workloadSecret map[string]any
	if err := jsonstrict.Decode(packaged.objects[2].raw, &workloadSecret); err != nil {
		return errors.New("runtime binding workload credential is invalid")
	}
	data, ok := workloadSecret["data"].(map[string]any)
	if !ok {
		return errors.New("runtime binding workload credential data is missing")
	}
	bindingEncoded, ok := data["binding.json"].(string)
	if !ok {
		return errors.New("runtime binding workload authority is missing")
	}
	bindingRaw, err := base64.StdEncoding.DecodeString(bindingEncoded)
	if err != nil {
		return errors.New("runtime binding workload authority encoding is invalid")
	}
	var binding WorkloadAuthorityBinding
	if err := jsonstrict.Decode(bindingRaw, &binding); err != nil {
		return errors.New("runtime binding workload authority is invalid")
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil || bindingDigest != packaged.receipt.WorkloadBindingDigest || digest.SHA256([]byte(binding.TargetClusterUID)) != packaged.workloadAuthority {
		return errors.New("runtime binding workload authority identity changed after verification")
	}
	return nil
}
