package runner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const EnablementStageCredentialPackageFormat = "ok147-enablement-stage-credential-package/v1"

type EnablementStageCredentialPackageConfig struct {
	Package             VerifiedEnablementStagePackage
	MaterializationTime time.Time
	Ledger              SubmissionStageCredentialSource
	ManagementWriter    SubmissionStageCredentialSource
}

type EnablementStageCredentialPackageReceipt struct {
	Format                  string                                   `json:"format"`
	State                   string                                   `json:"state"`
	StageID                 string                                   `json:"stageId"`
	EnablementPackageDigest string                                   `json:"enablementPackageDigest"`
	InstallationAuthority   string                                   `json:"installationAuthority"`
	MaterializedAt          string                                   `json:"materializedAt"`
	PackageDigest           string                                   `json:"packageDigest"`
	Credentials             []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed         bool                                     `json:"mutationAllowed"`
}

type enablementStageCredentialPackageIdentity struct {
	EnablementPackageDigest string                                   `json:"enablementPackageDigest"`
	InstallationAuthority   string                                   `json:"installationAuthority"`
	MaterializedAt          string                                   `json:"materializedAt"`
	Credentials             []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedEnablementStageCredentialPackage retains the two exact immutable
// Secret objects privately for a later installer boundary.
type VerifiedEnablementStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               EnablementStageCredentialPackageReceipt
	installationAuthority string
	verified              bool
}

// BuildEnablementStageCredentialPackage verifies two independently obtained
// short-lived TokenRequest results entirely offline. It exposes no Secret
// bytes, token, CA, subject or source path.
func BuildEnablementStageCredentialPackage(config EnablementStageCredentialPackageConfig) (VerifiedEnablementStageCredentialPackage, error) {
	packageReceipt, err := config.Package.Receipt()
	if err != nil || config.Package.managementAuthority == "" || config.Package.ledgerCredential == "" || config.Package.managementCredential == "" {
		return VerifiedEnablementStageCredentialPackage{}, errors.New("verified enablement package is required")
	}
	if config.Package.ledgerCredential == config.Package.managementCredential {
		return VerifiedEnablementStageCredentialPackage{}, errors.New("enablement credential names must be distinct")
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedEnablementStageCredentialPackage{}, errors.New("enablement credential materialization time is required")
	}
	bindings := []struct {
		role   string
		name   string
		source SubmissionStageCredentialSource
	}{
		{role: "ledger", name: config.Package.ledgerCredential, source: config.Ledger},
		{role: "writer", name: config.Package.managementCredential, source: config.ManagementWriter},
	}
	objects := make([]submissionStageCredentialObject, 0, len(bindings))
	receipts := make([]SubmissionStageCredentialObjectReceipt, 0, len(bindings))
	tokens := make([][]byte, 0, len(bindings))
	for _, binding := range bindings {
		object, receipt, token, err := buildSubmissionStageCredentialObject(
			packageReceipt.StageID, config.MaterializationTime.UTC(), binding.role, binding.name,
			config.Package.managementAuthority, binding.source,
		)
		if err != nil {
			return VerifiedEnablementStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, receipt)
		tokens = append(tokens, token)
	}
	if len(tokens[0]) == len(tokens[1]) && subtle.ConstantTimeCompare(tokens[0], tokens[1]) == 1 {
		return VerifiedEnablementStageCredentialPackage{}, errors.New("enablement ledger and writer credentials must be distinct")
	}
	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	identity, err := json.Marshal(enablementStageCredentialPackageIdentity{
		EnablementPackageDigest: packageReceipt.PackageDigest, InstallationAuthority: config.Package.managementAuthority,
		MaterializedAt: materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedEnablementStageCredentialPackage{}, errors.New("encode enablement credential package identity")
	}
	receipt := EnablementStageCredentialPackageReceipt{
		Format: EnablementStageCredentialPackageFormat, State: "VERIFIED", StageID: packageReceipt.StageID,
		EnablementPackageDigest: packageReceipt.PackageDigest, InstallationAuthority: config.Package.managementAuthority,
		MaterializedAt: materializedAt, PackageDigest: digest.SHA256(identity), Credentials: receipts, MutationAllowed: false,
	}
	return VerifiedEnablementStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.managementAuthority, verified: true,
	}, nil
}

func (packaged VerifiedEnablementStageCredentialPackage) Receipt() (EnablementStageCredentialPackageReceipt, error) {
	if err := verifyEnablementStageCredentialPackage(packaged); err != nil {
		return EnablementStageCredentialPackageReceipt{}, errors.New("enablement credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func verifyEnablementStageCredentialPackage(packaged VerifiedEnablementStageCredentialPackage) error {
	if !packaged.verified || packaged.receipt.Format != EnablementStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "enablement" || packaged.installationAuthority == "" || packaged.receipt.InstallationAuthority != packaged.installationAuthority || len(packaged.objects) != 2 || len(packaged.receipt.Credentials) != 2 {
		return errors.New("enablement credential package identity is incomplete")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.EnablementPackageDigest) {
		return errors.New("enablement package digest is invalid")
	}
	identity, err := json.Marshal(enablementStageCredentialPackageIdentity{
		EnablementPackageDigest: packaged.receipt.EnablementPackageDigest,
		InstallationAuthority:   packaged.receipt.InstallationAuthority,
		MaterializedAt:          packaged.receipt.MaterializedAt, Credentials: packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("enablement credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return errors.New("enablement credential materialization time is invalid")
	}
	expectedRoles := []string{"ledger", "writer"}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Credentials[index]
		if object.role != expectedRoles[index] || receipt.Role != expectedRoles[index] || object.role != receipt.Role || object.authority != packaged.installationAuthority || receipt.Authority != packaged.installationAuthority || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("enablement credential object identity changed after verification")
		}
	}
	return nil
}
