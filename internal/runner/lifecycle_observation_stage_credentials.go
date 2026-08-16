package runner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const LifecycleObservationStageCredentialPackageFormat = "ok147-lifecycle-observation-stage-credential-package/v1"

type LifecycleObservationStageCredentialPackageConfig struct {
	Package             VerifiedLifecycleObservationStagePackage
	MaterializationTime time.Time
	Ledger              SubmissionStageCredentialSource
	ManagementObserver  SubmissionStageCredentialSource
}

type LifecycleObservationStageCredentialPackageReceipt struct {
	Format                   string                                   `json:"format"`
	State                    string                                   `json:"state"`
	StageID                  string                                   `json:"stageId"`
	ObservationPackageDigest string                                   `json:"observationPackageDigest"`
	InstallationAuthority    string                                   `json:"installationAuthority"`
	MaterializedAt           string                                   `json:"materializedAt"`
	PackageDigest            string                                   `json:"packageDigest"`
	Credentials              []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed          bool                                     `json:"mutationAllowed"`
}

type lifecycleObservationStageCredentialPackageIdentity struct {
	ObservationPackageDigest string                                   `json:"observationPackageDigest"`
	InstallationAuthority    string                                   `json:"installationAuthority"`
	MaterializedAt           string                                   `json:"materializedAt"`
	Credentials              []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedLifecycleObservationStageCredentialPackage retains the two exact
// immutable Secret objects privately for a later installer boundary. Its
// public receipt contains neither token, CA, subject nor source path.
type VerifiedLifecycleObservationStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               LifecycleObservationStageCredentialPackageReceipt
	installationAuthority string
	verified              bool
}

// BuildLifecycleObservationStageCredentialPackage verifies two independently
// obtained short-lived TokenRequest results and creates the private ledger and
// read-only management observer Secrets entirely offline.
func BuildLifecycleObservationStageCredentialPackage(config LifecycleObservationStageCredentialPackageConfig) (VerifiedLifecycleObservationStageCredentialPackage, error) {
	packageReceipt, err := config.Package.Receipt()
	if err != nil || config.Package.managementAuthority == "" || config.Package.ledgerCredential == "" || config.Package.managementCredential == "" {
		return VerifiedLifecycleObservationStageCredentialPackage{}, errors.New("verified lifecycle observation package is required")
	}
	if config.Package.ledgerCredential == config.Package.managementCredential {
		return VerifiedLifecycleObservationStageCredentialPackage{}, errors.New("lifecycle observation credential names must be distinct")
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedLifecycleObservationStageCredentialPackage{}, errors.New("lifecycle observation credential materialization time is required")
	}
	bindings := []struct {
		role   string
		name   string
		source SubmissionStageCredentialSource
	}{
		{role: "ledger", name: config.Package.ledgerCredential, source: config.Ledger},
		{role: "observer", name: config.Package.managementCredential, source: config.ManagementObserver},
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
			return VerifiedLifecycleObservationStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, receipt)
		tokens = append(tokens, token)
	}
	if len(tokens[0]) == len(tokens[1]) && subtle.ConstantTimeCompare(tokens[0], tokens[1]) == 1 {
		return VerifiedLifecycleObservationStageCredentialPackage{}, errors.New("lifecycle observation ledger and observer credentials must be distinct")
	}
	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	identity, err := json.Marshal(lifecycleObservationStageCredentialPackageIdentity{
		ObservationPackageDigest: packageReceipt.PackageDigest,
		InstallationAuthority:    config.Package.managementAuthority,
		MaterializedAt:           materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedLifecycleObservationStageCredentialPackage{}, errors.New("encode lifecycle observation credential package identity")
	}
	receipt := LifecycleObservationStageCredentialPackageReceipt{
		Format: LifecycleObservationStageCredentialPackageFormat, State: "VERIFIED", StageID: packageReceipt.StageID,
		ObservationPackageDigest: packageReceipt.PackageDigest, InstallationAuthority: config.Package.managementAuthority,
		MaterializedAt: materializedAt, PackageDigest: digest.SHA256(identity), Credentials: receipts,
		MutationAllowed: false,
	}
	return VerifiedLifecycleObservationStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.managementAuthority, verified: true,
	}, nil
}

func (packaged VerifiedLifecycleObservationStageCredentialPackage) Receipt() (LifecycleObservationStageCredentialPackageReceipt, error) {
	if err := verifyLifecycleObservationStageCredentialPackage(packaged); err != nil {
		return LifecycleObservationStageCredentialPackageReceipt{}, errors.New("lifecycle observation credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func verifyLifecycleObservationStageCredentialPackage(packaged VerifiedLifecycleObservationStageCredentialPackage) error {
	if !packaged.verified || packaged.receipt.Format != LifecycleObservationStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "lifecycle-observation" || packaged.installationAuthority == "" || packaged.receipt.InstallationAuthority != packaged.installationAuthority || len(packaged.objects) != 2 || len(packaged.receipt.Credentials) != 2 {
		return errors.New("lifecycle observation credential package identity is incomplete")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.ObservationPackageDigest) {
		return errors.New("lifecycle observation package digest is invalid")
	}
	identity, err := json.Marshal(lifecycleObservationStageCredentialPackageIdentity{
		ObservationPackageDigest: packaged.receipt.ObservationPackageDigest,
		InstallationAuthority:    packaged.receipt.InstallationAuthority,
		MaterializedAt:           packaged.receipt.MaterializedAt,
		Credentials:              packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("lifecycle observation credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return errors.New("lifecycle observation credential materialization time is invalid")
	}
	expectedRoles := []string{"ledger", "observer"}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Credentials[index]
		if object.role != expectedRoles[index] || receipt.Role != expectedRoles[index] || object.role != receipt.Role || object.authority != packaged.installationAuthority || receipt.Authority != packaged.installationAuthority || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("lifecycle observation credential object identity changed after verification")
		}
	}
	return nil
}
