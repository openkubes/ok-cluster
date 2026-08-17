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

const NetworkObservationStageCredentialPackageFormat = "ok147-network-observation-stage-credential-package/v1"

type NetworkObservationStageCredentialPackageConfig struct {
	Package             VerifiedNetworkObservationStagePackage
	MaterializationTime time.Time
	WorkloadBindingPath string
	Ledger              SubmissionStageCredentialSource
	ManagementObserver  SubmissionStageCredentialSource
	WorkloadObserver    SubmissionStageCredentialSource
}

type NetworkObservationStageCredentialPackageReceipt struct {
	Format                   string                                   `json:"format"`
	State                    string                                   `json:"state"`
	StageID                  string                                   `json:"stageId"`
	ObservationPackageDigest string                                   `json:"observationPackageDigest"`
	WorkloadBindingDigest    string                                   `json:"workloadBindingDigest"`
	InstallationAuthority    string                                   `json:"installationAuthority"`
	MaterializedAt           string                                   `json:"materializedAt"`
	PackageDigest            string                                   `json:"packageDigest"`
	Credentials              []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed          bool                                     `json:"mutationAllowed"`
}

type networkObservationStageCredentialPackageIdentity struct {
	ObservationPackageDigest string                                   `json:"observationPackageDigest"`
	WorkloadBindingDigest    string                                   `json:"workloadBindingDigest"`
	InstallationAuthority    string                                   `json:"installationAuthority"`
	MaterializedAt           string                                   `json:"materializedAt"`
	Credentials              []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedNetworkObservationStageCredentialPackage retains three exact
// immutable Secrets privately. The workload Secret additionally carries the
// private workload binding; no private bytes or source paths enter its receipt.
type VerifiedNetworkObservationStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               NetworkObservationStageCredentialPackageReceipt
	installationAuthority string
	workloadAuthority     string
	verified              bool
}

// BuildNetworkObservationStageCredentialPackage verifies three independent,
// short-lived TokenRequest results and the package-bound workload identity.
// It creates private Secret bytes entirely offline and performs no API call.
func BuildNetworkObservationStageCredentialPackage(config NetworkObservationStageCredentialPackageConfig) (VerifiedNetworkObservationStageCredentialPackage, error) {
	packageReceipt, err := config.Package.Receipt()
	if err != nil || packageReceipt.StageID != "network-observation" {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("verified network observation package is required")
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("network observation credential materialization time is required")
	}
	binding, err := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, packageReceipt.WorkloadBindingDigest)
	if err != nil {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("verify private network observation workload binding")
	}
	if binding.IntentRevision != config.Package.intentRevision || binding.Endpoint != config.Package.workloadEndpoint || binding.CABundleDigest != config.Package.workloadCABundle || digest.SHA256([]byte(binding.TargetClusterUID)) != config.Package.workloadAuthority {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("network observation workload binding differs from verified package")
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
			return VerifiedNetworkObservationStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, receipt)
		tokens = append(tokens, token)
	}
	for left := range tokens {
		for right := left + 1; right < len(tokens); right++ {
			if len(tokens[left]) == len(tokens[right]) && subtle.ConstantTimeCompare(tokens[left], tokens[right]) == 1 {
				return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("network observation credentials must be pairwise distinct")
			}
		}
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("encode private network observation workload binding")
	}
	var workloadSecret map[string]any
	if err := jsonstrict.Decode(objects[2].raw, &workloadSecret); err != nil {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("decode private workload credential Secret")
	}
	data, ok := workloadSecret["data"].(map[string]any)
	if !ok {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("private workload credential Secret data is missing")
	}
	data["binding.json"] = base64.StdEncoding.EncodeToString(bindingRaw)
	objects[2].raw, err = json.Marshal(workloadSecret)
	if err != nil || len(objects[2].raw) > maximumStageCredentialObjectBytes {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("network observation workload credential Secret exceeds accepted size")
	}
	receipts[2].ObjectDigest = digest.SHA256(objects[2].raw)

	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	identity, err := json.Marshal(networkObservationStageCredentialPackageIdentity{
		ObservationPackageDigest: packageReceipt.PackageDigest,
		WorkloadBindingDigest:    packageReceipt.WorkloadBindingDigest,
		InstallationAuthority:    config.Package.managementAuthority,
		MaterializedAt:           materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedNetworkObservationStageCredentialPackage{}, errors.New("encode network observation credential package identity")
	}
	receipt := NetworkObservationStageCredentialPackageReceipt{
		Format: NetworkObservationStageCredentialPackageFormat, State: "VERIFIED", StageID: packageReceipt.StageID,
		ObservationPackageDigest: packageReceipt.PackageDigest, WorkloadBindingDigest: packageReceipt.WorkloadBindingDigest,
		InstallationAuthority: config.Package.managementAuthority, MaterializedAt: materializedAt,
		PackageDigest: digest.SHA256(identity), Credentials: receipts, MutationAllowed: false,
	}
	return VerifiedNetworkObservationStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.managementAuthority,
		workloadAuthority:     config.Package.workloadAuthority, verified: true,
	}, nil
}

func (packaged VerifiedNetworkObservationStageCredentialPackage) Receipt() (NetworkObservationStageCredentialPackageReceipt, error) {
	if err := verifyNetworkObservationStageCredentialPackage(packaged); err != nil {
		return NetworkObservationStageCredentialPackageReceipt{}, errors.New("network observation credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func verifyNetworkObservationStageCredentialPackage(packaged VerifiedNetworkObservationStageCredentialPackage) error {
	if !packaged.verified || packaged.receipt.Format != NetworkObservationStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.receipt.StageID != "network-observation" || packaged.installationAuthority == "" || packaged.receipt.InstallationAuthority != packaged.installationAuthority || !stageReceiptPrefixDigestPattern.MatchString(packaged.workloadAuthority) || len(packaged.objects) != 3 || len(packaged.receipt.Credentials) != 3 {
		return errors.New("network observation credential package identity is incomplete")
	}
	identity, err := json.Marshal(networkObservationStageCredentialPackageIdentity{
		ObservationPackageDigest: packaged.receipt.ObservationPackageDigest,
		WorkloadBindingDigest:    packaged.receipt.WorkloadBindingDigest,
		InstallationAuthority:    packaged.receipt.InstallationAuthority,
		MaterializedAt:           packaged.receipt.MaterializedAt, Credentials: packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest {
		return errors.New("network observation credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return errors.New("network observation credential materialization time is invalid")
	}
	expectedRoles := []string{"ledger", "management-observer", "workload-observer"}
	expectedAuthorities := []string{packaged.installationAuthority, packaged.installationAuthority, packaged.workloadAuthority}
	for index, object := range packaged.objects {
		receipt := packaged.receipt.Credentials[index]
		if object.role != expectedRoles[index] || receipt.Role != expectedRoles[index] || object.authority != expectedAuthorities[index] || receipt.Authority != expectedAuthorities[index] || object.name != receipt.Name || receipt.Namespace != submissionStageInputNamespace || digest.SHA256(object.raw) != receipt.ObjectDigest {
			return errors.New("network observation credential object identity changed after verification")
		}
	}
	var workloadSecret map[string]any
	if err := jsonstrict.Decode(packaged.objects[2].raw, &workloadSecret); err != nil {
		return errors.New("network observation workload credential is invalid")
	}
	data, ok := workloadSecret["data"].(map[string]any)
	if !ok {
		return errors.New("network observation workload credential data is missing")
	}
	bindingEncoded, ok := data["binding.json"].(string)
	if !ok {
		return errors.New("network observation workload binding is missing")
	}
	bindingRaw, err := base64.StdEncoding.DecodeString(bindingEncoded)
	if err != nil {
		return errors.New("network observation workload binding encoding is invalid")
	}
	var binding WorkloadAuthorityBinding
	if err := jsonstrict.Decode(bindingRaw, &binding); err != nil {
		return errors.New("network observation workload binding is invalid")
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil || bindingDigest != packaged.receipt.WorkloadBindingDigest || digest.SHA256([]byte(binding.TargetClusterUID)) != packaged.workloadAuthority {
		return errors.New("network observation workload binding identity changed after verification")
	}
	return nil
}
