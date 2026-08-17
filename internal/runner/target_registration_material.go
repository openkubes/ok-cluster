package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	TargetRegistrationMaterialReceiptFormat      = "ok147-target-registration-material/v1"
	minimumTargetRegistrationCredentialRemaining = 30 * time.Minute
)

type TargetRegistrationMaterializeConfig struct {
	Bundle              VerifiedTargetRegistrationStageBundle
	Runtime             VerifiedRuntimeBindingMaterial
	Credential          VerifiedTargetCredentialMaterial
	MaterializationTime time.Time
}

// TargetRegistrationMaterialReceipt is deliberately safe for durable public
// evidence. It binds the inputs used for materialization, but never the
// endpoint, CA, token, raw runtime UIDs or digest of the resulting Secret.
type TargetRegistrationMaterialReceipt struct {
	Format                           string `json:"format"`
	State                            string `json:"state"`
	StageID                          string `json:"stageId"`
	PlanDigest                       string `json:"planDigest"`
	TargetIdentityDigest             string `json:"targetIdentityDigest"`
	ProjectDigest                    string `json:"projectDigest"`
	RegistrationTemplateDigest       string `json:"registrationTemplateDigest"`
	RuntimeBindingDigest             string `json:"runtimeBindingDigest"`
	CredentialIssueReceiptDigest     string `json:"credentialIssueReceiptDigest"`
	MaterializationBindingDigest     string `json:"materializationBindingDigest"`
	ExpiresAt                        string `json:"expiresAt"`
	CredentialBytesInReceipt         bool   `json:"credentialBytesInReceipt"`
	MaterializedSecretDigestRetained bool   `json:"materializedSecretDigestRetained"`
	MutationAllowed                  bool   `json:"mutationAllowed"`
}

// VerifiedTargetRegistrationMaterial keeps the credential-bearing Secret
// private to the runner package so only the immediately following bounded
// launcher can consume it. Its Receipt method exposes only redacted bindings.
type VerifiedTargetRegistrationMaterial struct {
	project              []byte
	registration         []byte
	registrationDigest   string
	receipt              TargetRegistrationMaterialReceipt
	targetIdentityDigest string
	authority            string
	expiresAt            time.Time
	verified             bool
}

type targetRegistrationTLSConfig struct {
	CAData   string `json:"caData"`
	Insecure bool   `json:"insecure"`
}

type targetRegistrationSecretConfig struct {
	BearerToken     string                      `json:"bearerToken"`
	TLSClientConfig targetRegistrationTLSConfig `json:"tlsClientConfig"`
}

type targetRegistrationSafeBinding struct {
	PlanDigest                   string `json:"planDigest"`
	TargetIdentityDigest         string `json:"targetIdentityDigest"`
	ProjectDigest                string `json:"projectDigest"`
	RegistrationTemplateDigest   string `json:"registrationTemplateDigest"`
	RuntimeBindingDigest         string `json:"runtimeBindingDigest"`
	CredentialIssueReceiptDigest string `json:"credentialIssueReceiptDigest"`
}

// BuildTargetRegistrationMaterial replaces the six explicitly bound runtime
// placeholders in memory. It performs no API request and writes no file.
func BuildTargetRegistrationMaterial(config TargetRegistrationMaterializeConfig) (VerifiedTargetRegistrationMaterial, error) {
	if config.MaterializationTime.IsZero() || config.MaterializationTime.Location() != time.UTC {
		return VerifiedTargetRegistrationMaterial{}, errors.New("target-registration materialization time must be UTC")
	}
	if err := verifyTargetRegistrationStageBundle(config.Bundle); err != nil {
		return VerifiedTargetRegistrationMaterial{}, err
	}
	if err := verifyRuntimeBindingMaterial(config.Runtime); err != nil {
		return VerifiedTargetRegistrationMaterial{}, err
	}
	credentialReceipt, err := config.Credential.Receipt()
	if err != nil {
		return VerifiedTargetRegistrationMaterial{}, err
	}
	bundle, runtime := config.Bundle, config.Runtime
	if runtime.material.PlanDigest != bundle.plan.PlanDigest ||
		runtime.material.IntentRevision != bundle.plan.IntentRevision ||
		runtime.material.EnablementRevision != bundle.plan.EnablementRevision ||
		runtime.material.PlatformRevision != bundle.plan.PlatformRevision ||
		runtime.material.ExecutionFixture != bundle.plan.ExecutionFixture ||
		runtime.material.Target.Name != bundle.plan.ContractIdentity.Name ||
		runtime.material.Target.TargetIdentityScheme != "capi-cluster-uid/v1" {
		return VerifiedTargetRegistrationMaterial{}, errors.New("runtime binding differs from target-registration plan")
	}
	if digest.SHA256([]byte(runtime.material.Target.CAPIClusterUID)) != bundle.receipt.TargetIdentityDigest ||
		credentialReceipt.TargetIdentityDigest != bundle.receipt.TargetIdentityDigest ||
		config.Credential.targetIdentity != bundle.receipt.TargetIdentityDigest {
		return VerifiedTargetRegistrationMaterial{}, errors.New("target-registration target identity differs")
	}
	if config.Credential.endpoint != runtime.material.Target.WorkloadAPIEndpoint ||
		digest.SHA256(config.Credential.caBundle) != runtime.material.Target.WorkloadAPICADigest ||
		base64.StdEncoding.EncodeToString(config.Credential.caBundle) != runtime.material.Target.WorkloadAPICAData {
		return VerifiedTargetRegistrationMaterial{}, errors.New("target-registration credential authority differs from runtime binding")
	}
	issuedAt, err := time.Parse(time.RFC3339, credentialReceipt.IssuedAt)
	if err != nil || !config.Credential.expiresAt.Equal(mustParseTargetRegistrationTime(credentialReceipt.ExpiresAt)) ||
		config.MaterializationTime.Before(issuedAt) || config.Credential.expiresAt.Sub(config.MaterializationTime) < minimumTargetRegistrationCredentialRemaining {
		return VerifiedTargetRegistrationMaterial{}, errors.New("target-registration credential validity window is insufficient")
	}

	registration, err := decodeTargetRegistrationTemplate(bundle.projection.Registration.Raw)
	if err != nil {
		return VerifiedTargetRegistrationMaterial{}, err
	}
	metadata := registration["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	stringData := registration["stringData"].(map[string]any)
	annotations["openkubes.io/capi-cluster-uid"] = runtime.material.Target.CAPIClusterUID
	annotations["openkubes.io/workload-kube-system-uid"] = runtime.material.Target.KubeSystemUID
	annotations["openkubes.io/workload-api-ca-sha256"] = runtime.material.Target.WorkloadAPICADigest
	annotations["openkubes.io/token-expiration"] = credentialReceipt.ExpiresAt
	stringData["server"] = runtime.material.Target.WorkloadAPIEndpoint
	secretConfig, err := json.Marshal(targetRegistrationSecretConfig{
		BearerToken:     string(config.Credential.token),
		TLSClientConfig: targetRegistrationTLSConfig{CAData: runtime.material.Target.WorkloadAPICAData, Insecure: false},
	})
	if err != nil {
		return VerifiedTargetRegistrationMaterial{}, errors.New("encode target-registration credential config")
	}
	stringData["config"] = string(secretConfig)
	registrationRaw, err := canonicalTargetRegistrationValue(registration)
	if err != nil {
		return VerifiedTargetRegistrationMaterial{}, errors.New("canonicalize target-registration Secret")
	}
	credentialReceiptRaw, err := canonicalTargetRegistrationValue(credentialReceipt)
	if err != nil {
		return VerifiedTargetRegistrationMaterial{}, errors.New("canonicalize target-credential receipt")
	}
	binding := targetRegistrationSafeBinding{
		PlanDigest: bundle.plan.PlanDigest, TargetIdentityDigest: bundle.receipt.TargetIdentityDigest,
		ProjectDigest: bundle.receipt.ProjectDigest, RegistrationTemplateDigest: bundle.receipt.RegistrationTemplateDigest,
		RuntimeBindingDigest:         runtime.receipt.PrivateMaterialDigest,
		CredentialIssueReceiptDigest: digest.SHA256(credentialReceiptRaw),
	}
	bindingRaw, err := canonicalTargetRegistrationValue(binding)
	if err != nil {
		return VerifiedTargetRegistrationMaterial{}, errors.New("canonicalize target-registration binding")
	}
	receipt := TargetRegistrationMaterialReceipt{
		Format: TargetRegistrationMaterialReceiptFormat, State: "VERIFIED", StageID: "target-registration",
		PlanDigest: binding.PlanDigest, TargetIdentityDigest: binding.TargetIdentityDigest,
		ProjectDigest: binding.ProjectDigest, RegistrationTemplateDigest: binding.RegistrationTemplateDigest,
		RuntimeBindingDigest: binding.RuntimeBindingDigest, CredentialIssueReceiptDigest: binding.CredentialIssueReceiptDigest,
		MaterializationBindingDigest: digest.SHA256(bindingRaw), ExpiresAt: credentialReceipt.ExpiresAt,
		CredentialBytesInReceipt: false, MaterializedSecretDigestRetained: false, MutationAllowed: false,
	}
	return VerifiedTargetRegistrationMaterial{
		project: append([]byte(nil), bundle.projection.Project.Raw...), registration: registrationRaw,
		registrationDigest: digest.SHA256(registrationRaw), receipt: receipt,
		targetIdentityDigest: bundle.receipt.TargetIdentityDigest, authority: bundle.receipt.Authority,
		expiresAt: config.Credential.expiresAt, verified: true,
	}, nil
}

func (material VerifiedTargetRegistrationMaterial) Receipt() (TargetRegistrationMaterialReceipt, error) {
	if err := verifyTargetRegistrationMaterial(material); err != nil {
		return TargetRegistrationMaterialReceipt{}, err
	}
	return material.receipt, nil
}

func verifyTargetRegistrationMaterial(material VerifiedTargetRegistrationMaterial) error {
	if !material.verified || material.receipt.Format != TargetRegistrationMaterialReceiptFormat ||
		material.receipt.State != "VERIFIED" || material.receipt.StageID != "target-registration" ||
		material.receipt.CredentialBytesInReceipt || material.receipt.MaterializedSecretDigestRetained || material.receipt.MutationAllowed ||
		material.authority == "" || material.targetIdentityDigest != material.receipt.TargetIdentityDigest {
		return errors.New("target-registration material was not produced by verification")
	}
	for _, value := range []string{
		material.receipt.PlanDigest, material.receipt.TargetIdentityDigest, material.receipt.ProjectDigest,
		material.receipt.RegistrationTemplateDigest, material.receipt.RuntimeBindingDigest,
		material.receipt.CredentialIssueReceiptDigest, material.receipt.MaterializationBindingDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("target-registration material digest identity is invalid")
		}
	}
	if digest.SHA256(material.project) != material.receipt.ProjectDigest ||
		digest.SHA256(material.registration) != material.registrationDigest || material.registrationDigest == material.receipt.RegistrationTemplateDigest {
		return errors.New("target-registration material changed after verification")
	}
	expiresAt, err := time.Parse(time.RFC3339, material.receipt.ExpiresAt)
	if err != nil || !expiresAt.Equal(material.expiresAt) {
		return errors.New("target-registration material expiration is invalid")
	}
	bindingRaw, err := canonicalTargetRegistrationValue(targetRegistrationSafeBinding{
		PlanDigest: material.receipt.PlanDigest, TargetIdentityDigest: material.receipt.TargetIdentityDigest,
		ProjectDigest: material.receipt.ProjectDigest, RegistrationTemplateDigest: material.receipt.RegistrationTemplateDigest,
		RuntimeBindingDigest:         material.receipt.RuntimeBindingDigest,
		CredentialIssueReceiptDigest: material.receipt.CredentialIssueReceiptDigest,
	})
	if err != nil || digest.SHA256(bindingRaw) != material.receipt.MaterializationBindingDigest {
		return errors.New("target-registration material binding changed after verification")
	}
	return nil
}

func decodeTargetRegistrationTemplate(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("decode target-registration Secret template")
	}
	metadata, metadataOK := value["metadata"].(map[string]any)
	annotations, annotationsOK := metadata["annotations"].(map[string]any)
	stringData, stringDataOK := value["stringData"].(map[string]any)
	if !metadataOK || !annotationsOK || !stringDataOK ||
		annotations["openkubes.io/capi-cluster-uid"] != submission.RegistrationCAPIUIDPlaceholder ||
		annotations["openkubes.io/workload-kube-system-uid"] != submission.RegistrationWorkloadUIDPlaceholder ||
		annotations["openkubes.io/workload-api-ca-sha256"] != submission.RegistrationCADigestPlaceholder ||
		annotations["openkubes.io/token-expiration"] != submission.RegistrationExpirationPlaceholder ||
		stringData["server"] != submission.RegistrationEndpointPlaceholder ||
		stringData["config"] != submission.RegistrationConfigPlaceholder {
		return nil, errors.New("target-registration runtime placeholders differ")
	}
	return value, nil
}

func canonicalTargetRegistrationValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return contract.JCS(decoded)
}

func mustParseTargetRegistrationTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}
