package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	FullRunExecutionActivationPackageFormat = "ok147-full-run-execution-activation-package/v1"
	maximumFullRunExecutionPackageBytes     = 2 * 1024 * 1024
)

type FullRunExecutionActivationPackageConfig struct {
	ManifestPath                 string
	IndependentEvidencePublicKey string
	ActivationSecret             string
	EvidenceAuthority            ObservabilityEvidenceAuthorityPackageConfig
	JobTemplate                  []byte
	JobTemplateDigest            string
	Job                          FullRunExecutionJobValues
}

type FullRunExecutionActivationPackageReceipt struct {
	Format                        string   `json:"format"`
	State                         string   `json:"state"`
	PackageDigest                 string   `json:"packageDigest"`
	ActivationSecret              string   `json:"activationSecret"`
	ActivationSecretObjectDigest  string   `json:"activationSecretObjectDigest"`
	EvidenceAuthoritySecret       string   `json:"evidenceAuthoritySecret"`
	EvidenceAuthorityObjectDigest string   `json:"evidenceAuthorityObjectDigest"`
	JobEnvelopeDigest             string   `json:"jobEnvelopeDigest"`
	JobTemplateDigest             string   `json:"jobTemplateDigest"`
	BundleDigest                  string   `json:"bundleDigest"`
	SourceManifestDigest          string   `json:"sourceManifestDigest"`
	ManifestDigest                string   `json:"manifestDigest"`
	PlanDigest                    string   `json:"planDigest"`
	EvidenceActivationDigest      string   `json:"evidenceActivationDigest"`
	EvidenceKeyID                 string   `json:"evidenceKeyId"`
	CollectorAuthorityDigest      string   `json:"collectorAuthorityDigest"`
	CollectorCADigest             string   `json:"collectorCaDigest"`
	ImageDigest                   string   `json:"imageDigest"`
	ManagementAuthority           string   `json:"managementAuthority"`
	PrivateFileCount              int      `json:"privateFileCount"`
	ObjectKinds                   []string `json:"objectKinds"`
	MutationAllowed               bool     `json:"mutationAllowed"`
}

type VerifiedFullRunExecutionActivationPackage struct {
	raw                 []byte
	receipt             FullRunExecutionActivationPackageReceipt
	managementAuthority string
	verified            bool
}

// BuildFullRunExecutionActivationPackage binds the executor Secret, the
// separately credentialed Evidence Authority Secret and their shared Job
// envelope into one locally verified installation unit.
func BuildFullRunExecutionActivationPackage(config FullRunExecutionActivationPackageConfig) (VerifiedFullRunExecutionActivationPackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedFullRunExecutionActivationPackage{}, errors.New("full-run activation Job template differs from expected identity")
	}
	if !submissionStageInputNamePattern.MatchString(config.ActivationSecret) || len(config.ActivationSecret) > 63 ||
		!strings.HasPrefix(config.ActivationSecret, "ok147-") || config.ActivationSecret == config.EvidenceAuthority.ActivationSecret {
		return VerifiedFullRunExecutionActivationPackage{}, errors.New("full-run activation Secret identity is invalid")
	}
	bundle, err := BuildFullRunExecutionBundle(FullRunExecutionBundleConfig{
		ManifestPath: config.ManifestPath, IndependentEvidencePublicKey: config.IndependentEvidencePublicKey,
	})
	if err != nil {
		return VerifiedFullRunExecutionActivationPackage{}, err
	}
	bundleReceipt, err := bundle.Receipt()
	if err != nil {
		return VerifiedFullRunExecutionActivationPackage{}, err
	}
	config.EvidenceAuthority.ManifestPath = config.ManifestPath
	evidence, err := BuildObservabilityEvidenceAuthorityPackage(config.EvidenceAuthority)
	if err != nil {
		return VerifiedFullRunExecutionActivationPackage{}, err
	}
	evidenceReceipt, err := evidence.Receipt()
	if err != nil || evidenceReceipt.ManifestDigest != bundleReceipt.SourceManifestDigest || evidenceReceipt.EvidenceKeyID != bundleReceipt.EvidenceKeyID {
		return VerifiedFullRunExecutionActivationPackage{}, errors.New("full-run Evidence Authority differs from executor identity")
	}
	evidenceRaw, err := evidence.PrivateBytes()
	if err != nil {
		return VerifiedFullRunExecutionActivationPackage{}, err
	}
	binaryData := map[string]string{fullRunExecutionBundleIndexName: base64.StdEncoding.EncodeToString(bundle.indexRaw)}
	for path, raw := range bundle.files {
		binaryData[strings.ReplaceAll(path, "/", ".")] = base64.StdEncoding.EncodeToString(raw)
	}
	secret := postRuntimeActivationSecret{
		APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque", BinaryData: binaryData,
		Metadata: postRuntimeActivationSecretMetadata{
			Name: config.ActivationSecret, Namespace: submissionStageInputNamespace,
			Labels:      map[string]string{"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "full-run"},
			Annotations: map[string]string{"openkubes.io/bundle-digest": bundleReceipt.BundleDigest, "openkubes.io/manifest-digest": bundleReceipt.ManifestDigest},
		},
	}
	secretRaw, err := json.Marshal(secret)
	if err != nil || len(secretRaw) > maximumPostRuntimeExecutionSecretBytes {
		return VerifiedFullRunExecutionActivationPackage{}, errors.New("full-run activation Secret exceeds bounded object size")
	}
	document, _, err := loadFullRunExecutionManifest(config.ManifestPath)
	if err != nil {
		return VerifiedFullRunExecutionActivationPackage{}, errors.New("reload full-run source manifest")
	}
	values := config.Job
	values.ActivationSecret, values.EvidenceAuthoritySecret = config.ActivationSecret, config.EvidenceAuthority.ActivationSecret
	values.BundleDigest, values.ManifestDigest = bundleReceipt.BundleDigest, bundleReceipt.ManifestDigest
	values.EvidenceActivationDigest, values.EvidenceKeyID = evidenceReceipt.ActivationDigest, evidenceReceipt.EvidenceKeyID
	values.CollectorCADigest = evidenceReceipt.CollectorCADigest
	values.InfrastructureAPIURL = document.ProviderPrerequisites.Authority.Endpoint
	values.ManagementAPIURL = document.ClusterLifecycle.Authority.Endpoint
	values.ArgoAPIURL = document.TargetRegistration.GitOps.Endpoint
	values.AuthorizationAPIURL = document.Authorization.Endpoint
	values.CollectorAPIURL = config.EvidenceAuthority.CollectorEndpoint
	jobRaw, err := RenderFullRunExecutionJobTemplate(config.JobTemplate, values)
	if err != nil {
		return VerifiedFullRunExecutionActivationPackage{}, err
	}
	packageRaw := bytes.Join([][]byte{secretRaw, evidenceRaw, jobRaw}, []byte("\n---\n"))
	if len(packageRaw) > maximumFullRunExecutionPackageBytes {
		return VerifiedFullRunExecutionActivationPackage{}, errors.New("full-run activation package exceeds size limit")
	}
	receipt := FullRunExecutionActivationPackageReceipt{
		Format: FullRunExecutionActivationPackageFormat, State: "VERIFIED", PackageDigest: digest.SHA256(packageRaw),
		ActivationSecret: config.ActivationSecret, ActivationSecretObjectDigest: digest.SHA256(secretRaw),
		EvidenceAuthoritySecret: config.EvidenceAuthority.ActivationSecret, EvidenceAuthorityObjectDigest: digest.SHA256(evidenceRaw),
		JobEnvelopeDigest: digest.SHA256(jobRaw), JobTemplateDigest: config.JobTemplateDigest,
		BundleDigest: bundleReceipt.BundleDigest, SourceManifestDigest: bundleReceipt.SourceManifestDigest,
		ManifestDigest: bundleReceipt.ManifestDigest, PlanDigest: bundleReceipt.PlanDigest,
		EvidenceActivationDigest: evidenceReceipt.ActivationDigest, EvidenceKeyID: evidenceReceipt.EvidenceKeyID,
		CollectorAuthorityDigest: evidenceReceipt.CollectorAuthorityDigest, CollectorCADigest: evidenceReceipt.CollectorCADigest,
		ImageDigest:         config.Job.ImageDigest,
		ManagementAuthority: document.Plan.Expected.ManagementAuthority,
		PrivateFileCount:    len(bundle.files) + evidenceReceipt.PrivateFileCount,
		ObjectKinds:         []string{"Secret", "Secret", "NetworkPolicy", "Job"}, MutationAllowed: false,
	}
	return VerifiedFullRunExecutionActivationPackage{
		raw: packageRaw, receipt: receipt, managementAuthority: document.Plan.Expected.ManagementAuthority, verified: true,
	}, nil
}

func (packaged VerifiedFullRunExecutionActivationPackage) PrivateBytes() ([]byte, error) {
	if err := verifyFullRunExecutionActivationPackage(packaged); err != nil {
		return nil, errors.New("full-run activation package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedFullRunExecutionActivationPackage) Receipt() (FullRunExecutionActivationPackageReceipt, error) {
	if err := verifyFullRunExecutionActivationPackage(packaged); err != nil {
		return FullRunExecutionActivationPackageReceipt{}, errors.New("full-run activation package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyFullRunExecutionActivationPackage(packaged VerifiedFullRunExecutionActivationPackage) error {
	receipt := packaged.receipt
	if !packaged.verified || receipt.Format != FullRunExecutionActivationPackageFormat || receipt.State != "VERIFIED" || receipt.MutationAllowed ||
		len(packaged.raw) == 0 || digest.SHA256(packaged.raw) != receipt.PackageDigest || receipt.ActivationSecret == receipt.EvidenceAuthoritySecret ||
		receipt.ManagementAuthority == "" || receipt.ManagementAuthority != packaged.managementAuthority ||
		receipt.PrivateFileCount != len(fullRunExecutionBundleFiles)+len(observabilityEvidenceAuthorityProjectedFiles) ||
		len(receipt.ObjectKinds) != 4 || receipt.ObjectKinds[0] != "Secret" || receipt.ObjectKinds[1] != "Secret" ||
		receipt.ObjectKinds[2] != "NetworkPolicy" || receipt.ObjectKinds[3] != "Job" {
		return errors.New("full-run activation package identity is incomplete")
	}
	for _, identity := range []string{
		receipt.PackageDigest, receipt.ActivationSecretObjectDigest, receipt.EvidenceAuthorityObjectDigest,
		receipt.JobEnvelopeDigest, receipt.JobTemplateDigest, receipt.BundleDigest, receipt.SourceManifestDigest,
		receipt.ManifestDigest, receipt.PlanDigest, receipt.EvidenceActivationDigest, receipt.EvidenceKeyID,
		receipt.CollectorAuthorityDigest, receipt.CollectorCADigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(identity) {
			return errors.New("full-run activation package digest identity is incomplete")
		}
	}
	if !capabilityImageDigestPattern.MatchString(receipt.ImageDigest) {
		return errors.New("full-run activation package image identity is incomplete")
	}
	parts := bytes.SplitN(packaged.raw, []byte("\n---\n"), 3)
	if len(parts) != 3 || digest.SHA256(parts[0]) != receipt.ActivationSecretObjectDigest ||
		digest.SHA256(parts[1]) != receipt.EvidenceAuthorityObjectDigest || digest.SHA256(parts[2]) != receipt.JobEnvelopeDigest {
		return errors.New("full-run activation package components changed")
	}
	return nil
}
