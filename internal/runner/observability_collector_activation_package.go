package runner

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const (
	ObservabilityCollectorActivationFormat        = "ok147-observability-collector-activation/v1"
	ObservabilityCollectorActivationPackageFormat = "ok147-observability-collector-activation-package/v1"
	maximumObservabilityCollectorActivationBytes  = 512 * 1024

	observabilityCollectorActivationKey = "activation.json"
	observabilityCollectorWebhookKey    = "webhook-token"
	observabilityCollectorQueryKey      = "query-token"
	observabilityCollectorWorkloadKey   = "workload-token"
	observabilityCollectorWorkloadCAKey = "workload-ca.crt"
	observabilityCollectorTLSCertKey    = "tls.crt"
	observabilityCollectorTLSKeyKey     = "tls.key"

	observabilityCollectorRuntimeRoot = "/var/run/openkubes/collector"
	observabilityCollectorStateRoot   = "/var/lib/openkubes/observability-evidence"
	observabilityCollectorReceiver    = "ok147-independent-evidence"
	observabilityCollectorObserverSA  = "ok147-observability-autonomy"
)

// ObservabilityCollectorActivationPackageConfig binds the collector only
// after the workload runtime identity is durable. Construction performs local
// verification only and does not contact or mutate Kubernetes.
type ObservabilityCollectorActivationPackageConfig struct {
	ManifestPath           string
	ExpectedManifestDigest string
	ManifestReceiptPath    string
	ExpectedReceiptDigest  string
	RuntimeBinding         RuntimeBindingMaterialFileConfig
	ActivationSecret       string
	MaterializationTime    time.Time
	ObserverCredential     SubmissionStageCredentialSource
	WebhookTokenPath       string
	QueryTokenPath         string
	PublicEndpoint         string
	ListenAddress          string
	TLSCertificatePath     string
	TLSPrivateKeyPath      string
	MaximumRecordAge       time.Duration
}

type ObservabilityCollectorActivation struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	ManifestDigest            string `json:"manifestDigest"`
	ManifestReceiptDigest     string `json:"manifestReceiptDigest"`
	PlanDigest                string `json:"planDigest"`
	RuntimeBindingDigest      string `json:"runtimeBindingDigest"`
	ExecutionFixture          string `json:"executionFixture"`
	TargetClusterUID          string `json:"targetClusterUid"`
	WorkloadEndpoint          string `json:"workloadEndpoint"`
	WorkloadCADigest          string `json:"workloadCaDigest"`
	WorkloadTokenDigest       string `json:"workloadTokenDigest"`
	ObserverCredentialExpires string `json:"observerCredentialExpires"`
	ObserverEvidenceDigest    string `json:"observerEvidenceDigest"`
	WebhookAuthorityDigest    string `json:"webhookAuthorityDigest"`
	QueryAuthorityDigest      string `json:"queryAuthorityDigest"`
	PublicEndpoint            string `json:"publicEndpoint"`
	ListenAddress             string `json:"listenAddress"`
	TLSCertificateDigest      string `json:"tlsCertificateDigest"`
	ReceiverName              string `json:"receiverName"`
	ProfileDigest             string `json:"profileDigest"`
	MaximumRecordAge          string `json:"maximumRecordAge"`
	StateDirectory            string `json:"stateDirectory"`
	WebhookTokenPath          string `json:"webhookTokenPath"`
	QueryTokenPath            string `json:"queryTokenPath"`
	WorkloadTokenPath         string `json:"workloadTokenPath"`
	WorkloadCAPath            string `json:"workloadCaPath"`
	TLSCertificatePath        string `json:"tlsCertificatePath"`
	TLSPrivateKeyPath         string `json:"tlsPrivateKeyPath"`
}

type ObservabilityCollectorActivationPackageReceipt struct {
	Format                       string   `json:"format"`
	State                        string   `json:"state"`
	PackageDigest                string   `json:"packageDigest"`
	ActivationSecret             string   `json:"activationSecret"`
	SecretObjectDigest           string   `json:"secretObjectDigest"`
	ActivationDigest             string   `json:"activationDigest"`
	ManifestDigest               string   `json:"manifestDigest"`
	ManifestReceiptDigest        string   `json:"manifestReceiptDigest"`
	PlanDigest                   string   `json:"planDigest"`
	RuntimeBindingDigest         string   `json:"runtimeBindingDigest"`
	ExecutionFixture             string   `json:"executionFixture"`
	TargetClusterUIDDigest       string   `json:"targetClusterUidDigest"`
	WorkloadCADigest             string   `json:"workloadCaDigest"`
	ObserverCredentialExpires    string   `json:"observerCredentialExpires"`
	ObserverTokenRequestEvidence string   `json:"observerTokenRequestEvidence"`
	WebhookAuthorityDigest       string   `json:"webhookAuthorityDigest"`
	QueryAuthorityDigest         string   `json:"queryAuthorityDigest"`
	TLSCertificateDigest         string   `json:"tlsCertificateDigest"`
	PublicEndpointDigest         string   `json:"publicEndpointDigest"`
	ReceiverIdentityDigest       string   `json:"receiverIdentityDigest"`
	ProfileDigest                string   `json:"profileDigest"`
	PrivateFileCount             int      `json:"privateFileCount"`
	ObjectKinds                  []string `json:"objectKinds"`
	MutationAllowed              bool     `json:"mutationAllowed"`
}

type VerifiedObservabilityCollectorActivationPackage struct {
	raw      []byte
	receipt  ObservabilityCollectorActivationPackageReceipt
	verified bool
}

type observabilityCollectorObserverCredential struct {
	ExpiresAt                  string
	TokenRequestEvidenceDigest string
}

// BuildObservabilityCollectorActivationPackage creates one immutable private
// Secret containing the complete per-run collector activation. Raw target,
// endpoint, token, CA and key material never enter the public receipt.
func BuildObservabilityCollectorActivationPackage(config ObservabilityCollectorActivationPackageConfig) (VerifiedObservabilityCollectorActivationPackage, error) {
	if !submissionStageInputNamePattern.MatchString(config.ActivationSecret) || !strings.HasPrefix(config.ActivationSecret, "ok147-") ||
		len(config.ActivationSecret) > 63 || config.MaterializationTime.IsZero() ||
		!config.MaterializationTime.Equal(config.MaterializationTime.UTC().Truncate(time.Second)) {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector activation identity is invalid")
	}
	document, manifestDigest, err := loadFullRunExecutionManifest(config.ManifestPath)
	if err != nil || manifestDigest != config.ExpectedManifestDigest {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("verify observability collector full-run manifest")
	}
	manifestReceiptRaw, err := readBoundedRegular(config.ManifestReceiptPath, maximumRuntimeBindingMaterialFileBytes)
	if err != nil || digest.SHA256(manifestReceiptRaw) != config.ExpectedReceiptDigest {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("verify observability collector full-run manifest receipt")
	}
	var manifestReceipt FullRunExecutionManifestReceipt
	if err := jsonstrict.Decode(manifestReceiptRaw, &manifestReceipt); err != nil ||
		manifestReceipt.Format != FullRunExecutionManifestReceiptFormat || manifestReceipt.State != "VERIFIED" ||
		manifestReceipt.MutationAllowed || manifestReceipt.ManifestDigest != manifestDigest {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector manifest receipt is invalid")
	}
	expected := fullRunPlanExpected(document.Plan.Expected)
	plan, err := stageplan.Load(document.Plan.Path, expected)
	if err != nil || plan.PlanDigest != manifestReceipt.PlanDigest {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector manifest plan differs from receipt")
	}
	runtimeBinding, err := LoadRuntimeBindingMaterialFiles(config.RuntimeBinding)
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("verify observability collector runtime binding")
	}
	if config.RuntimeBinding.Bundle.PlanPath != document.Plan.Path ||
		config.RuntimeBinding.MaterialPath != document.RuntimeBinding.MaterialPath ||
		config.RuntimeBinding.ReceiptPath != document.RuntimeBinding.ReceiptPath {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector runtime binding paths differ from manifest")
	}
	runtimeReceipt, err := runtimeBinding.Receipt()
	if err != nil || runtimeReceipt.PlanDigest != manifestReceipt.PlanDigest ||
		runtimeBinding.material.ExecutionFixture != plan.ExecutionFixture {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector runtime binding differs from manifest")
	}
	targetAuthority := digest.SHA256([]byte(runtimeBinding.material.Target.CAPIClusterUID))
	expectedSubject := "system:serviceaccount:ok-observability:" + observabilityCollectorObserverSA
	if config.ObserverCredential.AuthorityIdentity != targetAuthority ||
		config.ObserverCredential.ExpectedSubject != expectedSubject ||
		len(config.ObserverCredential.ExpectedAudiences) != 1 ||
		config.ObserverCredential.ExpectedAudiences[0] != "https://kubernetes.default.svc" ||
		config.ObserverCredential.CABundleDigest != runtimeBinding.material.Target.WorkloadAPICADigest {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector observer credential identity is invalid")
	}
	observerReceipt, workloadToken, err := loadObservabilityCollectorObserverCredential(
		config.ObserverCredential, targetAuthority, expectedSubject, config.MaterializationTime.UTC(),
	)
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("verify observability collector observer credential")
	}
	workloadCA, err := readBoundedRegular(config.ObserverCredential.CAFile, maximumCABytes)
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("read observability collector workload CA")
	}
	expectedCA, err := base64.StdEncoding.Strict().DecodeString(runtimeBinding.material.Target.WorkloadAPICAData)
	if err != nil || !bytes.Equal(workloadCA, expectedCA) || digest.SHA256(workloadCA) != runtimeReceipt.WorkloadAPICADigest {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector workload CA differs from runtime binding")
	}
	webhookToken, err := readCollectorToken(config.WebhookTokenPath)
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("verify observability collector webhook authority")
	}
	queryToken, err := readCollectorToken(config.QueryTokenPath)
	if err != nil || subtle.ConstantTimeCompare(webhookToken, queryToken) == 1 ||
		subtle.ConstantTimeCompare(webhookToken, workloadToken) == 1 ||
		subtle.ConstantTimeCompare(queryToken, workloadToken) == 1 {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector authorities must be distinct")
	}
	certificateRaw, privateKeyRaw, certificateDigest, err := loadObservabilityCollectorTLS(
		config.TLSCertificatePath, config.TLSPrivateKeyPath, config.PublicEndpoint, config.MaterializationTime.UTC(),
	)
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, err
	}
	if err := validateObservabilityCollectorNetwork(config.PublicEndpoint, config.ListenAddress); err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, err
	}
	if config.MaximumRecordAge < time.Minute || config.MaximumRecordAge > maximumObservabilityIndependentEvidenceWindow {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector record age is invalid")
	}
	profile, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("load standard observability collector profile")
	}
	activation := ObservabilityCollectorActivation{
		Format: ObservabilityCollectorActivationFormat, State: "BOUND",
		ManifestDigest:        manifestReceipt.ManifestDigest,
		ManifestReceiptDigest: config.ExpectedReceiptDigest,
		PlanDigest:            manifestReceipt.PlanDigest,
		RuntimeBindingDigest:  runtimeReceipt.PrivateMaterialDigest, ExecutionFixture: plan.ExecutionFixture,
		TargetClusterUID:          runtimeBinding.material.Target.CAPIClusterUID,
		WorkloadEndpoint:          runtimeBinding.material.Target.WorkloadAPIEndpoint,
		WorkloadCADigest:          runtimeReceipt.WorkloadAPICADigest,
		WorkloadTokenDigest:       config.ObserverCredential.TokenDigest,
		ObserverCredentialExpires: observerReceipt.ExpiresAt,
		ObserverEvidenceDigest:    observerReceipt.TokenRequestEvidenceDigest,
		WebhookAuthorityDigest:    digest.SHA256(webhookToken),
		QueryAuthorityDigest:      digest.SHA256(queryToken),
		PublicEndpoint:            config.PublicEndpoint, ListenAddress: config.ListenAddress,
		TLSCertificateDigest: certificateDigest,
		ReceiverName:         observabilityCollectorReceiver, ProfileDigest: profile.Digest(),
		MaximumRecordAge: config.MaximumRecordAge.String(), StateDirectory: observabilityCollectorStateRoot,
		WebhookTokenPath:   observabilityCollectorRuntimeRoot + "/" + observabilityCollectorWebhookKey,
		QueryTokenPath:     observabilityCollectorRuntimeRoot + "/" + observabilityCollectorQueryKey,
		WorkloadTokenPath:  observabilityCollectorRuntimeRoot + "/" + observabilityCollectorWorkloadKey,
		WorkloadCAPath:     observabilityCollectorRuntimeRoot + "/" + observabilityCollectorWorkloadCAKey,
		TLSCertificatePath: observabilityCollectorRuntimeRoot + "/" + observabilityCollectorTLSCertKey,
		TLSPrivateKeyPath:  observabilityCollectorRuntimeRoot + "/" + observabilityCollectorTLSKeyKey,
	}
	activationRaw, err := canonicalObservabilityCollectorActivation(activation)
	if err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, err
	}
	binaryData := map[string]string{
		observabilityCollectorActivationKey: base64.StdEncoding.EncodeToString(activationRaw),
		observabilityCollectorWebhookKey:    base64.StdEncoding.EncodeToString(webhookToken),
		observabilityCollectorQueryKey:      base64.StdEncoding.EncodeToString(queryToken),
		observabilityCollectorWorkloadKey:   base64.StdEncoding.EncodeToString(workloadToken),
		observabilityCollectorWorkloadCAKey: base64.StdEncoding.EncodeToString(workloadCA),
		observabilityCollectorTLSCertKey:    base64.StdEncoding.EncodeToString(certificateRaw),
		observabilityCollectorTLSKeyKey:     base64.StdEncoding.EncodeToString(privateKeyRaw),
	}
	secret := postRuntimeActivationSecret{
		APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque", BinaryData: binaryData,
		Metadata: postRuntimeActivationSecretMetadata{
			Name: config.ActivationSecret, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok147-observability-evidence-collector",
				"openkubes.io/stage-id":  "independent-evidence",
			},
			Annotations: map[string]string{
				"openkubes.io/manifest-digest":   manifestReceipt.ManifestDigest,
				"openkubes.io/activation-digest": digest.SHA256(activationRaw),
			},
		},
	}
	raw, err := json.Marshal(secret)
	if err != nil || len(raw) == 0 || len(raw) > maximumObservabilityCollectorActivationBytes {
		return VerifiedObservabilityCollectorActivationPackage{}, errors.New("observability collector activation Secret exceeds bounded size")
	}
	receiverIdentity := digest.SHA256([]byte("ok147-observability-alert-receiver/v1\n" + observabilityCollectorReceiver))
	receipt := ObservabilityCollectorActivationPackageReceipt{
		Format: ObservabilityCollectorActivationPackageFormat, State: "VERIFIED",
		PackageDigest: digest.SHA256(raw), ActivationSecret: config.ActivationSecret, SecretObjectDigest: digest.SHA256(raw),
		ActivationDigest: digest.SHA256(activationRaw), ManifestDigest: manifestReceipt.ManifestDigest,
		ManifestReceiptDigest: config.ExpectedReceiptDigest,
		PlanDigest:            manifestReceipt.PlanDigest, RuntimeBindingDigest: runtimeReceipt.PrivateMaterialDigest,
		ExecutionFixture: plan.ExecutionFixture, TargetClusterUIDDigest: targetAuthority,
		WorkloadCADigest: runtimeReceipt.WorkloadAPICADigest, ObserverCredentialExpires: observerReceipt.ExpiresAt,
		ObserverTokenRequestEvidence: observerReceipt.TokenRequestEvidenceDigest,
		WebhookAuthorityDigest:       digest.SHA256(webhookToken), QueryAuthorityDigest: digest.SHA256(queryToken),
		TLSCertificateDigest: certificateDigest, PublicEndpointDigest: digest.SHA256([]byte(config.PublicEndpoint)),
		ReceiverIdentityDigest: receiverIdentity, ProfileDigest: profile.Digest(),
		PrivateFileCount: len(binaryData), ObjectKinds: []string{"Secret"}, MutationAllowed: false,
	}
	packaged := VerifiedObservabilityCollectorActivationPackage{raw: raw, receipt: receipt, verified: true}
	if err := verifyObservabilityCollectorActivationPackage(packaged); err != nil {
		return VerifiedObservabilityCollectorActivationPackage{}, err
	}
	return packaged, nil
}

func (packaged VerifiedObservabilityCollectorActivationPackage) PrivateBytes() ([]byte, error) {
	if err := verifyObservabilityCollectorActivationPackage(packaged); err != nil {
		return nil, errors.New("observability collector activation package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedObservabilityCollectorActivationPackage) Receipt() (ObservabilityCollectorActivationPackageReceipt, error) {
	if err := verifyObservabilityCollectorActivationPackage(packaged); err != nil {
		return ObservabilityCollectorActivationPackageReceipt{}, errors.New("observability collector activation package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyObservabilityCollectorActivationPackage(packaged VerifiedObservabilityCollectorActivationPackage) error {
	receipt := packaged.receipt
	if !packaged.verified || receipt.Format != ObservabilityCollectorActivationPackageFormat || receipt.State != "VERIFIED" ||
		receipt.MutationAllowed || len(packaged.raw) == 0 || digest.SHA256(packaged.raw) != receipt.PackageDigest ||
		receipt.SecretObjectDigest != receipt.PackageDigest || receipt.PrivateFileCount != 7 ||
		len(receipt.ObjectKinds) != 1 || receipt.ObjectKinds[0] != "Secret" {
		return errors.New("observability collector activation package identity is incomplete")
	}
	for _, value := range []string{
		receipt.ActivationDigest, receipt.ManifestDigest, receipt.ManifestReceiptDigest, receipt.PlanDigest, receipt.RuntimeBindingDigest,
		receipt.ExecutionFixture, receipt.TargetClusterUIDDigest, receipt.WorkloadCADigest,
		receipt.ObserverTokenRequestEvidence, receipt.WebhookAuthorityDigest, receipt.QueryAuthorityDigest,
		receipt.TLSCertificateDigest, receipt.PublicEndpointDigest, receipt.ReceiverIdentityDigest, receipt.ProfileDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("observability collector activation package digest is invalid")
		}
	}
	var secret postRuntimeActivationSecret
	if err := jsonstrict.Decode(packaged.raw, &secret); err != nil || secret.APIVersion != "v1" || secret.Kind != "Secret" ||
		!secret.Immutable || secret.Type != "Opaque" || secret.Metadata.Name != receipt.ActivationSecret ||
		secret.Metadata.Namespace != submissionStageInputNamespace || len(secret.BinaryData) != receipt.PrivateFileCount ||
		secret.Metadata.Labels["app.kubernetes.io/name"] != "ok147-observability-evidence-collector" ||
		secret.Metadata.Labels["openkubes.io/stage-id"] != "independent-evidence" ||
		secret.Metadata.Annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest ||
		secret.Metadata.Annotations["openkubes.io/activation-digest"] != receipt.ActivationDigest {
		return errors.New("observability collector activation Secret identity differs")
	}
	decode := func(key string) ([]byte, error) {
		raw, err := base64.StdEncoding.Strict().DecodeString(secret.BinaryData[key])
		if err != nil || len(raw) == 0 {
			return nil, errors.New("observability collector activation private file is invalid")
		}
		return raw, nil
	}
	activationRaw, err := decode(observabilityCollectorActivationKey)
	if err != nil || digest.SHA256(activationRaw) != receipt.ActivationDigest {
		return errors.New("observability collector activation identity differs")
	}
	var activation ObservabilityCollectorActivation
	if err := jsonstrict.Decode(activationRaw, &activation); err != nil {
		return errors.New("decode strict observability collector activation")
	}
	canonical, err := canonicalObservabilityCollectorActivation(activation)
	if err != nil || !bytes.Equal(canonical, activationRaw) || activation.ManifestDigest != receipt.ManifestDigest ||
		activation.ManifestReceiptDigest != receipt.ManifestReceiptDigest ||
		activation.PlanDigest != receipt.PlanDigest || activation.RuntimeBindingDigest != receipt.RuntimeBindingDigest ||
		activation.ExecutionFixture != receipt.ExecutionFixture ||
		digest.SHA256([]byte(activation.TargetClusterUID)) != receipt.TargetClusterUIDDigest ||
		activation.WorkloadCADigest != receipt.WorkloadCADigest ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.WorkloadTokenDigest) ||
		activation.ObserverCredentialExpires != receipt.ObserverCredentialExpires ||
		activation.ObserverEvidenceDigest != receipt.ObserverTokenRequestEvidence ||
		activation.WebhookAuthorityDigest != receipt.WebhookAuthorityDigest ||
		activation.QueryAuthorityDigest != receipt.QueryAuthorityDigest ||
		digest.SHA256([]byte(activation.PublicEndpoint)) != receipt.PublicEndpointDigest ||
		activation.TLSCertificateDigest != receipt.TLSCertificateDigest ||
		activation.ProfileDigest != receipt.ProfileDigest ||
		digest.SHA256([]byte("ok147-observability-alert-receiver/v1\n"+activation.ReceiverName)) != receipt.ReceiverIdentityDigest {
		return errors.New("observability collector activation differs from receipt")
	}
	webhook, webhookErr := decode(observabilityCollectorWebhookKey)
	query, queryErr := decode(observabilityCollectorQueryKey)
	workloadToken, workloadErr := decode(observabilityCollectorWorkloadKey)
	workloadCA, caErr := decode(observabilityCollectorWorkloadCAKey)
	certificateRaw, certErr := decode(observabilityCollectorTLSCertKey)
	privateKeyRaw, keyErr := decode(observabilityCollectorTLSKeyKey)
	if webhookErr != nil || queryErr != nil || workloadErr != nil || caErr != nil || certErr != nil || keyErr != nil ||
		digest.SHA256(webhook) != receipt.WebhookAuthorityDigest || digest.SHA256(query) != receipt.QueryAuthorityDigest ||
		digest.SHA256(workloadToken) != activation.WorkloadTokenDigest ||
		digest.SHA256(workloadCA) != receipt.WorkloadCADigest || digest.SHA256(certificateRaw) != receipt.TLSCertificateDigest ||
		subtle.ConstantTimeCompare(webhook, query) == 1 || subtle.ConstantTimeCompare(webhook, workloadToken) == 1 ||
		subtle.ConstantTimeCompare(query, workloadToken) == 1 {
		return errors.New("observability collector activation private authorities differ")
	}
	if _, err := tls.X509KeyPair(certificateRaw, privateKeyRaw); err != nil {
		return errors.New("observability collector activation TLS key pair differs")
	}
	return nil
}

func canonicalObservabilityCollectorActivation(activation ObservabilityCollectorActivation) ([]byte, error) {
	if activation.Format != ObservabilityCollectorActivationFormat || activation.State != "BOUND" ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.ManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.ManifestReceiptDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.PlanDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.RuntimeBindingDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.ExecutionFixture) ||
		!runtimeInputUIDPattern.MatchString(activation.TargetClusterUID) ||
		!validFullRunKubernetesEndpoint(activation.WorkloadEndpoint) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.WorkloadCADigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.WorkloadTokenDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.ObserverEvidenceDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.WebhookAuthorityDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.QueryAuthorityDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.TLSCertificateDigest) ||
		activation.ReceiverName != observabilityCollectorReceiver ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.ProfileDigest) ||
		activation.StateDirectory != observabilityCollectorStateRoot ||
		activation.WebhookTokenPath != observabilityCollectorRuntimeRoot+"/"+observabilityCollectorWebhookKey ||
		activation.QueryTokenPath != observabilityCollectorRuntimeRoot+"/"+observabilityCollectorQueryKey ||
		activation.WorkloadTokenPath != observabilityCollectorRuntimeRoot+"/"+observabilityCollectorWorkloadKey ||
		activation.WorkloadCAPath != observabilityCollectorRuntimeRoot+"/"+observabilityCollectorWorkloadCAKey ||
		activation.TLSCertificatePath != observabilityCollectorRuntimeRoot+"/"+observabilityCollectorTLSCertKey ||
		activation.TLSPrivateKeyPath != observabilityCollectorRuntimeRoot+"/"+observabilityCollectorTLSKeyKey {
		return nil, errors.New("observability collector activation identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, activation.ObserverCredentialExpires); err != nil {
		return nil, errors.New("observability collector observer expiry is invalid")
	}
	maximumRecordAge, err := time.ParseDuration(activation.MaximumRecordAge)
	if err != nil || maximumRecordAge < time.Minute || maximumRecordAge > maximumObservabilityIndependentEvidenceWindow {
		return nil, errors.New("observability collector record age is invalid")
	}
	if err := validateObservabilityCollectorNetwork(activation.PublicEndpoint, activation.ListenAddress); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(activation)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}

func validateObservabilityCollectorNetwork(publicEndpoint, listenAddress string) error {
	endpoint, err := url.Parse(publicEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return errors.New("observability collector public endpoint must be one literal HTTPS IP and port")
	}
	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil || net.ParseIP(host) == nil || port == "" || port != endpoint.Port() || strings.ContainsAny(listenAddress, "\r\n") {
		return errors.New("observability collector listen address differs from public endpoint")
	}
	return nil
}

func loadObservabilityCollectorTLS(certificatePath, privateKeyPath, publicEndpoint string, now time.Time) ([]byte, []byte, string, error) {
	if err := validateObservabilityEvidenceFile(certificatePath, 128*1024, false); err != nil ||
		validateObservabilityEvidenceFile(privateKeyPath, 128*1024, true) != nil {
		return nil, nil, "", errors.New("observability collector TLS file metadata is invalid")
	}
	certificateRaw, err := readBoundedRegular(certificatePath, 128*1024)
	if err != nil {
		return nil, nil, "", errors.New("read observability collector TLS certificate")
	}
	privateKeyRaw, err := readBoundedRegular(privateKeyPath, 128*1024)
	if err != nil {
		return nil, nil, "", errors.New("read observability collector TLS private key")
	}
	pair, err := tls.X509KeyPair(certificateRaw, privateKeyRaw)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, nil, "", errors.New("observability collector TLS key pair is invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		!observabilityCertificateHasUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, nil, "", errors.New("observability collector TLS certificate is not currently valid for server use")
	}
	endpoint, err := url.Parse(publicEndpoint)
	if err != nil || leaf.VerifyHostname(endpoint.Hostname()) != nil {
		return nil, nil, "", errors.New("observability collector TLS certificate differs from public endpoint")
	}
	return certificateRaw, privateKeyRaw, digest.SHA256(certificateRaw), nil
}

func loadObservabilityCollectorObserverCredential(source SubmissionStageCredentialSource, authority, expectedSubject string, now time.Time) (observabilityCollectorObserverCredential, []byte, error) {
	if source.AuthorityIdentity != authority || authority == "" || source.TokenFile == "" || source.CAFile == "" ||
		!stageReceiptPrefixDigestPattern.MatchString(source.TokenDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(source.CABundleDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(source.TokenRequestEvidenceDigest) {
		return observabilityCollectorObserverCredential{}, nil, errors.New("observability collector observer credential source is invalid")
	}
	token, err := readBoundedRegular(source.TokenFile, maximumTokenBytes)
	if err != nil || digest.SHA256(token) != source.TokenDigest {
		return observabilityCollectorObserverCredential{}, nil, errors.New("observability collector observer token differs from source")
	}
	ca, err := readBoundedRegular(source.CAFile, maximumCABytes)
	if err != nil || digest.SHA256(ca) != source.CABundleDigest || !validStageCredentialCA(ca, now) {
		return observabilityCollectorObserverCredential{}, nil, errors.New("observability collector observer CA differs from source")
	}
	claims, err := verifyStageCredentialJWTWithSubject(token, source, now, func(subject string) bool {
		return subject == expectedSubject
	})
	if err != nil {
		return observabilityCollectorObserverCredential{}, nil, err
	}
	audiences, err := tokenAudiences(claims.Audience)
	if err != nil || len(audiences) != 1 || audiences[0] != "https://kubernetes.default.svc" {
		return observabilityCollectorObserverCredential{}, nil, errors.New("observability collector observer audience differs")
	}
	return observabilityCollectorObserverCredential{
		ExpiresAt:                  source.ExpiresAt.UTC().Format(time.RFC3339),
		TokenRequestEvidenceDigest: source.TokenRequestEvidenceDigest,
	}, append([]byte(nil), token...), nil
}

func observabilityCertificateHasUsage(certificate *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, value := range certificate.ExtKeyUsage {
		if value == usage || value == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
