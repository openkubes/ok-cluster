package runner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityEvidenceAuthorityActivationFormat = "ok147-observability-evidence-authority-activation/v1"
	ObservabilityEvidenceAuthorityPackageFormat    = "ok147-observability-evidence-authority-package/v1"
	maximumObservabilityEvidenceAuthorityBytes     = 950 * 1024

	observabilityEvidenceAuthorityRoot           = "/var/run/openkubes/evidence-authority"
	observabilityEvidenceAuthorityHandoffRoot    = "/var/run/openkubes/handoff"
	observabilityEvidenceAuthorityActivationKey  = "activation.json"
	observabilityEvidenceAuthorityPrivateKeyKey  = "evidence-authority.key"
	observabilityEvidenceAuthorityCollectorToken = "collector-token"
	observabilityEvidenceAuthorityCollectorCA    = "collector-ca.crt"
)

// ObservabilityEvidenceAuthorityPackageConfig binds the secret-bearing half
// of the independent evidence producer. Package construction is local-only;
// the resulting Secret is intended for a container that does not receive any
// lifecycle or Kubernetes credential.
type ObservabilityEvidenceAuthorityPackageConfig struct {
	ManifestPath         string
	ActivationSecret     string
	PrivateKeyPath       string
	CollectorEndpoint    string
	CollectorTokenPath   string
	CollectorCAPath      string
	CollectorCADigest    string
	RuntimeAuthorityRoot string
	RuntimeHandoffRoot   string
	IdentityPollInterval time.Duration
	IdentityWaitTimeout  time.Duration
	EvidenceValidFor     time.Duration
	CollectionTimeout    time.Duration
}

type ObservabilityEvidenceAuthorityActivation struct {
	Format                 string `json:"format"`
	State                  string `json:"state"`
	ExpectedManifestDigest string `json:"expectedManifestDigest"`
	IdentityPath           string `json:"identityPath"`
	IdentityReceiptPath    string `json:"identityReceiptPath"`
	EvidenceOutputPath     string `json:"evidenceOutputPath"`
	PrivateKeyPath         string `json:"privateKeyPath"`
	CollectorEndpoint      string `json:"collectorEndpoint"`
	CollectorTokenPath     string `json:"collectorTokenPath"`
	CollectorCAPath        string `json:"collectorCaPath"`
	CollectorCADigest      string `json:"collectorCaDigest"`
	IdentityPollInterval   string `json:"identityPollInterval"`
	IdentityWaitTimeout    string `json:"identityWaitTimeout"`
	EvidenceValidity       string `json:"evidenceValidity"`
	CollectionTimeout      string `json:"collectionTimeout"`
}

type ObservabilityEvidenceAuthorityPackageReceipt struct {
	Format                   string   `json:"format"`
	State                    string   `json:"state"`
	PackageDigest            string   `json:"packageDigest"`
	ActivationSecret         string   `json:"activationSecret"`
	SecretObjectDigest       string   `json:"secretObjectDigest"`
	ActivationDigest         string   `json:"activationDigest"`
	ManifestDigest           string   `json:"manifestDigest"`
	EvidenceKeyID            string   `json:"evidenceKeyId"`
	CollectorAuthorityDigest string   `json:"collectorAuthorityDigest"`
	CollectorCADigest        string   `json:"collectorCaDigest"`
	PrivateFileCount         int      `json:"privateFileCount"`
	ObjectKinds              []string `json:"objectKinds"`
	MutationAllowed          bool     `json:"mutationAllowed"`
}

type VerifiedObservabilityEvidenceAuthorityPackage struct {
	raw      []byte
	receipt  ObservabilityEvidenceAuthorityPackageReceipt
	verified bool
}

// BuildObservabilityEvidenceAuthorityPackage creates one immutable private
// Secret object. It verifies the key pair, collector TLS material, exact
// full-run identity and all bounds without contacting either Kubernetes or the
// collector. The dynamic Cluster UID remains absent and arrives later through
// the shared private handoff.
func BuildObservabilityEvidenceAuthorityPackage(config ObservabilityEvidenceAuthorityPackageConfig) (VerifiedObservabilityEvidenceAuthorityPackage, error) {
	if !submissionStageInputNamePattern.MatchString(config.ActivationSecret) || len(config.ActivationSecret) > 63 ||
		!strings.HasPrefix(config.ActivationSecret, "ok147-") {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority Secret name is invalid")
	}
	if !absoluteCleanDirectory(config.RuntimeAuthorityRoot) || !absoluteCleanDirectory(config.RuntimeHandoffRoot) ||
		directoriesOverlap(config.RuntimeAuthorityRoot, config.RuntimeHandoffRoot) {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority runtime roots are invalid")
	}
	if config.IdentityPollInterval < time.Millisecond || config.IdentityPollInterval > 30*time.Second ||
		config.IdentityWaitTimeout < time.Second || config.IdentityWaitTimeout > 3*time.Hour ||
		config.EvidenceValidFor < minimumObservabilityIndependentEvidenceValidity || config.EvidenceValidFor > maximumObservabilityIndependentEvidenceWindow ||
		config.CollectionTimeout < time.Second || config.CollectionTimeout > maximumObservabilityIndependentEvidenceWindow {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority time bounds are invalid")
	}
	manifest, manifestReceipt, err := LoadFullRunExecutionManifest(config.ManifestPath)
	if err != nil || !manifest.verified || manifestReceipt.State != "VERIFIED" || manifestReceipt.MutationAllowed {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("verify observability evidence authority full-run manifest")
	}
	privateKeyRaw, keyID, err := loadObservabilityEvidenceAuthorityPrivateKey(config.PrivateKeyPath)
	if err != nil || keyID != manifest.document.PlatformObservation.Capability.IndependentEvidenceKeyID {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority key differs from full-run manifest")
	}
	if err := validateObservabilityEvidenceFile(config.CollectorTokenPath, maximumTokenBytes, true); err != nil {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority collector credential is invalid")
	}
	tokenRaw, err := readBoundedRegular(config.CollectorTokenPath, maximumTokenBytes)
	if err != nil {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("read observability evidence authority collector credential")
	}
	caRaw, err := readBoundedRegular(config.CollectorCAPath, maximumCABytes)
	if err != nil || digest.SHA256(caRaw) != config.CollectorCADigest {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority collector CA differs")
	}
	if _, err := OpenHTTPObservabilityIndependentEvidenceCollector(HTTPObservabilityIndependentEvidenceCollectorConfig{
		Endpoint: config.CollectorEndpoint, TokenFile: config.CollectorTokenPath,
		CAFile: config.CollectorCAPath, CABundleDigest: config.CollectorCADigest,
	}); err != nil {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("verify observability evidence authority collector binding")
	}
	activation := ObservabilityEvidenceAuthorityActivation{
		Format: ObservabilityEvidenceAuthorityActivationFormat, State: "BOUND",
		ExpectedManifestDigest: manifestReceipt.ManifestDigest,
		IdentityPath:           config.RuntimeHandoffRoot + "/observability-evidence-identity.json",
		IdentityReceiptPath:    config.RuntimeHandoffRoot + "/observability-evidence-identity-receipt.json",
		EvidenceOutputPath:     config.RuntimeHandoffRoot + "/observability-evidence.json",
		PrivateKeyPath:         config.RuntimeAuthorityRoot + "/" + observabilityEvidenceAuthorityPrivateKeyKey,
		CollectorEndpoint:      config.CollectorEndpoint,
		CollectorTokenPath:     config.RuntimeAuthorityRoot + "/" + observabilityEvidenceAuthorityCollectorToken,
		CollectorCAPath:        config.RuntimeAuthorityRoot + "/" + observabilityEvidenceAuthorityCollectorCA,
		CollectorCADigest:      config.CollectorCADigest,
		IdentityPollInterval:   config.IdentityPollInterval.String(), IdentityWaitTimeout: config.IdentityWaitTimeout.String(),
		EvidenceValidity: config.EvidenceValidFor.String(), CollectionTimeout: config.CollectionTimeout.String(),
	}
	activationRaw, err := canonicalObservabilityEvidenceAuthorityActivation(activation)
	if err != nil {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, err
	}
	binaryData := map[string]string{
		observabilityEvidenceAuthorityActivationKey:  base64.StdEncoding.EncodeToString(activationRaw),
		observabilityEvidenceAuthorityPrivateKeyKey:  base64.StdEncoding.EncodeToString(privateKeyRaw),
		observabilityEvidenceAuthorityCollectorToken: base64.StdEncoding.EncodeToString(tokenRaw),
		observabilityEvidenceAuthorityCollectorCA:    base64.StdEncoding.EncodeToString(caRaw),
	}
	secret := postRuntimeActivationSecret{
		APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque", BinaryData: binaryData,
		Metadata: postRuntimeActivationSecretMetadata{
			Name: config.ActivationSecret, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-evidence-authority", "openkubes.io/stage-id": "independent-evidence",
			},
			Annotations: map[string]string{
				"openkubes.io/manifest-digest":   manifestReceipt.ManifestDigest,
				"openkubes.io/activation-digest": digest.SHA256(activationRaw),
			},
		},
	}
	raw, err := json.Marshal(secret)
	if err != nil || len(raw) == 0 || len(raw) > maximumObservabilityEvidenceAuthorityBytes {
		return VerifiedObservabilityEvidenceAuthorityPackage{}, errors.New("observability evidence authority Secret exceeds bounded object size")
	}
	receipt := ObservabilityEvidenceAuthorityPackageReceipt{
		Format: ObservabilityEvidenceAuthorityPackageFormat, State: "VERIFIED",
		PackageDigest: digest.SHA256(raw), ActivationSecret: config.ActivationSecret,
		SecretObjectDigest: digest.SHA256(raw), ActivationDigest: digest.SHA256(activationRaw),
		ManifestDigest: manifestReceipt.ManifestDigest, EvidenceKeyID: keyID,
		CollectorAuthorityDigest: digest.SHA256([]byte(config.CollectorEndpoint)), CollectorCADigest: config.CollectorCADigest,
		PrivateFileCount: 4, ObjectKinds: []string{"Secret"}, MutationAllowed: false,
	}
	return VerifiedObservabilityEvidenceAuthorityPackage{raw: raw, receipt: receipt, verified: true}, nil
}

func (packaged VerifiedObservabilityEvidenceAuthorityPackage) PrivateBytes() ([]byte, error) {
	if err := verifyObservabilityEvidenceAuthorityPackage(packaged); err != nil {
		return nil, errors.New("observability evidence authority package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedObservabilityEvidenceAuthorityPackage) Receipt() (ObservabilityEvidenceAuthorityPackageReceipt, error) {
	if err := verifyObservabilityEvidenceAuthorityPackage(packaged); err != nil {
		return ObservabilityEvidenceAuthorityPackageReceipt{}, errors.New("observability evidence authority package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyObservabilityEvidenceAuthorityPackage(packaged VerifiedObservabilityEvidenceAuthorityPackage) error {
	receipt := packaged.receipt
	if !packaged.verified || receipt.Format != ObservabilityEvidenceAuthorityPackageFormat || receipt.State != "VERIFIED" ||
		receipt.MutationAllowed || len(packaged.raw) == 0 || digest.SHA256(packaged.raw) != receipt.PackageDigest ||
		receipt.SecretObjectDigest != receipt.PackageDigest || !stageReceiptPrefixDigestPattern.MatchString(receipt.ActivationDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.ManifestDigest) || !stageReceiptPrefixDigestPattern.MatchString(receipt.EvidenceKeyID) ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.CollectorAuthorityDigest) || !stageReceiptPrefixDigestPattern.MatchString(receipt.CollectorCADigest) ||
		receipt.PrivateFileCount != 4 || len(receipt.ObjectKinds) != 1 || receipt.ObjectKinds[0] != "Secret" {
		return errors.New("observability evidence authority package identity is incomplete")
	}
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(packaged.raw, &secret); err != nil || secret.Kind != "Secret" || !secret.Immutable || secret.Type != "Opaque" ||
		secret.Metadata.Name != receipt.ActivationSecret || secret.Metadata.Namespace != submissionStageInputNamespace ||
		secret.Metadata.Labels["app.kubernetes.io/name"] != "ok-cluster-evidence-authority" ||
		secret.Metadata.Labels["openkubes.io/stage-id"] != "independent-evidence" ||
		secret.Metadata.Annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest ||
		secret.Metadata.Annotations["openkubes.io/activation-digest"] != receipt.ActivationDigest ||
		len(secret.BinaryData) != receipt.PrivateFileCount {
		return errors.New("observability evidence authority Secret identity differs")
	}
	activationRaw, err := base64.StdEncoding.DecodeString(secret.BinaryData[observabilityEvidenceAuthorityActivationKey])
	if err != nil || digest.SHA256(activationRaw) != receipt.ActivationDigest {
		return errors.New("observability evidence authority activation identity differs")
	}
	var activation ObservabilityEvidenceAuthorityActivation
	if err := jsonstrict.Decode(activationRaw, &activation); err != nil {
		return errors.New("decode strict observability evidence authority activation")
	}
	canonical, err := canonicalObservabilityEvidenceAuthorityActivation(activation)
	if err != nil || !bytes.Equal(canonical, activationRaw) || activation.ExpectedManifestDigest != receipt.ManifestDigest ||
		activation.CollectorCADigest != receipt.CollectorCADigest || digest.SHA256([]byte(activation.CollectorEndpoint)) != receipt.CollectorAuthorityDigest {
		return errors.New("observability evidence authority activation differs from receipt")
	}
	privateKeyRaw, err := base64.StdEncoding.DecodeString(secret.BinaryData[observabilityEvidenceAuthorityPrivateKeyKey])
	if err != nil {
		return errors.New("decode observability evidence authority private key")
	}
	encoded := strings.TrimSuffix(string(privateKeyRaw), "\n")
	privateKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		digest.SHA256(ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)) != receipt.EvidenceKeyID {
		return errors.New("observability evidence authority key identity differs")
	}
	tokenRaw, tokenErr := base64.StdEncoding.DecodeString(secret.BinaryData[observabilityEvidenceAuthorityCollectorToken])
	caRaw, caErr := base64.StdEncoding.DecodeString(secret.BinaryData[observabilityEvidenceAuthorityCollectorCA])
	if tokenErr != nil || len(tokenRaw) == 0 || caErr != nil || digest.SHA256(caRaw) != receipt.CollectorCADigest {
		return errors.New("observability evidence authority collector material differs")
	}
	return nil
}

func loadObservabilityEvidenceAuthorityPrivateKey(path string) ([]byte, string, error) {
	if err := validateObservabilityEvidenceFile(path, maximumObservabilityEvidencePrivateKeyBytes, true); err != nil {
		return nil, "", err
	}
	raw, err := readBoundedRegular(path, maximumObservabilityEvidencePrivateKeyBytes)
	if err != nil {
		return nil, "", err
	}
	encoded := strings.TrimSuffix(string(raw), "\n")
	privateRaw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(privateRaw) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(privateRaw) != encoded {
		return nil, "", errors.New("observability evidence authority private key encoding is invalid")
	}
	privateKey := append(ed25519.PrivateKey(nil), privateRaw...)
	return raw, digest.SHA256(privateKey.Public().(ed25519.PublicKey)), nil
}

func canonicalObservabilityEvidenceAuthorityActivation(activation ObservabilityEvidenceAuthorityActivation) ([]byte, error) {
	handoffRoot := filepath.Dir(activation.IdentityPath)
	authorityRoot := filepath.Dir(activation.PrivateKeyPath)
	if activation.Format != ObservabilityEvidenceAuthorityActivationFormat || activation.State != "BOUND" ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.ExpectedManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(activation.CollectorCADigest) ||
		!absoluteCleanDirectory(handoffRoot) || !absoluteCleanDirectory(authorityRoot) || directoriesOverlap(handoffRoot, authorityRoot) ||
		activation.IdentityPath != handoffRoot+"/observability-evidence-identity.json" ||
		activation.IdentityReceiptPath != handoffRoot+"/observability-evidence-identity-receipt.json" ||
		activation.EvidenceOutputPath != handoffRoot+"/observability-evidence.json" ||
		activation.PrivateKeyPath != authorityRoot+"/"+observabilityEvidenceAuthorityPrivateKeyKey ||
		activation.CollectorTokenPath != authorityRoot+"/"+observabilityEvidenceAuthorityCollectorToken ||
		activation.CollectorCAPath != authorityRoot+"/"+observabilityEvidenceAuthorityCollectorCA ||
		activation.CollectorEndpoint == "" {
		return nil, errors.New("observability evidence authority activation identity is invalid")
	}
	pollInterval, pollErr := time.ParseDuration(activation.IdentityPollInterval)
	waitTimeout, waitErr := time.ParseDuration(activation.IdentityWaitTimeout)
	validFor, validErr := time.ParseDuration(activation.EvidenceValidity)
	collectionTimeout, collectionErr := time.ParseDuration(activation.CollectionTimeout)
	if pollErr != nil || pollInterval < time.Millisecond || pollInterval > 30*time.Second ||
		waitErr != nil || waitTimeout < time.Second || waitTimeout > 3*time.Hour ||
		validErr != nil || validFor < minimumObservabilityIndependentEvidenceValidity || validFor > maximumObservabilityIndependentEvidenceWindow ||
		collectionErr != nil || collectionTimeout < time.Second || collectionTimeout > maximumObservabilityIndependentEvidenceWindow {
		return nil, errors.New("observability evidence authority activation bounds are invalid")
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
