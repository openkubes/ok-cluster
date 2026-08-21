package runner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const ObservabilityEvidenceAuthorityMaterializationReceiptFormat = "ok147-observability-evidence-authority-materialization-receipt/v1"

var observabilityEvidenceAuthorityProjectedFiles = []string{
	observabilityEvidenceAuthorityActivationKey,
	observabilityEvidenceAuthorityPrivateKeyKey,
	observabilityEvidenceAuthorityCollectorToken,
	observabilityEvidenceAuthorityCollectorCA,
}

type ObservabilityEvidenceAuthorityMaterializationConfig struct {
	SourceDirectory           string
	DestinationDirectory      string
	ExpectedActivationDigest  string
	ExpectedEvidenceKeyID     string
	ExpectedCollectorCADigest string
}

type ObservabilityEvidenceAuthorityMaterializationReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	ActivationDigest          string `json:"activationDigest,omitempty"`
	ManifestDigest            string `json:"manifestDigest,omitempty"`
	EvidenceKeyID             string `json:"evidenceKeyId,omitempty"`
	CollectorCADigest         string `json:"collectorCaDigest,omitempty"`
	FileCount                 int    `json:"fileCount,omitempty"`
	TotalBytes                int    `json:"totalBytes,omitempty"`
	KubernetesMutationAllowed bool   `json:"kubernetesMutationAllowed"`
}

// MaterializeObservabilityEvidenceAuthority converts exactly four projected
// Secret entries into regular 0600 files. The signing key and collector
// credential never enter the executor workspace.
func MaterializeObservabilityEvidenceAuthority(config ObservabilityEvidenceAuthorityMaterializationConfig) (ObservabilityEvidenceAuthorityMaterializationReceipt, error) {
	receipt := ObservabilityEvidenceAuthorityMaterializationReceipt{
		Format: ObservabilityEvidenceAuthorityMaterializationReceiptFormat, State: "STOPPED_ZERO_WRITE", KubernetesMutationAllowed: false,
	}
	if !absoluteCleanDirectory(config.SourceDirectory) || config.DestinationDirectory != observabilityEvidenceAuthorityRoot ||
		directoriesOverlap(config.SourceDirectory, config.DestinationDirectory) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedActivationDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedEvidenceKeyID) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedCollectorCADigest) {
		return receipt, errors.New("observability evidence authority materialization configuration is invalid")
	}
	return materializeObservabilityEvidenceAuthority(config, receipt)
}

func materializeObservabilityEvidenceAuthority(config ObservabilityEvidenceAuthorityMaterializationConfig, receipt ObservabilityEvidenceAuthorityMaterializationReceipt) (ObservabilityEvidenceAuthorityMaterializationReceipt, error) {
	if _, err := os.Lstat(config.DestinationDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("observability evidence authority destination must be absent")
	}
	contents := make(map[string][]byte, len(observabilityEvidenceAuthorityProjectedFiles))
	for _, name := range observabilityEvidenceAuthorityProjectedFiles {
		raw, err := readProjectedPostRuntimeBundleFile(config.SourceDirectory, name, maximumObservabilityEvidenceAuthorityBytes)
		if err != nil {
			return receipt, errors.New("read projected observability evidence authority file")
		}
		receipt.TotalBytes += len(raw)
		if receipt.TotalBytes > maximumObservabilityEvidenceAuthorityBytes {
			return receipt, errors.New("observability evidence authority projection exceeds size limit")
		}
		contents[name] = raw
	}
	var activation ObservabilityEvidenceAuthorityActivation
	activationRaw := contents[observabilityEvidenceAuthorityActivationKey]
	if err := jsonstrict.Decode(activationRaw, &activation); err != nil {
		return receipt, errors.New("decode projected observability evidence authority activation")
	}
	canonical, err := canonicalObservabilityEvidenceAuthorityActivation(activation)
	if err != nil || !bytes.Equal(canonical, activationRaw) || digest.SHA256(activationRaw) != config.ExpectedActivationDigest ||
		filepath.Dir(activation.PrivateKeyPath) != observabilityEvidenceAuthorityRoot ||
		filepath.Dir(activation.IdentityPath) != observabilityEvidenceAuthorityHandoffRoot ||
		activation.CollectorCADigest != config.ExpectedCollectorCADigest {
		return receipt, errors.New("projected observability evidence authority activation differs")
	}
	privateEncoded := strings.TrimSuffix(string(contents[observabilityEvidenceAuthorityPrivateKeyKey]), "\n")
	privateKey, err := base64.StdEncoding.Strict().DecodeString(privateEncoded)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize || strings.ContainsAny(privateEncoded, " \t\r\n") ||
		digest.SHA256(ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)) != config.ExpectedEvidenceKeyID {
		return receipt, errors.New("projected observability evidence authority key differs")
	}
	token := string(contents[observabilityEvidenceAuthorityCollectorToken])
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return receipt, errors.New("projected observability evidence authority token is invalid")
	}
	caRaw := contents[observabilityEvidenceAuthorityCollectorCA]
	roots := x509.NewCertPool()
	if digest.SHA256(caRaw) != config.ExpectedCollectorCADigest || !roots.AppendCertsFromPEM(caRaw) {
		return receipt, errors.New("projected observability evidence authority CA differs")
	}
	receipt.ActivationDigest, receipt.ManifestDigest = config.ExpectedActivationDigest, activation.ExpectedManifestDigest
	receipt.EvidenceKeyID, receipt.CollectorCADigest = config.ExpectedEvidenceKeyID, config.ExpectedCollectorCADigest

	parentInfo, err := os.Lstat(filepath.Dir(config.DestinationDirectory))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return receipt, errors.New("observability evidence authority destination parent is invalid")
	}
	if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
		return receipt, errors.New("create observability evidence authority destination")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	for _, name := range observabilityEvidenceAuthorityProjectedFiles {
		if err := writeExclusivePostRuntimeBundleFile(filepath.Join(config.DestinationDirectory, name), contents[name]); err != nil {
			return receipt, err
		}
	}
	receipt.State, receipt.FileCount = "MATERIALIZED_VERIFIED", len(observabilityEvidenceAuthorityProjectedFiles)
	return receipt, nil
}
