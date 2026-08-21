package runner

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const ObservabilityCollectorActivationMaterializationReceiptFormat = "ok147-observability-collector-activation-materialization-receipt/v1"

var observabilityCollectorProjectedFiles = []string{
	observabilityCollectorWebhookKey,
	observabilityCollectorQueryKey,
	observabilityCollectorWorkloadKey,
	observabilityCollectorWorkloadCAKey,
	observabilityCollectorTLSCertKey,
	observabilityCollectorTLSKeyKey,
	observabilityCollectorActivationKey,
}

type ObservabilityCollectorActivationMaterializationConfig struct {
	SourceDirectory          string
	DestinationDirectory     string
	StateDirectory           string
	ExpectedActivationDigest string
	ExpectedManifestDigest   string
	ExpectedRuntimeBinding   string
	ExpectedPublicEndpoint   string
}

type ObservabilityCollectorActivationMaterializationReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	ActivationDigest          string `json:"activationDigest,omitempty"`
	ManifestDigest            string `json:"manifestDigest,omitempty"`
	RuntimeBindingDigest      string `json:"runtimeBindingDigest,omitempty"`
	TargetClusterUIDDigest    string `json:"targetClusterUidDigest,omitempty"`
	PublicEndpointDigest      string `json:"publicEndpointDigest,omitempty"`
	FileCount                 int    `json:"fileCount,omitempty"`
	TotalBytes                int    `json:"totalBytes,omitempty"`
	PrivateStateReady         bool   `json:"privateStateReady"`
	KubernetesMutationAllowed bool   `json:"kubernetesMutationAllowed"`
}

// MaterializeObservabilityCollectorActivation converts exactly seven
// projected Secret entries into private regular files and creates the private
// create-only delivery-state directory. It performs no Kubernetes request.
func MaterializeObservabilityCollectorActivation(config ObservabilityCollectorActivationMaterializationConfig) (ObservabilityCollectorActivationMaterializationReceipt, error) {
	receipt := ObservabilityCollectorActivationMaterializationReceipt{
		Format: ObservabilityCollectorActivationMaterializationReceiptFormat,
		State:  "STOPPED_ZERO_WRITE", KubernetesMutationAllowed: false,
	}
	if !absoluteCleanDirectory(config.SourceDirectory) ||
		config.DestinationDirectory != observabilityCollectorRuntimeRoot ||
		config.StateDirectory != observabilityCollectorStateRoot ||
		directoriesOverlap(config.SourceDirectory, config.DestinationDirectory) ||
		directoriesOverlap(config.SourceDirectory, config.StateDirectory) ||
		directoriesOverlap(config.DestinationDirectory, config.StateDirectory) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedActivationDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedRuntimeBinding) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedPublicEndpoint) {
		return receipt, errors.New("observability collector activation materialization configuration is invalid")
	}
	return materializeObservabilityCollectorActivation(config, receipt)
}

func materializeObservabilityCollectorActivation(config ObservabilityCollectorActivationMaterializationConfig, receipt ObservabilityCollectorActivationMaterializationReceipt) (ObservabilityCollectorActivationMaterializationReceipt, error) {
	if _, err := os.Lstat(config.DestinationDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("observability collector activation destination must be absent")
	}
	if _, err := os.Lstat(config.StateDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("observability collector state destination must be absent")
	}
	contents := make(map[string][]byte, len(observabilityCollectorProjectedFiles))
	for _, name := range observabilityCollectorProjectedFiles {
		raw, err := readProjectedPostRuntimeBundleFile(config.SourceDirectory, name, maximumObservabilityCollectorActivationBytes)
		if err != nil {
			return receipt, errors.New("read projected observability collector file")
		}
		receipt.TotalBytes += len(raw)
		if receipt.TotalBytes > maximumObservabilityCollectorActivationBytes {
			return receipt, errors.New("observability collector projection exceeds size limit")
		}
		contents[name] = raw
	}
	activationRaw := contents[observabilityCollectorActivationKey]
	var activation ObservabilityCollectorActivation
	if err := jsonstrict.Decode(activationRaw, &activation); err != nil {
		return receipt, errors.New("decode projected observability collector activation")
	}
	canonical, err := canonicalObservabilityCollectorActivation(activation)
	if err != nil || !bytes.Equal(canonical, activationRaw) ||
		digest.SHA256(activationRaw) != config.ExpectedActivationDigest ||
		activation.ManifestDigest != config.ExpectedManifestDigest ||
		activation.RuntimeBindingDigest != config.ExpectedRuntimeBinding ||
		digest.SHA256([]byte(activation.PublicEndpoint)) != config.ExpectedPublicEndpoint {
		return receipt, errors.New("projected observability collector activation differs")
	}
	webhook := contents[observabilityCollectorWebhookKey]
	query := contents[observabilityCollectorQueryKey]
	workloadToken := contents[observabilityCollectorWorkloadKey]
	if !validCollectorToken(webhook) || !validCollectorToken(query) || !validCollectorToken(workloadToken) ||
		digest.SHA256(webhook) != activation.WebhookAuthorityDigest ||
		digest.SHA256(query) != activation.QueryAuthorityDigest ||
		digest.SHA256(workloadToken) != activation.WorkloadTokenDigest ||
		subtle.ConstantTimeCompare(webhook, query) == 1 ||
		subtle.ConstantTimeCompare(webhook, workloadToken) == 1 ||
		subtle.ConstantTimeCompare(query, workloadToken) == 1 {
		return receipt, errors.New("projected observability collector authorities differ")
	}
	workloadCA := contents[observabilityCollectorWorkloadCAKey]
	roots := x509.NewCertPool()
	if digest.SHA256(workloadCA) != activation.WorkloadCADigest || !roots.AppendCertsFromPEM(workloadCA) {
		return receipt, errors.New("projected observability collector workload CA differs")
	}
	certificate := contents[observabilityCollectorTLSCertKey]
	privateKey := contents[observabilityCollectorTLSKeyKey]
	if digest.SHA256(certificate) != activation.TLSCertificateDigest {
		return receipt, errors.New("projected observability collector TLS certificate differs")
	}
	if _, err := tls.X509KeyPair(certificate, privateKey); err != nil {
		return receipt, errors.New("projected observability collector TLS key pair differs")
	}
	receipt.ActivationDigest = config.ExpectedActivationDigest
	receipt.ManifestDigest = activation.ManifestDigest
	receipt.RuntimeBindingDigest = activation.RuntimeBindingDigest
	receipt.TargetClusterUIDDigest = digest.SHA256([]byte(activation.TargetClusterUID))
	receipt.PublicEndpointDigest = config.ExpectedPublicEndpoint
	for _, parent := range []string{filepath.Dir(config.DestinationDirectory), filepath.Dir(config.StateDirectory)} {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return receipt, errors.New("observability collector destination parent is invalid")
		}
	}
	if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
		return receipt, errors.New("create observability collector activation destination")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	if err := os.Mkdir(config.StateDirectory, 0o700); err != nil {
		return receipt, errors.New("create observability collector state destination")
	}
	for _, name := range observabilityCollectorProjectedFiles {
		if err := writeExclusivePostRuntimeBundleFile(filepath.Join(config.DestinationDirectory, name), contents[name]); err != nil {
			return receipt, err
		}
	}
	receipt.State = "MATERIALIZED_VERIFIED"
	receipt.FileCount = len(observabilityCollectorProjectedFiles)
	receipt.PrivateStateReady = true
	return receipt, nil
}
