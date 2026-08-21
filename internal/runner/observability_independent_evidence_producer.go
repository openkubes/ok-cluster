package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	ObservabilityIndependentEvidenceReceiptFormat   = "ok147-observability-independent-evidence-receipt/v1"
	maximumObservabilityEvidencePrivateKeyBytes     = 8 * 1024
	minimumObservabilityIndependentEvidenceValidity = time.Minute
)

// ObservabilityIndependentEvidenceObservation is the closed result expected
// from a separately operated delivery/autonomy collector. It has no endpoint,
// credential, command, manifest or repair surface.
type ObservabilityIndependentEvidenceObservation struct {
	ReceiverDeliveryObserved    bool
	ReceiverIdentityDigest      string
	ClusterLocalServicesReady   bool
	ExternalClusterDependencies int
	AutonomyProfileDigest       string
}

type ObservabilityIndependentEvidenceCollector interface {
	Collect(context.Context, ObservabilityCapabilityObservationIdentity, string) (ObservabilityIndependentEvidenceObservation, error)
}

type ObservabilityIndependentEvidenceProducerConfig struct {
	OutputPath     string
	PrivateKeyPath string
	Profile        ObservabilityCapabilityCheckProfile
	ValidFor       time.Duration
	Timeout        time.Duration
	Clock          func() time.Time
	Collector      ObservabilityIndependentEvidenceCollector
}

type ObservabilityIndependentEvidenceReceipt struct {
	Format         string `json:"format"`
	State          string `json:"state"`
	EvidenceDigest string `json:"evidenceDigest,omitempty"`
	KeyID          string `json:"keyId,omitempty"`
	ObservedAt     string `json:"observedAt,omitempty"`
	ExpiresAt      string `json:"expiresAt,omitempty"`
	FileMode       string `json:"fileMode,omitempty"`
	FileSize       int    `json:"fileSize,omitempty"`
}

// ObservabilityIndependentEvidenceProducer signs exactly one collected
// observation and persists it create-only. It is intended for a separately
// authorized evidence process; the full runner only receives the public key.
type ObservabilityIndependentEvidenceProducer struct {
	outputPath string
	privateKey ed25519.PrivateKey
	keyID      string
	profile    ObservabilityCapabilityCheckProfile
	validFor   time.Duration
	timeout    time.Duration
	clock      func() time.Time
	collector  ObservabilityIndependentEvidenceCollector

	mu   sync.Mutex
	used bool
}

func OpenObservabilityIndependentEvidenceProducer(config ObservabilityIndependentEvidenceProducerConfig) (*ObservabilityIndependentEvidenceProducer, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || config.OutputPath == "" || config.PrivateKeyPath == "" || config.OutputPath == config.PrivateKeyPath ||
		config.Clock == nil || config.Collector == nil || config.Profile.Digest() == "" || config.Profile.Digest() != standard.Digest() ||
		config.ValidFor < minimumObservabilityIndependentEvidenceValidity || config.ValidFor > maximumObservabilityIndependentEvidenceWindow ||
		config.Timeout < time.Second || config.Timeout > maximumObservabilityIndependentEvidenceWindow {
		return nil, errors.New("observability independent evidence producer binding is invalid")
	}
	if err := validateRuntimeBindingOutputPath(config.OutputPath); err != nil {
		return nil, errors.New("observability independent evidence output is invalid")
	}
	if err := validateObservabilityEvidenceFile(config.PrivateKeyPath, maximumObservabilityEvidencePrivateKeyBytes, true); err != nil {
		return nil, errors.New("observability independent evidence private key is invalid")
	}
	privateRaw, err := readBoundedRegular(config.PrivateKeyPath, maximumObservabilityEvidencePrivateKeyBytes)
	if err != nil {
		return nil, errors.New("read observability independent evidence private key")
	}
	encoded := string(privateRaw)
	if len(encoded) > 0 && encoded[len(encoded)-1] == '\n' {
		encoded = encoded[:len(encoded)-1]
	}
	privateBytes, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(privateBytes) != encoded {
		return nil, errors.New("observability independent evidence private key encoding is invalid")
	}
	privateKey := append(ed25519.PrivateKey(nil), privateBytes...)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &ObservabilityIndependentEvidenceProducer{
		outputPath: config.OutputPath, privateKey: privateKey, keyID: digest.SHA256(publicKey), profile: config.Profile,
		validFor: config.ValidFor, timeout: config.Timeout, clock: config.Clock, collector: config.Collector,
	}, nil
}

func (producer *ObservabilityIndependentEvidenceProducer) Produce(ctx context.Context, identity ObservabilityCapabilityObservationIdentity) (ObservabilityIndependentEvidenceReceipt, error) {
	receipt := ObservabilityIndependentEvidenceReceipt{Format: ObservabilityIndependentEvidenceReceiptFormat, State: "PREWRITE"}
	if producer == nil || producer.collector == nil || producer.clock == nil || len(producer.privateKey) != ed25519.PrivateKeySize ||
		!validObservabilityObservationIdentity(identity) || identity.ProfileDigest != producer.profile.Digest() {
		return receipt, errors.New("observability independent evidence production identity is invalid")
	}
	producer.mu.Lock()
	if producer.used {
		producer.mu.Unlock()
		return receipt, errors.New("observability independent evidence producer is single-use")
	}
	producer.used = true
	producer.mu.Unlock()
	if err := validateRuntimeBindingOutputPath(producer.outputPath); err != nil {
		return receipt, errors.New("observability independent evidence output changed before collection")
	}
	bounded, cancel := context.WithTimeout(ctx, producer.timeout)
	defer cancel()
	observation, err := producer.collector.Collect(bounded, identity, producer.profile.alertName)
	if err != nil || bounded.Err() != nil {
		return receipt, errors.New("collect independent observability evidence")
	}
	if !platformInputDigestPattern.MatchString(observation.ReceiverIdentityDigest) ||
		!platformInputDigestPattern.MatchString(observation.AutonomyProfileDigest) || observation.ExternalClusterDependencies < 0 {
		return receipt, errors.New("independent observability evidence observation is invalid")
	}
	observedAt := producer.clock().UTC().Truncate(time.Second)
	payload := ObservabilityIndependentEvidencePayload{
		Format: ObservabilityIndependentEvidenceFormat, State: "OBSERVED", RunID: identity.RunID,
		TargetClusterUID: identity.TargetClusterUID, FixtureDigest: identity.FixtureDigest, ProfileDigest: identity.ProfileDigest,
		AlertName: producer.profile.alertName, ReceiverDeliveryObserved: observation.ReceiverDeliveryObserved,
		ReceiverIdentityDigest: observation.ReceiverIdentityDigest, ClusterLocalServicesReady: observation.ClusterLocalServicesReady,
		ExternalClusterDependencies: observation.ExternalClusterDependencies, AutonomyProfileDigest: observation.AutonomyProfileDigest,
		ObservedAt: observedAt.Format(time.RFC3339), ExpiresAt: observedAt.Add(producer.validFor).Format(time.RFC3339),
	}
	payloadRaw, err := canonicalObservabilityIndependentEvidencePayload(payload)
	if err != nil {
		return receipt, errors.New("canonicalize independent observability evidence")
	}
	envelope := ObservabilityIndependentEvidenceEnvelope{
		Payload: payload, EvidenceDigest: digest.SHA256(payloadRaw),
		Signature: ObservabilityIndependentEvidenceSignature{
			Algorithm: "Ed25519", KeyID: producer.keyID,
			Value: base64.StdEncoding.EncodeToString(ed25519.Sign(producer.privateKey, payloadRaw)),
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) == 0 || len(raw) > maximumObservabilityIndependentEvidenceBytes {
		return receipt, errors.New("encode independent observability evidence envelope")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	file, err := os.OpenFile(producer.outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		receipt.State = "STOPPED_ZERO_WRITE"
		return receipt, errors.New("create exclusive independent observability evidence")
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return receipt, errors.New("write independent observability evidence")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return receipt, errors.New("sync independent observability evidence")
	}
	if err := file.Close(); err != nil {
		return receipt, errors.New("close independent observability evidence")
	}
	info, err := os.Lstat(producer.outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(raw)) {
		return receipt, errors.New("independent observability evidence metadata differs after write")
	}
	stored, err := readBoundedRegular(producer.outputPath, maximumObservabilityIndependentEvidenceBytes)
	if err != nil || !bytes.Equal(stored, raw) {
		return receipt, errors.New("independent observability evidence differs after write")
	}
	receipt.State, receipt.EvidenceDigest, receipt.KeyID = "WRITTEN_VERIFIED", envelope.EvidenceDigest, producer.keyID
	receipt.ObservedAt, receipt.ExpiresAt, receipt.FileMode, receipt.FileSize = payload.ObservedAt, payload.ExpiresAt, "0600", len(raw)
	return receipt, nil
}
