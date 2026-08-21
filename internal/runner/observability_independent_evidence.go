package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityIndependentEvidenceFormat        = "ok147-observability-independent-evidence/v1"
	maximumObservabilityEvidencePublicKeyBytes    = 4 * 1024
	maximumObservabilityIndependentEvidenceBytes  = 64 * 1024
	maximumObservabilityIndependentEvidenceWindow = 30 * time.Minute
)

type ObservabilityIndependentEvidencePayload struct {
	Format                      string `json:"format"`
	State                       string `json:"state"`
	RunID                       string `json:"runId"`
	TargetClusterUID            string `json:"targetClusterUid"`
	FixtureDigest               string `json:"fixtureDigest"`
	ProfileDigest               string `json:"profileDigest"`
	AlertName                   string `json:"alertName"`
	ReceiverDeliveryObserved    bool   `json:"receiverDeliveryObserved"`
	ReceiverIdentityDigest      string `json:"receiverIdentityDigest"`
	ClusterLocalServicesReady   bool   `json:"clusterLocalServicesReady"`
	ExternalClusterDependencies int    `json:"externalClusterDependencies"`
	AutonomyProfileDigest       string `json:"autonomyProfileDigest"`
	ObservedAt                  string `json:"observedAt"`
	ExpiresAt                   string `json:"expiresAt"`
}

type ObservabilityIndependentEvidenceSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"`
}

type ObservabilityIndependentEvidenceEnvelope struct {
	Payload        ObservabilityIndependentEvidencePayload   `json:"payload"`
	EvidenceDigest string                                    `json:"evidenceDigest"`
	Signature      ObservabilityIndependentEvidenceSignature `json:"signature"`
}

type SignedObservabilityEvidenceFileConfig struct {
	Path          string
	PublicKeyPath string
	Clock         func() time.Time
}

// SignedObservabilityEvidenceFileSource verifies one fresh, independently
// signed envelope on every claim. It never trusts file placement or a digest
// alone as evidence authority.
type SignedObservabilityEvidenceFileSource struct {
	path      string
	publicKey ed25519.PublicKey
	keyID     string
	clock     func() time.Time
}

func OpenSignedObservabilityEvidenceFileSource(config SignedObservabilityEvidenceFileConfig) (*SignedObservabilityEvidenceFileSource, error) {
	if config.Path == "" || config.PublicKeyPath == "" || config.Path == config.PublicKeyPath || config.Clock == nil {
		return nil, errors.New("signed observability evidence source binding is invalid")
	}
	if err := validateObservabilityEvidenceFile(config.PublicKeyPath, maximumObservabilityEvidencePublicKeyBytes, false); err != nil {
		return nil, errors.New("signed observability evidence public key is invalid")
	}
	publicRaw, err := readBoundedRegular(config.PublicKeyPath, maximumObservabilityEvidencePublicKeyBytes)
	if err != nil {
		return nil, errors.New("read signed observability evidence public key")
	}
	encoded := strings.TrimSuffix(string(publicRaw), "\n")
	if encoded == "" || strings.ContainsAny(encoded, " \t\r\n") {
		return nil, errors.New("signed observability evidence public key encoding is invalid")
	}
	publicBytes, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return nil, errors.New("signed observability evidence public key encoding is invalid")
	}
	publicKey := append(ed25519.PublicKey(nil), publicBytes...)
	return &SignedObservabilityEvidenceFileSource{path: config.Path, publicKey: publicKey, keyID: digest.SHA256(publicKey), clock: config.Clock}, nil
}

func (source *SignedObservabilityEvidenceFileSource) Delivery(ctx context.Context, identity ObservabilityCapabilityObservationIdentity, alertName string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, errors.New("signed alert-delivery evidence context is done")
	}
	payload, err := source.load(identity)
	if err != nil || alertName == "" || payload.AlertName != alertName {
		return false, errors.New("signed alert-delivery evidence differs from the capability claim")
	}
	return payload.ReceiverDeliveryObserved, nil
}

func (source *SignedObservabilityEvidenceFileSource) Autonomy(ctx context.Context, identity ObservabilityCapabilityObservationIdentity) (bool, int, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, errors.New("signed autonomy evidence context is done")
	}
	payload, err := source.load(identity)
	if err != nil {
		return false, 0, errors.New("signed autonomy evidence differs from the capability claim")
	}
	return payload.ClusterLocalServicesReady, payload.ExternalClusterDependencies, nil
}

func (source *SignedObservabilityEvidenceFileSource) load(identity ObservabilityCapabilityObservationIdentity) (ObservabilityIndependentEvidencePayload, error) {
	if source == nil || source.clock == nil || len(source.publicKey) != ed25519.PublicKeySize || !validObservabilityObservationIdentity(identity) {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence claim identity is invalid")
	}
	if err := validateObservabilityEvidenceFile(source.path, maximumObservabilityIndependentEvidenceBytes, true); err != nil {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence file is invalid")
	}
	raw, err := readBoundedRegular(source.path, maximumObservabilityIndependentEvidenceBytes)
	if err != nil {
		return ObservabilityIndependentEvidencePayload{}, errors.New("read observability independent evidence")
	}
	var envelope ObservabilityIndependentEvidenceEnvelope
	if err := jsonstrict.Decode(raw, &envelope); err != nil {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence envelope is invalid")
	}
	payloadRaw, err := canonicalObservabilityIndependentEvidencePayload(envelope.Payload)
	if err != nil || envelope.EvidenceDigest != digest.SHA256(payloadRaw) {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence digest is invalid")
	}
	signatureBytes, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature.Value)
	if err != nil || envelope.Signature.Algorithm != "Ed25519" || envelope.Signature.KeyID != source.keyID || !ed25519.Verify(source.publicKey, payloadRaw, signatureBytes) {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence signature is invalid")
	}
	payload := envelope.Payload
	observedAt, observedErr := time.Parse(time.RFC3339, payload.ObservedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, payload.ExpiresAt)
	now := source.clock().UTC()
	if observedErr != nil || expiresErr != nil || payload.ObservedAt != observedAt.UTC().Format(time.RFC3339) || payload.ExpiresAt != expiresAt.UTC().Format(time.RFC3339) ||
		!expiresAt.After(observedAt) || expiresAt.Sub(observedAt) > maximumObservabilityIndependentEvidenceWindow || now.Before(observedAt) || !now.Before(expiresAt) {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence time binding is invalid")
	}
	if payload.Format != ObservabilityIndependentEvidenceFormat || payload.State != "OBSERVED" || payload.RunID != identity.RunID ||
		payload.TargetClusterUID != identity.TargetClusterUID || payload.FixtureDigest != identity.FixtureDigest || payload.ProfileDigest != identity.ProfileDigest ||
		payload.AlertName == "" || !platformInputDigestPattern.MatchString(payload.ReceiverIdentityDigest) || !platformInputDigestPattern.MatchString(payload.AutonomyProfileDigest) ||
		payload.ExternalClusterDependencies < 0 {
		return ObservabilityIndependentEvidencePayload{}, errors.New("observability independent evidence payload is invalid")
	}
	return payload, nil
}

func canonicalObservabilityIndependentEvidencePayload(payload ObservabilityIndependentEvidencePayload) ([]byte, error) {
	raw, err := json.Marshal(payload)
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

func validateObservabilityEvidenceFile(path string, maximum int64, private bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return errors.New("evidence file metadata is invalid")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return errors.New("evidence file permissions are not private")
	}
	return nil
}

func validObservabilityObservationIdentity(identity ObservabilityCapabilityObservationIdentity) bool {
	return capabilityNamespacePattern.MatchString(identity.RunID) && strings.HasPrefix(identity.RunID, "ok147-") && len(identity.RunID) == 30 &&
		runtimeInputUIDPattern.MatchString(identity.TargetClusterUID) && platformInputDigestPattern.MatchString(identity.FixtureDigest) && platformInputDigestPattern.MatchString(identity.ProfileDigest)
}

var _ ObservabilityAlertDeliveryEvidenceSource = (*SignedObservabilityEvidenceFileSource)(nil)
var _ ObservabilityAutonomyEvidenceSource = (*SignedObservabilityEvidenceFileSource)(nil)
