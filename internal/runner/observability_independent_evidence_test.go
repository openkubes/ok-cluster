package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestSignedObservabilityEvidenceFileSourceAcceptsExactFreshEnvelope(t *testing.T) {
	material := newSignedObservabilityEvidenceMaterial(t)
	source, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path: material.evidencePath, PublicKeyPath: material.publicKeyPath,
		Clock: func() time.Time { return material.observedAt.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := source.Delivery(context.Background(), material.identity, material.alertName)
	if err != nil || !delivered {
		t.Fatalf("exact delivery evidence failed: delivered=%v err=%v", delivered, err)
	}
	ready, dependencies, err := source.Autonomy(context.Background(), material.identity)
	if err != nil || !ready || dependencies != 0 {
		t.Fatalf("exact autonomy evidence failed: ready=%v dependencies=%d err=%v", ready, dependencies, err)
	}

	// The authority is bound when the source opens. Replacing the path later
	// cannot silently rotate the key for an already-open capability session.
	replacement, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(material.publicKeyPath, []byte(base64.StdEncoding.EncodeToString(replacement)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if delivered, err = source.Delivery(context.Background(), material.identity, material.alertName); err != nil || !delivered {
		t.Fatalf("opened authority changed with its path: delivered=%v err=%v", delivered, err)
	}
}

func TestSignedObservabilityEvidenceFileSourcePreservesCorrelatedFalse(t *testing.T) {
	material := newSignedObservabilityEvidenceMaterialWithPayload(t, func(payload *ObservabilityIndependentEvidencePayload) {
		payload.ReceiverDeliveryObserved = false
		payload.ClusterLocalServicesReady = false
		payload.ExternalClusterDependencies = 1
	})
	source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(time.Minute))
	delivered, err := source.Delivery(context.Background(), material.identity, material.alertName)
	if err != nil || delivered {
		t.Fatalf("correlated delivery absence was not preserved: delivered=%v err=%v", delivered, err)
	}
	ready, dependencies, err := source.Autonomy(context.Background(), material.identity)
	if err != nil || ready || dependencies != 1 {
		t.Fatalf("correlated autonomy failure was not preserved: ready=%v dependencies=%d err=%v", ready, dependencies, err)
	}
}

func TestSignedObservabilityEvidenceFileSourceFailsClosed(t *testing.T) {
	t.Run("foreign identity", func(t *testing.T) {
		material := newSignedObservabilityEvidenceMaterial(t)
		source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(time.Minute))
		foreign := material.identity
		foreign.TargetClusterUID = "cluster-uid-foreign-ok147"
		if _, err := source.Delivery(context.Background(), foreign, material.alertName); err == nil {
			t.Fatal("foreign target identity was accepted")
		}
	})

	t.Run("wrong alert", func(t *testing.T) {
		material := newSignedObservabilityEvidenceMaterial(t)
		source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(time.Minute))
		if _, err := source.Delivery(context.Background(), material.identity, "ForeignAlert"); err == nil {
			t.Fatal("foreign alert identity was accepted")
		}
	})

	t.Run("expired", func(t *testing.T) {
		material := newSignedObservabilityEvidenceMaterial(t)
		source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(10*time.Minute))
		if _, _, err := source.Autonomy(context.Background(), material.identity); err == nil {
			t.Fatal("expired evidence was accepted")
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		material := newSignedObservabilityEvidenceMaterial(t)
		raw, err := os.ReadFile(material.evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		var envelope ObservabilityIndependentEvidenceEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Payload.ReceiverDeliveryObserved = false
		writePrivateJSON(t, material.evidencePath, envelope)
		source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(time.Minute))
		if _, err := source.Delivery(context.Background(), material.identity, material.alertName); err == nil {
			t.Fatal("tampered payload was accepted")
		}
	})

	t.Run("non-private evidence file", func(t *testing.T) {
		material := newSignedObservabilityEvidenceMaterial(t)
		if err := os.Chmod(material.evidencePath, 0o644); err != nil {
			t.Fatal(err)
		}
		source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(time.Minute))
		if _, err := source.Delivery(context.Background(), material.identity, material.alertName); err == nil {
			t.Fatal("non-private evidence file was accepted")
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		material := newSignedObservabilityEvidenceMaterial(t)
		source := openSignedObservabilityEvidenceSource(t, material, material.observedAt.Add(time.Minute))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := source.Autonomy(ctx, material.identity); err == nil {
			t.Fatal("canceled evidence claim was accepted")
		}
	})
}

func TestSignedObservabilityEvidenceFileSourceRejectsNonCanonicalAuthority(t *testing.T) {
	material := newSignedObservabilityEvidenceMaterial(t)
	raw, err := os.ReadFile(material.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(material.publicKeyPath, append([]byte(" "), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path: material.evidencePath, PublicKeyPath: material.publicKeyPath, Clock: time.Now,
	}); err == nil {
		t.Fatal("non-canonical public-key encoding was accepted")
	}
}

type signedObservabilityEvidenceMaterial struct {
	evidencePath  string
	publicKeyPath string
	identity      ObservabilityCapabilityObservationIdentity
	alertName     string
	observedAt    time.Time
}

func newSignedObservabilityEvidenceMaterial(t *testing.T) signedObservabilityEvidenceMaterial {
	t.Helper()
	return newSignedObservabilityEvidenceMaterialWithPayload(t, nil)
}

func newSignedObservabilityEvidenceMaterialWithPayload(t *testing.T, mutate func(*ObservabilityIndependentEvidencePayload)) signedObservabilityEvidenceMaterial {
	t.Helper()
	run, err := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	identity := ObservabilityCapabilityObservationIdentity{
		RunID: run.RunID, TargetClusterUID: run.TargetClusterUID,
		FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest(),
	}
	observedAt := time.Date(2026, 8, 21, 8, 0, 0, 0, time.UTC)
	payload := ObservabilityIndependentEvidencePayload{
		Format: ObservabilityIndependentEvidenceFormat, State: "OBSERVED", RunID: identity.RunID,
		TargetClusterUID: identity.TargetClusterUID, FixtureDigest: identity.FixtureDigest, ProfileDigest: identity.ProfileDigest,
		AlertName: profile.alertName, ReceiverDeliveryObserved: true, ReceiverIdentityDigest: digest.SHA256([]byte("receiver-identity")),
		ClusterLocalServicesReady: true, ExternalClusterDependencies: 0, AutonomyProfileDigest: digest.SHA256([]byte("autonomy-profile")),
		ObservedAt: observedAt.Format(time.RFC3339), ExpiresAt: observedAt.Add(10 * time.Minute).Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(&payload)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payloadRaw, err := canonicalObservabilityIndependentEvidencePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := ObservabilityIndependentEvidenceEnvelope{
		Payload: payload, EvidenceDigest: digest.SHA256(payloadRaw),
		Signature: ObservabilityIndependentEvidenceSignature{
			Algorithm: "Ed25519", KeyID: digest.SHA256(publicKey), Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payloadRaw)),
		},
	}
	root := t.TempDir()
	evidencePath := filepath.Join(root, "independent-evidence.json")
	writePrivateJSON(t, evidencePath, envelope)
	publicKeyPath := filepath.Join(root, "authority.pub")
	if err := os.WriteFile(publicKeyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return signedObservabilityEvidenceMaterial{
		evidencePath: evidencePath, publicKeyPath: publicKeyPath, identity: identity,
		alertName: profile.alertName, observedAt: observedAt,
	}
}

func openSignedObservabilityEvidenceSource(t *testing.T, material signedObservabilityEvidenceMaterial, now time.Time) *SignedObservabilityEvidenceFileSource {
	t.Helper()
	source, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path: material.evidencePath, PublicKeyPath: material.publicKeyPath, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func writePrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
