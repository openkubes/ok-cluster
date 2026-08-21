package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

type recordingIndependentEvidenceCollector struct {
	identity    ObservabilityCapabilityObservationIdentity
	alertName   string
	observation ObservabilityIndependentEvidenceObservation
	err         error
	calls       int
}

func (collector *recordingIndependentEvidenceCollector) Collect(_ context.Context, identity ObservabilityCapabilityObservationIdentity, alertName string) (ObservabilityIndependentEvidenceObservation, error) {
	collector.identity, collector.alertName = identity, alertName
	collector.calls++
	return collector.observation, collector.err
}

func TestObservabilityIndependentEvidenceProducerWritesVerifiableEnvelope(t *testing.T) {
	material := newIndependentEvidenceProducerMaterial(t)
	producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := producer.Produce(context.Background(), material.identity)
	if err != nil || receipt.State != "WRITTEN_VERIFIED" || receipt.KeyID != digest.SHA256(material.publicKey) || receipt.FileMode != "0600" || receipt.FileSize == 0 {
		t.Fatalf("independent evidence receipt differs: %#v err=%v", receipt, err)
	}
	if material.collector.calls != 1 || material.collector.identity != material.identity || material.collector.alertName != material.config.Profile.alertName {
		t.Fatalf("collector binding differs: %#v", material.collector)
	}
	publicKeyPath := filepath.Join(material.root, "authority.pub")
	if err := os.WriteFile(publicKeyPath, []byte(base64.StdEncoding.EncodeToString(material.publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path: material.config.OutputPath, PublicKeyPath: publicKeyPath,
		Clock: func() time.Time { return material.now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := source.Delivery(context.Background(), material.identity, material.config.Profile.alertName)
	if err != nil || !delivered {
		t.Fatalf("producer output failed delivery verification: delivered=%v err=%v", delivered, err)
	}
	ready, dependencies, err := source.Autonomy(context.Background(), material.identity)
	if err != nil || !ready || dependencies != 0 {
		t.Fatalf("producer output failed autonomy verification: ready=%v dependencies=%d err=%v", ready, dependencies, err)
	}
	if _, err := producer.Produce(context.Background(), material.identity); err == nil || material.collector.calls != 1 {
		t.Fatal("single-use producer repeated collection")
	}
}

func TestObservabilityIndependentEvidenceProducerPreservesCorrelatedFalse(t *testing.T) {
	material := newIndependentEvidenceProducerMaterial(t)
	material.collector.observation.ReceiverDeliveryObserved = false
	material.collector.observation.ClusterLocalServicesReady = false
	material.collector.observation.ExternalClusterDependencies = 2
	producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := producer.Produce(context.Background(), material.identity); err != nil || receipt.State != "WRITTEN_VERIFIED" {
		t.Fatalf("correlated false evidence was not written: %#v err=%v", receipt, err)
	}
	publicKeyPath := filepath.Join(material.root, "authority.pub")
	if err := os.WriteFile(publicKeyPath, []byte(base64.StdEncoding.EncodeToString(material.publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path: material.config.OutputPath, PublicKeyPath: publicKeyPath, Clock: func() time.Time { return material.now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := source.Delivery(context.Background(), material.identity, material.config.Profile.alertName); err != nil || delivered {
		t.Fatalf("correlated false delivery changed: delivered=%v err=%v", delivered, err)
	}
	if ready, dependencies, err := source.Autonomy(context.Background(), material.identity); err != nil || ready || dependencies != 2 {
		t.Fatalf("correlated false autonomy changed: ready=%v dependencies=%d err=%v", ready, dependencies, err)
	}
}

func TestObservabilityIndependentEvidenceProducerFailsClosedBeforeWrite(t *testing.T) {
	t.Run("output appeared after open", func(t *testing.T) {
		material := newIndependentEvidenceProducerMaterial(t)
		producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(material.config.OutputPath, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		receipt, err := producer.Produce(context.Background(), material.identity)
		if err == nil || receipt.State != "PREWRITE" || material.collector.calls != 0 {
			t.Fatalf("pre-existing output reached collector: %#v calls=%d err=%v", receipt, material.collector.calls, err)
		}
	})

	t.Run("collector failure", func(t *testing.T) {
		material := newIndependentEvidenceProducerMaterial(t)
		material.collector.err = errors.New("private collector detail")
		producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := producer.Produce(context.Background(), material.identity)
		if err == nil || receipt.State != "PREWRITE" || !errors.Is(fileError(material.config.OutputPath), os.ErrNotExist) {
			t.Fatalf("collector failure wrote evidence: %#v err=%v", receipt, err)
		}
	})

	t.Run("invalid observation", func(t *testing.T) {
		material := newIndependentEvidenceProducerMaterial(t)
		material.collector.observation.AutonomyProfileDigest = "mutable"
		producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := producer.Produce(context.Background(), material.identity); err == nil {
			t.Fatal("invalid collector observation was signed")
		}
		if _, err := os.Lstat(material.config.OutputPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid collector observation created output")
		}
	})

	t.Run("canceled collection", func(t *testing.T) {
		material := newIndependentEvidenceProducerMaterial(t)
		producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := producer.Produce(ctx, material.identity); err == nil {
			t.Fatal("canceled collector result was signed")
		}
		if _, err := os.Lstat(material.config.OutputPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("canceled collection created output")
		}
	})

	t.Run("foreign profile identity", func(t *testing.T) {
		material := newIndependentEvidenceProducerMaterial(t)
		producer, err := OpenObservabilityIndependentEvidenceProducer(material.config)
		if err != nil {
			t.Fatal(err)
		}
		foreign := material.identity
		foreign.ProfileDigest = digest.SHA256([]byte("foreign-profile"))
		if _, err := producer.Produce(context.Background(), foreign); err == nil || material.collector.calls != 0 {
			t.Fatal("foreign profile identity reached collector")
		}
	})
}

func TestObservabilityIndependentEvidenceProducerRejectsExposedPrivateKey(t *testing.T) {
	material := newIndependentEvidenceProducerMaterial(t)
	if err := os.Chmod(material.config.PrivateKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObservabilityIndependentEvidenceProducer(material.config); err == nil {
		t.Fatal("exposed evidence private key was accepted")
	}
}

type independentEvidenceProducerMaterial struct {
	root      string
	config    ObservabilityIndependentEvidenceProducerConfig
	identity  ObservabilityCapabilityObservationIdentity
	collector *recordingIndependentEvidenceCollector
	publicKey ed25519.PublicKey
	now       time.Time
}

func newIndependentEvidenceProducerMaterial(t *testing.T) independentEvidenceProducerMaterial {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(root, "authority.key")
	if err := os.WriteFile(privateKeyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	collector := &recordingIndependentEvidenceCollector{observation: ObservabilityIndependentEvidenceObservation{
		ReceiverDeliveryObserved: true, ReceiverIdentityDigest: digest.SHA256([]byte("receiver")), ClusterLocalServicesReady: true,
		ExternalClusterDependencies: 0, AutonomyProfileDigest: digest.SHA256([]byte("autonomy")),
	}}
	now := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	return independentEvidenceProducerMaterial{
		root: root, identity: identity, collector: collector, publicKey: publicKey, now: now,
		config: ObservabilityIndependentEvidenceProducerConfig{
			OutputPath: filepath.Join(root, "evidence.json"), PrivateKeyPath: privateKeyPath, Profile: profile,
			ValidFor: 10 * time.Minute, Timeout: time.Minute, Clock: func() time.Time { return now }, Collector: collector,
		},
	}
}

func fileError(path string) error {
	_, err := os.Lstat(path)
	return err
}
