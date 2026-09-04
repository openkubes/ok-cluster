package runner

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const observabilityEvidenceAuthorityExecutionOverhead = 10 * time.Second

type ObservabilityEvidenceAuthorityActivationRuntime struct {
	Clock func() time.Time
	Wait  ObservationWaiter
}

// ObservabilityEvidenceAuthorityExecution is a single-use, separately
// credentialed producer process. Opening it reads and verifies only local
// private files. Run is the sole collector contact and evidence-write boundary.
type ObservabilityEvidenceAuthorityExecution struct {
	activation ObservabilityEvidenceAuthorityActivation
	producer   *ObservabilityIndependentEvidenceProducer
	wait       ObservationWaiter

	mu   sync.Mutex
	used bool
}

// OpenObservabilityEvidenceAuthorityActivation verifies the canonical
// activation, pinned TLS collector and private signing key without contacting
// an API or creating a file.
func OpenObservabilityEvidenceAuthorityActivation(path string, runtime ObservabilityEvidenceAuthorityActivationRuntime) (*ObservabilityEvidenceAuthorityExecution, error) {
	if runtime.Clock == nil || runtime.Wait == nil || validateObservabilityEvidenceFile(path, maximumObservabilityEvidenceAuthorityBytes, true) != nil {
		return nil, errors.New("observability evidence authority activation runtime is invalid")
	}
	raw, err := readBoundedRegular(path, maximumObservabilityEvidenceAuthorityBytes)
	if err != nil {
		return nil, errors.New("read observability evidence authority activation")
	}
	var activation ObservabilityEvidenceAuthorityActivation
	if err := jsonstrict.Decode(raw, &activation); err != nil {
		return nil, errors.New("decode strict observability evidence authority activation")
	}
	canonical, err := canonicalObservabilityEvidenceAuthorityActivation(activation)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("observability evidence authority activation is not canonical")
	}
	pollInterval, _ := time.ParseDuration(activation.IdentityPollInterval)
	waitTimeout, _ := time.ParseDuration(activation.IdentityWaitTimeout)
	validFor, _ := time.ParseDuration(activation.EvidenceValidity)
	collectionTimeout, _ := time.ParseDuration(activation.CollectionTimeout)
	profile, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil {
		return nil, errors.New("open standard observability evidence authority profile")
	}
	collector, err := OpenHTTPObservabilityIndependentEvidenceCollector(HTTPObservabilityIndependentEvidenceCollectorConfig{
		Endpoint: activation.CollectorEndpoint, TokenFile: activation.CollectorTokenPath,
		CAFile: activation.CollectorCAPath, CABundleDigest: activation.CollectorCADigest,
	})
	if err != nil {
		return nil, errors.New("open observability evidence authority collector")
	}
	producer, err := OpenObservabilityIndependentEvidenceProducer(ObservabilityIndependentEvidenceProducerConfig{
		OutputPath: activation.EvidenceOutputPath, PrivateKeyPath: activation.PrivateKeyPath,
		Profile: profile, ValidFor: validFor, Timeout: collectionTimeout, Clock: runtime.Clock, Collector: collector,
	})
	if err != nil {
		return nil, errors.New("open observability evidence authority producer")
	}
	activation.IdentityPollInterval = pollInterval.String()
	activation.IdentityWaitTimeout = waitTimeout.String()
	activation.EvidenceValidity = validFor.String()
	activation.CollectionTimeout = collectionTimeout.String()
	return &ObservabilityEvidenceAuthorityExecution{activation: activation, producer: producer, wait: runtime.Wait}, nil
}

func (execution *ObservabilityEvidenceAuthorityExecution) Run(ctx context.Context) (ObservabilityIndependentEvidenceReceipt, error) {
	receipt := ObservabilityIndependentEvidenceReceipt{Format: ObservabilityIndependentEvidenceReceiptFormat, State: "STOPPED_ZERO_WRITE"}
	if execution == nil || execution.producer == nil || execution.wait == nil {
		return receipt, errors.New("observability evidence authority execution is unavailable")
	}
	execution.mu.Lock()
	if execution.used {
		execution.mu.Unlock()
		return receipt, errors.New("observability evidence authority execution is single-use")
	}
	execution.used = true
	execution.mu.Unlock()
	pollInterval, _ := time.ParseDuration(execution.activation.IdentityPollInterval)
	waitTimeout, _ := time.ParseDuration(execution.activation.IdentityWaitTimeout)
	collectionTimeout, _ := time.ParseDuration(execution.activation.CollectionTimeout)
	bounded, cancel := context.WithTimeout(ctx, waitTimeout+collectionTimeout+observabilityEvidenceAuthorityExecutionOverhead)
	defer cancel()
	identity, err := WaitForObservabilityIndependentEvidenceIdentity(bounded, ObservabilityIndependentEvidenceIdentityWaitConfig{
		IdentityPath: execution.activation.IdentityPath, ReceiptPath: execution.activation.IdentityReceiptPath,
		ExecutorTerminalPath:   filepath.Join(filepath.Dir(execution.activation.IdentityPath), FullRunExecutorTerminalMarkerName),
		ExpectedManifestDigest: execution.activation.ExpectedManifestDigest,
		PollInterval:           pollInterval, Timeout: waitTimeout, Wait: execution.wait,
	})
	if errors.Is(err, errFullRunExecutorTerminatedBeforeEvidenceIdentity) {
		return receipt, nil
	}
	if err != nil {
		return receipt, errors.New("load runtime-bound observability evidence identity")
	}
	return execution.producer.Produce(bounded, identity)
}
