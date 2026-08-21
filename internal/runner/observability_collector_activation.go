package runner

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

type ObservabilityCollectorActivationRuntime struct {
	Clock func() time.Time
}

type ObservabilityCollectorServeFunc func(context.Context, string, http.Handler, []byte, []byte) error

// ObservabilityCollectorActivationExecution is one locally verified,
// single-use collector process. Opening reads only its private activation
// directory; Serve is the sole network-listen boundary.
type ObservabilityCollectorActivationExecution struct {
	activation  ObservabilityCollectorActivation
	collector   *ObservabilityIndependentEvidenceCollectorServer
	receipt     ObservabilityIndependentEvidenceCollectorServerReceipt
	certificate []byte
	privateKey  []byte

	mu   sync.Mutex
	used bool
}

// OpenObservabilityCollectorActivation verifies the canonical activation and
// every private file by digest before composing the exact read-only workload
// observer and collector. It performs no API request and opens no listener.
func OpenObservabilityCollectorActivation(path string, runtime ObservabilityCollectorActivationRuntime) (*ObservabilityCollectorActivationExecution, error) {
	if runtime.Clock == nil || validateObservabilityEvidenceFile(path, maximumObservabilityCollectorActivationBytes, true) != nil ||
		filepath.Clean(path) != path || filepath.Base(path) != observabilityCollectorActivationKey ||
		filepath.Dir(path) != observabilityCollectorRuntimeRoot {
		return nil, errors.New("observability collector activation runtime is invalid")
	}
	return openObservabilityCollectorActivation(path, observabilityCollectorStateRoot, runtime)
}

func openObservabilityCollectorActivation(path, stateDirectory string, runtime ObservabilityCollectorActivationRuntime) (*ObservabilityCollectorActivationExecution, error) {
	if runtime.Clock == nil || validateObservabilityEvidenceFile(path, maximumObservabilityCollectorActivationBytes, true) != nil ||
		!absoluteCleanDirectory(filepath.Dir(path)) || !absoluteCleanDirectory(stateDirectory) {
		return nil, errors.New("observability collector activation runtime is invalid")
	}
	raw, err := readBoundedRegular(path, maximumObservabilityCollectorActivationBytes)
	if err != nil {
		return nil, errors.New("read observability collector activation")
	}
	var activation ObservabilityCollectorActivation
	if err := jsonstrict.Decode(raw, &activation); err != nil {
		return nil, errors.New("decode strict observability collector activation")
	}
	canonical, err := canonicalObservabilityCollectorActivation(activation)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("observability collector activation is not canonical")
	}
	now := runtime.Clock().UTC()
	expiresAt, err := time.Parse(time.RFC3339, activation.ObserverCredentialExpires)
	if err != nil || !now.Before(expiresAt) {
		return nil, errors.New("observability collector observer credential is expired")
	}
	root := filepath.Dir(path)
	webhookPath := root + "/" + observabilityCollectorWebhookKey
	queryPath := root + "/" + observabilityCollectorQueryKey
	workloadPath := root + "/" + observabilityCollectorWorkloadKey
	workloadCAPath := root + "/" + observabilityCollectorWorkloadCAKey
	certificatePath := root + "/" + observabilityCollectorTLSCertKey
	privateKeyPath := root + "/" + observabilityCollectorTLSKeyKey
	webhook, err := readCollectorToken(webhookPath)
	if err != nil || digest.SHA256(webhook) != activation.WebhookAuthorityDigest {
		return nil, errors.New("observability collector webhook authority differs")
	}
	query, err := readCollectorToken(queryPath)
	if err != nil || digest.SHA256(query) != activation.QueryAuthorityDigest {
		return nil, errors.New("observability collector query authority differs")
	}
	workload, err := readCollectorToken(workloadPath)
	if err != nil || digest.SHA256(workload) != activation.WorkloadTokenDigest ||
		subtle.ConstantTimeCompare(webhook, query) == 1 ||
		subtle.ConstantTimeCompare(webhook, workload) == 1 ||
		subtle.ConstantTimeCompare(query, workload) == 1 {
		return nil, errors.New("observability collector private authorities differ")
	}
	if validateObservabilityEvidenceFile(workloadCAPath, maximumCABytes, true) != nil ||
		validateObservabilityEvidenceFile(certificatePath, 128*1024, true) != nil {
		return nil, errors.New("observability collector private certificate material is invalid")
	}
	workloadCA, err := readBoundedRegular(workloadCAPath, maximumCABytes)
	if err != nil || digest.SHA256(workloadCA) != activation.WorkloadCADigest {
		return nil, errors.New("observability collector workload CA differs")
	}
	certificate, privateKey, certificateDigest, err := loadObservabilityCollectorTLS(
		certificatePath, privateKeyPath, activation.PublicEndpoint, now,
	)
	if err != nil || certificateDigest != activation.TLSCertificateDigest {
		return nil, errors.New("observability collector TLS identity differs")
	}
	profile, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || profile.Digest() != activation.ProfileDigest {
		return nil, errors.New("observability collector profile differs")
	}
	maximumRecordAge, err := time.ParseDuration(activation.MaximumRecordAge)
	if err != nil {
		return nil, errors.New("observability collector record age differs")
	}
	autonomy, err := OpenKubernetesObservabilityAutonomyObserver(KubernetesObservabilityAutonomyObserverConfig{
		Endpoint: activation.WorkloadEndpoint, TokenFile: workloadPath, CAFile: workloadCAPath,
		CABundleDigest: activation.WorkloadCADigest, TargetClusterUID: activation.TargetClusterUID, Profile: profile,
	})
	if err != nil {
		return nil, errors.New("open observability collector autonomy observer")
	}
	collector, err := OpenObservabilityIndependentEvidenceCollectorServer(ObservabilityIndependentEvidenceCollectorServerConfig{
		WebhookTokenFile: webhookPath, QueryTokenFile: queryPath, StateDirectory: stateDirectory,
		ReceiverName: activation.ReceiverName, Profile: profile, MaximumRecordAge: maximumRecordAge,
		Clock: runtime.Clock, AutonomyObserver: autonomy,
	})
	if err != nil {
		return nil, errors.New("open observability collector server")
	}
	receipt, err := collector.Receipt()
	if err != nil || receipt.ProfileDigest != activation.ProfileDigest ||
		receipt.ReceiverIdentityDigest != digest.SHA256([]byte("ok147-observability-alert-receiver/v1\n"+activation.ReceiverName)) ||
		receipt.MaximumRecordAge != activation.MaximumRecordAge {
		return nil, errors.New("observability collector server differs from activation")
	}
	return &ObservabilityCollectorActivationExecution{
		activation: activation, collector: collector, receipt: receipt,
		certificate: append([]byte(nil), certificate...), privateKey: append([]byte(nil), privateKey...),
	}, nil
}

func (execution *ObservabilityCollectorActivationExecution) Receipt() (ObservabilityIndependentEvidenceCollectorServerReceipt, error) {
	if execution == nil || execution.collector == nil || execution.receipt.State != "VERIFIED" {
		return ObservabilityIndependentEvidenceCollectorServerReceipt{}, errors.New("observability collector activation execution is invalid")
	}
	return execution.receipt, nil
}

// Serve opens the exact bound listener once. The injected serving function is
// used by the CLI and keeps listener mechanics independently testable.
func (execution *ObservabilityCollectorActivationExecution) Serve(ctx context.Context, serve ObservabilityCollectorServeFunc) error {
	if execution == nil || execution.collector == nil || serve == nil {
		return errors.New("observability collector activation execution is unavailable")
	}
	execution.mu.Lock()
	if execution.used {
		execution.mu.Unlock()
		return errors.New("observability collector activation execution is single-use")
	}
	execution.used = true
	execution.mu.Unlock()
	return serve(ctx, execution.activation.ListenAddress, execution.collector,
		append([]byte(nil), execution.certificate...), append([]byte(nil), execution.privateKey...))
}
