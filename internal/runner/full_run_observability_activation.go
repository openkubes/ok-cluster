package runner

import (
	"errors"
	"time"
)

// KubernetesObservabilityFullRunActivationConfig contains the only
// process-local input not carried by the private execution manifest: the
// pinned public key used to verify independent Observability evidence.
type KubernetesObservabilityFullRunActivationConfig struct {
	IndependentEvidencePublicKeyPath string
	Clock                            func() time.Time
	Wait                             ObservationWaiter
}

// OpenKubernetesObservabilityFullRunActivation composes the verified private
// manifest, lifecycle-derived authority bridge and concrete Observability
// capability factory. It performs no API request or stage action; Run remains
// the only mutation boundary.
func OpenKubernetesObservabilityFullRunActivation(path string, runtime KubernetesObservabilityFullRunActivationConfig) (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
	receipt := FullRunExecutionActivationReceipt{Format: FullRunExecutionActivationReceiptFormat, State: "STOPPED"}
	if runtime.IndependentEvidencePublicKeyPath == "" || runtime.Clock == nil || runtime.Wait == nil {
		return nil, receipt, errors.New("Kubernetes observability full-run runtime is incomplete")
	}
	manifest, manifestReceipt, err := LoadFullRunExecutionManifest(path)
	receipt.Manifest = manifestReceipt
	if err != nil {
		return nil, receipt, errors.New("load Kubernetes observability full-run manifest")
	}
	document := manifest.document
	workload := NewDeferredFullRunWorkloadAuthorityResolver()
	evidence, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path:          document.PlatformObservation.Capability.IndependentEvidencePath,
		PublicKeyPath: runtime.IndependentEvidencePublicKeyPath,
		Clock:         runtime.Clock,
	})
	if err != nil {
		return nil, receipt, errors.New("open full-run independent Observability evidence")
	}
	profile, err := StandardObservabilityCapabilityCheckProfile(document.PlatformObservation.Capability.Namespace)
	if err != nil {
		return nil, receipt, errors.New("open full-run Observability profile")
	}
	pollInterval, err := time.ParseDuration(document.PlatformObservation.Capability.PollInterval)
	if err != nil {
		return nil, receipt, errors.New("parse full-run Observability polling")
	}
	capability, err := NewKubernetesObservabilityPlatformCapabilityFactory(KubernetesObservabilityPlatformCapabilityFactoryConfig{
		WorkloadAuthority: workload, IndependentEvidence: evidence,
		Fixture: ObservabilitySyntheticFixtureConfig{
			PushgatewayImage: document.PlatformObservation.Capability.PushgatewayImage,
			LogEmitterImage:  document.PlatformObservation.Capability.LogEmitterImage,
		},
		Profile: profile, PollInterval: pollInterval, Clock: runtime.Clock,
	})
	if err != nil {
		return nil, receipt, errors.New("open full-run Observability capability factory")
	}
	config, err := manifest.ExecutionConfig(FullRunExecutionManifestRuntime{
		PlatformCapability: capability, Clock: runtime.Clock, Wait: runtime.Wait,
	})
	if err != nil {
		return nil, receipt, errors.New("open concrete full-run execution configuration")
	}
	config.WorkloadAuthorityBinder = workload
	execution, err := OpenFullRunExecution(config)
	if err != nil {
		return nil, receipt, errors.New("open concrete Kubernetes observability full-run execution")
	}
	receipt.State = "PREPARED"
	return &FullRunExecutionActivation{execution: execution, manifest: manifestReceipt}, receipt, nil
}
