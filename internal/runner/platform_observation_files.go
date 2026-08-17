package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

// PlatformObservationStageFileRuntimeConfig binds restart-safe private runtime
// material and one already produced capability assertion to the exact
// execution history. Target identity is derived inside the runner and is not
// accepted as a second CLI-provided source of truth.
type PlatformObservationStageFileRuntimeConfig struct {
	Bundle                   StageResumeConfig
	Profile                  observation.PlatformProfile
	Ledger                   KubernetesLedgerConfig
	Argo                     KubernetesAuthorityConfig
	RuntimeMaterialPath      string
	RuntimeReceiptPath       string
	CapabilityPath           string
	ExpectedCapabilityDigest string
	PollInterval             time.Duration
	PollTimeout              time.Duration
	Clock                    func() time.Time
	Wait                     ObservationWaiter
}

// LoadPlatformObservationStageFileRuntime performs only bounded local file
// reads. It does not open credentials or contact any Kubernetes API.
func LoadPlatformObservationStageFileRuntime(config PlatformObservationStageFileRuntimeConfig) (PlatformObservationStageRuntimeConfig, error) {
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle: config.Bundle, MaterialPath: config.RuntimeMaterialPath, ReceiptPath: config.RuntimeReceiptPath,
	})
	if err != nil {
		return PlatformObservationStageRuntimeConfig{}, errors.New("load verified platform observation runtime binding")
	}
	capability, err := LoadPlatformCapabilityFile(PlatformCapabilityFileConfig{
		Path: config.CapabilityPath, ExpectedEvidenceDigest: config.ExpectedCapabilityDigest,
		ExpectedIntentRevision: config.Bundle.PlanExpected.IntentRevision, ExpectedPlatformRevision: config.Bundle.PlanExpected.PlatformRevision,
		ExpectedExecutionFixture: config.Bundle.PlanExpected.ExecutionFixture, ExpectedTargetClusterUID: runtime.material.Target.CAPIClusterUID,
		ExpectedContractDigest: config.Profile.CapabilityContractDigest, ExpectedExecutableDigest: config.Profile.CapabilityExecutableDigest,
	})
	if err != nil {
		return PlatformObservationStageRuntimeConfig{}, errors.New("load runtime-bound platform capability evidence")
	}
	return PlatformObservationStageRuntimeConfig{
		Ledger: config.Ledger, Argo: config.Argo, Runtime: runtime, Capability: capability,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout, Clock: config.Clock, Wait: config.Wait,
	}, nil
}
