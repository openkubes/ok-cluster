package runner

import (
	"context"
	"errors"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

// sharedPlatformCapabilityResolver turns one single-use first-run probe into
// one immutable in-memory assertion shared by Stage 11 and Stage 12. It never
// retries the underlying probe: success and failure are both cached.
type sharedPlatformCapabilityResolver struct {
	resolver PlatformCapabilityResolver

	mu            sync.Mutex
	policyDigest  string
	profileDigest string
	source        *sharedPlatformCapabilitySource
}

type sharedPlatformCapabilitySource struct {
	source observation.PlatformCapabilitySource

	once  sync.Once
	state observation.PlatformCapabilityState
	err   error
}

func newSharedPlatformCapabilityResolver(resolver PlatformCapabilityResolver) (*sharedPlatformCapabilityResolver, error) {
	if resolver == nil {
		return nil, errors.New("first-run Platform capability resolver is required")
	}
	return &sharedPlatformCapabilityResolver{resolver: resolver}, nil
}

func (resolver *sharedPlatformCapabilityResolver) ResolvePlatformCapability(ctx context.Context, policy observation.Policy, profile observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
	if resolver == nil || resolver.resolver == nil {
		return nil, errors.New("shared Platform capability resolver is required")
	}
	policyDigest, err := observation.PolicyDigest(policy)
	if err != nil {
		return nil, errors.New("first-run Platform capability policy is invalid")
	}
	profileDigest, err := observation.PlatformProfileDigest(profile)
	if err != nil {
		return nil, errors.New("first-run Platform capability profile is invalid")
	}

	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.source != nil {
		if resolver.policyDigest != policyDigest || resolver.profileDigest != profileDigest {
			return nil, errors.New("first-run Platform capability identity changed after binding")
		}
		return resolver.source, nil
	}
	source, err := resolver.resolver.ResolvePlatformCapability(ctx, policy, clonePlatformProfile(profile))
	if err != nil || source == nil {
		return nil, errors.New("resolve first-run Platform capability")
	}
	shared := &sharedPlatformCapabilitySource{source: source}
	resolver.policyDigest, resolver.profileDigest, resolver.source = policyDigest, profileDigest, shared
	return shared, nil
}

func (source *sharedPlatformCapabilitySource) Capability(ctx context.Context) (observation.PlatformCapabilityState, error) {
	if source == nil || source.source == nil {
		return observation.PlatformCapabilityState{}, errors.New("shared Platform capability source is required")
	}
	source.once.Do(func() {
		state, err := source.source.Capability(ctx)
		if err != nil {
			source.err = errors.New("bounded first-run Platform capability failed")
			return
		}
		if err := observation.ValidatePlatformCapabilityState(state); err != nil {
			source.err = errors.New("bounded first-run Platform capability result is invalid")
			return
		}
		source.state = state
	})
	if source.err != nil {
		return observation.PlatformCapabilityState{}, source.err
	}
	return source.state, nil
}

func loadFirstRunPlatformObservationRuntime(config PlatformObservationStageFileRuntimeConfig, capability PlatformCapabilityResolver) (PlatformObservationStageRuntimeConfig, error) {
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle: config.Bundle, MaterialPath: config.RuntimeMaterialPath, ReceiptPath: config.RuntimeReceiptPath,
	})
	if err != nil {
		return PlatformObservationStageRuntimeConfig{}, errors.New("load first-run platform observation runtime binding")
	}
	policy := runtimeObservationPolicy(config.Bundle, runtime.material.Target.CAPIClusterUID, []string{"PlatformReady"})
	source, err := capability.ResolvePlatformCapability(context.Background(), policy, clonePlatformProfile(config.Profile))
	if err != nil || source == nil {
		return PlatformObservationStageRuntimeConfig{}, errors.New("resolve first-run Platform capability source")
	}
	return PlatformObservationStageRuntimeConfig{
		Ledger: config.Ledger, Argo: config.Argo, Runtime: runtime, Capability: source,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout, Clock: config.Clock, Wait: config.Wait,
	}, nil
}

func loadFirstRunAggregateEvidenceRuntime(config AggregateEvidenceStageFileRuntimeConfig, capability PlatformCapabilityResolver) (AggregateEvidenceStageRuntimeConfig, error) {
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle: config.Bundle, MaterialPath: config.RuntimeMaterialPath, ReceiptPath: config.RuntimeReceiptPath,
	})
	if err != nil {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("load first-run aggregate runtime binding")
	}
	if config.ExpectedWorkloadEndpoint == "" || runtime.material.Target.WorkloadAPIEndpoint != config.ExpectedWorkloadEndpoint ||
		config.WorkloadCAFile == "" || (config.WorkloadTokenFile != "") == (config.WorkloadKubeconfigFile != "") {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("first-run aggregate workload binding is invalid")
	}
	argoCA, err := readBoundedRegular(config.Argo.CAFile, maximumCABytes)
	if err != nil {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("read bounded first-run aggregate GitOps CA")
	}
	config.Argo.CABundleDigest = digest.SHA256(argoCA)
	workload := &runtimeBindingWorkloadAuthorityResolver{
		targetUID: runtime.material.Target.CAPIClusterUID, endpoint: runtime.material.Target.WorkloadAPIEndpoint,
		caDigest: runtime.material.Target.WorkloadAPICADigest, tokenFile: config.WorkloadTokenFile,
		kubeconfigFile: config.WorkloadKubeconfigFile, caFile: config.WorkloadCAFile,
	}
	return AggregateEvidenceStageRuntimeConfig{
		Ledger: config.Ledger,
		Observer: KubernetesAggregateObserverConfig{
			Management: config.Management, ExpectedManagementAuthority: config.Bundle.PlanExpected.ManagementAuthority,
			Argo: config.Argo, ExpectedArgoAuthority: config.Bundle.PlanExpected.GitOpsAuthority,
			Namespace: config.Bundle.PlanExpected.ContractIdentity.Namespace, Name: config.Bundle.PlanExpected.ContractIdentity.Name,
			HCPName:        config.Bundle.PlanExpected.ContractIdentity.Name + "-cilium",
			NetworkProfile: config.NetworkProfile, PlatformProfile: config.PlatformProfile,
			WorkloadAuthority: workload, PlatformCapability: capability, Clock: config.Clock,
		},
		Runtime: runtime,
	}, nil
}

func runtimeObservationPolicy(bundle StageResumeConfig, targetUID string, required []string) observation.Policy {
	return observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: bundle.PlanExpected.IntentRevision,
		EnablementRevision: bundle.PlanExpected.EnablementRevision, PlatformRevision: bundle.PlanExpected.PlatformRevision,
		TargetClusterUID: targetUID, Required: append([]string(nil), required...),
	}
}

var _ PlatformCapabilityResolver = (*sharedPlatformCapabilityResolver)(nil)
var _ observation.PlatformCapabilitySource = (*sharedPlatformCapabilitySource)(nil)
