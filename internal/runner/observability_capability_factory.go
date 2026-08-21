package runner

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

type KubernetesObservabilityPlatformCapabilityFactoryConfig struct {
	WorkloadAuthority   WorkloadAuthorityResolver
	IndependentEvidence *SignedObservabilityEvidenceFileSource
	Fixture             ObservabilitySyntheticFixtureConfig
	Profile             ObservabilityCapabilityCheckProfile
	PollInterval        time.Duration
	Clock               func() time.Time
}

// KubernetesObservabilityPlatformCapabilityFactory is the concrete production
// composition for the already-closed observability adapter. Opening it reads
// no workload credential and contacts no API. Runtime authority is resolved
// only after CAPI has supplied the exact target Cluster UID.
type KubernetesObservabilityPlatformCapabilityFactory struct {
	config KubernetesObservabilityPlatformCapabilityFactoryConfig
}

func NewKubernetesObservabilityPlatformCapabilityFactory(config KubernetesObservabilityPlatformCapabilityFactoryConfig) (*KubernetesObservabilityPlatformCapabilityFactory, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || config.WorkloadAuthority == nil || config.IndependentEvidence == nil || config.Clock == nil ||
		config.IndependentEvidence.clock == nil || len(config.IndependentEvidence.publicKey) != ed25519.PublicKeySize ||
		config.Profile.Digest() == "" || config.Profile.Digest() != standard.Digest() ||
		!capabilityImageDigestPattern.MatchString(config.Fixture.PushgatewayImage) || !capabilityImageDigestPattern.MatchString(config.Fixture.LogEmitterImage) ||
		config.PollInterval < time.Millisecond || config.PollInterval > 30*time.Second {
		return nil, errors.New("Kubernetes observability capability factory binding is invalid")
	}
	return &KubernetesObservabilityPlatformCapabilityFactory{config: config}, nil
}

func (factory *KubernetesObservabilityPlatformCapabilityFactory) OpenFullRunPlatformCapability(binding FullRunPlatformCapabilityBinding) (PlatformCapabilityResolver, error) {
	if factory == nil || factory.config.WorkloadAuthority == nil || factory.config.IndependentEvidence == nil || factory.config.Clock == nil ||
		binding.Namespace != factory.config.Profile.namespace || binding.Timeout < time.Minute || binding.Timeout > 30*time.Minute ||
		binding.CleanupTimeout < 10*time.Second || binding.CleanupTimeout > 2*time.Minute ||
		binding.PollInterval != factory.config.PollInterval || binding.PushgatewayImage != factory.config.Fixture.PushgatewayImage ||
		binding.LogEmitterImage != factory.config.Fixture.LogEmitterImage || binding.IndependentEvidencePath != factory.config.IndependentEvidence.path ||
		binding.IndependentEvidenceKeyID != factory.config.IndependentEvidence.keyID {
		return nil, errors.New("full-run observability capability binding is invalid")
	}
	for _, value := range []string{binding.IntentRevision, binding.PlatformRevision, binding.ExecutionFixture, binding.ContractDigest, binding.ExecutableDigest} {
		if !platformInputDigestPattern.MatchString(value) {
			return nil, errors.New("full-run observability capability revision is invalid")
		}
	}
	return &kubernetesObservabilityPlatformCapabilityResolver{factory: factory, binding: binding}, nil
}

type kubernetesObservabilityPlatformCapabilityResolver struct {
	factory *KubernetesObservabilityPlatformCapabilityFactory
	binding FullRunPlatformCapabilityBinding

	mu   sync.Mutex
	used bool
}

func (resolver *kubernetesObservabilityPlatformCapabilityResolver) ResolvePlatformCapability(ctx context.Context, policy observation.Policy, profile observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
	if resolver == nil || resolver.factory == nil || resolver.factory.config.WorkloadAuthority == nil || resolver.factory.config.IndependentEvidence == nil || resolver.factory.config.Clock == nil {
		return nil, errors.New("Kubernetes observability capability resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("Kubernetes observability capability resolution cancelled")
	}
	if _, err := observation.PolicyDigest(policy); err != nil {
		return nil, errors.New("runtime-bound observability policy is invalid")
	}
	if _, err := observation.PlatformProfileDigest(profile); err != nil || policy.TargetClusterUID == "" ||
		policy.IntentRevision != resolver.binding.IntentRevision || policy.PlatformRevision != resolver.binding.PlatformRevision ||
		profile.IntentRevision != resolver.binding.IntentRevision || profile.PlatformRevision != resolver.binding.PlatformRevision ||
		profile.ExecutionFixture != resolver.binding.ExecutionFixture || profile.CapabilityContractDigest != resolver.binding.ContractDigest ||
		profile.CapabilityExecutableDigest != resolver.binding.ExecutableDigest {
		return nil, errors.New("runtime-bound observability profile differs from full-run binding")
	}
	resolver.mu.Lock()
	if resolver.used {
		resolver.mu.Unlock()
		return nil, errors.New("Kubernetes observability capability resolver is single-use")
	}
	resolver.used = true
	resolver.mu.Unlock()

	request := PlatformCapabilityProbeRequest{
		Format: PlatformCapabilityProbeRequestFormat, TargetClusterUID: policy.TargetClusterUID,
		IntentRevision: resolver.binding.IntentRevision, PlatformRevision: resolver.binding.PlatformRevision,
		ExecutionFixture: resolver.binding.ExecutionFixture, ContractDigest: resolver.binding.ContractDigest,
		ExecutableDigest: resolver.binding.ExecutableDigest,
	}
	run, err := observabilityCapabilityRun(request, resolver.binding.Namespace)
	if err != nil {
		return nil, errors.New("construct runtime-bound observability run")
	}
	workload, err := resolver.factory.config.WorkloadAuthority.ResolveWorkloadAuthority(ctx, policy)
	if err != nil || workload.AuthorityIdentity != policy.TargetClusterUID || workload.CABundleDigest == "" {
		return nil, errors.New("resolve runtime-bound observability workload authority")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(workload)
	if err != nil || digest.SHA256(transport.caData) != workload.CABundleDigest || !transport.clientCertificate || transport.bearerToken != "" {
		return nil, errors.New("open runtime-bound observability workload authority")
	}
	fixtureClient, err := NewKubernetesCapabilityFixtureClient(KubernetesCapabilityFixtureClientConfig{
		Endpoint: workload.Endpoint, ClientCertificate: true, AuthorityIdentity: workload.AuthorityIdentity, Client: transport.client,
	}, run, resolver.factory.config.Fixture)
	if err != nil {
		return nil, errors.New("open runtime-bound observability fixture client")
	}
	backendClient, err := newKubernetesObservabilityBackendClient(KubernetesObservabilityBackendClientConfig{
		Endpoint: workload.Endpoint, ClientCertificate: true, AuthorityIdentity: workload.AuthorityIdentity,
		Client: transport.client, Profile: resolver.factory.config.Profile,
	})
	if err != nil {
		return nil, errors.New("open runtime-bound observability backend client")
	}
	backend, err := newKubernetesObservabilityCapabilityBackend(
		backendClient, resolver.factory.config.IndependentEvidence, resolver.factory.config.IndependentEvidence,
		resolver.factory.config.Profile, resolver.factory.config.PollInterval,
	)
	if err != nil {
		return nil, errors.New("open runtime-bound observability backend")
	}
	checks, err := NewStandardObservabilityCapabilityChecks(backend, resolver.factory.config.Profile)
	if err != nil {
		return nil, errors.New("open runtime-bound observability checks")
	}
	capabilityTransport, err := newKubernetesObservabilityTransport(fixtureClient, run, checks)
	if err != nil {
		return nil, errors.New("open runtime-bound observability transport")
	}
	probe, err := NewObservabilityCapabilityProbe(capabilityTransport, ObservabilityCapabilityProbeConfig{
		Namespace: resolver.binding.Namespace, ExpectedContractDigest: resolver.binding.ContractDigest,
		ExpectedExecutableDigest: resolver.binding.ExecutableDigest, Timeout: resolver.binding.Timeout, CleanupTimeout: resolver.binding.CleanupTimeout,
	})
	if err != nil {
		return nil, errors.New("open runtime-bound observability probe")
	}
	firstRun, err := NewFirstRunPlatformCapabilityResolver(probe, resolver.factory.config.Clock)
	if err != nil {
		return nil, errors.New("open first-run observability capability")
	}
	return firstRun.ResolvePlatformCapability(ctx, policy, profile)
}

var _ FullRunPlatformCapabilityFactory = (*KubernetesObservabilityPlatformCapabilityFactory)(nil)
var _ PlatformCapabilityResolver = (*kubernetesObservabilityPlatformCapabilityResolver)(nil)
