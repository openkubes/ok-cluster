package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

// WorkloadAuthorityResolver materializes the bounded workload API authority
// only after submission has bound the immutable CAPI Cluster UID. It must not
// return a reusable multi-cluster administrator identity.
type WorkloadAuthorityResolver interface {
	ResolveWorkloadAuthority(context.Context, observation.Policy) (KubernetesAuthorityConfig, error)
}

// PlatformCapabilityResolver returns capability evidence for the exact
// runtime-bound execution. A pre-existing assertion from another target or
// revision is rejected by the Platform evaluator.
type PlatformCapabilityResolver interface {
	ResolvePlatformCapability(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error)
}

// WorkloadAuthorityResolverFunc adapts a bounded function to a resolver.
type WorkloadAuthorityResolverFunc func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error)

func (resolve WorkloadAuthorityResolverFunc) ResolveWorkloadAuthority(ctx context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
	return resolve(ctx, policy)
}

// PlatformCapabilityResolverFunc adapts a bounded function to a resolver.
type PlatformCapabilityResolverFunc func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error)

func (resolve PlatformCapabilityResolverFunc) ResolvePlatformCapability(ctx context.Context, policy observation.Policy, profile observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
	return resolve(ctx, policy, profile)
}

// KubernetesAggregateObserverConfig binds the three observation authorities
// and immutable Network/Platform semantics. Workload authority and capability
// proof are deliberately lazy because their concrete target UID does not exist
// before the CAPI submission response.
type KubernetesAggregateObserverConfig struct {
	Management                  KubernetesAuthorityConfig
	ExpectedManagementAuthority string
	Argo                        KubernetesAuthorityConfig
	ExpectedArgoAuthority       string
	Namespace                   string
	Name                        string
	HCPName                     string
	NetworkProfile              observation.NetworkProfile
	PlatformProfile             observation.PlatformProfile
	WorkloadAuthority           WorkloadAuthorityResolver
	PlatformCapability          PlatformCapabilityResolver
	Clock                       func() time.Time
}

// KubernetesAggregateObserver lazily materializes only the source domains
// required by the runtime-bound observation policy and only after the prior
// authority stage is current. It has no polling, retry, mutation, status
// publication, or persistent controller loop.
type KubernetesAggregateObserver struct {
	config  KubernetesAggregateObserverConfig
	openers kubernetesAggregateSourceOpeners
}

type kubernetesAggregateSourceOpeners struct {
	capi     func(KubernetesAuthorityConfig, string, string, string) (observation.CAPIEvidenceSource, error)
	network  func(KubernetesNetworkObserverConfig) (observation.NetworkEvidenceSource, error)
	platform func(KubernetesPlatformObserverConfig) (observation.PlatformEvidenceSource, error)
}

// OpenKubernetesAggregateObserver validates and freezes the pre-runtime
// inputs. It performs no file read and no Kubernetes request.
func OpenKubernetesAggregateObserver(config KubernetesAggregateObserverConfig) (*KubernetesAggregateObserver, error) {
	if config.ExpectedManagementAuthority == "" || config.ExpectedArgoAuthority == "" || config.Namespace == "" || config.Name == "" || config.HCPName == "" || config.WorkloadAuthority == nil || config.PlatformCapability == nil || config.Clock == nil {
		return nil, errors.New("aggregate Kubernetes observer binding is incomplete")
	}
	if _, err := observation.NetworkProfileDigest(config.NetworkProfile); err != nil {
		return nil, errors.New("aggregate Kubernetes observer Network profile is invalid")
	}
	if _, err := observation.PlatformProfileDigest(config.PlatformProfile); err != nil {
		return nil, errors.New("aggregate Kubernetes observer Platform profile is invalid")
	}
	config.PlatformProfile = clonePlatformProfile(config.PlatformProfile)
	return &KubernetesAggregateObserver{
		config: config,
		openers: kubernetesAggregateSourceOpeners{
			capi: func(authority KubernetesAuthorityConfig, expected, namespace, name string) (observation.CAPIEvidenceSource, error) {
				return OpenKubernetesCAPILifecycleObserver(authority, expected, namespace, name)
			},
			network: func(config KubernetesNetworkObserverConfig) (observation.NetworkEvidenceSource, error) {
				return OpenKubernetesNetworkSourceCollector(config)
			},
			platform: func(config KubernetesPlatformObserverConfig) (observation.PlatformEvidenceSource, error) {
				return OpenKubernetesPlatformSourceCollector(config)
			},
		},
	}, nil
}

// Observe receives only a post-submission policy. Resolver and credential
// materialization cannot occur until that policy carries the concrete target
// Cluster UID and matches both immutable profiles.
func (observer *KubernetesAggregateObserver) Observe(ctx context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	if observer == nil {
		return observation.VerifiedResult{}, errors.New("aggregate Kubernetes observer is required")
	}
	if err := ctx.Err(); err != nil {
		return observation.VerifiedResult{}, errors.New("aggregate Kubernetes observation cancelled")
	}
	if _, err := observation.PolicyDigest(policy); err != nil {
		return observation.VerifiedResult{}, errors.New("runtime-bound observation policy is invalid")
	}
	if observer.config.NetworkProfile.IntentRevision != policy.IntentRevision || observer.config.NetworkProfile.EnablementRevision != policy.EnablementRevision {
		return observation.VerifiedResult{}, errors.New("Network profile differs from runtime-bound observation policy")
	}
	if observer.config.PlatformProfile.IntentRevision != policy.IntentRevision || observer.config.PlatformProfile.PlatformRevision != policy.PlatformRevision {
		return observation.VerifiedResult{}, errors.New("Platform profile differs from runtime-bound observation policy")
	}

	required := requiredObservationDomains(policy.Required)
	capiSource := observation.CAPIEvidenceSource(unusedCAPISource{})
	networkSource := observation.NetworkEvidenceSource(unusedNetworkSource{})
	platformSource := observation.PlatformEvidenceSource(unusedPlatformSource{})

	if required.capi {
		var err error
		capiSource, err = observer.openers.capi(observer.config.Management, observer.config.ExpectedManagementAuthority, observer.config.Namespace, observer.config.Name)
		if err != nil {
			return observation.VerifiedResult{}, errors.New("open bounded CAPI observation source")
		}
	}
	if required.network {
		networkSource = lazyNetworkEvidenceSource{open: func(stageCtx context.Context) (observation.NetworkEvidenceSource, error) {
			workload, err := observer.config.WorkloadAuthority.ResolveWorkloadAuthority(stageCtx, policy)
			if err != nil {
				return nil, errors.New("resolve bounded workload observation authority")
			}
			if workload.AuthorityIdentity != policy.TargetClusterUID {
				return nil, errors.New("workload observation authority differs from runtime-bound target Cluster")
			}
			source, err := observer.openers.network(KubernetesNetworkObserverConfig{
				Management: observer.config.Management, Workload: workload,
				ExpectedManagementAuthority: observer.config.ExpectedManagementAuthority,
				TargetClusterUID:            policy.TargetClusterUID, Namespace: observer.config.Namespace,
				Name: observer.config.Name, HCPName: observer.config.HCPName, Clock: observer.config.Clock,
			})
			if err != nil || source == nil {
				return nil, errors.New("open bounded NetworkReady observation source")
			}
			return source, nil
		}}
	}
	if required.platform {
		platformSource = lazyPlatformEvidenceSource{open: func(stageCtx context.Context) (observation.PlatformEvidenceSource, error) {
			capability, err := observer.config.PlatformCapability.ResolvePlatformCapability(stageCtx, policy, clonePlatformProfile(observer.config.PlatformProfile))
			if err != nil || capability == nil {
				return nil, errors.New("resolve bounded Platform capability evidence")
			}
			source, err := observer.openers.platform(KubernetesPlatformObserverConfig{
				Argo: observer.config.Argo, ExpectedArgoAuthority: observer.config.ExpectedArgoAuthority,
				Profile: clonePlatformProfile(observer.config.PlatformProfile), Capability: capability,
				TargetClusterUID: policy.TargetClusterUID, Clock: observer.config.Clock,
			})
			if err != nil || source == nil {
				return nil, errors.New("open bounded PlatformReady observation source")
			}
			return source, nil
		}}
	}

	aggregate, err := observation.NewAggregateObserver(observation.AggregateObserverConfig{
		CAPI: capiSource, Network: networkSource, Platform: platformSource,
		NetworkProfile: observer.config.NetworkProfile, Clock: observer.config.Clock,
	})
	if err != nil {
		return observation.VerifiedResult{}, errors.New("compose bounded aggregate observation")
	}
	return aggregate.Observe(ctx, policy)
}

func clonePlatformProfile(profile observation.PlatformProfile) observation.PlatformProfile {
	profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), profile.RequiredApplications...)
	return profile
}

type observationDomains struct{ capi, network, platform bool }

func requiredObservationDomains(conditions []string) observationDomains {
	var domains observationDomains
	for _, condition := range conditions {
		switch condition {
		case "InfrastructureReady", "ControlPlaneAvailable":
			domains.capi = true
		case "NetworkReady":
			domains.network = true
		case "PlatformReady":
			domains.platform = true
		}
	}
	return domains
}

type unusedCAPISource struct{}

func (unusedCAPISource) Collect(context.Context, observation.Policy) ([]observation.Evidence, error) {
	return nil, errors.New("unused CAPI source was called")
}

type unusedNetworkSource struct{}

func (unusedNetworkSource) Observe(context.Context, observation.Policy, observation.NetworkProfile) (observation.Evidence, error) {
	return observation.Evidence{}, errors.New("unused Network source was called")
}

type unusedPlatformSource struct{}

func (unusedPlatformSource) Observe(context.Context, observation.Policy) (observation.Evidence, error) {
	return observation.Evidence{}, errors.New("unused Platform source was called")
}

type lazyNetworkEvidenceSource struct {
	open func(context.Context) (observation.NetworkEvidenceSource, error)
}

func (source lazyNetworkEvidenceSource) Observe(ctx context.Context, policy observation.Policy, profile observation.NetworkProfile) (observation.Evidence, error) {
	opened, err := source.open(ctx)
	if err != nil {
		return observation.Evidence{}, errors.New("materialize bounded NetworkReady source")
	}
	return opened.Observe(ctx, policy, profile)
}

type lazyPlatformEvidenceSource struct {
	open func(context.Context) (observation.PlatformEvidenceSource, error)
}

func (source lazyPlatformEvidenceSource) Observe(ctx context.Context, policy observation.Policy) (observation.Evidence, error) {
	opened, err := source.open(ctx)
	if err != nil {
		return observation.Evidence{}, errors.New("materialize bounded PlatformReady source")
	}
	return opened.Observe(ctx, policy)
}
