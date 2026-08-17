package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestKubernetesAggregateObserverBindsRuntimeTargetBeforeOpeningSources(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	var order []string
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(_ context.Context, received observation.Policy) (KubernetesAuthorityConfig, error) {
		order = append(order, "resolve-workload")
		if received.TargetClusterUID != policy.TargetClusterUID {
			t.Fatal("workload resolver did not receive runtime-bound target")
		}
		return KubernetesAuthorityConfig{AuthorityIdentity: received.TargetClusterUID}, nil
	})
	config.PlatformCapability = PlatformCapabilityResolverFunc(func(_ context.Context, received observation.Policy, profile observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
		order = append(order, "resolve-capability")
		if received.TargetClusterUID != policy.TargetClusterUID || profile.TargetIdentityScheme != "capi-cluster-uid/v1" {
			t.Fatal("capability resolver received an unbound runtime identity")
		}
		profile.RequiredApplications[0].Name = "resolver-mutation-must-not-escape"
		return inertPlatformCapabilitySource{}, nil
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	capi := &aggregateRunnerCAPISource{policy: policy, order: &order}
	network := &aggregateRunnerNetworkSource{policy: policy, order: &order}
	platform := &aggregateRunnerPlatformSource{policy: policy, order: &order}
	observer.openers = kubernetesAggregateSourceOpeners{
		capi: func(_ KubernetesAuthorityConfig, expected, namespace, name string) (observation.CAPIEvidenceSource, error) {
			order = append(order, "open-capi")
			if expected != "ok-mgmt" || namespace != "disposable-ok147" || name != "disposable-ok147" {
				t.Fatal("CAPI opener received a different authority binding")
			}
			return capi, nil
		},
		network: func(received KubernetesNetworkObserverConfig) (observation.NetworkEvidenceSource, error) {
			order = append(order, "open-network")
			if received.TargetClusterUID != policy.TargetClusterUID || received.Workload.AuthorityIdentity != policy.TargetClusterUID {
				t.Fatal("Network opener did not receive runtime-bound target")
			}
			return network, nil
		},
		platform: func(received KubernetesPlatformObserverConfig) (observation.PlatformEvidenceSource, error) {
			order = append(order, "open-platform")
			if received.TargetClusterUID != policy.TargetClusterUID || received.Profile.TargetIdentityScheme != "capi-cluster-uid/v1" || received.Profile.RequiredApplications[0].Name != "disposable-ok147-core" {
				t.Fatal("Platform opener did not receive runtime-bound target")
			}
			return platform, nil
		},
	}

	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := result.Receipt()
	if err != nil || receipt.Ready != "True" {
		t.Fatalf("unexpected aggregate result: receipt=%#v err=%v", receipt, err)
	}
	expected := []string{"open-capi", "collect-capi", "resolve-workload", "open-network", "observe-network", "resolve-capability", "open-platform", "observe-platform"}
	if strings.Join(order, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected lazy source order: %v", order)
	}
}

func TestKubernetesAggregateObserverDefersRuntimeResolversUntilTheirStage(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	workloadCalls, capabilityCalls := 0, 0
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
		workloadCalls++
		return KubernetesAuthorityConfig{}, errors.New("must remain closed")
	})
	config.PlatformCapability = PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
		capabilityCalls++
		return nil, errors.New("must remain closed")
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	pending := aggregateRunnerEvidence(policy, "InfrastructureReady")
	pending.Status = "Unknown"
	pending.Reason = "Provisioning"
	observer.openers.capi = func(KubernetesAuthorityConfig, string, string, string) (observation.CAPIEvidenceSource, error) {
		return &aggregateRunnerCAPISource{policy: policy, evidence: []observation.Evidence{pending, aggregateRunnerEvidence(policy, "ControlPlaneAvailable")}}, nil
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "Unknown" || workloadCalls != 0 || capabilityCalls != 0 {
		t.Fatalf("runtime authority opened before CAPI convergence: receipt=%#v calls=%d/%d", receipt, workloadCalls, capabilityCalls)
	}
}

func TestKubernetesAggregateObserverDefersPlatformResolverUntilNetworkReady(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	workloadCalls, capabilityCalls := 0, 0
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(_ context.Context, received observation.Policy) (KubernetesAuthorityConfig, error) {
		workloadCalls++
		return KubernetesAuthorityConfig{AuthorityIdentity: received.TargetClusterUID}, nil
	})
	config.PlatformCapability = PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
		capabilityCalls++
		return nil, errors.New("must remain closed")
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	observer.openers.capi = func(KubernetesAuthorityConfig, string, string, string) (observation.CAPIEvidenceSource, error) {
		return &aggregateRunnerCAPISource{policy: policy}, nil
	}
	observer.openers.network = func(KubernetesNetworkObserverConfig) (observation.NetworkEvidenceSource, error) {
		pending := aggregateRunnerEvidence(policy, "NetworkReady")
		pending.Status = "Unknown"
		pending.Reason = "ProbePending"
		return &aggregateRunnerNetworkSource{policy: policy, evidence: &pending}, nil
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "Unknown" || workloadCalls != 1 || capabilityCalls != 0 {
		t.Fatalf("Platform authority opened before NetworkReady: receipt=%#v calls=%d/%d", receipt, workloadCalls, capabilityCalls)
	}
}

func TestKubernetesAggregateObserverMaterializesOnlyRequiredDomains(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	policy.Required = []string{"InfrastructureReady", "ControlPlaneAvailable"}
	workloadCalls, capabilityCalls := 0, 0
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
		workloadCalls++
		return KubernetesAuthorityConfig{}, errors.New("must not run")
	})
	config.PlatformCapability = PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
		capabilityCalls++
		return nil, errors.New("must not run")
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	capi := &aggregateRunnerCAPISource{policy: policy}
	observer.openers = kubernetesAggregateSourceOpeners{
		capi: func(KubernetesAuthorityConfig, string, string, string) (observation.CAPIEvidenceSource, error) {
			return capi, nil
		},
		network: func(KubernetesNetworkObserverConfig) (observation.NetworkEvidenceSource, error) {
			t.Fatal("Network source opened although NetworkReady was not required")
			return nil, nil
		},
		platform: func(KubernetesPlatformObserverConfig) (observation.PlatformEvidenceSource, error) {
			t.Fatal("Platform source opened although PlatformReady was not required")
			return nil, nil
		},
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" || workloadCalls != 0 || capabilityCalls != 0 {
		t.Fatalf("unused runtime domains were materialized: receipt=%#v workload=%d capability=%d", receipt, workloadCalls, capabilityCalls)
	}
}

func TestKubernetesAggregateObserverFailsBeforeRuntimeResolution(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	resolverCalls := 0
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
		resolverCalls++
		return KubernetesAuthorityConfig{}, nil
	})
	config.PlatformCapability = PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
		resolverCalls++
		return inertPlatformCapabilitySource{}, nil
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	policy.TargetClusterUID = ""
	if _, err := observer.Observe(context.Background(), policy); err == nil || resolverCalls != 0 {
		t.Fatalf("unbound policy reached a runtime resolver: err=%v calls=%d", err, resolverCalls)
	}
}

func TestKubernetesAggregateObserverRedactsResolverFailure(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	secret := "/private/tmp/secret-workload-kubeconfig"
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
		return KubernetesAuthorityConfig{}, errors.New(secret)
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	observer.openers.capi = func(KubernetesAuthorityConfig, string, string, string) (observation.CAPIEvidenceSource, error) {
		return &aggregateRunnerCAPISource{policy: policy}, nil
	}
	_, err = observer.Observe(context.Background(), policy)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("resolver failure was accepted or disclosed details: %v", err)
	}
}

func TestKubernetesAggregateObserverRejectsForeignWorkloadAuthority(t *testing.T) {
	policy, config := aggregateRunnerFixture()
	config.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
		return KubernetesAuthorityConfig{AuthorityIdentity: "other-cluster-uid"}, nil
	})
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	observer.openers.capi = func(KubernetesAuthorityConfig, string, string, string) (observation.CAPIEvidenceSource, error) {
		return &aggregateRunnerCAPISource{policy: policy}, nil
	}
	if _, err := observer.Observe(context.Background(), policy); err == nil {
		t.Fatal("foreign workload authority reached the Network source opener")
	}
}

func TestOpenKubernetesAggregateObserverFreezesPlatformMembership(t *testing.T) {
	_, config := aggregateRunnerFixture()
	observer, err := OpenKubernetesAggregateObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	config.PlatformProfile.RequiredApplications[0].Name = "mutated-after-open"
	if observer.config.PlatformProfile.RequiredApplications[0].Name != "disposable-ok147-core" {
		t.Fatal("aggregate observer retained mutable Platform membership")
	}
}

func aggregateRunnerFixture() (observation.Policy, KubernetesAggregateObserverConfig) {
	digest := func(character string) string { return "sha256:" + strings.Repeat(character, 64) }
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: digest("a"), EnablementRevision: digest("b"), PlatformRevision: digest("c"),
		TargetClusterUID: "cluster-uid-disposable-ok147", Required: []string{"InfrastructureReady", "ControlPlaneAvailable", "NetworkReady", "PlatformReady"},
	}
	networkProfile := observation.NetworkProfile{
		Format: observation.NetworkProfileFormat, IntentRevision: policy.IntentRevision, EnablementRevision: policy.EnablementRevision,
		ExpectedNodeCount: 2, ExpectedHCPSpecDigest: digest("d"), ExpectedHRPSpecDigest: digest("e"),
		ExpectedImages: observation.NetworkImages{
			CiliumAgent:    "example.invalid/cilium@sha256:" + strings.Repeat("1", 64),
			CiliumEnvoy:    "example.invalid/envoy@sha256:" + strings.Repeat("2", 64),
			CiliumOperator: "example.invalid/operator@sha256:" + strings.Repeat("3", 64),
		},
		MinimumProbeFreshnessSeconds: 60, MaximumProbeIntervalSeconds: 60, CacheExposureSeconds: 30,
	}
	platformProfile := observation.PlatformProfile{
		Format: observation.PlatformProfileFormat, IntentRevision: policy.IntentRevision, PlatformRevision: policy.PlatformRevision,
		ExecutionFixture: digest("f"), TargetIdentityScheme: "capi-cluster-uid/v1", ArgoNamespace: "argocd", RegistrationName: "disposable-ok147",
		RequiredApplications:     []observation.PlatformApplicationExpectation{{Name: "disposable-ok147-core", SpecDigest: digest("7")}},
		CapabilityContractDigest: digest("8"), CapabilityExecutableDigest: digest("9"), MaximumCapabilityAgeSeconds: 3600,
	}
	return policy, KubernetesAggregateObserverConfig{
		Management: KubernetesAuthorityConfig{AuthorityIdentity: "ok-mgmt"}, ExpectedManagementAuthority: "ok-mgmt",
		Argo: KubernetesAuthorityConfig{AuthorityIdentity: "ok-shared"}, ExpectedArgoAuthority: "ok-shared",
		Namespace: "disposable-ok147", Name: "disposable-ok147", HCPName: "disposable-ok147-cilium",
		NetworkProfile: networkProfile, PlatformProfile: platformProfile,
		WorkloadAuthority: WorkloadAuthorityResolverFunc(func(_ context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
			return KubernetesAuthorityConfig{AuthorityIdentity: policy.TargetClusterUID}, nil
		}),
		PlatformCapability: PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
			return inertPlatformCapabilitySource{}, nil
		}),
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) },
	}
}

type aggregateRunnerCAPISource struct {
	policy   observation.Policy
	order    *[]string
	evidence []observation.Evidence
}

func (source *aggregateRunnerCAPISource) Collect(context.Context, observation.Policy) ([]observation.Evidence, error) {
	if source.order != nil {
		*source.order = append(*source.order, "collect-capi")
	}
	if source.evidence != nil {
		return source.evidence, nil
	}
	return []observation.Evidence{aggregateRunnerEvidence(source.policy, "InfrastructureReady"), aggregateRunnerEvidence(source.policy, "ControlPlaneAvailable")}, nil
}

type aggregateRunnerNetworkSource struct {
	policy   observation.Policy
	order    *[]string
	evidence *observation.Evidence
}

func (source *aggregateRunnerNetworkSource) Observe(context.Context, observation.Policy, observation.NetworkProfile) (observation.Evidence, error) {
	if source.order != nil {
		*source.order = append(*source.order, "observe-network")
	}
	if source.evidence != nil {
		return *source.evidence, nil
	}
	return aggregateRunnerEvidence(source.policy, "NetworkReady"), nil
}

type aggregateRunnerPlatformSource struct {
	policy observation.Policy
	order  *[]string
}

func (source *aggregateRunnerPlatformSource) Observe(context.Context, observation.Policy) (observation.Evidence, error) {
	if source.order != nil {
		*source.order = append(*source.order, "observe-platform")
	}
	return aggregateRunnerEvidence(source.policy, "PlatformReady"), nil
}

func aggregateRunnerEvidence(policy observation.Policy, condition string) observation.Evidence {
	value := observation.Evidence{
		Type: condition, SourceUID: "source-uid-" + strings.ToLower(condition), TargetClusterUID: policy.TargetClusterUID,
		Status: "True", Reason: condition, EvidenceDigest: "sha256:" + strings.Repeat("6", 64),
	}
	switch condition {
	case "InfrastructureReady", "ControlPlaneAvailable":
		value.Source, value.SourceUID = "CAPICluster", policy.TargetClusterUID
		value.DesiredRevision, value.ObservedRevision = policy.IntentRevision, policy.IntentRevision
		value.Generation, value.ObservedGeneration = 3, 3
	case "NetworkReady":
		value.Source = "BoundedNetworkEvaluator"
		value.DesiredRevision, value.ObservedRevision = policy.EnablementRevision, policy.EnablementRevision
	case "PlatformReady":
		value.Source = "BoundedPlatformEvaluator"
		value.DesiredRevision, value.ObservedRevision = policy.PlatformRevision, policy.PlatformRevision
	}
	return value
}
