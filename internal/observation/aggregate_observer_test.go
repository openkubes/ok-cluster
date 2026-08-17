package observation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAggregateObserverComposesAuthoritativeSourcesOnce(t *testing.T) {
	policy, profile := aggregateFixture()
	order := []string{}
	capi := &fakeCAPIEvidenceSource{evidence: []Evidence{
		aggregateEvidence(policy, "InfrastructureReady"),
		aggregateEvidence(policy, "ControlPlaneAvailable"),
	}, order: &order}
	network := &fakeNetworkEvidenceSource{evidence: aggregateEvidence(policy, "NetworkReady"), order: &order}
	platform := &fakePlatformEvidenceSource{evidence: aggregateEvidence(policy, "PlatformReady"), order: &order}
	clock := time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC)
	observer, err := NewAggregateObserver(AggregateObserverConfig{
		CAPI: capi, Network: network, Platform: platform, NetworkProfile: profile,
		Clock: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := result.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Ready != "True" || receipt.Reason != "AllRequiredConditionsSatisfied" || receipt.EvaluatedAt != clock.Format(time.RFC3339Nano) || len(receipt.Conditions) != 4 {
		t.Fatalf("unexpected aggregate receipt: %#v", receipt)
	}
	if capi.calls != 1 || network.calls != 1 || platform.calls != 1 || network.profile != profile || strings.Join(order, ",") != "CAPI,Network,Platform" {
		t.Fatalf("source composition differs: capi=%d network=%d platform=%d profile=%#v", capi.calls, network.calls, platform.calls, network.profile)
	}
}

func TestAggregateObserverCallsOnlyRequiredDomains(t *testing.T) {
	policy, profile := aggregateFixture()
	policy.Required = []string{"InfrastructureReady"}
	capi := &fakeCAPIEvidenceSource{evidence: []Evidence{
		aggregateEvidence(policy, "InfrastructureReady"),
		aggregateEvidence(policy, "ControlPlaneAvailable"),
	}}
	network := &fakeNetworkEvidenceSource{err: errors.New("must not be called")}
	platform := &fakePlatformEvidenceSource{err: errors.New("must not be called")}
	observer, err := NewAggregateObserver(AggregateObserverConfig{
		CAPI: capi, Network: network, Platform: platform, NetworkProfile: profile,
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" || len(receipt.Conditions) != 1 || capi.calls != 1 || network.calls != 0 || platform.calls != 0 {
		t.Fatalf("unrequired source was called or retained: %#v calls=%d/%d/%d", receipt, capi.calls, network.calls, platform.calls)
	}
}

func TestAggregateObserverKeepsDownstreamAuthoritiesClosedUntilPriorStageReady(t *testing.T) {
	policy, profile := aggregateFixture()

	t.Run("CAPI pending keeps Network and Platform closed", func(t *testing.T) {
		infrastructure := aggregateEvidence(policy, "InfrastructureReady")
		infrastructure.Status = "Unknown"
		infrastructure.Reason = "Provisioning"
		capi := &fakeCAPIEvidenceSource{evidence: []Evidence{infrastructure, aggregateEvidence(policy, "ControlPlaneAvailable")}}
		network := &fakeNetworkEvidenceSource{err: errors.New("must not be called")}
		platform := &fakePlatformEvidenceSource{err: errors.New("must not be called")}
		observer, err := NewAggregateObserver(AggregateObserverConfig{
			CAPI: capi, Network: network, Platform: platform, NetworkProfile: profile,
			Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := observer.Observe(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		receipt, _ := result.Receipt()
		if receipt.Ready != "Unknown" || network.calls != 0 || platform.calls != 0 {
			t.Fatalf("downstream source opened before CAPI convergence: receipt=%#v calls=%d/%d", receipt, network.calls, platform.calls)
		}
	})

	t.Run("Network pending keeps Platform closed", func(t *testing.T) {
		networkEvidence := aggregateEvidence(policy, "NetworkReady")
		networkEvidence.Status = "Unknown"
		networkEvidence.Reason = "ProbePending"
		capi := &fakeCAPIEvidenceSource{evidence: []Evidence{aggregateEvidence(policy, "InfrastructureReady"), aggregateEvidence(policy, "ControlPlaneAvailable")}}
		network := &fakeNetworkEvidenceSource{evidence: networkEvidence}
		platform := &fakePlatformEvidenceSource{err: errors.New("must not be called")}
		observer, err := NewAggregateObserver(AggregateObserverConfig{
			CAPI: capi, Network: network, Platform: platform, NetworkProfile: profile,
			Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := observer.Observe(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		receipt, _ := result.Receipt()
		if receipt.Ready != "Unknown" || network.calls != 1 || platform.calls != 0 {
			t.Fatalf("Platform source opened before Network convergence: receipt=%#v calls=%d/%d", receipt, network.calls, platform.calls)
		}
	})
}

func TestAggregateObserverPreservesConflictingAuthority(t *testing.T) {
	policy, profile := aggregateFixture()
	policy.Required = []string{"InfrastructureReady"}
	item := aggregateEvidence(policy, "InfrastructureReady")
	capi := &fakeCAPIEvidenceSource{evidence: []Evidence{item, item}}
	observer, err := NewAggregateObserver(AggregateObserverConfig{
		CAPI: capi, Network: &fakeNetworkEvidenceSource{}, Platform: &fakePlatformEvidenceSource{},
		NetworkProfile: profile, Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "Unknown" || receipt.Reason != "ConflictingAuthority" {
		t.Fatalf("duplicate source authority was not retained fail-closed: %#v", receipt)
	}
}

func TestAggregateObserverFailsClosedAndRedactsSources(t *testing.T) {
	policy, profile := aggregateFixture()
	tests := map[string]AggregateObserverConfig{
		"CAPI error": {
			CAPI: &fakeCAPIEvidenceSource{err: errors.New("sensitive CAPI detail")}, Network: &fakeNetworkEvidenceSource{}, Platform: &fakePlatformEvidenceSource{},
		},
		"CAPI foreign domain": {
			CAPI: &fakeCAPIEvidenceSource{evidence: []Evidence{aggregateEvidence(policy, "PlatformReady")}}, Network: &fakeNetworkEvidenceSource{}, Platform: &fakePlatformEvidenceSource{},
		},
		"network error": {
			CAPI: &fakeCAPIEvidenceSource{evidence: []Evidence{aggregateEvidence(policy, "InfrastructureReady"), aggregateEvidence(policy, "ControlPlaneAvailable")}}, Network: &fakeNetworkEvidenceSource{err: errors.New("sensitive network detail")}, Platform: &fakePlatformEvidenceSource{},
		},
		"network foreign domain": {
			CAPI: &fakeCAPIEvidenceSource{evidence: []Evidence{aggregateEvidence(policy, "InfrastructureReady"), aggregateEvidence(policy, "ControlPlaneAvailable")}}, Network: &fakeNetworkEvidenceSource{evidence: aggregateEvidence(policy, "PlatformReady")}, Platform: &fakePlatformEvidenceSource{},
		},
		"platform error": {
			CAPI: &fakeCAPIEvidenceSource{evidence: []Evidence{aggregateEvidence(policy, "InfrastructureReady"), aggregateEvidence(policy, "ControlPlaneAvailable")}}, Network: &fakeNetworkEvidenceSource{evidence: aggregateEvidence(policy, "NetworkReady")}, Platform: &fakePlatformEvidenceSource{err: errors.New("sensitive platform detail")},
		},
		"platform foreign domain": {
			CAPI: &fakeCAPIEvidenceSource{evidence: []Evidence{aggregateEvidence(policy, "InfrastructureReady"), aggregateEvidence(policy, "ControlPlaneAvailable")}}, Network: &fakeNetworkEvidenceSource{evidence: aggregateEvidence(policy, "NetworkReady")}, Platform: &fakePlatformEvidenceSource{evidence: aggregateEvidence(policy, "NetworkReady")},
		},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			config.NetworkProfile = profile
			config.Clock = func() time.Time { return time.Date(2026, 8, 16, 12, 30, 0, 0, time.UTC) }
			observer, err := NewAggregateObserver(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := observer.Observe(context.Background(), policy); err == nil {
				t.Fatal("invalid or failed source was accepted")
			} else if strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("raw source detail leaked: %v", err)
			}
		})
	}
}

func TestNewAggregateObserverRequiresAllSources(t *testing.T) {
	valid := AggregateObserverConfig{
		CAPI: &fakeCAPIEvidenceSource{}, Network: &fakeNetworkEvidenceSource{}, Platform: &fakePlatformEvidenceSource{},
		Clock: func() time.Time { return time.Now() },
	}
	for name, mutate := range map[string]func(*AggregateObserverConfig){
		"CAPI":     func(config *AggregateObserverConfig) { config.CAPI = nil },
		"network":  func(config *AggregateObserverConfig) { config.Network = nil },
		"platform": func(config *AggregateObserverConfig) { config.Platform = nil },
		"clock":    func(config *AggregateObserverConfig) { config.Clock = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := NewAggregateObserver(config); err == nil {
				t.Fatal("incomplete aggregate observer accepted")
			}
		})
	}
}

func aggregateFixture() (Policy, NetworkProfile) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	digestC := "sha256:" + strings.Repeat("c", 64)
	policy := Policy{
		Format: PolicyFormat, IntentRevision: digestA, EnablementRevision: digestB, PlatformRevision: digestC,
		TargetClusterUID: "cluster-uid-1", Required: []string{"InfrastructureReady", "ControlPlaneAvailable", "NetworkReady", "PlatformReady"},
	}
	return policy, NetworkProfile{Format: NetworkProfileFormat, IntentRevision: digestA, EnablementRevision: digestB}
}

func aggregateEvidence(policy Policy, condition string) Evidence {
	evidence := Evidence{
		Type: condition, TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: condition,
		SourceUID: "source-uid-" + strings.ToLower(condition), EvidenceDigest: "sha256:" + strings.Repeat("d", 64),
	}
	switch condition {
	case "InfrastructureReady", "ControlPlaneAvailable":
		evidence.Source = "CAPICluster"
		evidence.SourceUID = policy.TargetClusterUID
		evidence.DesiredRevision, evidence.ObservedRevision = policy.IntentRevision, policy.IntentRevision
		evidence.Generation, evidence.ObservedGeneration = 7, 7
	case "NetworkReady":
		evidence.Source = "BoundedNetworkEvaluator"
		evidence.DesiredRevision, evidence.ObservedRevision = policy.EnablementRevision, policy.EnablementRevision
	case "PlatformReady":
		evidence.Source = "BoundedPlatformEvaluator"
		evidence.DesiredRevision, evidence.ObservedRevision = policy.PlatformRevision, policy.PlatformRevision
	}
	return evidence
}

type fakeCAPIEvidenceSource struct {
	evidence []Evidence
	err      error
	calls    int
	order    *[]string
}

func (source *fakeCAPIEvidenceSource) Collect(context.Context, Policy) ([]Evidence, error) {
	source.calls++
	if source.order != nil {
		*source.order = append(*source.order, "CAPI")
	}
	return source.evidence, source.err
}

type fakeNetworkEvidenceSource struct {
	evidence Evidence
	err      error
	profile  NetworkProfile
	calls    int
	order    *[]string
}

func (source *fakeNetworkEvidenceSource) Observe(_ context.Context, _ Policy, profile NetworkProfile) (Evidence, error) {
	source.calls++
	if source.order != nil {
		*source.order = append(*source.order, "Network")
	}
	source.profile = profile
	return source.evidence, source.err
}

type fakePlatformEvidenceSource struct {
	evidence Evidence
	err      error
	calls    int
	order    *[]string
}

func (source *fakePlatformEvidenceSource) Observe(context.Context, Policy) (Evidence, error) {
	source.calls++
	if source.order != nil {
		*source.order = append(*source.order, "Platform")
	}
	return source.evidence, source.err
}
