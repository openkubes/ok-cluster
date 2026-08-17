package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestPlatformStageObserverBindsHistoricalTargetAndConverges(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, err := LoadPlatformObservationStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	current := time.Date(2026, 8, 17, 21, 0, 0, 0, time.UTC)
	source := &fakePlatformStageSource{statuses: []string{"Unknown", "True"}}
	observer, err := NewPlatformStageObserver(PlatformStageObserverConfig{
		Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: targetAccessRuntimeUID,
		Source: source, Profile: bundle.profile, PollInterval: time.Second, PollTimeout: time.Minute,
		Clock: func() time.Time { return current },
		Wait:  func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background())
	if err != nil || result.Outcome != "SUCCEEDED" || !stageReceiptPrefixDigestPattern.MatchString(result.EvidenceDigest) || source.calls != 2 {
		t.Fatalf("unexpected platform observation: %#v calls=%d err=%v", result, source.calls, err)
	}
	if binding := observer.Binding(); binding.StageID != "platform-observation" || binding.Authority != "gitops" || binding.PlanDigest != bundle.plan.PlanDigest {
		t.Fatalf("unexpected platform stage binding: %#v", binding)
	}
	if source.policy.TargetClusterUID != targetAccessRuntimeUID || source.policy.PlatformRevision != bundle.plan.PlatformRevision || len(source.policy.Required) != 1 || source.policy.Required[0] != "PlatformReady" {
		t.Fatalf("platform source received an unbound policy: %#v", source.policy)
	}
}

func TestPlatformStageObserverReturnsTerminalFalseAndBoundedUnknown(t *testing.T) {
	for name, testCase := range map[string]struct {
		statuses []string
		want     string
		calls    int
	}{
		"terminal false":  {statuses: []string{"False"}, want: "FAILED", calls: 1},
		"bounded unknown": {statuses: []string{"Unknown"}, want: "STOPPED", calls: 3},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := platformObservationBundleFixture(t)
			bundle, _ := LoadPlatformObservationStageBundle(fixture.config)
			current := time.Date(2026, 8, 17, 21, 0, 0, 0, time.UTC)
			source := &fakePlatformStageSource{statuses: testCase.statuses}
			observer, err := NewPlatformStageObserver(PlatformStageObserverConfig{
				Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: targetAccessRuntimeUID,
				Source: source, Profile: bundle.profile, PollInterval: time.Second, PollTimeout: 2 * time.Second,
				Clock: func() time.Time { return current },
				Wait:  func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := observer.Observe(context.Background())
			if err != nil || result.Outcome != testCase.want || source.calls != testCase.calls {
				t.Fatalf("unexpected terminal platform result: %#v calls=%d err=%v", result, source.calls, err)
			}
		})
	}
}

func TestPlatformStageObserverRejectsForeignTargetProfileAndIncompleteHistory(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, _ := LoadPlatformObservationStageBundle(fixture.config)
	base := PlatformStageObserverConfig{
		Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: targetAccessRuntimeUID,
		Source: &fakePlatformStageSource{statuses: []string{"True"}}, Profile: bundle.profile,
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	}
	for name, mutate := range map[string]func(*PlatformStageObserverConfig){
		"same-name replacement": func(config *PlatformStageObserverConfig) { config.TargetClusterUID = "replacement-runtime-uid" },
		"incomplete prefix":     func(config *PlatformStageObserverConfig) { config.ReceiptPrefix = config.ReceiptPrefix[:9] },
		"foreign profile":       func(config *PlatformStageObserverConfig) { config.Profile.PlatformRevision = runnerStageSHA("f") },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := NewPlatformStageObserver(config); err == nil {
				t.Fatal("unsafe platform stage boundary was accepted")
			}
		})
	}
}

func TestPlatformStageObserverRedactsSourceFailure(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, _ := LoadPlatformObservationStageBundle(fixture.config)
	observer, err := NewPlatformStageObserver(PlatformStageObserverConfig{
		Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: targetAccessRuntimeUID,
		Source: &fakePlatformStageSource{err: errors.New("sensitive Argo endpoint")}, Profile: bundle.profile,
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = observer.Observe(context.Background())
	if err == nil || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("platform source failure leaked detail or was accepted: %v", err)
	}
}

type fakePlatformStageSource struct {
	statuses []string
	err      error
	calls    int
	policy   observation.Policy
}

func (source *fakePlatformStageSource) Observe(_ context.Context, policy observation.Policy) (observation.Evidence, error) {
	source.calls++
	source.policy = policy
	if source.err != nil {
		return observation.Evidence{}, source.err
	}
	status := source.statuses[len(source.statuses)-1]
	if source.calls <= len(source.statuses) {
		status = source.statuses[source.calls-1]
	}
	reason := "PlatformConverged"
	if status == "False" {
		reason = "PlatformInvariantFailed"
	} else if status == "Unknown" {
		reason = "PlatformEvidencePending"
	}
	return observation.Evidence{
		Type: "PlatformReady", Source: "BoundedPlatformEvaluator", SourceUID: "platform-evidence-ok147",
		TargetClusterUID: policy.TargetClusterUID, Status: status, Reason: reason,
		DesiredRevision: policy.PlatformRevision, ObservedRevision: policy.PlatformRevision,
		EvidenceDigest: runnerStageSHA("7"),
	}, nil
}
