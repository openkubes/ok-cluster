package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestNetworkStageObserverBindsHistoricalTargetAndConverges(t *testing.T) {
	plan, prefix, runtimeUID := networkObserverPrefix(t, true)
	current := time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
	source := &fakeNetworkStageSource{statuses: []string{"Unknown", "True"}}
	observer, err := NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID, Source: source,
		Profile: networkStageProfile(plan), PollInterval: time.Second, PollTimeout: time.Minute,
		Clock: func() time.Time { return current },
		Wait:  func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	binding := observer.Binding()
	if binding.StageID != "network-observation" || binding.Authority != "workload" || binding.PlanDigest != plan.PlanDigest {
		t.Fatalf("unexpected network stage binding: %#v", binding)
	}
	if result.Outcome != "SUCCEEDED" || !platformInputDigestPattern.MatchString(result.EvidenceDigest) || source.calls != 2 {
		t.Fatalf("unexpected network observation: %#v calls=%d", result, source.calls)
	}
	if source.policy.TargetClusterUID != runtimeUID || source.policy.IntentRevision != plan.IntentRevision || source.policy.EnablementRevision != plan.EnablementRevision || len(source.policy.Required) != 1 || source.policy.Required[0] != "NetworkReady" {
		t.Fatalf("network source received an unbound policy: %#v", source.policy)
	}
}

func TestNetworkStageObserverWaitsThroughFalseUntilConvergedOrBounded(t *testing.T) {
	for name, testCase := range map[string]struct {
		statuses []string
		want     string
		calls    int
	}{
		"transient false": {statuses: []string{"False", "True"}, want: "SUCCEEDED", calls: 2},
		"bounded false":   {statuses: []string{"False"}, want: "FAILED", calls: 3},
		"bounded unknown": {statuses: []string{"Unknown"}, want: "STOPPED", calls: 3},
	} {
		t.Run(name, func(t *testing.T) {
			plan, prefix, runtimeUID := networkObserverPrefix(t, true)
			current := time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
			source := &fakeNetworkStageSource{statuses: testCase.statuses}
			observer, err := NewNetworkStageObserver(NetworkStageObserverConfig{
				Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID, Source: source,
				Profile: networkStageProfile(plan), PollInterval: time.Second, PollTimeout: 2 * time.Second,
				Clock: func() time.Time { return current },
				Wait:  func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := observer.Observe(context.Background())
			if err != nil || result.Outcome != testCase.want || source.calls != testCase.calls {
				t.Fatalf("unexpected terminal network result: %#v calls=%d err=%v", result, source.calls, err)
			}
		})
	}
}

func TestNetworkStageObserverDefersKnownMVPWarmupAcrossReasonChanges(t *testing.T) {
	plan, prefix, runtimeUID := networkObserverPrefix(t, true)
	current := time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
	source := &fakeNetworkStageSource{
		statuses: []string{"Unknown"},
		reasons:  []string{"NodeNetworkNotReady", "CiliumRolloutNotReady", "CiliumAgentPodsNotReady", "FunctionalProbePending"},
	}
	observer, err := NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID, Source: source,
		Profile: networkStageProfile(plan), PollInterval: time.Minute, PollTimeout: 10 * time.Minute,
		Clock:                  func() time.Time { return current },
		Wait:                   func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
		AllowMVPWarmupDeferral: true, MVPWarmupDeferralDelay: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background())
	if err != nil || result.Outcome != "SUCCEEDED" || source.calls != 6 {
		t.Fatalf("bounded functional probe deferral failed: %#v calls=%d err=%v", result, source.calls, err)
	}

	current = time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
	source = &fakeNetworkStageSource{statuses: []string{"False"}, reasons: []string{"FunctionalProbeStale"}}
	observer, err = NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID, Source: source,
		Profile: networkStageProfile(plan), PollInterval: time.Minute, PollTimeout: 6 * time.Minute,
		Clock:                  func() time.Time { return current },
		Wait:                   func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
		AllowMVPWarmupDeferral: true, MVPWarmupDeferralDelay: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err = observer.Observe(context.Background())
	if err != nil || result.Outcome != "SUCCEEDED" || source.calls != 2 {
		t.Fatalf("stale functional probe was not deferred: %#v calls=%d err=%v", result, source.calls, err)
	}

	current = time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
	source = &fakeNetworkStageSource{statuses: []string{"False"}, reasons: []string{"FunctionalProbeFailed"}}
	observer, err = NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID, Source: source,
		Profile: networkStageProfile(plan), PollInterval: time.Minute, PollTimeout: 6 * time.Minute,
		Clock:                  func() time.Time { return current },
		Wait:                   func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
		AllowMVPWarmupDeferral: true, MVPWarmupDeferralDelay: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err = observer.Observe(context.Background())
	if err != nil || result.Outcome != "FAILED" {
		t.Fatalf("real functional probe failure was deferred: %#v err=%v", result, err)
	}

	current = time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
	source = &fakeNetworkStageSource{statuses: []string{"Unknown"}, reasons: []string{"RequiredEvidenceMissing"}}
	observer, err = NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID, Source: source,
		Profile: networkStageProfile(plan), PollInterval: time.Minute, PollTimeout: 6 * time.Minute,
		Clock:                  func() time.Time { return current },
		Wait:                   func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
		AllowMVPWarmupDeferral: true, MVPWarmupDeferralDelay: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err = observer.Observe(context.Background())
	if err != nil || result.Outcome != "STOPPED" {
		t.Fatalf("unknown non-warmup evidence was deferred: %#v err=%v", result, err)
	}
}

func TestNetworkStageObserverRejectsForeignTargetAndIncompleteHistory(t *testing.T) {
	plan, prefix, runtimeUID := networkObserverPrefix(t, true)
	base := NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID,
		Source: &fakeNetworkStageSource{statuses: []string{"True"}}, Profile: networkStageProfile(plan),
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	}
	for name, mutate := range map[string]func(*NetworkStageObserverConfig){
		"same-name replacement": func(config *NetworkStageObserverConfig) { config.TargetClusterUID = "replacement-cluster-uid" },
		"incomplete prefix":     func(config *NetworkStageObserverConfig) { config.ReceiptPrefix = config.ReceiptPrefix[:3] },
		"foreign profile": func(config *NetworkStageObserverConfig) {
			config.Profile.EnablementRevision = bundleSHA("9")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := NewNetworkStageObserver(config); err == nil {
				t.Fatal("unsafe network stage boundary was accepted")
			}
		})
	}

	plan, prefix, runtimeUID = networkObserverPrefix(t, false)
	base.Plan, base.ReceiptPrefix, base.TargetClusterUID, base.Profile = plan, prefix, runtimeUID, networkStageProfile(plan)
	if _, err := NewNetworkStageObserver(base); err == nil {
		t.Fatal("historical lifecycle receipt without target UID digest was accepted")
	}
}

func TestNetworkStageObserverRedactsSourceFailure(t *testing.T) {
	plan, prefix, runtimeUID := networkObserverPrefix(t, true)
	observer, err := NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: plan, ReceiptPrefix: prefix, TargetClusterUID: runtimeUID,
		Source: &fakeNetworkStageSource{err: errors.New("sensitive target endpoint")}, Profile: networkStageProfile(plan),
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = observer.Observe(context.Background())
	if err == nil || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("network source failure leaked detail or was accepted: %v", err)
	}
}

type fakeNetworkStageSource struct {
	statuses []string
	reasons  []string
	err      error
	calls    int
	policy   observation.Policy
	profile  observation.NetworkProfile
}

func (source *fakeNetworkStageSource) Observe(_ context.Context, policy observation.Policy, profile observation.NetworkProfile) (observation.Evidence, error) {
	source.calls++
	source.policy, source.profile = policy, profile
	if source.err != nil {
		return observation.Evidence{}, source.err
	}
	status := source.statuses[len(source.statuses)-1]
	if source.calls <= len(source.statuses) {
		status = source.statuses[source.calls-1]
	}
	reason := "NetworkConverged"
	if len(source.reasons) > 0 {
		reason = source.reasons[len(source.reasons)-1]
		if source.calls <= len(source.reasons) {
			reason = source.reasons[source.calls-1]
		}
	} else if status == "False" {
		reason = "NetworkInvariantFailed"
	} else if status == "Unknown" {
		reason = "NetworkEvidencePending"
	}
	return observation.Evidence{
		Type: "NetworkReady", Source: "BoundedNetworkEvaluator", SourceUID: "network-evidence-ok147",
		TargetClusterUID: policy.TargetClusterUID, Status: status, Reason: reason,
		DesiredRevision: policy.EnablementRevision, ObservedRevision: policy.EnablementRevision,
		EvidenceDigest: bundleSHA("7"),
	}, nil
}

func networkObserverPrefix(t *testing.T, withTargetDigest bool) (stageplan.Binding, []stagereceipt.Verified, string) {
	t.Helper()
	plan := submissionBundleFixture(t, false, "").plan
	at := time.Date(2026, 8, 16, 19, 0, 0, 0, time.UTC)
	const runtimeUID = "cluster-runtime-uid-147"
	provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", bundleSHA("1"), bundleSHA("2"), at)
	if err != nil {
		t.Fatal(err)
	}
	targetDigest := ""
	if withTargetDigest {
		targetDigest = digest.SHA256([]byte(runtimeUID))
	}
	lifecycle, err := stagereceipt.NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", bundleSHA("3"), bundleSHA("4"), targetDigest, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lifecycleObservation, err := stagereceipt.New(plan, "lifecycle-observation", []stagereceipt.Verified{lifecycle}, "SUCCEEDED", "NOT_APPLICABLE", "", bundleSHA("5"), at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	enablement, err := stagereceipt.New(plan, "enablement", []stagereceipt.Verified{lifecycleObservation}, "SUCCEEDED", "ATTEMPTED", bundleSHA("6"), bundleSHA("7"), at.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return plan, []stagereceipt.Verified{provider, lifecycle, lifecycleObservation, enablement}, runtimeUID
}

func networkStageProfile(plan stageplan.Binding) observation.NetworkProfile {
	profile := runnerNetworkProfile()
	profile.IntentRevision = plan.IntentRevision
	profile.EnablementRevision = plan.EnablementRevision
	return profile
}
