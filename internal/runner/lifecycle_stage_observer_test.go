package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestLifecycleStageObserverBindsSubmissionIdentityAndConverges(t *testing.T) {
	plan, cursor, runtimeUID := lifecycleObserverCursor(t, true)
	current := time.Date(2026, 8, 16, 20, 0, 0, 0, time.UTC)
	source := &fakeRuntimeBoundCAPISource{runtimeUID: runtimeUID, followupStatus: "True"}
	observer, err := NewLifecycleStageObserver(LifecycleStageObserverConfig{
		Plan: plan, Cursor: cursor, Source: source, PollInterval: time.Second, PollTimeout: time.Minute,
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
	if result.Outcome != "SUCCEEDED" || !platformInputDigestPattern.MatchString(result.EvidenceDigest) || source.boundCalls != 1 || source.collectCalls != 1 {
		t.Fatalf("unexpected lifecycle observation: %#v source=%#v", result, source)
	}
	if source.boundDigest != digest.SHA256([]byte(runtimeUID)) || source.boundPolicy.TargetClusterUID != "" || source.collectPolicy.TargetClusterUID != runtimeUID {
		t.Fatalf("runtime identity was not derived from the lifecycle receipt: %#v", source)
	}
}

func TestLifecycleStageObserverPollsFalseUntilConvergedOrBounded(t *testing.T) {
	for name, testCase := range map[string]struct {
		initial, followup, want string
		collectCalls            int
	}{
		"transient false converges":   {initial: "False", followup: "True", want: "SUCCEEDED", collectCalls: 1},
		"persistent false is bounded": {initial: "False", followup: "False", want: "FAILED", collectCalls: 2},
		"bounded unknown":             {initial: "Unknown", followup: "Unknown", want: "STOPPED", collectCalls: 2},
	} {
		t.Run(name, func(t *testing.T) {
			plan, cursor, runtimeUID := lifecycleObserverCursor(t, true)
			current := time.Date(2026, 8, 16, 20, 0, 0, 0, time.UTC)
			source := &fakeRuntimeBoundCAPISource{runtimeUID: runtimeUID, initialStatus: testCase.initial, followupStatus: testCase.followup}
			observer, err := NewLifecycleStageObserver(LifecycleStageObserverConfig{
				Plan: plan, Cursor: cursor, Source: source, PollInterval: time.Second, PollTimeout: 2 * time.Second,
				Clock: func() time.Time { return current },
				Wait:  func(_ context.Context, wait time.Duration) error { current = current.Add(wait); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := observer.Observe(context.Background())
			if err != nil || result.Outcome != testCase.want {
				t.Fatalf("unexpected terminal lifecycle result: %#v %v", result, err)
			}
			if source.collectCalls != testCase.collectCalls {
				t.Fatalf("unexpected lifecycle poll count: got %d want %d", source.collectCalls, testCase.collectCalls)
			}
		})
	}
}

func TestLifecycleStageObserverFailsClosedAtDurableCorrelationBoundary(t *testing.T) {
	plan, cursor, runtimeUID := lifecycleObserverCursor(t, true)
	for name, source := range map[string]*fakeRuntimeBoundCAPISource{
		"same-name replacement": {runtimeUID: "replacement-runtime-uid", followupStatus: "True"},
		"source failure":        {runtimeUID: runtimeUID, err: errors.New("sensitive management endpoint")},
	} {
		t.Run(name, func(t *testing.T) {
			observer, err := NewLifecycleStageObserver(LifecycleStageObserverConfig{
				Plan: plan, Cursor: cursor, Source: source, PollInterval: time.Second, PollTimeout: time.Minute,
				Clock: time.Now, Wait: func(context.Context, time.Duration) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = observer.Observe(context.Background())
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unsafe correlation failure was accepted or leaked: %v", err)
			}
		})
	}
}

func TestLifecycleStageObserverRequiresReceiptBoundTargetIdentity(t *testing.T) {
	plan, cursor, _ := lifecycleObserverCursor(t, false)
	if _, err := NewLifecycleStageObserver(LifecycleStageObserverConfig{
		Plan: plan, Cursor: cursor, Source: &fakeRuntimeBoundCAPISource{}, PollInterval: time.Second, PollTimeout: time.Minute,
		Clock: time.Now, Wait: func(context.Context, time.Duration) error { return nil },
	}); err == nil {
		t.Fatal("historical lifecycle receipt without target UID digest was accepted")
	}
}

type fakeRuntimeBoundCAPISource struct {
	runtimeUID     string
	initialStatus  string
	followupStatus string
	err            error
	boundDigest    string
	boundPolicy    observation.Policy
	collectPolicy  observation.Policy
	boundCalls     int
	collectCalls   int
}

func (source *fakeRuntimeBoundCAPISource) CollectBound(_ context.Context, policy observation.Policy, expectedDigest string) (observation.Policy, []observation.Evidence, error) {
	source.boundCalls++
	source.boundDigest, source.boundPolicy = expectedDigest, policy
	if source.err != nil {
		return observation.Policy{}, nil, source.err
	}
	if digest.SHA256([]byte(source.runtimeUID)) != expectedDigest {
		return observation.Policy{}, nil, errors.New("runtime identity mismatch")
	}
	bound, err := observation.BindTarget(policy, source.runtimeUID)
	if err != nil {
		return observation.Policy{}, nil, err
	}
	return bound, lifecycleEvidence(bound, source.initialStatus), nil
}

func (source *fakeRuntimeBoundCAPISource) Collect(_ context.Context, policy observation.Policy) ([]observation.Evidence, error) {
	source.collectCalls++
	source.collectPolicy = policy
	if source.err != nil {
		return nil, source.err
	}
	return lifecycleEvidence(policy, source.followupStatus), nil
}

func lifecycleEvidence(policy observation.Policy, status string) []observation.Evidence {
	if status == "" || status == "Unknown" {
		return nil
	}
	reason := "LifecycleReady"
	if status == "False" {
		reason = "LifecycleUnavailable"
	}
	evidence := make([]observation.Evidence, 0, 2)
	for index, condition := range []string{"InfrastructureReady", "ControlPlaneAvailable"} {
		evidence = append(evidence, observation.Evidence{
			Type: condition, Source: "CAPICluster", SourceUID: policy.TargetClusterUID, TargetClusterUID: policy.TargetClusterUID,
			Status: status, Reason: reason, DesiredRevision: policy.IntentRevision, ObservedRevision: policy.IntentRevision,
			Generation: 7, ObservedGeneration: 7, EvidenceDigest: bundleSHA(string(rune('1' + index))),
		})
	}
	return evidence
}

func lifecycleObserverCursor(t *testing.T, withTargetDigest bool) (stageplan.Binding, stagecursor.Cursor, string) {
	t.Helper()
	fixture := submissionBundleFixture(t, false, "")
	plan := fixture.plan
	at := time.Date(2026, 8, 16, 19, 0, 0, 0, time.UTC)
	provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", bundleSHA("8"), bundleSHA("9"), at)
	if err != nil {
		t.Fatal(err)
	}
	const runtimeUID = "cluster-runtime-uid-147"
	var lifecycle stagereceipt.Verified
	if withTargetDigest {
		lifecycle, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", bundleSHA("1"), bundleSHA("2"), digest.SHA256([]byte(runtimeUID)), at.Add(time.Second))
	} else {
		lifecycle, err = stagereceipt.New(plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", bundleSHA("1"), bundleSHA("2"), at.Add(time.Second))
	}
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{provider, lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	return plan, cursor, runtimeUID
}
