package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestBoundedPollingObserverStopsAtFirstTerminalResult(t *testing.T) {
	policy, _ := aggregateRunnerFixture()
	unknown := pollingResult(t, policy, "Unknown")
	ready := pollingResult(t, policy, "True")
	current := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	source := &sequenceObservationSource{results: []observation.VerifiedResult{unknown, unknown, ready}}
	waits := 0
	observer, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: source, Interval: 10 * time.Second, Timeout: time.Minute, Clock: func() time.Time { return current },
		Wait: func(_ context.Context, duration time.Duration) error {
			waits++
			current = current.Add(duration)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" || source.calls != 3 || waits != 2 {
		t.Fatalf("poller did not stop at first terminal result: receipt=%#v calls=%d waits=%d", receipt, source.calls, waits)
	}
}

func TestBoundedPollingObserverReturnsLastUnknownAtDeadline(t *testing.T) {
	policy, _ := aggregateRunnerFixture()
	unknown := pollingResult(t, policy, "Unknown")
	current := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	source := &sequenceObservationSource{fallback: unknown}
	observer, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: source, Interval: 10 * time.Second, Timeout: 25 * time.Second, Clock: func() time.Time { return current },
		Wait: func(_ context.Context, duration time.Duration) error { current = current.Add(duration); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "Unknown" || source.calls != 4 || !current.Equal(time.Date(2026, 8, 16, 12, 0, 25, 0, time.UTC)) {
		t.Fatalf("deadline did not return last fail-closed evidence: receipt=%#v calls=%d now=%s", receipt, source.calls, current)
	}
}

func TestBoundedPollingObserverDoesNotRetryFalseOrOperationalError(t *testing.T) {
	policy, _ := aggregateRunnerFixture()
	falseResult := pollingResult(t, policy, "False")
	for name, source := range map[string]*sequenceObservationSource{
		"terminal false": {results: []observation.VerifiedResult{falseResult}},
		"source error":   {err: errors.New("secret API detail")},
	} {
		t.Run(name, func(t *testing.T) {
			waits := 0
			observer, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
				Source: source, Interval: time.Second, Timeout: time.Minute, Clock: time.Now,
				Wait: func(context.Context, time.Duration) error { waits++; return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := observer.Observe(context.Background(), policy)
			if name == "terminal false" {
				receipt, receiptErr := result.Receipt()
				if err != nil || receiptErr != nil || receipt.Ready != "False" {
					t.Fatalf("terminal False was not returned: %#v %v %v", receipt, err, receiptErr)
				}
			} else if err == nil || strings.Contains(err.Error(), "secret API") {
				t.Fatalf("operational error retried or leaked: %v", err)
			}
			if source.calls != 1 || waits != 0 {
				t.Fatalf("terminal observation was retried: calls=%d waits=%d", source.calls, waits)
			}
		})
	}
}

func TestBoundedPollingObserverContinuesAfterLaterErrorOnlyWhenEnabled(t *testing.T) {
	policy, _ := aggregateRunnerFixture()
	unknown := pollingResult(t, policy, "Unknown")
	ready := pollingResult(t, policy, "True")
	current := time.Date(2026, 9, 2, 19, 0, 0, 0, time.UTC)
	source := &sequenceObservationSource{
		results: []observation.VerifiedResult{unknown, ready},
		errors:  []error{nil, errors.New("transient private source detail"), nil},
	}
	observer, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: source, Interval: time.Second, Timeout: time.Minute,
		Clock:                           func() time.Time { return current },
		Wait:                            func(_ context.Context, duration time.Duration) error { current = current.Add(duration); return nil },
		ContinueOnErrorAfterObservation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" || source.calls != 3 {
		t.Fatalf("later transient failure did not remain bounded and pollable: receipt=%#v calls=%d", receipt, source.calls)
	}

	firstError := &sequenceObservationSource{err: errors.New("initial private source detail")}
	observer, err = NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: firstError, Interval: time.Second, Timeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil }, ContinueOnErrorAfterObservation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Observe(context.Background(), policy); err == nil || strings.Contains(err.Error(), "private") || firstError.calls != 1 {
		t.Fatalf("initial source failure did not remain fail-closed and redacted: calls=%d err=%v", firstError.calls, err)
	}
}

func pollingResult(t *testing.T, policy observation.Policy, readiness string) observation.VerifiedResult {
	t.Helper()
	evidence := []observation.Evidence{}
	if readiness == "True" || readiness == "False" {
		for _, condition := range policy.Required {
			item := aggregateRunnerEvidence(policy, condition)
			if readiness == "False" && condition == "PlatformReady" {
				item.Status, item.Reason = "False", "PlatformCapabilityFailed"
			}
			evidence = append(evidence, item)
		}
	}
	result, err := observation.Evaluate(policy, observation.Bundle{
		Format: observation.BundleFormat, IntentRevision: policy.IntentRevision,
		EvaluatedAt: "2026-08-16T12:00:00Z", Evidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type sequenceObservationSource struct {
	results  []observation.VerifiedResult
	fallback observation.VerifiedResult
	err      error
	errors   []error
	calls    int
}

func (source *sequenceObservationSource) Observe(context.Context, observation.Policy) (observation.VerifiedResult, error) {
	source.calls++
	if source.calls <= len(source.errors) && source.errors[source.calls-1] != nil {
		return observation.VerifiedResult{}, source.errors[source.calls-1]
	}
	if source.err != nil {
		return observation.VerifiedResult{}, source.err
	}
	if len(source.results) > 0 {
		result := source.results[0]
		source.results = source.results[1:]
		return result, nil
	}
	return source.fallback, nil
}
