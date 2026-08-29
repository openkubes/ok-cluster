package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

type ObservationSource interface {
	Observe(context.Context, observation.Policy) (observation.VerifiedResult, error)
}

type ObservationWaiter func(context.Context, time.Duration) error

type BoundedPollingObserverConfig struct {
	Source          ObservationSource
	Interval        time.Duration
	Timeout         time.Duration
	Clock           func() time.Time
	Wait            ObservationWaiter
	ContinueOnFalse bool
}

// BoundedPollingObserver repeats only read-oriented aggregate observation.
// It never repeats submission, capability execution after a terminal result,
// mutation or an operationally failed observation.
type BoundedPollingObserver struct {
	config BoundedPollingObserverConfig
}

func NewBoundedPollingObserver(config BoundedPollingObserverConfig) (*BoundedPollingObserver, error) {
	if config.Source == nil || config.Clock == nil || config.Wait == nil || config.Interval < time.Second || config.Interval > 5*time.Minute || config.Timeout < config.Interval || config.Timeout > 6*time.Hour {
		return nil, errors.New("bounded polling observer configuration is invalid")
	}
	return &BoundedPollingObserver{config: config}, nil
}

func (observer *BoundedPollingObserver) Observe(ctx context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	if observer == nil || observer.config.Source == nil {
		return observation.VerifiedResult{}, errors.New("bounded polling observer is required")
	}
	if err := ctx.Err(); err != nil {
		return observation.VerifiedResult{}, errors.New("bounded observation polling cancelled")
	}
	started := observer.config.Clock()
	deadline := started.Add(observer.config.Timeout)
	var last observation.VerifiedResult
	for {
		result, err := observer.config.Source.Observe(ctx, policy)
		if err != nil {
			return observation.VerifiedResult{}, errors.New("bounded aggregate observation failed")
		}
		receipt, err := result.Receipt()
		if err != nil {
			return observation.VerifiedResult{}, errors.New("aggregate observer returned an unverified result")
		}
		last = result
		if receipt.Ready == "True" || (receipt.Ready == "False" && !observer.config.ContinueOnFalse) {
			return result, nil
		}
		if receipt.Ready != "Unknown" && receipt.Ready != "False" {
			return observation.VerifiedResult{}, errors.New("aggregate observer returned an invalid readiness state")
		}
		now := observer.config.Clock()
		if !now.Before(deadline) {
			return last, nil
		}
		wait := observer.config.Interval
		if remaining := deadline.Sub(now); remaining < wait {
			wait = remaining
		}
		if err := observer.config.Wait(ctx, wait); err != nil {
			return observation.VerifiedResult{}, errors.New("bounded observation polling interrupted")
		}
	}
}

func WaitWithTimer(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ ObservationSource = (*KubernetesAggregateObserver)(nil)
