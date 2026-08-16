package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

type RuntimeBoundCAPISource interface {
	CollectBound(context.Context, observation.Policy, string) (observation.Policy, []observation.Evidence, error)
	Collect(context.Context, observation.Policy) ([]observation.Evidence, error)
}

type LifecycleStageObserverConfig struct {
	Plan         stageplan.Binding
	Cursor       stagecursor.Cursor
	Source       RuntimeBoundCAPISource
	PollInterval time.Duration
	PollTimeout  time.Duration
	Clock        func() time.Time
	Wait         ObservationWaiter
}

type KubernetesLifecycleStageObserverConfig struct {
	Plan         stageplan.Binding
	Cursor       stagecursor.Cursor
	Management   KubernetesAuthorityConfig
	PollInterval time.Duration
	PollTimeout  time.Duration
	Clock        func() time.Time
	Wait         ObservationWaiter
}

type LifecycleStageObserver struct {
	binding                execution.StageObservationBinding
	source                 RuntimeBoundCAPISource
	policy                 observation.Policy
	targetClusterUIDDigest string
	pollInterval           time.Duration
	pollLimit              time.Duration
	clock                  func() time.Time
	wait                   ObservationWaiter
}

var _ execution.StageObserver = (*LifecycleStageObserver)(nil)

// OpenKubernetesLifecycleStageObserver binds the exact management authority
// and reads its bounded credential files, but performs no Kubernetes request.
func OpenKubernetesLifecycleStageObserver(config KubernetesLifecycleStageObserverConfig) (*LifecycleStageObserver, error) {
	source, err := OpenKubernetesCAPILifecycleObserver(
		config.Management,
		config.Plan.Authorities.Management,
		config.Plan.ContractIdentity.Namespace,
		config.Plan.ContractIdentity.Name,
	)
	if err != nil {
		return nil, errors.New("open bounded lifecycle observation source")
	}
	return NewLifecycleStageObserver(LifecycleStageObserverConfig{
		Plan: config.Plan, Cursor: config.Cursor, Source: source,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout,
		Clock: config.Clock, Wait: config.Wait,
	})
}

// NewLifecycleStageObserver derives its target binding only from the verified
// cluster-lifecycle predecessor receipt. No caller-supplied UID is accepted.
func NewLifecycleStageObserver(config LifecycleStageObserverConfig) (*LifecycleStageObserver, error) {
	if config.Source == nil || config.Clock == nil || config.Wait == nil {
		return nil, errors.New("lifecycle stage observer source, clock, and waiter are required")
	}
	decision, err := config.Cursor.Decision()
	if err != nil {
		return nil, err
	}
	if decision.State != "NEXT" || decision.StageID != "lifecycle-observation" || decision.Kind != "Observation" || decision.Authority != "management" || decision.RequiresAuthorization {
		return nil, errors.New("stage cursor does not select lifecycle observation")
	}
	predecessors, err := config.Cursor.Predecessors()
	if err != nil || len(predecessors) != 1 {
		return nil, errors.New("lifecycle observation predecessor is incomplete")
	}
	predecessor, err := predecessors[0].Receipt()
	if err != nil || predecessor.PlanDigest != config.Plan.PlanDigest || predecessor.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(predecessor.TargetClusterUIDDigest) {
		return nil, errors.New("lifecycle predecessor lacks durable target correlation")
	}
	stage, stageDigest, err := config.Plan.Stage(decision.StageID)
	if err != nil || stageDigest != decision.StageDigest {
		return nil, errors.New("lifecycle observation stage differs from verified plan")
	}
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: config.Plan.IntentRevision,
		EnablementRevision: config.Plan.EnablementRevision, PlatformRevision: config.Plan.PlatformRevision,
		Required: []string{"InfrastructureReady", "ControlPlaneAvailable"},
	}
	return &LifecycleStageObserver{
		binding: execution.StageObservationBinding{
			PlanDigest: config.Plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Authority: stage.Authority, ContractRevision: config.Plan.IntentRevision,
		},
		source: config.Source, policy: policy, targetClusterUIDDigest: predecessor.TargetClusterUIDDigest,
		pollInterval: config.PollInterval, pollLimit: config.PollTimeout, clock: config.Clock, wait: config.Wait,
	}, nil
}

func (observer *LifecycleStageObserver) Binding() execution.StageObservationBinding {
	if observer == nil {
		return execution.StageObservationBinding{}
	}
	return observer.binding
}

func (observer *LifecycleStageObserver) Observe(ctx context.Context) (execution.StageObservationResult, error) {
	if observer == nil {
		return execution.StageObservationResult{}, errors.New("lifecycle stage observer is required")
	}
	boundPolicy, evidence, err := observer.source.CollectBound(ctx, observer.policy, observer.targetClusterUIDDigest)
	if err != nil {
		return execution.StageObservationResult{}, errors.New("establish durable lifecycle observation correlation")
	}
	first, err := evaluateLifecycleEvidence(boundPolicy, evidence, observer.clock())
	if err != nil {
		return execution.StageObservationResult{}, errors.New("evaluate initial lifecycle evidence")
	}
	source := &lifecyclePollingSource{first: &first, source: observer.source, clock: observer.clock}
	polling, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: source, Interval: observer.pollInterval, Timeout: observer.pollLimit,
		Clock: observer.clock, Wait: observer.wait,
	})
	if err != nil {
		return execution.StageObservationResult{}, err
	}
	result, err := polling.Observe(ctx, boundPolicy)
	if err != nil {
		return execution.StageObservationResult{}, errors.New("bounded lifecycle convergence observation failed")
	}
	receipt, err := result.Receipt()
	if err != nil {
		return execution.StageObservationResult{}, err
	}
	evidenceDigest, err := result.EvidenceDigest()
	if err != nil {
		return execution.StageObservationResult{}, err
	}
	completedAt, err := time.Parse(time.RFC3339Nano, receipt.EvaluatedAt)
	if err != nil {
		return execution.StageObservationResult{}, errors.New("lifecycle observation completion time is invalid")
	}
	outcome := "STOPPED"
	if receipt.Ready == "True" {
		outcome = "SUCCEEDED"
	} else if receipt.Ready == "False" {
		outcome = "FAILED"
	}
	return execution.StageObservationResult{Outcome: outcome, EvidenceDigest: evidenceDigest, CompletedAt: completedAt}, nil
}

type lifecyclePollingSource struct {
	first  *observation.VerifiedResult
	source RuntimeBoundCAPISource
	clock  func() time.Time
}

func (source *lifecyclePollingSource) Observe(ctx context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	if source.first != nil {
		result := *source.first
		source.first = nil
		return result, nil
	}
	evidence, err := source.source.Collect(ctx, policy)
	if err != nil {
		return observation.VerifiedResult{}, err
	}
	return evaluateLifecycleEvidence(policy, evidence, source.clock())
}

func evaluateLifecycleEvidence(policy observation.Policy, evidence []observation.Evidence, at time.Time) (observation.VerifiedResult, error) {
	return observation.Evaluate(policy, observation.Bundle{
		Format: observation.BundleFormat, IntentRevision: policy.IntentRevision,
		EvaluatedAt: at.UTC().Format(time.RFC3339Nano), Evidence: evidence,
	})
}
