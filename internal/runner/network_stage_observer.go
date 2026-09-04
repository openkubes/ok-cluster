package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

type NetworkStageObserverConfig struct {
	Plan                   stageplan.Binding
	ReceiptPrefix          []stagereceipt.Verified
	TargetClusterUID       string
	Source                 observation.NetworkEvidenceSource
	Profile                observation.NetworkProfile
	PollInterval           time.Duration
	PollTimeout            time.Duration
	Clock                  func() time.Time
	Wait                   ObservationWaiter
	AllowMVPWarmupDeferral bool
	MVPWarmupDeferralDelay time.Duration
}

// NetworkStageObserver is the stage-specific adapter around the existing
// bounded NetworkReady source and deterministic observation evaluator. It has
// no mutation, repair, arbitrary query, or persistent status publication path.
type NetworkStageObserver struct {
	binding                execution.StageObservationBinding
	source                 observation.NetworkEvidenceSource
	profile                observation.NetworkProfile
	policy                 observation.Policy
	pollInterval           time.Duration
	pollLimit              time.Duration
	clock                  func() time.Time
	wait                   ObservationWaiter
	allowMVPWarmupDeferral bool
	mvpWarmupDeferralDelay time.Duration
}

var _ execution.StageObserver = (*NetworkStageObserver)(nil)

// NewNetworkStageObserver derives stage selection from the complete verified
// receipt prefix and correlates the private raw target UID to the durable
// digest emitted by cluster-lifecycle. A same-name replacement is rejected.
func NewNetworkStageObserver(config NetworkStageObserverConfig) (*NetworkStageObserver, error) {
	if config.Source == nil || config.Clock == nil || config.Wait == nil {
		return nil, errors.New("network stage observer source, clock, and waiter are required")
	}
	if config.AllowMVPWarmupDeferral && (config.MVPWarmupDeferralDelay < config.PollInterval || config.MVPWarmupDeferralDelay > config.PollTimeout) {
		return nil, errors.New("network MVP warmup deferral boundary is invalid")
	}
	cursor, err := stagecursor.Evaluate(config.Plan, config.ReceiptPrefix)
	if err != nil {
		return nil, errors.New("verify network observation receipt prefix")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "network-observation" || decision.Kind != "Observation" || decision.Authority != "workload" || decision.RequiresAuthorization || decision.Operation != "" {
		return nil, errors.New("stage receipt prefix does not select network observation")
	}
	if len(config.ReceiptPrefix) != 4 {
		return nil, errors.New("network observation receipt prefix is incomplete")
	}
	lifecycle, err := config.ReceiptPrefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) || digest.SHA256([]byte(config.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return nil, errors.New("network observation target differs from durable lifecycle correlation")
	}
	if err := observation.ValidateNetworkProfile(config.Profile); err != nil || config.Profile.IntentRevision != config.Plan.IntentRevision || config.Profile.EnablementRevision != config.Plan.EnablementRevision {
		return nil, errors.New("network profile differs from the verified execution plan")
	}
	stage, stageDigest, err := config.Plan.Stage(decision.StageID)
	if err != nil || stageDigest != decision.StageDigest {
		return nil, errors.New("network observation stage differs from verified plan")
	}
	return &NetworkStageObserver{
		binding: execution.StageObservationBinding{
			PlanDigest: config.Plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Authority: stage.Authority, ContractRevision: config.Plan.IntentRevision,
		},
		source: config.Source, profile: config.Profile,
		policy: observation.Policy{
			Format: observation.PolicyFormat, IntentRevision: config.Plan.IntentRevision,
			EnablementRevision: config.Plan.EnablementRevision, PlatformRevision: config.Plan.PlatformRevision,
			TargetClusterUID: config.TargetClusterUID, Required: []string{"NetworkReady"},
		},
		pollInterval: config.PollInterval, pollLimit: config.PollTimeout,
		clock: config.Clock, wait: config.Wait,
		allowMVPWarmupDeferral: config.AllowMVPWarmupDeferral,
		mvpWarmupDeferralDelay: config.MVPWarmupDeferralDelay,
	}, nil
}

func (observer *NetworkStageObserver) Binding() execution.StageObservationBinding {
	if observer == nil {
		return execution.StageObservationBinding{}
	}
	return observer.binding
}

func (observer *NetworkStageObserver) Observe(ctx context.Context) (execution.StageObservationResult, error) {
	if observer == nil {
		return execution.StageObservationResult{}, errors.New("network stage observer is required")
	}
	polling, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: &networkPollingSource{
			source: observer.source, profile: observer.profile, clock: observer.clock,
			allowMVPWarmupDeferral: observer.allowMVPWarmupDeferral,
			mvpWarmupDeferralDelay: observer.mvpWarmupDeferralDelay,
		},
		Interval: observer.pollInterval, Timeout: observer.pollLimit, Clock: observer.clock, Wait: observer.wait,
		ContinueOnFalse: true, ContinueOnErrorAfterObservation: true,
		ContinueOnInitialError: observation.IsTransientNetworkSourceError,
	})
	if err != nil {
		return execution.StageObservationResult{}, err
	}
	result, err := polling.Observe(ctx, observer.policy)
	if err != nil {
		return execution.StageObservationResult{}, errors.New("bounded network convergence observation failed")
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
		return execution.StageObservationResult{}, errors.New("network observation completion time is invalid")
	}
	outcome := "STOPPED"
	if receipt.Ready == "True" {
		outcome = "SUCCEEDED"
	} else if receipt.Ready == "False" {
		outcome = "FAILED"
	}
	return execution.StageObservationResult{Outcome: outcome, EvidenceDigest: evidenceDigest, CompletedAt: completedAt}, nil
}

type networkPollingSource struct {
	source                 observation.NetworkEvidenceSource
	profile                observation.NetworkProfile
	clock                  func() time.Time
	allowMVPWarmupDeferral bool
	mvpWarmupDeferralDelay time.Duration
	mvpWarmupPendingSince  time.Time
}

func (source *networkPollingSource) Observe(ctx context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	evidence, err := source.source.Observe(ctx, policy, source.profile)
	if err != nil {
		return observation.VerifiedResult{}, err
	}
	if source.allowMVPWarmupDeferral && isMVPNetworkWarmup(evidence) {
		now := source.clock()
		if source.mvpWarmupPendingSince.IsZero() {
			source.mvpWarmupPendingSince = now
		}
		if !now.Before(source.mvpWarmupPendingSince.Add(source.mvpWarmupDeferralDelay)) {
			evidence.Status = "True"
			evidence.Reason = "MVPNetworkWarmupDeferred"
		}
	} else {
		source.mvpWarmupPendingSince = time.Time{}
	}
	return observation.Evaluate(policy, observation.Bundle{
		Format: observation.BundleFormat, IntentRevision: policy.IntentRevision,
		EvaluatedAt: source.clock().UTC().Format(time.RFC3339Nano), Evidence: []observation.Evidence{evidence},
	})
}

// isMVPNetworkWarmup is deliberately narrower than Status=Unknown. It permits
// only the normal CAAPH/Cilium rollout states already proven to converge late
// in DEV, plus the fixed Cilium cache-freshness classification. Source,
// transport, authorization, TLS, identity and schema errors do not produce
// evidence and therefore cannot enter this deferral path. All other False
// evidence remains terminal.
func isMVPNetworkWarmup(evidence observation.Evidence) bool {
	if evidence.Type != "NetworkReady" || evidence.Source != "BoundedNetworkEvaluator" {
		return false
	}
	if evidence.Status == "False" {
		// The collector reached the fixed Cilium health endpoint but its cached
		// response is older than the advertised publication interval. This is a
		// bounded cache-freshness race, not a component/identity failure.
		return evidence.Reason == "FunctionalProbeStale"
	}
	if evidence.Status != "Unknown" {
		return false
	}
	switch evidence.Reason {
	case "EnablementSourceNotReady", "EnablementReleaseNotReady", "NodeInventoryNotReady",
		"NodeNetworkNotReady", "CiliumRolloutNotReady", "CiliumAgentPodsNotReady", "FunctionalProbePending":
		return true
	default:
		return false
	}
}
