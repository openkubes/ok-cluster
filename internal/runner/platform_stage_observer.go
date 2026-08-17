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

type PlatformStageObserverConfig struct {
	Plan             stageplan.Binding
	ReceiptPrefix    []stagereceipt.Verified
	TargetClusterUID string
	Source           observation.PlatformEvidenceSource
	Profile          observation.PlatformProfile
	PollInterval     time.Duration
	PollTimeout      time.Duration
	Clock            func() time.Time
	Wait             ObservationWaiter
}

// PlatformStageObserver is a read-only adapter around exact Argo Application
// GETs, an independently bounded capability assertion and deterministic
// PlatformReady evaluation. It has no sync, repair or status-write path.
type PlatformStageObserver struct {
	binding      execution.StageObservationBinding
	source       observation.PlatformEvidenceSource
	profile      observation.PlatformProfile
	policy       observation.Policy
	pollInterval time.Duration
	pollLimit    time.Duration
	clock        func() time.Time
	wait         ObservationWaiter
}

var _ execution.StageObserver = (*PlatformStageObserver)(nil)

func NewPlatformStageObserver(config PlatformStageObserverConfig) (*PlatformStageObserver, error) {
	if config.Source == nil || config.Clock == nil || config.Wait == nil {
		return nil, errors.New("platform stage observer source, clock, and waiter are required")
	}
	cursor, err := stagecursor.Evaluate(config.Plan, config.ReceiptPrefix)
	if err != nil {
		return nil, errors.New("verify platform observation receipt prefix")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "platform-observation" || decision.Kind != "Observation" || decision.Authority != "gitops" || decision.RequiresAuthorization || decision.Operation != "" {
		return nil, errors.New("stage receipt prefix does not select platform observation")
	}
	if len(config.ReceiptPrefix) != 10 {
		return nil, errors.New("platform observation receipt prefix is incomplete")
	}
	lifecycle, err := config.ReceiptPrefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) || digest.SHA256([]byte(config.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return nil, errors.New("platform observation target differs from durable lifecycle correlation")
	}
	platformApplications, err := config.ReceiptPrefix[9].Receipt()
	if err != nil || platformApplications.StageID != "platform-applications" || platformApplications.State != "SUCCEEDED" || platformApplications.MutationState != "ATTEMPTED" {
		return nil, errors.New("platform observation lacks successful Application submission")
	}
	if err := observation.ValidatePlatformProfile(config.Profile); err != nil || config.Profile.IntentRevision != config.Plan.IntentRevision || config.Profile.PlatformRevision != config.Plan.PlatformRevision || config.Profile.ExecutionFixture != config.Plan.ExecutionFixture {
		return nil, errors.New("platform profile differs from the verified execution plan")
	}
	stage, stageDigest, err := config.Plan.Stage(decision.StageID)
	if err != nil || stageDigest != decision.StageDigest {
		return nil, errors.New("platform observation stage differs from verified plan")
	}
	profile := config.Profile
	profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), config.Profile.RequiredApplications...)
	return &PlatformStageObserver{
		binding: execution.StageObservationBinding{
			PlanDigest: config.Plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Authority: stage.Authority, ContractRevision: config.Plan.IntentRevision,
		},
		source: config.Source, profile: profile,
		policy: observation.Policy{
			Format: observation.PolicyFormat, IntentRevision: config.Plan.IntentRevision,
			EnablementRevision: config.Plan.EnablementRevision, PlatformRevision: config.Plan.PlatformRevision,
			TargetClusterUID: config.TargetClusterUID, Required: []string{"PlatformReady"},
		},
		pollInterval: config.PollInterval, pollLimit: config.PollTimeout, clock: config.Clock, wait: config.Wait,
	}, nil
}

func (observer *PlatformStageObserver) Binding() execution.StageObservationBinding {
	if observer == nil {
		return execution.StageObservationBinding{}
	}
	return observer.binding
}

func (observer *PlatformStageObserver) Observe(ctx context.Context) (execution.StageObservationResult, error) {
	if observer == nil {
		return execution.StageObservationResult{}, errors.New("platform stage observer is required")
	}
	polling, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source:   &platformPollingSource{source: observer.source, clock: observer.clock},
		Interval: observer.pollInterval, Timeout: observer.pollLimit, Clock: observer.clock, Wait: observer.wait,
	})
	if err != nil {
		return execution.StageObservationResult{}, err
	}
	result, err := polling.Observe(ctx, observer.policy)
	if err != nil {
		return execution.StageObservationResult{}, errors.New("bounded platform convergence observation failed")
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
		return execution.StageObservationResult{}, errors.New("platform observation completion time is invalid")
	}
	outcome := "STOPPED"
	if receipt.Ready == "True" {
		outcome = "SUCCEEDED"
	} else if receipt.Ready == "False" {
		outcome = "FAILED"
	}
	return execution.StageObservationResult{Outcome: outcome, EvidenceDigest: evidenceDigest, CompletedAt: completedAt}, nil
}

type platformPollingSource struct {
	source observation.PlatformEvidenceSource
	clock  func() time.Time
}

func (source *platformPollingSource) Observe(ctx context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	evidence, err := source.source.Observe(ctx, policy)
	if err != nil {
		return observation.VerifiedResult{}, err
	}
	return observation.Evaluate(policy, observation.Bundle{
		Format: observation.BundleFormat, IntentRevision: policy.IntentRevision,
		EvaluatedAt: source.clock().UTC().Format(time.RFC3339Nano), Evidence: []observation.Evidence{evidence},
	})
}
