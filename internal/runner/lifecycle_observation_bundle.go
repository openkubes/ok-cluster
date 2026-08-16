package runner

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// VerifiedLifecycleObservationStageBundle retains one reverified plan and
// receipt prefix. Its private fields prevent a caller from substituting a
// cursor or predecessor between local verification and runtime opening.
type VerifiedLifecycleObservationStageBundle struct {
	plan     stageplan.Binding
	cursor   stagecursor.Cursor
	verified bool
}

type LifecycleObservationStageRuntimeConfig struct {
	Ledger       KubernetesLedgerConfig
	Management   KubernetesAuthorityConfig
	PollInterval time.Duration
	PollTimeout  time.Duration
	Clock        func() time.Time
	Wait         ObservationWaiter
}

// OpenedLifecycleObservationStage exposes only the one bounded Run method.
// Plan, cursor, credentials and source implementation remain private.
type OpenedLifecycleObservationStage struct {
	operation execution.ObservationStageOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	verified  bool
}

// LoadLifecycleObservationStageBundle verifies an explicit canonical receipt
// prefix and requires it to select exactly lifecycle-observation.
func LoadLifecycleObservationStageBundle(config StageResumeConfig) (VerifiedLifecycleObservationStageBundle, error) {
	plan, cursor, err := loadStageResume(config)
	if err != nil {
		return VerifiedLifecycleObservationStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil {
		return VerifiedLifecycleObservationStageBundle{}, err
	}
	if decision.State != "NEXT" || decision.StageID != "lifecycle-observation" || decision.Kind != "Observation" || decision.Authority != "management" || decision.RequiresAuthorization || decision.Operation != "" {
		return VerifiedLifecycleObservationStageBundle{}, errors.New("verified prefix does not select lifecycle observation")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil || len(predecessors) != 1 {
		return VerifiedLifecycleObservationStageBundle{}, errors.New("lifecycle observation predecessor is incomplete")
	}
	predecessor, err := predecessors[0].Receipt()
	if err != nil || predecessor.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(predecessor.TargetClusterUIDDigest) {
		return VerifiedLifecycleObservationStageBundle{}, errors.New("lifecycle predecessor lacks durable target correlation")
	}
	return VerifiedLifecycleObservationStageBundle{plan: plan, cursor: cursor, verified: true}, nil
}

// Decision returns the already verified, redaction-safe cursor decision.
func (bundle VerifiedLifecycleObservationStageBundle) Decision() (stagecursor.Decision, error) {
	if !bundle.verified {
		return stagecursor.Decision{}, errors.New("lifecycle observation stage bundle is not verified")
	}
	return bundle.cursor.Decision()
}

// Open constructs the exact ledger and management observation capabilities.
// It reads bounded credentials once but performs no Kubernetes API request.
func (bundle VerifiedLifecycleObservationStageBundle) Open(config LifecycleObservationStageRuntimeConfig) (OpenedLifecycleObservationStage, error) {
	if !bundle.verified || config.Clock == nil || config.Wait == nil {
		return OpenedLifecycleObservationStage{}, errors.New("verified lifecycle observation bundle, clock, and waiter are required")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return OpenedLifecycleObservationStage{}, errors.New("open lifecycle observation ledger")
	}
	source, managementToken, err := openKubernetesCAPILifecycleObserver(
		config.Management,
		bundle.plan.Authorities.Management,
		bundle.plan.ContractIdentity.Namespace,
		bundle.plan.ContractIdentity.Name,
	)
	if err != nil {
		return OpenedLifecycleObservationStage{}, errors.New("open lifecycle observation management source")
	}
	if len(ledgerToken) == len(managementToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(managementToken)) == 1 {
		return OpenedLifecycleObservationStage{}, errors.New("ledger and observation credentials must be distinct")
	}
	observer, err := NewLifecycleStageObserver(LifecycleStageObserverConfig{
		Plan: bundle.plan, Cursor: bundle.cursor, Source: source,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout,
		Clock: config.Clock, Wait: config.Wait,
	})
	if err != nil {
		return OpenedLifecycleObservationStage{}, err
	}
	return OpenedLifecycleObservationStage{
		operation: execution.ObservationStageOperation{Ledger: store, Observer: observer},
		plan:      bundle.plan, cursor: bundle.cursor, verified: true,
	}, nil
}

func (stage OpenedLifecycleObservationStage) Run(ctx context.Context) (execution.ObservationStageRunReceipt, error) {
	if !stage.verified {
		return execution.ObservationStageRunReceipt{}, errors.New("lifecycle observation stage is not opened")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor)
}
