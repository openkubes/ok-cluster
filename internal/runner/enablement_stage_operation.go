package runner

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// KubernetesEnablementStageOperationConfig binds the exact HCP submission to
// the management authority and durable stage ledger.
type KubernetesEnablementStageOperationConfig struct {
	Ledger     KubernetesLedgerConfig
	Authority  KubernetesAuthorityConfig
	Plan       stageplan.Binding
	Projection submission.EnablementPlan
	Clock      func() time.Time
}

// OpenKubernetesEnablementStageOperation reads bounded credentials and
// constructs the shared operation without contacting Kubernetes.
func OpenKubernetesEnablementStageOperation(config KubernetesEnablementStageOperationConfig) (execution.StagedOperation, error) {
	if config.Clock == nil {
		return execution.StagedOperation{}, errors.New("enablement operation clock is required")
	}
	if config.Authority.AuthorityIdentity != config.Plan.Authorities.Management {
		return execution.StagedOperation{}, errors.New("enablement credential authority differs from management")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open enablement stage ledger")
	}
	submitter, authorityToken, err := openKubernetesSubmissionClient(config.Authority)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open enablement submission authority")
	}
	if len(ledgerToken) == len(authorityToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(authorityToken)) == 1 {
		return execution.StagedOperation{}, errors.New("ledger and enablement credentials must be distinct")
	}
	mutator, err := execution.NewEnablementMutator(config.Plan, config.Projection, submitter)
	if err != nil {
		return execution.StagedOperation{}, err
	}
	return execution.StagedOperation{Ledger: store, Mutator: mutator, Clock: config.Clock}, nil
}
