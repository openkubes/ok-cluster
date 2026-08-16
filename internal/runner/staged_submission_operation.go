package runner

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// KubernetesSubmissionStageOperationConfig binds one staged exact-create
// operation to one ledger and one write authority. It has no authority map,
// dispatcher, retry or fallback credential.
type KubernetesSubmissionStageOperationConfig struct {
	Ledger     KubernetesLedgerConfig
	Authority  KubernetesAuthorityConfig
	Plan       stageplan.Binding
	StageID    string
	Projection submission.Plan
	Clock      func() time.Time
}

// OpenKubernetesSubmissionStageOperation constructs the same staged operation
// usable by a local process or ephemeral Job. Construction reads bounded
// credential files but performs no Kubernetes API request.
func OpenKubernetesSubmissionStageOperation(config KubernetesSubmissionStageOperationConfig) (execution.StagedOperation, error) {
	if config.Clock == nil {
		return execution.StagedOperation{}, errors.New("staged submission operation clock is required")
	}
	stage, _, err := config.Plan.Stage(config.StageID)
	if err != nil {
		return execution.StagedOperation{}, err
	}
	var expectedAuthority string
	switch stage.ID {
	case "provider-prerequisites":
		expectedAuthority = config.Plan.Authorities.Infrastructure
	case "cluster-lifecycle":
		expectedAuthority = config.Plan.Authorities.Management
	default:
		return execution.StagedOperation{}, errors.New("stage has no Kubernetes submission-operation composition")
	}
	if config.Authority.AuthorityIdentity != expectedAuthority {
		return execution.StagedOperation{}, errors.New("submission credential authority differs from the selected stage")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open staged execution ledger")
	}
	submitter, authorityToken, err := openKubernetesSubmissionClient(config.Authority)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open staged submission authority")
	}
	if len(ledgerToken) == len(authorityToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(authorityToken)) == 1 {
		return execution.StagedOperation{}, errors.New("ledger and write authority credentials must be distinct")
	}
	mutator, err := execution.NewSubmissionPlaneMutator(config.Plan, stage.ID, config.Projection, submitter)
	if err != nil {
		return execution.StagedOperation{}, err
	}
	return execution.StagedOperation{Ledger: store, Mutator: mutator, Clock: config.Clock}, nil
}
