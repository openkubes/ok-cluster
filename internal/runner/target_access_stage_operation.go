package runner

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// KubernetesTargetAccessStageOperationConfig binds one verified target-access
// projection to the durable ledger and private runtime-bound workload files.
type KubernetesTargetAccessStageOperationConfig struct {
	Ledger     KubernetesLedgerConfig
	Workload   WorkloadAuthorityFileResolverConfig
	Plan       stageplan.Binding
	Projection submission.TargetAccessPlan
	Clock      func() time.Time
}

// OpenKubernetesTargetAccessStageOperation verifies the private raw target UID
// against the public digest and reads bounded credentials without API contact.
func OpenKubernetesTargetAccessStageOperation(config KubernetesTargetAccessStageOperationConfig) (execution.StagedOperation, error) {
	if config.Clock == nil {
		return execution.StagedOperation{}, errors.New("target-access operation clock is required")
	}
	binding, authority, err := loadWorkloadAuthorityFiles(config.Workload)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open runtime-bound target-access authority")
	}
	if binding.IntentRevision != config.Plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != config.Projection.TargetIdentityDigest || config.Projection.Workload.Identity != config.Projection.TargetIdentityDigest {
		return execution.StagedOperation{}, errors.New("target-access credential differs from the runtime-bound target")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open target-access stage ledger")
	}
	// The API client retains only the public target digest in its receipts. The
	// raw UID was verified above and remains private runtime material.
	authority.AuthorityIdentity = config.Projection.TargetIdentityDigest
	submitter, workloadToken, err := openKubernetesSubmissionClient(authority)
	if err != nil {
		return execution.StagedOperation{}, errors.New("open target-access submission authority")
	}
	if len(ledgerToken) == len(workloadToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(workloadToken)) == 1 {
		return execution.StagedOperation{}, errors.New("ledger and target-access credentials must be distinct")
	}
	mutator, err := execution.NewTargetAccessMutator(config.Plan, config.Projection, submitter)
	if err != nil {
		return execution.StagedOperation{}, err
	}
	return execution.StagedOperation{Ledger: store, Mutator: mutator, Clock: config.Clock}, nil
}
