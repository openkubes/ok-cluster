package runner

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// KubernetesExecutionOperationConfig is the complete runtime composition for
// one bounded create execution. It contains no implicit authority, retry,
// rollback, renderer or status publisher.
type KubernetesExecutionOperationConfig struct {
	Ledger         KubernetesLedgerConfig
	Infrastructure KubernetesAuthorityConfig
	Management     KubernetesAuthorityConfig
	Observer       KubernetesAggregateObserverConfig
	PollInterval   time.Duration
	PollTimeout    time.Duration
	Clock          func() time.Time
	Wait           ObservationWaiter
}

// OpenKubernetesExecutionOperation materializes the four bounded runtime
// capabilities without contacting a Kubernetes API. Credential files are read
// once during construction, and infra/mgmt write credentials must be distinct.
func OpenKubernetesExecutionOperation(config KubernetesExecutionOperationConfig) (execution.Operation, error) {
	if config.Clock == nil || config.Wait == nil {
		return execution.Operation{}, errors.New("execution clock and bounded waiter are required")
	}
	if config.Infrastructure.AuthorityIdentity == config.Management.AuthorityIdentity || config.Infrastructure.Endpoint == config.Management.Endpoint {
		return execution.Operation{}, errors.New("infrastructure and management write authorities must be distinct")
	}
	if config.Observer.Management != config.Management || config.Observer.ExpectedManagementAuthority != config.Management.AuthorityIdentity {
		return execution.Operation{}, errors.New("observation management authority differs from submission authority")
	}
	if config.Observer.Argo.AuthorityIdentity == "" || config.Observer.ExpectedArgoAuthority != config.Observer.Argo.AuthorityIdentity {
		return execution.Operation{}, errors.New("GitOps observation authority is not explicitly bound")
	}

	store, err := OpenKubernetesLedger(config.Ledger)
	if err != nil {
		return execution.Operation{}, errors.New("open bounded execution ledger")
	}
	infrastructure, infrastructureToken, err := openKubernetesSubmissionClient(config.Infrastructure)
	if err != nil {
		return execution.Operation{}, errors.New("open infrastructure submission authority")
	}
	management, managementToken, err := openKubernetesSubmissionClient(config.Management)
	if err != nil {
		return execution.Operation{}, errors.New("open management submission authority")
	}
	if len(infrastructureToken) == len(managementToken) && subtle.ConstantTimeCompare([]byte(infrastructureToken), []byte(managementToken)) == 1 {
		return execution.Operation{}, errors.New("infrastructure and management write credentials must be distinct")
	}

	observerConfig := config.Observer
	observerConfig.Clock = config.Clock
	aggregate, err := OpenKubernetesAggregateObserver(observerConfig)
	if err != nil {
		return execution.Operation{}, errors.New("open bounded aggregate observer")
	}
	polling, err := NewBoundedPollingObserver(BoundedPollingObserverConfig{
		Source: aggregate, Interval: config.PollInterval, Timeout: config.PollTimeout,
		Clock: config.Clock, Wait: config.Wait,
	})
	if err != nil {
		return execution.Operation{}, errors.New("open bounded convergence observer")
	}

	submitter := submission.Executor{Infrastructure: infrastructure, Management: management}
	return execution.Operation{Ledger: store, Submitter: submitter, Observer: polling, Clock: config.Clock}, nil
}
