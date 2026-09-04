package runner

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

type VerifiedNetworkObservationStageBundle struct {
	plan     stageplan.Binding
	cursor   stagecursor.Cursor
	prefix   []stagereceipt.Verified
	verified bool
}

type NetworkObservationStageRuntimeConfig struct {
	Ledger                       KubernetesLedgerConfig
	Management                   KubernetesAuthorityConfig
	Workload                     WorkloadAuthorityFileResolverConfig
	NetworkProfilePath           string
	ExpectedNetworkProfileDigest string
	PollInterval                 time.Duration
	PollTimeout                  time.Duration
	Clock                        func() time.Time
	Wait                         ObservationWaiter
}

type OpenedNetworkObservationStage struct {
	operation execution.ObservationStageOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	verified  bool
}

// LoadNetworkObservationStageBundle retains the complete verified receipt
// prefix because target correlation originates at cluster-lifecycle rather
// than the direct enablement predecessor.
func LoadNetworkObservationStageBundle(config StageResumeConfig) (VerifiedNetworkObservationStageBundle, error) {
	plan, cursor, prefix, err := loadStageResumeWithPrefix(config)
	if err != nil {
		return VerifiedNetworkObservationStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "network-observation" || decision.Kind != "Observation" || decision.Authority != "workload" || decision.RequiresAuthorization || decision.Operation != "" {
		return VerifiedNetworkObservationStageBundle{}, errors.New("verified prefix does not select network observation")
	}
	if len(prefix) != 4 {
		return VerifiedNetworkObservationStageBundle{}, errors.New("network observation receipt prefix is incomplete")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedNetworkObservationStageBundle{}, errors.New("network observation history lacks durable target correlation")
	}
	return VerifiedNetworkObservationStageBundle{plan: plan, cursor: cursor, prefix: prefix, verified: true}, nil
}

func (bundle VerifiedNetworkObservationStageBundle) Decision() (stagecursor.Decision, error) {
	if !bundle.verified {
		return stagecursor.Decision{}, errors.New("network observation stage bundle is not verified")
	}
	return bundle.cursor.Decision()
}

// Open reads each bounded local input and credential once, builds isolated TLS
// clients, and performs no Kubernetes request.
func (bundle VerifiedNetworkObservationStageBundle) Open(config NetworkObservationStageRuntimeConfig) (OpenedNetworkObservationStage, error) {
	if !bundle.verified || config.Clock == nil || config.Wait == nil {
		return OpenedNetworkObservationStage{}, errors.New("verified network observation bundle, clock, and waiter are required")
	}
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil {
		return OpenedNetworkObservationStage{}, errors.New("read durable network target correlation")
	}
	binding, workload, err := loadWorkloadAuthorityFiles(config.Workload)
	if err != nil {
		return OpenedNetworkObservationStage{}, errors.New("open network workload authority binding")
	}
	if binding.IntentRevision != bundle.plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return OpenedNetworkObservationStage{}, errors.New("network workload authority differs from durable lifecycle target")
	}
	loadedProfile, err := LoadNetworkProfileFile(NetworkProfileFileConfig{
		Path: config.NetworkProfilePath, ExpectedProfileDigest: config.ExpectedNetworkProfileDigest,
		ExpectedIntentRevision: bundle.plan.IntentRevision, ExpectedEnablementRevision: bundle.plan.EnablementRevision,
	})
	if err != nil {
		return OpenedNetworkObservationStage{}, errors.New("open verified network profile")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return OpenedNetworkObservationStage{}, errors.New("open network observation ledger")
	}
	source, managementToken, workloadToken, err := openKubernetesNetworkSourceCollector(KubernetesNetworkObserverConfig{
		Management: config.Management, Workload: workload,
		ExpectedManagementAuthority: bundle.plan.Authorities.Management,
		TargetClusterUID:            binding.TargetClusterUID, Namespace: bundle.plan.ContractIdentity.Namespace,
		Name: bundle.plan.ContractIdentity.Name, HCPName: bundle.plan.ContractIdentity.Name + "-cilium", Clock: config.Clock,
	})
	if err != nil {
		return OpenedNetworkObservationStage{}, errors.New("open bounded network observation source")
	}
	if sameSecret(ledgerToken, managementToken) || sameSecret(ledgerToken, workloadToken) {
		return OpenedNetworkObservationStage{}, errors.New("ledger and network observation credentials must be distinct")
	}
	observer, err := NewNetworkStageObserver(NetworkStageObserverConfig{
		Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: binding.TargetClusterUID,
		Source: source, Profile: loadedProfile.Profile,
		PollInterval: config.PollInterval, PollTimeout: config.PollTimeout, Clock: config.Clock, Wait: config.Wait,
		AllowMVPWarmupDeferral: true, MVPWarmupDeferralDelay: mvpNetworkWarmupDeferralDelay(config.PollInterval, config.PollTimeout),
	})
	if err != nil {
		return OpenedNetworkObservationStage{}, err
	}
	return OpenedNetworkObservationStage{
		operation: execution.ObservationStageOperation{Ledger: store, Observer: observer},
		plan:      bundle.plan, cursor: bundle.cursor, verified: true,
	}, nil
}

func mvpNetworkWarmupDeferralDelay(interval, timeout time.Duration) time.Duration {
	// The deferred evidence is intentionally emitted after one full polling
	// interval. The bounded observation has already established the CAPI,
	// CAAPH, Node and Cilium-rollout predicates before it can classify only the
	// functional probe cache as stale. Waiting another five minutes adds no
	// safety signal for the MVP continuation and repeatedly expires launches.
	if interval <= 0 || timeout < interval {
		return 0
	}
	return interval
}

func (stage OpenedNetworkObservationStage) Run(ctx context.Context) (execution.ObservationStageRunReceipt, error) {
	if !stage.verified {
		return execution.ObservationStageRunReceipt{}, errors.New("network observation stage is not opened")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor)
}

// Retry performs one explicitly bound read-only retry after an immutable
// FAILED network observation receipt.
func (stage OpenedNetworkObservationStage) Retry(ctx context.Context, failedReceiptDigest string) (execution.ObservationStageRunReceipt, error) {
	if !stage.verified {
		return execution.ObservationStageRunReceipt{}, errors.New("network observation stage is not opened")
	}
	return stage.operation.Retry(ctx, stage.plan, stage.cursor, failedReceiptDigest)
}

func sameSecret(first, second string) bool {
	return len(first) == len(second) && subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}
