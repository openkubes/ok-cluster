package runner

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

type AggregateEvidenceStageRuntimeConfig struct {
	Ledger   KubernetesLedgerConfig
	Observer KubernetesAggregateObserverConfig
	Runtime  VerifiedRuntimeBindingMaterial
}

type OpenedAggregateEvidenceStage struct {
	operation execution.EvaluationStageOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	verified  bool
}

// Open validates credentials and composes the final bounded source pass, but
// performs no Kubernetes request.
func (bundle VerifiedAggregateEvidenceStageBundle) Open(config AggregateEvidenceStageRuntimeConfig) (OpenedAggregateEvidenceStage, error) {
	if err := verifyAggregateEvidenceStageBundle(bundle); err != nil {
		return OpenedAggregateEvidenceStage{}, err
	}
	if err := verifyRuntimeBindingMaterial(config.Runtime); err != nil ||
		config.Runtime.receipt.PlanDigest != bundle.plan.PlanDigest || config.Runtime.material.PlanDigest != bundle.plan.PlanDigest ||
		config.Runtime.material.IntentRevision != bundle.plan.IntentRevision || config.Runtime.material.EnablementRevision != bundle.plan.EnablementRevision ||
		config.Runtime.material.PlatformRevision != bundle.plan.PlatformRevision || config.Runtime.material.ExecutionFixture != bundle.plan.ExecutionFixture ||
		config.Runtime.receipt.TargetClusterUIDDigest != digest.SHA256([]byte(config.Runtime.material.Target.CAPIClusterUID)) {
		return OpenedAggregateEvidenceStage{}, errors.New("aggregate evidence runtime differs from verified execution target")
	}
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil || lifecycle.TargetClusterUIDDigest != config.Runtime.receipt.TargetClusterUIDDigest {
		return OpenedAggregateEvidenceStage{}, errors.New("aggregate evidence runtime differs from durable lifecycle target")
	}
	if config.Observer.ExpectedManagementAuthority != bundle.plan.Authorities.Management || config.Observer.Management.AuthorityIdentity != bundle.plan.Authorities.Management ||
		config.Observer.ExpectedArgoAuthority != bundle.plan.Authorities.GitOps || config.Observer.Argo.AuthorityIdentity != bundle.plan.Authorities.GitOps ||
		config.Observer.Namespace != bundle.plan.ContractIdentity.Namespace || config.Observer.Name != bundle.plan.ContractIdentity.Name || config.Observer.HCPName != bundle.plan.ContractIdentity.Name+"-cilium" {
		return OpenedAggregateEvidenceStage{}, errors.New("aggregate evidence source authorities differ from verified plan")
	}
	networkDigest, networkErr := observation.NetworkProfileDigest(config.Observer.NetworkProfile)
	platformDigest, platformErr := observation.PlatformProfileDigest(config.Observer.PlatformProfile)
	if networkErr != nil || platformErr != nil || config.Observer.NetworkProfile.IntentRevision != bundle.plan.IntentRevision || config.Observer.NetworkProfile.EnablementRevision != bundle.plan.EnablementRevision || config.Observer.PlatformProfile.IntentRevision != bundle.plan.IntentRevision || config.Observer.PlatformProfile.PlatformRevision != bundle.plan.PlatformRevision || config.Observer.PlatformProfile.ExecutionFixture != bundle.plan.ExecutionFixture || networkDigest == "" || platformDigest == "" {
		return OpenedAggregateEvidenceStage{}, errors.New("aggregate evidence source profiles differ from verified plan")
	}
	networkStage, _, networkStageErr := bundle.plan.Stage("network-observation")
	platformStage, _, platformStageErr := bundle.plan.Stage("platform-observation")
	if networkStageErr != nil || platformStageErr != nil || len(networkStage.Inputs) != 1 || networkStage.Inputs[0].Digest != networkDigest || len(platformStage.Inputs) != 1 || platformStage.Inputs[0].Digest != platformDigest {
		return OpenedAggregateEvidenceStage{}, errors.New("aggregate evidence source profiles differ from bound observation stages")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return OpenedAggregateEvidenceStage{}, errors.New("open aggregate evidence ledger")
	}
	managementToken, _, err := openBoundedKubernetesHTTP(config.Observer.Management.TokenFile, config.Observer.Management.CAFile)
	if err != nil {
		return OpenedAggregateEvidenceStage{}, errors.New("open aggregate management observation credential")
	}
	argoToken, _, err := openBoundedKubernetesHTTP(config.Observer.Argo.TokenFile, config.Observer.Argo.CAFile)
	if err != nil {
		return OpenedAggregateEvidenceStage{}, errors.New("open aggregate platform observation credential")
	}
	if sameSecret(ledgerToken, managementToken) || sameSecret(ledgerToken, argoToken) || sameSecret(managementToken, argoToken) {
		return OpenedAggregateEvidenceStage{}, errors.New("aggregate evidence credentials must be pairwise distinct")
	}
	aggregate, err := OpenKubernetesAggregateObserver(config.Observer)
	if err != nil {
		return OpenedAggregateEvidenceStage{}, errors.New("open bounded Kubernetes aggregate observer")
	}
	evaluator, err := NewAggregateEvidenceStageEvaluator(AggregateEvidenceStageEvaluatorConfig{
		Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: config.Runtime.material.Target.CAPIClusterUID,
		Profile: bundle.profile, Source: aggregate,
	})
	if err != nil {
		return OpenedAggregateEvidenceStage{}, err
	}
	return OpenedAggregateEvidenceStage{
		operation: execution.EvaluationStageOperation{Ledger: store, Evaluator: evaluator},
		plan:      bundle.plan, cursor: bundle.cursor, verified: true,
	}, nil
}

func (stage OpenedAggregateEvidenceStage) Run(ctx context.Context) (execution.EvaluationStageRunReceipt, error) {
	if !stage.verified {
		return execution.EvaluationStageRunReceipt{}, errors.New("aggregate evidence stage is not opened")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor)
}
