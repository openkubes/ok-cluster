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

type AggregateEvidenceStageEvaluatorConfig struct {
	Plan             stageplan.Binding
	ReceiptPrefix    []stagereceipt.Verified
	TargetClusterUID string
	Profile          AggregateEvidenceProfile
	Source           ObservationSource
}

// AggregateEvidenceStageEvaluator adapts the already bounded aggregate
// observer to the final Evaluation stage. It performs exactly one source pass;
// prior convergence stages already own polling.
type AggregateEvidenceStageEvaluator struct {
	binding execution.StageEvaluationBinding
	policy  observation.Policy
	source  ObservationSource
}

var _ execution.StageEvaluator = (*AggregateEvidenceStageEvaluator)(nil)

func NewAggregateEvidenceStageEvaluator(config AggregateEvidenceStageEvaluatorConfig) (*AggregateEvidenceStageEvaluator, error) {
	if config.Source == nil {
		return nil, errors.New("aggregate evidence source is required")
	}
	cursor, err := stagecursor.Evaluate(config.Plan, config.ReceiptPrefix)
	if err != nil {
		return nil, errors.New("verify aggregate evidence receipt prefix")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "aggregate-evidence" || decision.Kind != "Evaluation" || decision.Authority != "runner" || decision.RequiresAuthorization || decision.Operation != "" {
		return nil, errors.New("stage receipt prefix does not select aggregate evidence evaluation")
	}
	if len(config.ReceiptPrefix) != 11 {
		return nil, errors.New("aggregate evidence receipt prefix is incomplete")
	}
	lifecycle, err := config.ReceiptPrefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !platformInputDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) || digest.SHA256([]byte(config.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return nil, errors.New("aggregate evidence target differs from durable lifecycle correlation")
	}
	if err := validateAggregateEvidenceProfile(config.Profile); err != nil || config.Profile.IntentRevision != config.Plan.IntentRevision || config.Profile.EnablementRevision != config.Plan.EnablementRevision || config.Profile.PlatformRevision != config.Plan.PlatformRevision || config.Profile.ExecutionFixture != config.Plan.ExecutionFixture {
		return nil, errors.New("aggregate evidence profile differs from verified execution plan")
	}
	stage, stageDigest, err := config.Plan.Stage(decision.StageID)
	if err != nil || stageDigest != decision.StageDigest {
		return nil, errors.New("aggregate evidence stage differs from verified plan")
	}
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: config.Profile.IntentRevision,
		EnablementRevision: config.Profile.EnablementRevision, PlatformRevision: config.Profile.PlatformRevision,
		TargetClusterUID: config.TargetClusterUID, Required: append([]string(nil), config.Profile.Required...),
	}
	if _, err := observation.PolicyDigest(policy); err != nil {
		return nil, errors.New("runtime-bound aggregate evidence policy is invalid")
	}
	return &AggregateEvidenceStageEvaluator{
		binding: execution.StageEvaluationBinding{
			PlanDigest: config.Plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Authority: stage.Authority, ContractRevision: config.Plan.IntentRevision,
		},
		policy: policy, source: config.Source,
	}, nil
}

func (evaluator *AggregateEvidenceStageEvaluator) Binding() execution.StageEvaluationBinding {
	if evaluator == nil {
		return execution.StageEvaluationBinding{}
	}
	return evaluator.binding
}

func (evaluator *AggregateEvidenceStageEvaluator) Evaluate(ctx context.Context) (execution.StageEvaluationResult, error) {
	if evaluator == nil || evaluator.source == nil {
		return execution.StageEvaluationResult{}, errors.New("aggregate evidence evaluator is required")
	}
	result, err := evaluator.source.Observe(ctx, evaluator.policy)
	if err != nil {
		return execution.StageEvaluationResult{}, errors.New("bounded aggregate evidence collection failed")
	}
	receipt, err := result.Receipt()
	if err != nil {
		return execution.StageEvaluationResult{}, errors.New("aggregate evidence result is unverified")
	}
	policyDigest, err := observation.PolicyDigest(evaluator.policy)
	if err != nil || receipt.IntentRevision != evaluator.policy.IntentRevision || receipt.PolicyDigest != policyDigest || len(receipt.Conditions) != len(evaluator.policy.Required) {
		return execution.StageEvaluationResult{}, errors.New("aggregate evidence result differs from runtime policy")
	}
	evidenceDigest, err := result.EvidenceDigest()
	if err != nil {
		return execution.StageEvaluationResult{}, err
	}
	completedAt, err := time.Parse(time.RFC3339Nano, receipt.EvaluatedAt)
	if err != nil {
		return execution.StageEvaluationResult{}, errors.New("aggregate evidence completion time is invalid")
	}
	outcome := "STOPPED"
	if receipt.Ready == "True" {
		outcome = "SUCCEEDED"
	} else if receipt.Ready == "False" {
		outcome = "FAILED"
	} else if receipt.Ready != "Unknown" {
		return execution.StageEvaluationResult{}, errors.New("aggregate evidence readiness is invalid")
	}
	return execution.StageEvaluationResult{Outcome: outcome, EvidenceDigest: evidenceDigest, CompletedAt: completedAt}, nil
}
