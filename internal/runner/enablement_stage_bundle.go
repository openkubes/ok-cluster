package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// EnablementStageBundleConfig binds the complete verified prefix, signed grant
// and externally rendered HCP artifact. Loading is non-mutating.
type EnablementStageBundleConfig struct {
	PlanPath           string
	PlanExpected       stageplan.Expected
	Receipts           []StageReceiptSource
	GrantPath          string
	GrantPublicKeyPath string
	EvaluationTime     time.Time
	ArtifactPath       string
	ExpectedObject     projection.ResourceIdentity
}

type VerifiedEnablementStageBundle struct {
	plan       stageplan.Binding
	cursor     stagecursor.Cursor
	grant      authorization.VerifiedStageGrant
	projection submission.EnablementPlan
	verified   bool
}

type BoundEnablementStage struct {
	operation execution.StagedOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	grant     authorization.VerifiedStageGrant
	verified  bool
}

// LoadEnablementStageBundle verifies the fourth-stage preclaim chain without
// reading a credential, opening the ledger or contacting Kubernetes.
func LoadEnablementStageBundle(config EnablementStageBundleConfig) (VerifiedEnablementStageBundle, error) {
	if config.Receipts == nil {
		return VerifiedEnablementStageBundle{}, errors.New("enablement receipt prefix must be explicit")
	}
	if config.EvaluationTime.IsZero() {
		return VerifiedEnablementStageBundle{}, errors.New("enablement authorization evaluation time is required")
	}
	plan, err := stageplan.Load(config.PlanPath, config.PlanExpected)
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	prefix := make([]stagereceipt.Verified, 0, len(config.Receipts))
	predecessors := []stagereceipt.Verified{}
	for _, source := range config.Receipts {
		verified, err := stagereceipt.Load(source.Path, source.Digest, plan, predecessors)
		if err != nil {
			return VerifiedEnablementStageBundle{}, err
		}
		prefix = append(prefix, verified)
		predecessors = []stagereceipt.Verified{verified}
	}
	cursor, err := stagecursor.Evaluate(plan, prefix)
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	if decision.State != "NEXT" || decision.StageID != "enablement" || !decision.RequiresAuthorization || decision.Operation != "CreateEnablement" {
		return VerifiedEnablementStageBundle{}, errors.New("artifact bundle does not select the enablement stage")
	}
	stage, _, err := plan.Stage("enablement")
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	if len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.enablement" {
		return VerifiedEnablementStageBundle{}, errors.New("enablement stage must bind exactly one renderer artifact")
	}
	projected, err := submission.LoadEnablement(config.ArtifactPath, submission.EnablementExpected{
		ArtifactDigest: stage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		ExecutionFixture: plan.ExecutionFixture, ManagementAuthority: plan.Authorities.Management,
		ObjectIdentity: config.ExpectedObject,
	})
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	directPredecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	grant, err := authorization.LoadStage(config.GrantPath, config.GrantPublicKeyPath, plan, "enablement", directPredecessors, config.EvaluationTime)
	if err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	if _, err := authorization.BindStageGrant(grant, plan, "enablement", directPredecessors); err != nil {
		return VerifiedEnablementStageBundle{}, err
	}
	return VerifiedEnablementStageBundle{plan: plan, cursor: cursor, grant: grant, projection: projected, verified: true}, nil
}

func (bundle VerifiedEnablementStageBundle) Decision() (stagecursor.Decision, error) {
	if !bundle.verified {
		return stagecursor.Decision{}, errors.New("enablement stage bundle was not produced by verification")
	}
	return bundle.cursor.Decision()
}

// Open binds verified artifacts to bounded credentials but performs no API
// request. The returned operation owns the single-use durable claim.
func (bundle VerifiedEnablementStageBundle) Open(config SubmissionStageRuntimeConfig) (BoundEnablementStage, error) {
	if !bundle.verified {
		return BoundEnablementStage{}, errors.New("enablement stage bundle was not produced by verification")
	}
	operation, err := OpenKubernetesEnablementStageOperation(KubernetesEnablementStageOperationConfig{
		Ledger: config.Ledger, Authority: config.Authority, Plan: bundle.plan, Projection: bundle.projection, Clock: config.Clock,
	})
	if err != nil {
		return BoundEnablementStage{}, err
	}
	return BoundEnablementStage{operation: operation, plan: bundle.plan, cursor: bundle.cursor, grant: bundle.grant, verified: true}, nil
}

func (stage BoundEnablementStage) Run(ctx context.Context) (execution.StagedOperationReceipt, error) {
	if !stage.verified {
		return execution.StagedOperationReceipt{}, errors.New("enablement stage runtime was not produced by verification")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor, stage.grant)
}
