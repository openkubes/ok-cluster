package runner

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

type StageReceiptSource struct {
	Path   string
	Digest string
}

// SubmissionStageBundleConfig contains only independently supplied artifact
// paths, digests and expected identities. An explicit empty receipt slice is
// required for the first stage.
type SubmissionStageBundleConfig struct {
	ExpectedStageID          string
	PlanPath                 string
	PlanExpected             stageplan.Expected
	Receipts                 []StageReceiptSource
	GrantPath                string
	GrantPublicKeyPath       string
	ProjectionManifestPath   string
	ProjectionRoot           string
	ProviderAccessPolicyPath string
	EvaluationTime           time.Time
}

// VerifiedSubmissionStageBundle retains only values produced by verification.
// Its internals are consumed by the shared local/Job runtime below.
type VerifiedSubmissionStageBundle struct {
	plan              stageplan.Binding
	cursor            stagecursor.Cursor
	grant             authorization.VerifiedStageGrant
	projectionBinding projection.Binding
	projection        submission.Plan
	providerAccess    submission.VerifiedProviderAccessPolicy
	hasProviderAccess bool
	stageID           string
	verified          bool
}

type SubmissionStageRuntimeConfig struct {
	Ledger                       KubernetesLedgerConfig
	Authority                    KubernetesAuthorityConfig
	ProviderAccessKubeconfigFile string
	Clock                        func() time.Time
}

type BoundSubmissionStage struct {
	operation execution.StagedOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	grant     authorization.VerifiedStageGrant
	verified  bool
}

// LoadSubmissionStageBundle verifies the full preclaim artifact chain for one
// of the two typed Contract-to-CAPI submission stages. It performs no mutation,
// credential read, ledger access or Kubernetes request.
func LoadSubmissionStageBundle(config SubmissionStageBundleConfig) (VerifiedSubmissionStageBundle, error) {
	if config.Receipts == nil {
		return VerifiedSubmissionStageBundle{}, errors.New("stage receipt prefix must be explicit")
	}
	if config.EvaluationTime.IsZero() {
		return VerifiedSubmissionStageBundle{}, errors.New("stage authorization evaluation time is required")
	}
	plan, err := stageplan.Load(config.PlanPath, config.PlanExpected)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	prefix := make([]stagereceipt.Verified, 0, len(config.Receipts))
	predecessors := []stagereceipt.Verified{}
	for _, source := range config.Receipts {
		verified, err := stagereceipt.Load(source.Path, source.Digest, plan, predecessors)
		if err != nil {
			return VerifiedSubmissionStageBundle{}, err
		}
		prefix = append(prefix, verified)
		predecessors = []stagereceipt.Verified{verified}
	}
	cursor, err := stagecursor.Evaluate(plan, prefix)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	if decision.State != "NEXT" || !decision.RequiresAuthorization {
		return VerifiedSubmissionStageBundle{}, errors.New("artifact bundle does not select a mutating next stage")
	}
	if config.ExpectedStageID != "provider-prerequisites" && config.ExpectedStageID != "cluster-lifecycle" {
		return VerifiedSubmissionStageBundle{}, errors.New("expected Contract-to-CAPI stage is required")
	}
	if decision.StageID != config.ExpectedStageID {
		return VerifiedSubmissionStageBundle{}, errors.New("stage cursor differs from the independently expected stage")
	}
	artifactName, inputName, err := submissionStageArtifact(decision.StageID)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	root := config.ProjectionRoot
	if root == "" && config.ProjectionManifestPath != "" {
		root = filepath.Dir(config.ProjectionManifestPath)
	}
	projectionBinding, err := projection.Verify(config.ProjectionManifestPath, root, plan.IntentRevision, plan.ContractIdentity)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	artifactDigest, err := verifiedProjectionArtifact(projectionBinding, artifactName)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	if err := plan.RequireInput(decision.StageID, inputName, artifactDigest); err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	projected, err := submission.Load(root, projectionBinding)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	providerAccess, hasProviderAccess, err := loadSubmissionProviderAccessPolicy(config, plan, decision.StageID)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	directPredecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	grant, err := authorization.LoadStage(config.GrantPath, config.GrantPublicKeyPath, plan, decision.StageID, directPredecessors, config.EvaluationTime)
	if err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	if _, err := authorization.BindStageGrant(grant, plan, decision.StageID, directPredecessors); err != nil {
		return VerifiedSubmissionStageBundle{}, err
	}
	return VerifiedSubmissionStageBundle{
		plan:              plan,
		cursor:            cursor,
		grant:             grant,
		projectionBinding: projectionBinding,
		projection:        projected,
		providerAccess:    providerAccess,
		hasProviderAccess: hasProviderAccess,
		stageID:           decision.StageID,
		verified:          true,
	}, nil
}

func (bundle VerifiedSubmissionStageBundle) Decision() (stagecursor.Decision, error) {
	if !bundle.verified {
		return stagecursor.Decision{}, errors.New("submission stage bundle was not produced by verification")
	}
	return bundle.cursor.Decision()
}

// Open binds the verified artifact bundle to runtime credentials without
// invoking it. Local and Job callers receive the same BoundSubmissionStage.
func (bundle VerifiedSubmissionStageBundle) Open(config SubmissionStageRuntimeConfig) (BoundSubmissionStage, error) {
	if !bundle.verified {
		return BoundSubmissionStage{}, errors.New("submission stage bundle was not produced by verification")
	}
	projectionPlan, err := bindSubmissionProviderAccess(bundle, config.ProviderAccessKubeconfigFile)
	if err != nil {
		return BoundSubmissionStage{}, err
	}
	operation, err := OpenKubernetesSubmissionStageOperation(KubernetesSubmissionStageOperationConfig{
		Ledger: config.Ledger, Authority: config.Authority, Plan: bundle.plan,
		StageID: bundle.stageID, Projection: projectionPlan, Clock: config.Clock,
	})
	if err != nil {
		return BoundSubmissionStage{}, err
	}
	return BoundSubmissionStage{operation: operation, plan: bundle.plan, cursor: bundle.cursor, grant: bundle.grant, verified: true}, nil
}

func bindSubmissionProviderAccess(bundle VerifiedSubmissionStageBundle, kubeconfigFile string) (submission.Plan, error) {
	projectionPlan := bundle.projection
	if !bundle.hasProviderAccess {
		if kubeconfigFile != "" {
			return submission.Plan{}, errors.New("provider-access credential is not bound by the selected stage")
		}
		return projectionPlan, nil
	}
	if bundle.stageID != "cluster-lifecycle" || kubeconfigFile == "" {
		return submission.Plan{}, errors.New("cluster-lifecycle provider-access runtime is incomplete")
	}
	object, err := bundle.providerAccess.MaterializeSecret(kubeconfigFile)
	if err != nil {
		return submission.Plan{}, err
	}
	projectionPlan.Management.Objects = append([]submission.Object{object}, projectionPlan.Management.Objects...)
	return projectionPlan, nil
}

func loadSubmissionProviderAccessPolicy(config SubmissionStageBundleConfig, plan stageplan.Binding, stageID string) (submission.VerifiedProviderAccessPolicy, bool, error) {
	stage, _, err := plan.Stage(stageID)
	if err != nil {
		return submission.VerifiedProviderAccessPolicy{}, false, err
	}
	providerDigest := ""
	for _, input := range stage.Inputs {
		if input.Name == "stage.provider-access" {
			providerDigest = input.Digest
			break
		}
	}
	if providerDigest == "" {
		if config.ProviderAccessPolicyPath != "" {
			return submission.VerifiedProviderAccessPolicy{}, false, errors.New("provider-access policy is not bound by the selected stage")
		}
		return submission.VerifiedProviderAccessPolicy{}, false, nil
	}
	if stageID != "cluster-lifecycle" || config.ProviderAccessPolicyPath == "" {
		return submission.VerifiedProviderAccessPolicy{}, false, errors.New("cluster-lifecycle provider-access policy is incomplete")
	}
	policy, err := submission.LoadProviderAccessPolicy(config.ProviderAccessPolicyPath, submission.ProviderAccessExpected{
		PolicyDigest: providerDigest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, ExecutionFixture: plan.ExecutionFixture,
		ManagementAuthority: plan.Authorities.Management, ProviderAuthority: plan.Authorities.Infrastructure,
	})
	if err != nil {
		return submission.VerifiedProviderAccessPolicy{}, false, err
	}
	return policy, true, nil
}

func (stage BoundSubmissionStage) Run(ctx context.Context) (execution.StagedOperationReceipt, error) {
	if !stage.verified {
		return execution.StagedOperationReceipt{}, errors.New("submission stage runtime was not produced by verification")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor, stage.grant)
}

func submissionStageArtifact(stageID string) (string, string, error) {
	switch stageID {
	case "provider-prerequisites":
		return "ok-infra-prerequisites.yaml", "projection.provider-prerequisites", nil
	case "cluster-lifecycle":
		return "ok-mgmt-lifecycle.yaml", "projection.cluster-lifecycle", nil
	default:
		return "", "", errors.New("next stage has no Contract-to-CAPI artifact binding")
	}
}

func verifiedProjectionArtifact(binding projection.Binding, name string) (string, error) {
	for _, artifact := range binding.Artifacts {
		if artifact.Name == name {
			return artifact.Digest, nil
		}
	}
	return "", errors.New("verified projection does not contain the selected stage artifact")
}
