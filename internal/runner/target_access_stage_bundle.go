package runner

import (
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const TargetAccessStageBundleReceiptFormat = "ok147-target-access-stage-bundle/v1"

// TargetAccessStageBundleConfig binds the complete successful prefix, one
// CreateTargetAccess grant and one externally rendered eight-object artifact.
// Loading remains entirely offline.
type TargetAccessStageBundleConfig struct {
	PlanPath           string
	PlanExpected       stageplan.Expected
	Receipts           []StageReceiptSource
	GrantPath          string
	GrantPublicKeyPath string
	EvaluationTime     time.Time
	ArtifactPath       string
	ExpectedObjects    []projection.ResourceIdentity
}

type TargetAccessStageBundleReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	PlanDigest           string   `json:"planDigest"`
	StageID              string   `json:"stageId"`
	AuthorizationDigest  string   `json:"authorizationDigest"`
	ArtifactDigest       string   `json:"artifactDigest"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	ObjectDigests        []string `json:"objectDigests"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

type VerifiedTargetAccessStageBundle struct {
	plan       stageplan.Binding
	cursor     stagecursor.Cursor
	prefix     []stagereceipt.Verified
	grant      authorization.VerifiedStageGrant
	projection submission.TargetAccessPlan
	receipt    TargetAccessStageBundleReceipt
	verified   bool
}

// LoadTargetAccessStageBundle verifies every immutable input needed before a
// later claim/open boundary. It reads no credential and contacts no API.
func LoadTargetAccessStageBundle(config TargetAccessStageBundleConfig) (VerifiedTargetAccessStageBundle, error) {
	if config.Receipts == nil || config.EvaluationTime.IsZero() {
		return VerifiedTargetAccessStageBundle{}, errors.New("target-access receipt prefix and authorization evaluation time are required")
	}
	plan, cursor, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: config.Receipts,
	})
	if err != nil {
		return VerifiedTargetAccessStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-access" || decision.Authority != "workload" || !decision.RequiresAuthorization || decision.Operation != "CreateTargetAccess" {
		return VerifiedTargetAccessStageBundle{}, errors.New("verified prefix does not select target access")
	}
	if len(prefix) != 6 {
		return VerifiedTargetAccessStageBundle{}, errors.New("target access requires the exact six-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedTargetAccessStageBundle{}, errors.New("target access lacks durable workload identity")
	}
	runtimeBinding, err := prefix[5].Receipt()
	if err != nil || runtimeBinding.StageID != "runtime-binding" || runtimeBinding.State != "SUCCEEDED" {
		return VerifiedTargetAccessStageBundle{}, errors.New("target access lacks successful runtime binding")
	}
	stage, _, err := plan.Stage("target-access")
	if err != nil {
		return VerifiedTargetAccessStageBundle{}, err
	}
	if len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.target-access" {
		return VerifiedTargetAccessStageBundle{}, errors.New("target-access stage must bind exactly one renderer artifact")
	}
	projected, err := submission.LoadTargetAccess(config.ArtifactPath, submission.TargetAccessExpected{
		ArtifactDigest: stage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: lifecycle.TargetClusterUIDDigest, WorkloadAuthority: lifecycle.TargetClusterUIDDigest,
		Objects: config.ExpectedObjects,
	})
	if err != nil {
		return VerifiedTargetAccessStageBundle{}, err
	}
	directPredecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedTargetAccessStageBundle{}, err
	}
	grant, err := authorization.LoadStage(config.GrantPath, config.GrantPublicKeyPath, plan, "target-access", directPredecessors, config.EvaluationTime)
	if err != nil {
		return VerifiedTargetAccessStageBundle{}, err
	}
	if _, err := authorization.BindStageGrant(grant, plan, "target-access", directPredecessors); err != nil {
		return VerifiedTargetAccessStageBundle{}, err
	}
	objectDigests := make([]string, len(projected.Workload.Objects))
	for index := range projected.Workload.Objects {
		objectDigests[index] = projected.Workload.Objects[index].Digest
	}
	receipt := TargetAccessStageBundleReceipt{
		Format: TargetAccessStageBundleReceiptFormat, State: "VERIFIED", PlanDigest: plan.PlanDigest, StageID: "target-access",
		AuthorizationDigest: grant.Receipt().AuthorizationDigest, ArtifactDigest: projected.ArtifactDigest,
		TargetIdentityDigest: lifecycle.TargetClusterUIDDigest, ObjectDigests: objectDigests, MutationAllowed: false,
	}
	return VerifiedTargetAccessStageBundle{
		plan: plan, cursor: cursor, prefix: prefix, grant: grant, projection: projected, receipt: receipt, verified: true,
	}, nil
}

func (bundle VerifiedTargetAccessStageBundle) Decision() (stagecursor.Decision, error) {
	if !bundle.verified {
		return stagecursor.Decision{}, errors.New("target-access stage bundle was not produced by verification")
	}
	return bundle.cursor.Decision()
}

func (bundle VerifiedTargetAccessStageBundle) Receipt() (TargetAccessStageBundleReceipt, error) {
	if !bundle.verified || bundle.receipt.Format != TargetAccessStageBundleReceiptFormat || bundle.receipt.State != "VERIFIED" || bundle.receipt.StageID != "target-access" || bundle.receipt.MutationAllowed || len(bundle.receipt.ObjectDigests) != 8 {
		return TargetAccessStageBundleReceipt{}, errors.New("target-access stage bundle was not produced by verification")
	}
	receipt := bundle.receipt
	receipt.ObjectDigests = append([]string(nil), bundle.receipt.ObjectDigests...)
	return receipt, nil
}
