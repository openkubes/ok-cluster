package runner

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const TargetRegistrationStageBundleReceiptFormat = "ok147-target-registration-stage-bundle/v1"

type TargetRegistrationStageBundleConfig struct {
	PlanPath           string
	PlanExpected       stageplan.Expected
	Receipts           []StageReceiptSource
	GrantPath          string
	GrantPublicKeyPath string
	EvaluationTime     time.Time
	ArtifactPath       string
	Expected           submission.TargetRegistrationExpected
}

type TargetRegistrationStageHandoffConfig struct {
	Handoff            *VerifiedTargetCredentialStageHandoff
	GrantPath          string
	GrantPublicKeyPath string
	EvaluationTime     time.Time
	ArtifactPath       string
	Expected           submission.TargetRegistrationExpected
}

type TargetRegistrationStageBundleReceipt struct {
	Format                     string `json:"format"`
	State                      string `json:"state"`
	PlanDigest                 string `json:"planDigest"`
	StageID                    string `json:"stageId"`
	AuthorizationDigest        string `json:"authorizationDigest"`
	ArtifactDigest             string `json:"artifactDigest"`
	TargetIdentityDigest       string `json:"targetIdentityDigest"`
	ProjectDigest              string `json:"projectDigest"`
	RegistrationTemplateDigest string `json:"registrationTemplateDigest"`
	Authority                  string `json:"authority"`
	CredentialMaterialPresent  bool   `json:"credentialMaterialPresent"`
	MutationAllowed            bool   `json:"mutationAllowed"`
}

type VerifiedTargetRegistrationStageBundle struct {
	plan       stageplan.Binding
	cursor     stagecursor.Cursor
	prefix     []stagereceipt.Verified
	grant      authorization.VerifiedStageGrant
	projection submission.TargetRegistrationPlan
	receipt    TargetRegistrationStageBundleReceipt
	handoff    *VerifiedTargetCredentialStageHandoff
	verified   bool
}

type TargetRegistrationStageRuntimeConfig struct {
	Ledger              KubernetesLedgerConfig
	GitOps              KubernetesAuthorityConfig
	Runtime             VerifiedRuntimeBindingMaterial
	Credential          VerifiedTargetCredentialMaterial
	MaterializationTime time.Time
	Clock               func() time.Time
}

type TargetRegistrationStageHandoffRuntimeConfig struct {
	Ledger              KubernetesLedgerConfig
	GitOps              KubernetesAuthorityConfig
	Runtime             VerifiedRuntimeBindingMaterial
	MaterializationTime time.Time
	Clock               func() time.Time
}

type BoundTargetRegistrationStage struct {
	operation execution.StagedOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	grant     authorization.VerifiedStageGrant
	verified  bool
}

// LoadTargetRegistrationStageBundle verifies the eight-stage predecessor
// chain, exact GitOps projection and RegisterTarget grant without opening the
// in-memory target credential or contacting either Kubernetes API.
func LoadTargetRegistrationStageBundle(config TargetRegistrationStageBundleConfig) (VerifiedTargetRegistrationStageBundle, error) {
	if config.Receipts == nil || config.EvaluationTime.IsZero() {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target-registration receipt prefix and authorization evaluation time are required")
	}
	plan, cursor, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: config.Receipts,
	})
	if err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	return loadTargetRegistrationStageBundle(plan, cursor, prefix, targetRegistrationStageLoadConfig{
		GrantPath: config.GrantPath, GrantPublicKeyPath: config.GrantPublicKeyPath, EvaluationTime: config.EvaluationTime,
		ArtifactPath: config.ArtifactPath, Expected: config.Expected,
	})
}

// LoadTargetRegistrationStageBundleFromHandoff consumes no credential. It
// verifies a newly available Stage-9 grant against the exact durable Stage-8
// receipt retained by the same process.
func LoadTargetRegistrationStageBundleFromHandoff(config TargetRegistrationStageHandoffConfig) (VerifiedTargetRegistrationStageBundle, error) {
	if config.Handoff == nil || config.EvaluationTime.IsZero() {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target-registration handoff and authorization evaluation time are required")
	}
	plan, cursor, prefix, err := config.Handoff.registrationContext()
	if err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	bundle, err := loadTargetRegistrationStageBundle(plan, cursor, prefix, targetRegistrationStageLoadConfig{
		GrantPath: config.GrantPath, GrantPublicKeyPath: config.GrantPublicKeyPath, EvaluationTime: config.EvaluationTime,
		ArtifactPath: config.ArtifactPath, Expected: config.Expected,
	})
	if err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	bundle.handoff = config.Handoff
	return bundle, nil
}

type targetRegistrationStageLoadConfig struct {
	GrantPath          string
	GrantPublicKeyPath string
	EvaluationTime     time.Time
	ArtifactPath       string
	Expected           submission.TargetRegistrationExpected
}

func loadTargetRegistrationStageBundle(plan stageplan.Binding, cursor stagecursor.Cursor, prefix []stagereceipt.Verified, config targetRegistrationStageLoadConfig) (VerifiedTargetRegistrationStageBundle, error) {
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-registration" || decision.Kind != "Submission" || decision.Authority != "gitops" || !decision.RequiresAuthorization || decision.Operation != "RegisterTarget" {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("verified prefix does not select target registration")
	}
	if len(prefix) != 8 {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target registration requires the exact eight-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target registration lacks durable workload identity")
	}
	credential, err := prefix[7].Receipt()
	if err != nil || credential.StageID != "target-credential" || credential.State != "SUCCEEDED" || credential.MutationState != "ATTEMPTED" {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target registration lacks successful credential issuance")
	}
	stage, _, err := plan.Stage("target-registration")
	if err != nil || len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.target-registration" {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target-registration stage must bind exactly one projection artifact")
	}
	expected := config.Expected
	if expected.ArtifactDigest != stage.Inputs[0].Digest || expected.ContractIdentity != plan.ContractIdentity || expected.IntentRevision != plan.IntentRevision || expected.PlatformRevision != plan.PlatformRevision || expected.ExecutionFixture != plan.ExecutionFixture || expected.TargetIdentityDigest != lifecycle.TargetClusterUIDDigest || expected.ArgoAuthority != plan.Authorities.GitOps {
		return VerifiedTargetRegistrationStageBundle{}, errors.New("target-registration expected identities differ from verified stage plan")
	}
	projected, err := submission.LoadTargetRegistration(config.ArtifactPath, expected)
	if err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	directPredecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	grant, err := authorization.LoadStage(config.GrantPath, config.GrantPublicKeyPath, plan, "target-registration", directPredecessors, config.EvaluationTime)
	if err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	if _, err := authorization.BindStageGrant(grant, plan, "target-registration", directPredecessors); err != nil {
		return VerifiedTargetRegistrationStageBundle{}, err
	}
	receipt := TargetRegistrationStageBundleReceipt{
		Format: TargetRegistrationStageBundleReceiptFormat, State: "VERIFIED", PlanDigest: plan.PlanDigest,
		StageID: "target-registration", AuthorizationDigest: grant.Receipt().AuthorizationDigest,
		ArtifactDigest: projected.ArtifactDigest, TargetIdentityDigest: projected.TargetIdentityDigest,
		ProjectDigest: projected.Project.Digest, RegistrationTemplateDigest: projected.Registration.Digest,
		Authority: projected.Authority, CredentialMaterialPresent: false, MutationAllowed: false,
	}
	return VerifiedTargetRegistrationStageBundle{
		plan: plan, cursor: cursor, prefix: prefix, grant: grant, projection: projected, receipt: receipt, verified: true,
	}, nil
}

func (bundle VerifiedTargetRegistrationStageBundle) Decision() (stagecursor.Decision, error) {
	if err := verifyTargetRegistrationStageBundle(bundle); err != nil {
		return stagecursor.Decision{}, err
	}
	return bundle.cursor.Decision()
}

func (bundle VerifiedTargetRegistrationStageBundle) Receipt() (TargetRegistrationStageBundleReceipt, error) {
	if err := verifyTargetRegistrationStageBundle(bundle); err != nil {
		return TargetRegistrationStageBundleReceipt{}, err
	}
	return bundle.receipt, nil
}

// Open binds the verified offline bundle to its private runtime, target
// credential, GitOps writer and durable ledger. It reads bounded credential
// files but performs no API request and no mutation.
func (bundle VerifiedTargetRegistrationStageBundle) Open(config TargetRegistrationStageRuntimeConfig) (BoundTargetRegistrationStage, error) {
	if err := verifyTargetRegistrationStageBundle(bundle); err != nil || config.Clock == nil {
		return BoundTargetRegistrationStage{}, errors.New("verified target-registration bundle and clock are required")
	}
	material, err := BuildTargetRegistrationMaterial(TargetRegistrationMaterializeConfig{
		Bundle: bundle, Runtime: config.Runtime, Credential: config.Credential, MaterializationTime: config.MaterializationTime,
	})
	if err != nil {
		return BoundTargetRegistrationStage{}, err
	}
	launcher, err := OpenKubernetesTargetRegistrationLauncher(TargetRegistrationLauncherConfig{Authority: config.GitOps, Clock: config.Clock}, material)
	if err != nil {
		return BoundTargetRegistrationStage{}, err
	}
	ledgerStore, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return BoundTargetRegistrationStage{}, errors.New("open target-registration stage ledger")
	}
	if len(ledgerToken) == len(launcher.token) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(launcher.token)) == 1 {
		return BoundTargetRegistrationStage{}, errors.New("ledger and target-registration writer credentials must be distinct")
	}
	mutator, err := NewTargetRegistrationStageMutator(bundle.plan, material, launcher)
	if err != nil {
		return BoundTargetRegistrationStage{}, err
	}
	return BoundTargetRegistrationStage{
		operation: execution.StagedOperation{Ledger: ledgerStore, Mutator: mutator, Clock: config.Clock},
		plan:      bundle.plan, cursor: bundle.cursor, grant: bundle.grant, verified: true,
	}, nil
}

// OpenHandoff consumes the memory-only credential exactly once and binds it to
// the already verified Stage-9 projection, writer and durable ledger.
func (bundle VerifiedTargetRegistrationStageBundle) OpenHandoff(config TargetRegistrationStageHandoffRuntimeConfig) (BoundTargetRegistrationStage, error) {
	if err := verifyTargetRegistrationStageBundle(bundle); err != nil || bundle.handoff == nil || config.Clock == nil || config.MaterializationTime.IsZero() {
		return BoundTargetRegistrationStage{}, errors.New("target-registration bundle was not loaded from an in-process handoff")
	}
	credential, err := bundle.handoff.takeCredential()
	if err != nil {
		return BoundTargetRegistrationStage{}, err
	}
	return bundle.Open(TargetRegistrationStageRuntimeConfig{
		Ledger: config.Ledger, GitOps: config.GitOps, Runtime: config.Runtime, Credential: credential,
		MaterializationTime: config.MaterializationTime, Clock: config.Clock,
	})
}

func (stage BoundTargetRegistrationStage) Run(ctx context.Context) (execution.StagedOperationReceipt, error) {
	if !stage.verified {
		return execution.StagedOperationReceipt{}, errors.New("target-registration stage runtime was not produced by verification")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor, stage.grant)
}

func verifyTargetRegistrationStageBundle(bundle VerifiedTargetRegistrationStageBundle) error {
	if !bundle.verified || bundle.receipt.Format != TargetRegistrationStageBundleReceiptFormat || bundle.receipt.State != "VERIFIED" || bundle.receipt.StageID != "target-registration" || bundle.receipt.CredentialMaterialPresent || bundle.receipt.MutationAllowed || len(bundle.prefix) != 8 {
		return errors.New("target-registration stage bundle was not produced by verification")
	}
	for _, value := range []string{
		bundle.receipt.PlanDigest, bundle.receipt.AuthorizationDigest, bundle.receipt.ArtifactDigest,
		bundle.receipt.TargetIdentityDigest, bundle.receipt.ProjectDigest, bundle.receipt.RegistrationTemplateDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("target-registration stage bundle digest identity is invalid")
		}
	}
	if bundle.receipt.Authority == "" || bundle.projection.Authority != bundle.receipt.Authority || bundle.projection.TargetIdentityDigest != bundle.receipt.TargetIdentityDigest {
		return errors.New("target-registration stage bundle identity changed after verification")
	}
	if bundle.projection.Format != submission.TargetRegistrationPlanFormat || bundle.projection.MutationAllowed ||
		bundle.projection.ArtifactDigest != bundle.receipt.ArtifactDigest ||
		bundle.projection.IntentRevision != bundle.plan.IntentRevision ||
		bundle.projection.PlatformRevision != bundle.plan.PlatformRevision ||
		bundle.projection.ExecutionFixture != bundle.plan.ExecutionFixture ||
		bundle.projection.Project.Digest != bundle.receipt.ProjectDigest ||
		bundle.projection.Registration.Digest != bundle.receipt.RegistrationTemplateDigest ||
		digest.SHA256(bundle.projection.Project.Raw) != bundle.receipt.ProjectDigest ||
		digest.SHA256(bundle.projection.Registration.Raw) != bundle.receipt.RegistrationTemplateDigest {
		return errors.New("target-registration projection changed after verification")
	}
	return nil
}
