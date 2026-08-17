package runner

import (
	"errors"
	"sort"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const PlatformApplicationsStageBundleReceiptFormat = "ok147-platform-applications-stage-bundle/v1"

type PlatformApplicationsStageBundleConfig struct {
	PlanPath           string
	PlanExpected       stageplan.Expected
	Receipts           []StageReceiptSource
	GrantPath          string
	GrantPublicKeyPath string
	EvaluationTime     time.Time
	ArtifactPath       string
	Expected           submission.PlatformApplicationsExpected
}

type PlatformApplicationsStageBundleReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	PlanDigest           string   `json:"planDigest"`
	StageID              string   `json:"stageId"`
	AuthorizationDigest  string   `json:"authorizationDigest"`
	ArtifactDigest       string   `json:"artifactDigest"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	ProfileDigest        string   `json:"profileDigest"`
	ApplicationDigests   []string `json:"applicationDigests"`
	Authority            string   `json:"authority"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

type VerifiedPlatformApplicationsStageBundle struct {
	plan       stageplan.Binding
	cursor     stagecursor.Cursor
	prefix     []stagereceipt.Verified
	grant      authorization.VerifiedStageGrant
	projection submission.PlatformApplicationsPlan
	profile    observation.PlatformProfile
	receipt    PlatformApplicationsStageBundleReceipt
	verified   bool
}

// LoadPlatformApplicationsStageBundle verifies the exact nine-stage
// predecessor chain, immutable Platform profile, three Application objects and
// CreatePlatformApplications grant. It performs no credential read, API
// request, ledger access or mutation.
func LoadPlatformApplicationsStageBundle(config PlatformApplicationsStageBundleConfig) (VerifiedPlatformApplicationsStageBundle, error) {
	if config.Receipts == nil || config.EvaluationTime.IsZero() {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform-applications receipt prefix and authorization evaluation time are required")
	}
	plan, cursor, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: config.Receipts,
	})
	if err != nil {
		return VerifiedPlatformApplicationsStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "platform-applications" || decision.Kind != "Submission" || decision.Authority != "gitops" || !decision.RequiresAuthorization || decision.Operation != "CreatePlatformApplications" {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("verified prefix does not select platform Applications")
	}
	if len(prefix) != 9 {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform Applications require the exact nine-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform Applications lack durable workload identity")
	}
	registration, err := prefix[8].Receipt()
	if err != nil || registration.StageID != "target-registration" || registration.State != "SUCCEEDED" || registration.MutationState != "ATTEMPTED" {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform Applications lack successful target registration")
	}
	stage, _, err := plan.Stage("platform-applications")
	if err != nil || len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.platform-applications" {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform-applications stage must bind exactly one projection artifact")
	}
	expected := config.Expected
	if expected.ArtifactDigest != stage.Inputs[0].Digest || expected.ContractIdentity != plan.ContractIdentity || expected.IntentRevision != plan.IntentRevision || expected.PlatformRevision != plan.PlatformRevision || expected.ExecutionFixture != plan.ExecutionFixture || expected.TargetIdentityDigest != lifecycle.TargetClusterUIDDigest || expected.ArgoAuthority != plan.Authorities.GitOps {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform-applications expected identities differ from verified stage plan")
	}
	projected, err := submission.LoadPlatformApplications(config.ArtifactPath, expected)
	if err != nil {
		return VerifiedPlatformApplicationsStageBundle{}, err
	}
	profile := expected.Profile
	profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), expected.Profile.RequiredApplications...)
	profileDigest, err := observation.PlatformProfileDigest(profile)
	if err != nil {
		return VerifiedPlatformApplicationsStageBundle{}, errors.New("platform Applications profile is invalid")
	}
	directPredecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedPlatformApplicationsStageBundle{}, err
	}
	grant, err := authorization.LoadStage(config.GrantPath, config.GrantPublicKeyPath, plan, "platform-applications", directPredecessors, config.EvaluationTime)
	if err != nil {
		return VerifiedPlatformApplicationsStageBundle{}, err
	}
	if _, err := authorization.BindStageGrant(grant, plan, "platform-applications", directPredecessors); err != nil {
		return VerifiedPlatformApplicationsStageBundle{}, err
	}
	applicationDigests := make([]string, len(projected.Applications))
	for index, application := range projected.Applications {
		applicationDigests[index] = application.Digest
	}
	sort.Strings(applicationDigests)
	receipt := PlatformApplicationsStageBundleReceipt{
		Format: PlatformApplicationsStageBundleReceiptFormat, State: "VERIFIED", PlanDigest: plan.PlanDigest,
		StageID: "platform-applications", AuthorizationDigest: grant.Receipt().AuthorizationDigest,
		ArtifactDigest: projected.ArtifactDigest, TargetIdentityDigest: projected.TargetIdentityDigest,
		ProfileDigest: profileDigest, ApplicationDigests: applicationDigests,
		Authority: projected.Authority, MutationAllowed: false,
	}
	return VerifiedPlatformApplicationsStageBundle{
		plan: plan, cursor: cursor, prefix: prefix, grant: grant, projection: projected,
		profile: profile, receipt: receipt, verified: true,
	}, nil
}

func (bundle VerifiedPlatformApplicationsStageBundle) Decision() (stagecursor.Decision, error) {
	if err := verifyPlatformApplicationsStageBundle(bundle); err != nil {
		return stagecursor.Decision{}, err
	}
	return bundle.cursor.Decision()
}

func (bundle VerifiedPlatformApplicationsStageBundle) Receipt() (PlatformApplicationsStageBundleReceipt, error) {
	if err := verifyPlatformApplicationsStageBundle(bundle); err != nil {
		return PlatformApplicationsStageBundleReceipt{}, err
	}
	receipt := bundle.receipt
	receipt.ApplicationDigests = append([]string(nil), bundle.receipt.ApplicationDigests...)
	return receipt, nil
}

func verifyPlatformApplicationsStageBundle(bundle VerifiedPlatformApplicationsStageBundle) error {
	if !bundle.verified || bundle.receipt.Format != PlatformApplicationsStageBundleReceiptFormat || bundle.receipt.State != "VERIFIED" || bundle.receipt.StageID != "platform-applications" || bundle.receipt.MutationAllowed || len(bundle.prefix) != 9 || len(bundle.receipt.ApplicationDigests) != 3 || len(bundle.projection.Applications) != 3 {
		return errors.New("platform-applications stage bundle was not produced by verification")
	}
	for _, value := range []string{
		bundle.receipt.PlanDigest, bundle.receipt.AuthorizationDigest, bundle.receipt.ArtifactDigest,
		bundle.receipt.TargetIdentityDigest, bundle.receipt.ProfileDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("platform-applications stage bundle digest identity is invalid")
		}
	}
	if bundle.receipt.PlanDigest != bundle.plan.PlanDigest ||
		bundle.receipt.AuthorizationDigest != bundle.grant.Receipt().AuthorizationDigest ||
		bundle.receipt.ArtifactDigest != bundle.projection.ArtifactDigest ||
		bundle.receipt.TargetIdentityDigest != bundle.projection.TargetIdentityDigest {
		return errors.New("platform-applications stage bundle binding changed after verification")
	}
	if bundle.receipt.Authority == "" || bundle.receipt.Authority != bundle.plan.Authorities.GitOps || bundle.projection.Authority != bundle.receipt.Authority || bundle.projection.TargetIdentityDigest != bundle.receipt.TargetIdentityDigest {
		return errors.New("platform-applications stage bundle identity changed after verification")
	}
	profileDigest, err := observation.PlatformProfileDigest(bundle.profile)
	if err != nil || profileDigest != bundle.receipt.ProfileDigest {
		return errors.New("platform-applications profile changed after verification")
	}
	if bundle.projection.Format != submission.PlatformApplicationsPlanFormat || bundle.projection.MutationAllowed ||
		bundle.projection.ArtifactDigest != bundle.receipt.ArtifactDigest ||
		bundle.projection.IntentRevision != bundle.plan.IntentRevision ||
		bundle.projection.PlatformRevision != bundle.plan.PlatformRevision ||
		bundle.projection.ExecutionFixture != bundle.plan.ExecutionFixture {
		return errors.New("platform-applications projection changed after verification")
	}
	digests := make([]string, len(bundle.projection.Applications))
	for index, application := range bundle.projection.Applications {
		if !stageReceiptPrefixDigestPattern.MatchString(application.Digest) || digest.SHA256(application.Raw) != application.Digest {
			return errors.New("platform Application changed after verification")
		}
		digests[index] = application.Digest
	}
	sort.Strings(digests)
	for index := range digests {
		if digests[index] != bundle.receipt.ApplicationDigests[index] {
			return errors.New("platform Application set changed after verification")
		}
	}
	return nil
}
