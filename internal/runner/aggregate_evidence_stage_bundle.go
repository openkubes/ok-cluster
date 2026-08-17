package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

type AggregateEvidenceStageBundleConfig struct {
	StageResumeConfig
	Profile               AggregateEvidenceProfile
	ExpectedProfileDigest string
}

type VerifiedAggregateEvidenceStageBundle struct {
	plan          stageplan.Binding
	cursor        stagecursor.Cursor
	prefix        []stagereceipt.Verified
	profile       AggregateEvidenceProfile
	profileDigest string
	verified      bool
}

// LoadAggregateEvidenceStageBundle closes the offline Stage-12 boundary. It
// verifies the exact eleven-receipt history and aggregation semantics without
// opening a credential or contacting any Kubernetes API.
func LoadAggregateEvidenceStageBundle(config AggregateEvidenceStageBundleConfig) (VerifiedAggregateEvidenceStageBundle, error) {
	plan, cursor, prefix, err := loadStageResumeWithPrefix(config.StageResumeConfig)
	if err != nil {
		return VerifiedAggregateEvidenceStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "aggregate-evidence" || decision.Kind != "Evaluation" || decision.Authority != "runner" || decision.RequiresAuthorization || decision.Operation != "" {
		return VerifiedAggregateEvidenceStageBundle{}, errors.New("verified prefix does not select aggregate evidence evaluation")
	}
	if len(prefix) != 11 {
		return VerifiedAggregateEvidenceStageBundle{}, errors.New("aggregate evidence evaluation requires the exact eleven-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || lifecycle.State != "SUCCEEDED" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedAggregateEvidenceStageBundle{}, errors.New("aggregate evidence evaluation lacks durable workload identity")
	}
	for _, index := range []int{2, 4, 10} {
		receipt, receiptErr := prefix[index].Receipt()
		if receiptErr != nil || receipt.State != "SUCCEEDED" || receipt.MutationState != "NOT_APPLICABLE" || !stageReceiptPrefixDigestPattern.MatchString(receipt.EvidenceDigest) {
			return VerifiedAggregateEvidenceStageBundle{}, errors.New("aggregate evidence evaluation lacks a successful authoritative observation")
		}
	}
	profileDigest, err := AggregateEvidenceProfileDigest(config.Profile)
	if err != nil || config.ExpectedProfileDigest != profileDigest {
		return VerifiedAggregateEvidenceStageBundle{}, errors.New("aggregate evidence profile identity is invalid")
	}
	stage, _, err := plan.Stage("aggregate-evidence")
	if err != nil || len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.aggregate-evidence" || stage.Inputs[0].Digest != profileDigest || config.Profile.IntentRevision != plan.IntentRevision || config.Profile.EnablementRevision != plan.EnablementRevision || config.Profile.PlatformRevision != plan.PlatformRevision || config.Profile.ExecutionFixture != plan.ExecutionFixture {
		return VerifiedAggregateEvidenceStageBundle{}, errors.New("aggregate evidence profile differs from verified stage plan")
	}
	profile := config.Profile
	profile.Required = append([]string(nil), config.Profile.Required...)
	return VerifiedAggregateEvidenceStageBundle{plan: plan, cursor: cursor, prefix: prefix, profile: profile, profileDigest: profileDigest, verified: true}, nil
}

func (bundle VerifiedAggregateEvidenceStageBundle) Decision() (stagecursor.Decision, error) {
	if err := verifyAggregateEvidenceStageBundle(bundle); err != nil {
		return stagecursor.Decision{}, err
	}
	return bundle.cursor.Decision()
}

func verifyAggregateEvidenceStageBundle(bundle VerifiedAggregateEvidenceStageBundle) error {
	if !bundle.verified || len(bundle.prefix) != 11 || !stageReceiptPrefixDigestPattern.MatchString(bundle.profileDigest) {
		return errors.New("aggregate evidence stage bundle is not verified")
	}
	digest, err := AggregateEvidenceProfileDigest(bundle.profile)
	if err != nil || digest != bundle.profileDigest || bundle.profile.IntentRevision != bundle.plan.IntentRevision || bundle.profile.EnablementRevision != bundle.plan.EnablementRevision || bundle.profile.PlatformRevision != bundle.plan.PlatformRevision || bundle.profile.ExecutionFixture != bundle.plan.ExecutionFixture {
		return errors.New("aggregate evidence profile changed after verification")
	}
	return nil
}
