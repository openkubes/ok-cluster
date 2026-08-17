package runner

import (
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const AggregateEvidenceProfileFormat = "ok147-aggregate-evidence-profile/v1"

const maximumAggregateEvidenceProfileBytes = 64 * 1024

var aggregateEvidenceRequiredConditions = []string{
	"InfrastructureReady",
	"ControlPlaneAvailable",
	"NetworkReady",
	"PlatformReady",
}

// AggregateEvidenceProfile is the immutable, pre-runtime Stage-12 input. It
// binds the required facts but deliberately excludes the CAPI Cluster UID,
// which only exists after lifecycle submission and is supplied by the verified
// private runtime binding.
type AggregateEvidenceProfile struct {
	Format             string   `json:"format"`
	IntentRevision     string   `json:"intentRevision"`
	EnablementRevision string   `json:"enablementRevision"`
	PlatformRevision   string   `json:"platformRevision"`
	ExecutionFixture   string   `json:"executionFixture"`
	Required           []string `json:"required"`
}

type AggregateEvidenceProfileFileConfig struct {
	Path                       string
	ExpectedProfileDigest      string
	ExpectedIntentRevision     string
	ExpectedEnablementRevision string
	ExpectedPlatformRevision   string
	ExpectedExecutionFixture   string
}

type LoadedAggregateEvidenceProfile struct {
	Profile AggregateEvidenceProfile
	Digest  string
}

func AggregateEvidenceProfileForPlan(plan stageplan.Binding) AggregateEvidenceProfile {
	return AggregateEvidenceProfile{
		Format: AggregateEvidenceProfileFormat, IntentRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision,
		ExecutionFixture: plan.ExecutionFixture,
		Required:         append([]string(nil), aggregateEvidenceRequiredConditions...),
	}
}

func AggregateEvidenceProfileDigest(profile AggregateEvidenceProfile) (string, error) {
	if err := validateAggregateEvidenceProfile(profile); err != nil {
		return "", err
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return "", errors.New("encode aggregate evidence profile")
	}
	return digest.SHA256(raw), nil
}

// LoadAggregateEvidenceProfileFile reads one bounded regular strict-JSON
// document and binds it to identities obtained from the verified staged plan.
func LoadAggregateEvidenceProfileFile(config AggregateEvidenceProfileFileConfig) (LoadedAggregateEvidenceProfile, error) {
	if config.Path == "" || !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedProfileDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedIntentRevision) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedEnablementRevision) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedPlatformRevision) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedExecutionFixture) {
		return LoadedAggregateEvidenceProfile{}, errors.New("aggregate evidence profile file binding is invalid")
	}
	raw, err := readBoundedRegular(config.Path, maximumAggregateEvidenceProfileBytes)
	if err != nil {
		return LoadedAggregateEvidenceProfile{}, errors.New("read bounded aggregate evidence profile")
	}
	var profile AggregateEvidenceProfile
	if err := jsonstrict.Decode(raw, &profile); err != nil {
		return LoadedAggregateEvidenceProfile{}, errors.New("decode strict aggregate evidence profile")
	}
	if profile.IntentRevision != config.ExpectedIntentRevision || profile.EnablementRevision != config.ExpectedEnablementRevision ||
		profile.PlatformRevision != config.ExpectedPlatformRevision || profile.ExecutionFixture != config.ExpectedExecutionFixture {
		return LoadedAggregateEvidenceProfile{}, errors.New("aggregate evidence profile identity differs from verified execution input")
	}
	profileDigest, err := AggregateEvidenceProfileDigest(profile)
	if err != nil {
		return LoadedAggregateEvidenceProfile{}, errors.New("validate semantic aggregate evidence profile")
	}
	if profileDigest != config.ExpectedProfileDigest {
		return LoadedAggregateEvidenceProfile{}, errors.New("aggregate evidence profile digest differs from verified execution input")
	}
	profile.Required = append([]string(nil), profile.Required...)
	return LoadedAggregateEvidenceProfile{Profile: profile, Digest: profileDigest}, nil
}

func validateAggregateEvidenceProfile(profile AggregateEvidenceProfile) error {
	if profile.Format != AggregateEvidenceProfileFormat || !stageReceiptPrefixDigestPattern.MatchString(profile.IntentRevision) || !stageReceiptPrefixDigestPattern.MatchString(profile.EnablementRevision) || !stageReceiptPrefixDigestPattern.MatchString(profile.PlatformRevision) || !stageReceiptPrefixDigestPattern.MatchString(profile.ExecutionFixture) || len(profile.Required) != len(aggregateEvidenceRequiredConditions) {
		return errors.New("aggregate evidence profile identity is invalid")
	}
	for index, required := range aggregateEvidenceRequiredConditions {
		if profile.Required[index] != required {
			return errors.New("aggregate evidence required condition profile is invalid")
		}
	}
	return nil
}
