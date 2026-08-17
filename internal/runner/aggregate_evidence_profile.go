package runner

import (
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const AggregateEvidenceProfileFormat = "ok147-aggregate-evidence-profile/v1"

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
