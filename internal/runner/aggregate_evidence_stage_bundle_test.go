package runner

import (
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestAggregateEvidenceStageBundleLoadsExactReadOnlyCursor(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(fixture)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "aggregate-evidence" || decision.Kind != "Evaluation" || decision.Authority != "runner" || decision.RequiresAuthorization || decision.Operation != "" {
		t.Fatalf("unexpected aggregate evidence decision: %#v %v", decision, err)
	}
	if _, err := (VerifiedAggregateEvidenceStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified aggregate evidence bundle exposed decision")
	}
}

func TestAggregateEvidenceStageBundleRejectsProfileOrHistoryMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*AggregateEvidenceStageBundleConfig){
		"incomplete prefix": func(config *AggregateEvidenceStageBundleConfig) { config.Receipts = config.Receipts[:10] },
		"foreign digest":    func(config *AggregateEvidenceStageBundleConfig) { config.ExpectedProfileDigest = runnerStageSHA("f") },
		"foreign revision": func(config *AggregateEvidenceStageBundleConfig) {
			config.Profile.PlatformRevision = runnerStageSHA("f")
		},
		"missing condition": func(config *AggregateEvidenceStageBundleConfig) {
			config.Profile.Required = config.Profile.Required[:3]
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := aggregateEvidenceBundleFixture(t)
			mutate(&fixture)
			if _, err := LoadAggregateEvidenceStageBundle(fixture); err == nil {
				t.Fatal("invalid aggregate evidence bundle was accepted")
			}
		})
	}
}

func aggregateEvidenceBundleFixture(t *testing.T) AggregateEvidenceStageBundleConfig {
	t.Helper()
	base := platformObservationBundleFixture(t)
	plan, _, prefix, err := loadStageResumeWithPrefix(base.config.StageResumeConfig)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 17, 22, 0, 0, 0, time.UTC)
	receipt, err := stagereceipt.New(plan, "platform-observation", []stagereceipt.Verified{prefix[9]}, "SUCCEEDED", "NOT_APPLICABLE", "", runnerStageSHA("e"), at)
	if err != nil {
		t.Fatal(err)
	}
	receipts := appendStageReceipt(t, t.TempDir(), base.config.Receipts, receipt, "platform-observation.json")
	profile := AggregateEvidenceProfileForPlan(plan)
	profileDigest, err := AggregateEvidenceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	return AggregateEvidenceStageBundleConfig{
		StageResumeConfig: StageResumeConfig{PlanPath: base.config.PlanPath, PlanExpected: base.config.PlanExpected, Receipts: receipts},
		Profile:           profile, ExpectedProfileDigest: profileDigest,
	}
}
