package runner

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestAggregateEvidenceProfileFileBindsCanonicalIdentity(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	root := t.TempDir()
	profilePath := writeAggregateEvidenceProfile(t, root, fixture.Profile)
	loaded, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: profilePath, ExpectedProfileDigest: fixture.ExpectedProfileDigest,
		ExpectedIntentRevision: fixture.Profile.IntentRevision, ExpectedEnablementRevision: fixture.Profile.EnablementRevision,
		ExpectedPlatformRevision: fixture.Profile.PlatformRevision, ExpectedExecutionFixture: fixture.Profile.ExecutionFixture,
	})
	if err != nil || loaded.Digest != fixture.ExpectedProfileDigest || !reflect.DeepEqual(loaded.Profile, fixture.Profile) {
		t.Fatalf("aggregate evidence profile did not load: %#v %v", loaded, err)
	}
	loaded.Profile.Required[0] = "changed"
	again, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: profilePath, ExpectedProfileDigest: fixture.ExpectedProfileDigest,
		ExpectedIntentRevision: fixture.Profile.IntentRevision, ExpectedEnablementRevision: fixture.Profile.EnablementRevision,
		ExpectedPlatformRevision: fixture.Profile.PlatformRevision, ExpectedExecutionFixture: fixture.Profile.ExecutionFixture,
	})
	if err != nil || again.Profile.Required[0] != aggregateEvidenceRequiredConditions[0] {
		t.Fatal("caller mutated subsequently loaded aggregate evidence profile")
	}
}

func TestAggregateEvidenceProfileFileRejectsMalformedOrForeignInput(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	root := t.TempDir()
	profilePath := writeAggregateEvidenceProfile(t, root, fixture.Profile)
	base := AggregateEvidenceProfileFileConfig{
		Path: profilePath, ExpectedProfileDigest: fixture.ExpectedProfileDigest,
		ExpectedIntentRevision: fixture.Profile.IntentRevision, ExpectedEnablementRevision: fixture.Profile.EnablementRevision,
		ExpectedPlatformRevision: fixture.Profile.PlatformRevision, ExpectedExecutionFixture: fixture.Profile.ExecutionFixture,
	}
	for name, mutate := range map[string]func(*AggregateEvidenceProfileFileConfig){
		"foreign digest": func(config *AggregateEvidenceProfileFileConfig) { config.ExpectedProfileDigest = runnerStageSHA("f") },
		"foreign intent": func(config *AggregateEvidenceProfileFileConfig) { config.ExpectedIntentRevision = runnerStageSHA("f") },
		"missing path":   func(config *AggregateEvidenceProfileFileConfig) { config.Path = "" },
		"foreign platform": func(config *AggregateEvidenceProfileFileConfig) {
			config.ExpectedPlatformRevision = runnerStageSHA("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := LoadAggregateEvidenceProfileFile(config); err == nil {
				t.Fatal("unsafe aggregate evidence profile was accepted")
			}
		})
	}
	malformed := writeBundleFile(t, root, "aggregate-malformed.json", []byte(`{"format":"ok147-aggregate-evidence-profile/v1","unknown":true}`))
	base.Path = malformed
	if _, err := LoadAggregateEvidenceProfileFile(base); err == nil {
		t.Fatal("unknown aggregate evidence profile field was accepted")
	}
}

func TestBuildAggregateEvidenceStageInputContainsOnlyPublicBoundInputs(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	root := t.TempDir()
	profilePath := writeAggregateEvidenceProfile(t, root, fixture.Profile)
	networkPath, networkDigest, platformPath, platformDigest := writeAggregateSourceProfiles(t, root, fixture)
	input, err := BuildAggregateEvidenceStageInput(AggregateEvidenceStageInputConfig{
		Bundle: fixture.StageResumeConfig, AggregateEvidenceProfilePath: profilePath,
		ExpectedAggregateProfileDigest: fixture.ExpectedProfileDigest,
		NetworkProfilePath:             networkPath, ExpectedNetworkProfileDigest: networkDigest,
		PlatformProfilePath: platformPath, ExpectedPlatformProfileDigest: platformDigest,
		ConfigMapName: "ok147-aggregate-evidence-input",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := input.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := input.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if object["kind"] != "ConfigMap" || object["immutable"] != true || objectAt(t, object, "metadata")["name"] != "ok147-aggregate-evidence-input" {
		t.Fatalf("unexpected aggregate evidence input: %#v", object)
	}
	data := objectAt(t, object, "data")
	wantKeys := append([]string{"aggregate-evidence-profile.json", "network-profile.json", "platform-profile.json", "receipt-prefix.json", "staged-plan.json"}, aggregateEvidenceReceiptFiles...)
	sort.Strings(wantKeys)
	gotKeys := make([]string, 0, len(data))
	for key := range data {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) || data["token"] != nil || data["ca.crt"] != nil || data["runtime-binding.json"] != nil || data["capability-evidence.json"] != nil {
		t.Fatalf("aggregate evidence public input boundary differs: %v", gotKeys)
	}
	if receipt.Format != AggregateEvidenceStageInputFormat || receipt.StageID != "aggregate-evidence" || receipt.ConfigMapDigest != digest.SHA256(raw) || receipt.AggregateProfileDigest != fixture.ExpectedProfileDigest || receipt.NetworkProfileDigest != networkDigest || receipt.PlatformProfileDigest != platformDigest || !reflect.DeepEqual(receipt.DataKeys, wantKeys) {
		t.Fatalf("unexpected aggregate evidence input receipt: %#v", receipt)
	}
	raw[0] = 'x'
	again, _ := input.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained aggregate evidence input")
	}
}

func TestBuildAggregateEvidenceStageInputFailsClosed(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	root := t.TempDir()
	profilePath := writeAggregateEvidenceProfile(t, root, fixture.Profile)
	networkPath, networkDigest, platformPath, platformDigest := writeAggregateSourceProfiles(t, root, fixture)
	valid := AggregateEvidenceStageInputConfig{
		Bundle: fixture.StageResumeConfig, AggregateEvidenceProfilePath: profilePath,
		ExpectedAggregateProfileDigest: fixture.ExpectedProfileDigest,
		NetworkProfilePath:             networkPath, ExpectedNetworkProfileDigest: networkDigest,
		PlatformProfilePath: platformPath, ExpectedPlatformProfileDigest: platformDigest,
		ConfigMapName: "ok147-aggregate-evidence-input",
	}
	for name, mutate := range map[string]func(*AggregateEvidenceStageInputConfig){
		"missing receipt": func(config *AggregateEvidenceStageInputConfig) { config.Bundle.Receipts = config.Bundle.Receipts[:10] },
		"invalid name":    func(config *AggregateEvidenceStageInputConfig) { config.ConfigMapName = "aggregate-evidence-input" },
		"foreign digest": func(config *AggregateEvidenceStageInputConfig) {
			config.ExpectedAggregateProfileDigest = runnerStageSHA("f")
		},
		"foreign network profile": func(config *AggregateEvidenceStageInputConfig) {
			config.ExpectedNetworkProfileDigest = runnerStageSHA("f")
		},
		"foreign platform profile": func(config *AggregateEvidenceStageInputConfig) {
			config.ExpectedPlatformProfileDigest = runnerStageSHA("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := BuildAggregateEvidenceStageInput(config); err == nil {
				t.Fatal("unsafe aggregate evidence stage input was accepted")
			}
		})
	}
	if _, err := (VerifiedAggregateEvidenceStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified aggregate evidence input bytes were exposed")
	}
	if _, err := (VerifiedAggregateEvidenceStageInput{}).Receipt(); err == nil {
		t.Fatal("unverified aggregate evidence input receipt was exposed")
	}
	if !strings.HasPrefix(valid.ConfigMapName, "ok147-") {
		t.Fatal("test fixture no longer exercises OK-147 name boundary")
	}
}

func writeAggregateEvidenceProfile(t *testing.T, root string, profile AggregateEvidenceProfile) string {
	t.Helper()
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	return writeBundleFile(t, root, "aggregate-evidence-profile.json", raw)
}

func writeAggregateSourceProfiles(t *testing.T, root string, fixture AggregateEvidenceStageBundleConfig) (string, string, string, string) {
	t.Helper()
	bundle, err := LoadAggregateEvidenceStageBundle(fixture)
	if err != nil {
		t.Fatal(err)
	}
	networkProfile := runnerAggregateNetworkProfile(bundleExpected(bundle))
	networkDigest, err := observation.NetworkProfileDigest(networkProfile)
	if err != nil {
		t.Fatal(err)
	}
	_, platformProfile := runnerPlatformApplications(t, bundleExpected(bundle))
	platformDigest, err := observation.PlatformProfileDigest(platformProfile)
	if err != nil {
		t.Fatal(err)
	}
	networkRaw, err := json.Marshal(networkProfile)
	if err != nil {
		t.Fatal(err)
	}
	platformRaw, err := json.Marshal(platformProfile)
	if err != nil {
		t.Fatal(err)
	}
	return writeBundleFile(t, root, "network-profile.json", networkRaw), networkDigest,
		writeBundleFile(t, root, "platform-profile.json", platformRaw), platformDigest
}
