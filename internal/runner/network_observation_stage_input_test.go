package runner

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestBuildNetworkObservationStageInputContainsOnlyPublicBoundInputs(t *testing.T) {
	config := networkObservationStageInputConfig(t)
	input, err := BuildNetworkObservationStageInput(config)
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
	if object["kind"] != "ConfigMap" || object["immutable"] != true || objectAt(t, object, "metadata")["name"] != config.ConfigMapName {
		t.Fatalf("unexpected network observation input: %#v", object)
	}
	data := objectAt(t, object, "data")
	wantKeys := []string{
		"enablement-receipt.json", "lifecycle-observation-receipt.json", "lifecycle-receipt.json",
		"network-profile.json", "provider-receipt.json", "receipt-prefix.json", "staged-plan.json",
	}
	gotKeys := make([]string, 0, len(data))
	for key := range data {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) || data["workload-binding.json"] != nil || data["token"] != nil || data["ca.crt"] != nil {
		t.Fatalf("network observation public input boundary differs: %v", gotKeys)
	}
	if receipt.Format != NetworkObservationStageInputFormat || receipt.StageID != "network-observation" || receipt.ConfigMapDigest != digest.SHA256(raw) || !reflect.DeepEqual(receipt.DataKeys, wantKeys) {
		t.Fatalf("unexpected network observation input receipt: %#v", receipt)
	}
	profile := networkStageProfile(loadNetworkInputPlan(t, config))
	profileDigest, _ := observation.NetworkProfileDigest(profile)
	if receipt.NetworkProfileDigest != profileDigest || !stageReceiptPrefixDigestPattern.MatchString(receipt.ReceiptPrefixDigest) {
		t.Fatalf("input semantic identities differ: %#v", receipt)
	}
	raw[0] = 'x'
	again, _ := input.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained network observation input")
	}
	receipt.DataKeys[0] = "changed"
	againReceipt, _ := input.Receipt()
	if againReceipt.DataKeys[0] != wantKeys[0] {
		t.Fatal("caller mutated retained input receipt")
	}
}

func TestBuildNetworkObservationStageInputFailsClosed(t *testing.T) {
	valid := networkObservationStageInputConfig(t)
	for name, mutate := range map[string]func(*NetworkObservationStageInputConfig){
		"missing receipt": func(config *NetworkObservationStageInputConfig) {
			config.Bundle.Receipts = config.Bundle.Receipts[:3]
		},
		"foreign profile digest": func(config *NetworkObservationStageInputConfig) {
			config.ExpectedNetworkProfileDigest = bundleSHA("f")
		},
		"invalid ConfigMap name": func(config *NetworkObservationStageInputConfig) {
			config.ConfigMapName = "network-input"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := BuildNetworkObservationStageInput(config); err == nil {
				t.Fatal("unsafe network observation input was accepted")
			}
		})
	}
	if _, err := (VerifiedNetworkObservationStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified network input bytes were exposed")
	}
	if _, err := (VerifiedNetworkObservationStageInput{}).Receipt(); err == nil {
		t.Fatal("unverified network input receipt was exposed")
	}
}

func networkObservationStageInputConfig(t *testing.T) NetworkObservationStageInputConfig {
	t.Helper()
	bundleConfig := networkObservationBundleConfig(t, true)
	plan, _, _, err := loadStageResumeWithPrefix(bundleConfig)
	if err != nil {
		t.Fatal(err)
	}
	profile := networkStageProfile(plan)
	profilePath := writeBundleFile(t, t.TempDir(), "network-profile.json", mustJSON(t, profile))
	profileDigest, err := observation.NetworkProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	return NetworkObservationStageInputConfig{
		Bundle: bundleConfig, NetworkProfilePath: profilePath,
		ExpectedNetworkProfileDigest: profileDigest, ConfigMapName: "ok147-network-observation-input",
	}
}

func loadNetworkInputPlan(t *testing.T, config NetworkObservationStageInputConfig) stageplan.Binding {
	t.Helper()
	plan, _, _, err := loadStageResumeWithPrefix(config.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
