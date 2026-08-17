package runner

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildRuntimeBindingStageInputContainsOnlyPublicBoundInputs(t *testing.T) {
	config := runtimeBindingBundleConfig(t)
	input, err := BuildRuntimeBindingStageInput(config, "ok147-runtime-binding-input")
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
	if object["kind"] != "ConfigMap" || object["immutable"] != true || objectAt(t, object, "metadata")["name"] != "ok147-runtime-binding-input" {
		t.Fatalf("unexpected runtime binding input: %#v", object)
	}
	data := objectAt(t, object, "data")
	wantKeys := []string{
		"enablement-receipt.json", "lifecycle-observation-receipt.json", "lifecycle-receipt.json",
		"network-observation-receipt.json", "provider-receipt.json", "receipt-prefix.json", "staged-plan.json",
	}
	gotKeys := make([]string, 0, len(data))
	for key := range data {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) || data["workload-binding.json"] != nil || data["token"] != nil || data["ca.crt"] != nil || data["runtime-binding.json"] != nil {
		t.Fatalf("runtime binding public input boundary differs: %v", gotKeys)
	}
	if receipt.Format != RuntimeBindingStageInputFormat || receipt.StageID != "runtime-binding" || receipt.ConfigMapDigest != digest.SHA256(raw) || !stageReceiptPrefixDigestPattern.MatchString(receipt.ReceiptPrefixDigest) || !reflect.DeepEqual(receipt.DataKeys, wantKeys) {
		t.Fatalf("unexpected runtime binding input receipt: %#v", receipt)
	}
	raw[0] = 'x'
	again, _ := input.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained runtime binding input")
	}
	receipt.DataKeys[0] = "changed"
	againReceipt, _ := input.Receipt()
	if againReceipt.DataKeys[0] != wantKeys[0] {
		t.Fatal("caller mutated retained runtime binding input receipt")
	}
}

func TestBuildRuntimeBindingStageInputFailsClosed(t *testing.T) {
	valid := runtimeBindingBundleConfig(t)
	for name, mutate := range map[string]func(*StageResumeConfig, *string){
		"missing receipt": func(config *StageResumeConfig, _ *string) { config.Receipts = config.Receipts[:4] },
		"invalid name":    func(_ *StageResumeConfig, name *string) { *name = "runtime-binding-input" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			name := "ok147-runtime-binding-input"
			mutate(&config, &name)
			if _, err := BuildRuntimeBindingStageInput(config, name); err == nil {
				t.Fatal("unsafe runtime binding input was accepted")
			}
		})
	}
	if _, err := (VerifiedRuntimeBindingStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified runtime binding input bytes were exposed")
	}
	if _, err := (VerifiedRuntimeBindingStageInput{}).Receipt(); err == nil {
		t.Fatal("unverified runtime binding input receipt was exposed")
	}
}
