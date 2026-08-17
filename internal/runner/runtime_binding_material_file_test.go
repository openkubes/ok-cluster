package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestLoadRuntimeBindingMaterialFilesReplaysPrivateBinding(t *testing.T) {
	config := runtimeBindingMaterialConfig(t)
	material, err := BuildRuntimeBindingMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	materialPath, receiptPath := writeRuntimeBindingReplayFiles(t, material)
	receipts := appendSuccessfulRuntimeBindingReceipt(t, config.Bundle)
	loaded, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle:       StageResumeConfig{PlanPath: config.Bundle.PlanPath, PlanExpected: config.Bundle.PlanExpected, Receipts: receipts},
		MaterialPath: materialPath, ReceiptPath: receiptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := material.Receipt()
	got, err := loaded.Receipt()
	if err != nil || got != want {
		t.Fatalf("replayed runtime binding differs: %#v %#v %v", got, want, err)
	}
	first, _ := loaded.Bytes()
	first[0] = 'x'
	again, _ := loaded.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated replayed runtime binding")
	}
}

func TestLoadRuntimeBindingMaterialFilesFailsClosed(t *testing.T) {
	base := runtimeBindingMaterialConfig(t)
	material, err := BuildRuntimeBindingMaterial(base)
	if err != nil {
		t.Fatal(err)
	}
	materialPath, receiptPath := writeRuntimeBindingReplayFiles(t, material)
	receipts := appendSuccessfulRuntimeBindingReceipt(t, base.Bundle)
	valid := RuntimeBindingMaterialFileConfig{
		Bundle:       StageResumeConfig{PlanPath: base.Bundle.PlanPath, PlanExpected: base.Bundle.PlanExpected, Receipts: receipts},
		MaterialPath: materialPath, ReceiptPath: receiptPath,
	}
	for name, mutate := range map[string]func(*RuntimeBindingMaterialFileConfig){
		"incomplete history": func(config *RuntimeBindingMaterialFileConfig) { config.Bundle.Receipts = config.Bundle.Receipts[:5] },
		"missing material": func(config *RuntimeBindingMaterialFileConfig) {
			config.MaterialPath = filepath.Join(t.TempDir(), "missing")
		},
		"missing receipt": func(config *RuntimeBindingMaterialFileConfig) {
			config.ReceiptPath = filepath.Join(t.TempDir(), "missing")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := LoadRuntimeBindingMaterialFiles(config); err == nil {
				t.Fatal("unsafe runtime binding replay was accepted")
			}
		})
	}

	receiptRaw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt RuntimeBindingMaterialReceipt
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.PrivateMaterialDigest = runnerStageSHA("f")
	changedReceipt, _ := json.Marshal(receipt)
	changedReceiptPath := writeBundleFile(t, t.TempDir(), "changed-receipt.json", changedReceipt)
	valid.ReceiptPath = changedReceiptPath
	if _, err := LoadRuntimeBindingMaterialFiles(valid); err == nil {
		t.Fatal("foreign private material digest was accepted")
	}

	materialRaw, err := os.ReadFile(materialPath)
	if err != nil {
		t.Fatal(err)
	}
	pretty := append([]byte("\n"), materialRaw...)
	valid.ReceiptPath = receiptPath
	valid.MaterialPath = writeBundleFile(t, t.TempDir(), "noncanonical.json", pretty)
	if _, err := LoadRuntimeBindingMaterialFiles(valid); err == nil {
		t.Fatal("non-canonical runtime binding material was accepted")
	}
}

func writeRuntimeBindingReplayFiles(t *testing.T, material VerifiedRuntimeBindingMaterial) (string, string) {
	t.Helper()
	root := t.TempDir()
	materialRaw, err := material.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return writeBundleFile(t, root, "runtime-binding.json", materialRaw), writeBundleFile(t, root, "runtime-binding-receipt.json", receiptRaw)
}

func appendSuccessfulRuntimeBindingReceipt(t *testing.T, bundle StageResumeConfig) []StageReceiptSource {
	t.Helper()
	plan, _, prefix, err := loadStageResumeWithPrefix(bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt := successfulRuntimeBindingStageReceipt(t, plan, prefix)
	return appendStageReceipt(t, t.TempDir(), bundle.Receipts, receipt, "runtime-binding.json")
}

func successfulRuntimeBindingStageReceipt(t *testing.T, plan stageplan.Binding, prefix []stagereceipt.Verified) stagereceipt.Verified {
	t.Helper()
	receipt, err := stagereceipt.New(plan, "runtime-binding", []stagereceipt.Verified{prefix[4]}, "SUCCEEDED", "NOT_APPLICABLE", "", runnerStageSHA("a"), time.Date(2026, 8, 17, 20, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
