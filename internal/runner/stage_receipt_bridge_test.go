package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestStageReceiptBridgeLoadsDurableReceiptAndPersistsExactSource(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	plan, _, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := stagereceipt.New(plan, "target-credential", []stagereceipt.Verified{prefix[6]}, "SUCCEEDED", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2"), time.Date(2026, 8, 17, 23, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := store.StoreStageReceipt(context.Background(), plan, verified, []stagereceipt.Verified{prefix[6]})
	if err != nil {
		t.Fatal(err)
	}
	runReceipt := execution.StagedOperationReceipt{
		Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest,
		StageID: "target-credential", StageReceiptDigest: receiptDigest,
	}
	material, err := LoadStageReceiptMaterial(context.Background(), StageReceiptBridgeConfig{
		Bundle: StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts},
		Ledger: store, Run: StagedOperationReceiptReference(runReceipt),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := material.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wantRaw, _ := verified.Bytes()
	if string(raw) != string(wantRaw) {
		t.Fatal("stage receipt bridge changed canonical bytes")
	}
	outputRoot := t.TempDir()
	if err := os.Chmod(outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputRoot, "target-credential.json")
	source, err := material.Persist(output)
	if err != nil {
		t.Fatal(err)
	}
	if source.Path != output || source.Digest != receiptDigest {
		t.Fatalf("unexpected stage receipt source: %#v", source)
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("stage receipt output metadata differs: %#v %v", info, err)
	}
	combined := append(append([]StageReceiptSource{}, fixture.config.Receipts...), source)
	decision, err := InspectStageResume(StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: combined})
	if err != nil || decision.StageID != "target-registration" {
		t.Fatalf("persisted receipt did not advance exact cursor: %#v %v", decision, err)
	}
	if _, err := material.Persist(output); err == nil {
		t.Fatal("existing receipt output was overwritten")
	}
	raw[0] ^= 1
	again, _ := material.Bytes()
	if string(again) != string(wantRaw) {
		t.Fatal("caller mutated verified stage receipt material")
	}
}

func TestStageReceiptBridgeFailsClosedOnForeignOrMalformedRunReference(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	plan, _, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	verified, _ := stagereceipt.New(plan, "target-credential", []stagereceipt.Verified{prefix[6]}, "SUCCEEDED", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2"), time.Now().UTC())
	receiptDigest, _ := store.StoreStageReceipt(context.Background(), plan, verified, []stagereceipt.Verified{prefix[6]})
	valid := StageReceiptBridgeConfig{
		Bundle: StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts},
		Ledger: store,
		Run:    StageRunReceiptReference{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest, StageID: "target-credential", StageReceiptDigest: receiptDigest},
	}
	for name, mutate := range map[string]func(*StageReceiptBridgeConfig){
		"missing ledger":    func(config *StageReceiptBridgeConfig) { config.Ledger = nil },
		"wrong format":      func(config *StageReceiptBridgeConfig) { config.Run.Format = execution.ObservationStageReceiptFormat },
		"failed state":      func(config *StageReceiptBridgeConfig) { config.Run.State = "COMPLETED_FAILED" },
		"foreign plan":      func(config *StageReceiptBridgeConfig) { config.Run.PlanDigest = runnerStageSHA("f") },
		"foreign stage":     func(config *StageReceiptBridgeConfig) { config.Run.StageID = "target-registration" },
		"foreign digest":    func(config *StageReceiptBridgeConfig) { config.Run.StageReceiptDigest = runnerStageSHA("f") },
		"incomplete prefix": func(config *StageReceiptBridgeConfig) { config.Bundle.Receipts = config.Bundle.Receipts[:6] },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := LoadStageReceiptMaterial(context.Background(), config); err == nil {
				t.Fatal("unsafe stage receipt bridge input was accepted")
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadStageReceiptMaterial(cancelled, valid); err == nil {
		t.Fatal("cancelled stage receipt bridge load was accepted")
	}
	if _, err := (VerifiedStageReceiptMaterial{}).Bytes(); err == nil {
		t.Fatal("unverified stage receipt material exposed bytes")
	}
}

func TestStageReceiptBridgeAcceptsObservationReceiptForObservationCursor(t *testing.T) {
	fixture := aggregateEvidenceBundleFixture(t)
	beforeObservation := StageResumeConfig{
		PlanPath: fixture.PlanPath, PlanExpected: fixture.PlanExpected,
		Receipts: append([]StageReceiptSource(nil), fixture.Receipts[:10]...),
	}
	plan, _, prefix, err := loadStageResumeWithPrefix(beforeObservation)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := stagereceipt.New(plan, "platform-observation", []stagereceipt.Verified{prefix[9]}, "SUCCEEDED", "NOT_APPLICABLE", "", runnerStageSHA("e"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := store.StoreStageReceipt(context.Background(), plan, verified, []stagereceipt.Verified{prefix[9]})
	if err != nil {
		t.Fatal(err)
	}
	reference := ObservationStageReceiptReference(execution.ObservationStageRunReceipt{
		Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest,
		StageID: "platform-observation", StageReceiptDigest: receiptDigest,
	})
	material, err := LoadStageReceiptMaterial(context.Background(), StageReceiptBridgeConfig{Bundle: beforeObservation, Ledger: store, Run: reference})
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := material.Bytes(); err != nil || digest.SHA256(raw) != receiptDigest {
		t.Fatalf("observation receipt bridge differs: %v", err)
	}
}

func TestStageReceiptBridgePersistenceRequiresPrivateAbsoluteDestination(t *testing.T) {
	material := VerifiedStageReceiptMaterial{raw: []byte("{}"), digest: runnerStageSHA("a"), stageID: "target-credential", verified: true}
	// Refresh the digest so this deliberately minimal material reaches path validation.
	material.digest = digest.SHA256(material.raw)
	if _, err := material.Persist("relative.json"); err == nil {
		t.Fatal("relative stage receipt output was accepted")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := material.Persist(filepath.Join(root, "receipt.json")); err == nil {
		t.Fatal("broad stage receipt output directory was accepted")
	}
}
