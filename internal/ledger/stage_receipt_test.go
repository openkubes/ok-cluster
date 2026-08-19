package ledger

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestStageReceiptSurvivesLedgerRecreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	first, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 17, 0, 0, 0, time.UTC)
	receipt, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stageSHA("1"), stageSHA("e"), at)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := first.StoreStageReceipt(context.Background(), plan, receipt, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := first.StoreStageReceipt(context.Background(), plan, receipt, []stagereceipt.Verified{}); err != nil || replay != digest {
		t.Fatalf("exact receipt replay is not idempotent: %s %v", replay, err)
	}

	replacement, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := replacement.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", digest, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	if loadedDigest, _ := loaded.Digest(); loadedDigest != digest {
		t.Fatalf("loaded digest = %s, want %s", loadedDigest, digest)
	}
	if _, err := replacement.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", stageSHA("f"), []stagereceipt.Verified{}); err == nil {
		t.Fatal("receipt loaded under a different independently supplied digest")
	}
	lifecycle, err := stagereceipt.New(plan, "cluster-lifecycle", []stagereceipt.Verified{loaded}, "SUCCEEDED", "ATTEMPTED", stageSHA("2"), stageSHA("d"), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lifecycleDigest, err := replacement.StoreStageReceipt(context.Background(), plan, lifecycle, []stagereceipt.Verified{loaded})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err = replacement.LoadStageReceipt(context.Background(), plan, "cluster-lifecycle", lifecycleDigest, []stagereceipt.Verified{loaded})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := stagereceipt.New(plan, "lifecycle-observation", []stagereceipt.Verified{lifecycle}, "SUCCEEDED", "NOT_APPLICABLE", "", stageSHA("c"), at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observationDigest, err := replacement.StoreStageReceipt(context.Background(), plan, observation, []stagereceipt.Verified{lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.LoadStageReceipt(context.Background(), plan, "lifecycle-observation", observationDigest, []stagereceipt.Verified{lifecycle}); err != nil {
		t.Fatal(err)
	}
}

func TestStageReceiptSlotPreservesRetryOutcome(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 17, 0, 0, 0, time.UTC)
	first, _ := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stageSHA("1"), stageSHA("e"), at)
	conflict, _ := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "FAILED", "ATTEMPTED", stageSHA("2"), stageSHA("f"), at.Add(time.Second))
	if _, err := store.StoreStageReceipt(context.Background(), plan, first, []stagereceipt.Verified{}); err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := first.Digest()
	conflictDigest, _ := conflict.Digest()
	if _, err := store.StoreStageReceipt(context.Background(), plan, conflict, []stagereceipt.Verified{}); err != nil {
		t.Fatalf("retry receipt was not preserved: %v", err)
	}
	for _, expected := range []string{firstDigest, conflictDigest} {
		loaded, err := store.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", expected, []stagereceipt.Verified{})
		if err != nil {
			t.Fatalf("load immutable attempt %s: %v", expected, err)
		}
		if got, _ := loaded.Digest(); got != expected {
			t.Fatalf("loaded retry digest = %s, want %s", got, expected)
		}
	}
}

func TestKubernetesStorePersistsStageReceiptByExactSlot(t *testing.T) {
	api := newFakeConfigMapAPI(t)
	ledger, err := New(newTestKubernetesStore(t, api.client()))
	if err != nil {
		t.Fatal(err)
	}
	plan := verifiedStagePlan(t)
	receipt, _ := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stageSHA("1"), stageSHA("e"), time.Date(2026, 8, 16, 17, 0, 0, 0, time.UTC))
	digest, err := ledger.StoreStageReceipt(context.Background(), plan, receipt, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", digest, []stagereceipt.Verified{}); err != nil {
		t.Fatal(err)
	}
	if api.nonExactRequests.Load() != 0 {
		t.Fatalf("store issued %d non-exact requests", api.nonExactRequests.Load())
	}
	key, err := stageReceiptKey(plan, "provider-prerequisites")
	if err != nil {
		t.Fatal(err)
	}
	name, recordType, err := kubernetesRecordIdentity("stage-receipts", key)
	if err != nil {
		t.Fatal(err)
	}
	if len(name) > 63 || recordType != "stage-receipt" {
		t.Fatalf("stage receipt identity = %s/%s", name, recordType)
	}
}
