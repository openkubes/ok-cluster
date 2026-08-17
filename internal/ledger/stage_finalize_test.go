package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestFinalizeStageReceiptBridgesDurableOutcome(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	grant := verifiedStageGrantFor(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	claim, err := store.ClaimStage(context.Background(), grant, at)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := store.CompleteStage(context.Background(), claim, "SUCCEEDED", "ATTEMPTED", stageSHA("e"), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := store.InspectStage(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.FinalizeStageReceipt(context.Background(), plan, grant, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verified.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != outcome.Outcome || receipt.MutationState != outcome.MutationState || receipt.OperationOutcomeDigest != inspection.OutcomeDigest || receipt.EvidenceDigest != outcome.EvidenceDigest || receipt.CompletedAt != outcome.CompletedAt {
		t.Fatalf("final receipt does not bind durable outcome: %#v", receipt)
	}
	digest, _ := verified.Digest()
	if _, err := store.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", digest, []stagereceipt.Verified{}); err != nil {
		t.Fatal(err)
	}
	if replay, err := store.FinalizeStageReceipt(context.Background(), plan, grant, []stagereceipt.Verified{}); err != nil {
		t.Fatal(err)
	} else if replayDigest, _ := replay.Digest(); replayDigest != digest {
		t.Fatal("idempotent finalization changed receipt identity")
	}
}

func TestFinalizeStageReceiptRequiresCompletedOutcome(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "ledger"))
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	grant := verifiedStageGrantFor(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	if _, err := store.ClaimStage(context.Background(), grant, at); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeStageReceipt(context.Background(), plan, grant, []stagereceipt.Verified{}); err == nil {
		t.Fatal("claimed but incomplete stage produced a final receipt")
	}
}

func TestFinalizeStageReceiptRejectsDifferentPredecessorChain(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "ledger"))
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	bound, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stageSHA("1"), stageSHA("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	other, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stageSHA("2"), stageSHA("b"), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	grant := verifiedStageGrantFor(t, plan, "cluster-lifecycle", []stagereceipt.Verified{bound}, at.Add(2*time.Second))
	claim, err := store.ClaimStage(context.Background(), grant, at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteStage(context.Background(), claim, "SUCCEEDED", "ATTEMPTED", stageSHA("e"), at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeStageReceipt(context.Background(), plan, grant, []stagereceipt.Verified{other}); err == nil {
		t.Fatal("stage outcome was finalized against a different predecessor receipt")
	}
}

func TestFinalizeLifecycleReceiptCarriesOnlyTargetUIDDigest(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "ledger"))
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stageSHA("1"), stageSHA("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	grant := verifiedStageGrantFor(t, plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, at.Add(time.Second))
	claim, err := store.ClaimStage(context.Background(), grant, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	const rawUID = "cluster-runtime-uid-147"
	targetDigest := digest.SHA256([]byte(rawUID))
	outcome, err := store.CompleteStageWithTarget(context.Background(), claim, "SUCCEEDED", "ATTEMPTED", stageSHA("e"), targetDigest, at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.FinalizeStageReceipt(context.Background(), plan, grant, []stagereceipt.Verified{provider})
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := verified.Receipt()
	if outcome.TargetClusterUIDDigest != targetDigest || receipt.TargetClusterUIDDigest != targetDigest {
		t.Fatalf("target identity digest did not survive finalization: %#v %#v", outcome, receipt)
	}
	for _, value := range []any{outcome, receipt} {
		raw, _ := json.Marshal(value)
		if bytes.Contains(raw, []byte(rawUID)) {
			t.Fatalf("raw target UID escaped into redaction-safe evidence: %s", raw)
		}
	}
	receiptDigest, _ := verified.Digest()
	loaded, err := store.LoadStageReceipt(context.Background(), plan, "cluster-lifecycle", receiptDigest, []stagereceipt.Verified{provider})
	if err != nil {
		t.Fatal(err)
	}
	loadedReceipt, _ := loaded.Receipt()
	if loadedReceipt.TargetClusterUIDDigest != targetDigest {
		t.Fatal("persisted target identity digest was lost on restart")
	}
}

func TestCompleteStageRejectsTargetBindingOutsideLifecycleSuccess(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "ledger"))
	plan := verifiedStagePlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	grant := verifiedStageGrantFor(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	claim, _ := store.ClaimStage(context.Background(), grant, at)
	if _, err := store.CompleteStageWithTarget(context.Background(), claim, "SUCCEEDED", "ATTEMPTED", stageSHA("e"), stageSHA("7"), at.Add(time.Second)); err == nil {
		t.Fatal("provider stage accepted a target Cluster identity binding")
	}
}
