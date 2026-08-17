package execution

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestBindingStagePersistsAndResumesWithoutRebinding(t *testing.T) {
	plan, cursor, at := runtimeBindingCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	binder := &fakeStageBinder{
		binding: binderBinding(t, plan, "runtime-binding"),
		result:  StageBindingResult{Outcome: "SUCCEEDED", EvidenceDigest: stagedSHA("e"), CompletedAt: at},
	}
	operation := BindingStageOperation{Ledger: store, Binder: binder}
	first, err := operation.Run(context.Background(), plan, cursor)
	if err != nil || first.State != "COMPLETED_SUCCEEDED" || first.StageReceiptDigest == "" || binder.calls != 1 {
		t.Fatalf("unexpected binding run: %#v calls=%d err=%v", first, binder.calls, err)
	}
	replayed, err := operation.Run(context.Background(), plan, cursor)
	if err != nil || replayed != first || binder.calls != 1 {
		t.Fatalf("persisted binding was executed again: %#v calls=%d err=%v", replayed, binder.calls, err)
	}
}

func TestBindingStagePersistsTerminalResultWithoutRawError(t *testing.T) {
	plan, cursor, at := runtimeBindingCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	binder := &fakeStageBinder{
		binding: binderBinding(t, plan, "runtime-binding"),
		result:  StageBindingResult{Outcome: "STOPPED", EvidenceDigest: stagedSHA("f"), CompletedAt: at},
	}
	receipt, err := (BindingStageOperation{Ledger: store, Binder: binder}).Run(context.Background(), plan, cursor)
	var resultErr *BindingStageResultError
	if !errors.As(err, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("terminal binding was not retained: %#v %v", receipt, err)
	}
}

func TestBindingStageFailsClosedBeforePersistence(t *testing.T) {
	plan, cursor, at := runtimeBindingCursor(t)
	for name, mutate := range map[string]func(*fakeStageBinder){
		"foreign binding": func(binder *fakeStageBinder) { binder.binding.Authority = "workload" },
		"raw failure":     func(binder *fakeStageBinder) { binder.err = errors.New("sensitive endpoint detail") },
		"bad evidence":    func(binder *fakeStageBinder) { binder.result.EvidenceDigest = "invalid" },
		"missing time":    func(binder *fakeStageBinder) { binder.result.CompletedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
			binder := &fakeStageBinder{
				binding: binderBinding(t, plan, "runtime-binding"),
				result:  StageBindingResult{Outcome: "SUCCEEDED", EvidenceDigest: stagedSHA("e"), CompletedAt: at},
			}
			mutate(binder)
			receipt, err := (BindingStageOperation{Ledger: store, Binder: binder}).Run(context.Background(), plan, cursor)
			if err == nil || strings.Contains(err.Error(), "sensitive") || receipt.StageReceiptDigest != "" {
				t.Fatalf("unsafe binding result was accepted: %#v %v", receipt, err)
			}
		})
	}
}

func TestBindingStageRejectsObservationCursor(t *testing.T) {
	plan, cursor, _ := lifecycleObservationCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	binder := &fakeStageBinder{}
	if _, err := (BindingStageOperation{Ledger: store, Binder: binder}).Run(context.Background(), plan, cursor); err == nil || binder.calls != 0 {
		t.Fatalf("observation cursor reached binder: calls=%d err=%v", binder.calls, err)
	}
}

type fakeStageBinder struct {
	binding StageBinderBinding
	result  StageBindingResult
	err     error
	calls   int
}

func (binder *fakeStageBinder) Binding() StageBinderBinding { return binder.binding }

func (binder *fakeStageBinder) Bind(context.Context) (StageBindingResult, error) {
	binder.calls++
	return binder.result, binder.err
}

func runtimeBindingCursor(t *testing.T) (stageplan.Binding, stagecursor.Cursor, time.Time) {
	t.Helper()
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC)
	provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stagedSHA("1"), stagedSHA("a"), at.Add(-5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := stagereceipt.NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", stagedSHA("2"), stagedSHA("b"), stagedSHA("7"), at.Add(-4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lifecycleObservation, err := stagereceipt.New(plan, "lifecycle-observation", []stagereceipt.Verified{lifecycle}, "SUCCEEDED", "NOT_APPLICABLE", "", stagedSHA("c"), at.Add(-3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	enablement, err := stagereceipt.New(plan, "enablement", []stagereceipt.Verified{lifecycleObservation}, "SUCCEEDED", "ATTEMPTED", stagedSHA("3"), stagedSHA("d"), at.Add(-2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	network, err := stagereceipt.New(plan, "network-observation", []stagereceipt.Verified{enablement}, "SUCCEEDED", "NOT_APPLICABLE", "", stagedSHA("e"), at.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{provider, lifecycle, lifecycleObservation, enablement, network})
	if err != nil {
		t.Fatal(err)
	}
	return plan, cursor, at
}

func binderBinding(t *testing.T, plan stageplan.Binding, stageID string) StageBinderBinding {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	return StageBinderBinding{PlanDigest: plan.PlanDigest, StageID: stageID, StageDigest: stageDigest, Authority: stage.Authority, ContractRevision: plan.IntentRevision}
}
