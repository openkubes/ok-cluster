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

func TestObservationStagePersistsAndResumesWithoutReobservation(t *testing.T) {
	plan, cursor, at := lifecycleObservationCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	observer := &fakeStageObserver{
		binding: observationBinding(t, plan, "lifecycle-observation"),
		result:  StageObservationResult{Outcome: "SUCCEEDED", EvidenceDigest: stagedSHA("e"), CompletedAt: at},
	}
	operation := ObservationStageOperation{Ledger: store, Observer: observer}
	first, err := operation.Run(context.Background(), plan, cursor)
	if err != nil || first.State != "COMPLETED_SUCCEEDED" || first.StageReceiptDigest == "" || observer.calls != 1 {
		t.Fatalf("unexpected observation run: %#v calls=%d err=%v", first, observer.calls, err)
	}
	replayed, err := operation.Run(context.Background(), plan, cursor)
	if err != nil || replayed != first || observer.calls != 1 {
		t.Fatalf("persisted observation was executed again: %#v calls=%d err=%v", replayed, observer.calls, err)
	}
}

func TestObservationStagePersistsTerminalResultWithoutRawError(t *testing.T) {
	plan, cursor, at := lifecycleObservationCursor(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	observer := &fakeStageObserver{
		binding: observationBinding(t, plan, "lifecycle-observation"),
		result:  StageObservationResult{Outcome: "STOPPED", EvidenceDigest: stagedSHA("f"), CompletedAt: at},
	}
	receipt, err := (ObservationStageOperation{Ledger: store, Observer: observer}).Run(context.Background(), plan, cursor)
	var resultErr *ObservationStageResultError
	if !errors.As(err, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("terminal observation was not retained: %#v %v", receipt, err)
	}
}

func TestObservationStageFailsClosedBeforePersistence(t *testing.T) {
	plan, cursor, at := lifecycleObservationCursor(t)
	for name, mutate := range map[string]func(*fakeStageObserver){
		"foreign binding": func(observer *fakeStageObserver) { observer.binding.Authority = "workload" },
		"raw failure":     func(observer *fakeStageObserver) { observer.err = errors.New("sensitive endpoint detail") },
		"bad result":      func(observer *fakeStageObserver) { observer.result.EvidenceDigest = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
			observer := &fakeStageObserver{
				binding: observationBinding(t, plan, "lifecycle-observation"),
				result:  StageObservationResult{Outcome: "SUCCEEDED", EvidenceDigest: stagedSHA("e"), CompletedAt: at},
			}
			mutate(observer)
			receipt, err := (ObservationStageOperation{Ledger: store, Observer: observer}).Run(context.Background(), plan, cursor)
			if err == nil || strings.Contains(err.Error(), "sensitive") || receipt.StageReceiptDigest != "" {
				t.Fatalf("unsafe observation result was accepted: %#v %v", receipt, err)
			}
		})
	}
}

func TestObservationStageRejectsMutatingCursor(t *testing.T) {
	plan := stagedPlan(t)
	cursor, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{})
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	observer := &fakeStageObserver{}
	if _, err := (ObservationStageOperation{Ledger: store, Observer: observer}).Run(context.Background(), plan, cursor); err == nil || observer.calls != 0 {
		t.Fatalf("mutating cursor reached observer: calls=%d err=%v", observer.calls, err)
	}
}

type fakeStageObserver struct {
	binding StageObservationBinding
	result  StageObservationResult
	err     error
	calls   int
}

func (observer *fakeStageObserver) Binding() StageObservationBinding { return observer.binding }

func (observer *fakeStageObserver) Observe(context.Context) (StageObservationResult, error) {
	observer.calls++
	return observer.result, observer.err
}

func lifecycleObservationCursor(t *testing.T) (stageplan.Binding, stagecursor.Cursor, time.Time) {
	t.Helper()
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 19, 0, 0, 0, time.UTC)
	provider, _ := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stagedSHA("1"), stagedSHA("a"), at.Add(-2*time.Second))
	lifecycle, err := stagereceipt.NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", stagedSHA("2"), stagedSHA("b"), stagedSHA("7"), at.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{provider, lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	return plan, cursor, at
}

func observationBinding(t *testing.T, plan stageplan.Binding, stageID string) StageObservationBinding {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	return StageObservationBinding{PlanDigest: plan.PlanDigest, StageID: stageID, StageDigest: stageDigest, Authority: stage.Authority, ContractRevision: plan.IntentRevision}
}
