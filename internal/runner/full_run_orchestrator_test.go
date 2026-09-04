package runner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openkubes/ok-cluster/internal/execution"
)

type fakePostRuntimeContinuation struct {
	binding PostRuntimeContinuationBinding
	receipt PostRuntimeExecutionReceipt
	err     error
	calls   atomic.Int32
}

type fakePreRuntimeContinuation struct {
	receipt PreRuntimeOrchestrationReceipt
	err     error
}

func (continuation *fakePreRuntimeContinuation) Run(context.Context) (PreRuntimeOrchestrationReceipt, error) {
	return continuation.receipt, continuation.err
}

func (continuation *fakePostRuntimeContinuation) ContinuationBinding() (PostRuntimeContinuationBinding, error) {
	if continuation == nil {
		return PostRuntimeContinuationBinding{}, errors.New("missing continuation")
	}
	return continuation.binding.clone(), nil
}

func (continuation *fakePostRuntimeContinuation) Run(context.Context) (PostRuntimeExecutionReceipt, error) {
	continuation.calls.Add(1)
	return continuation.receipt, continuation.err
}

func TestFullRunOrchestrationComposesExactTwelveStageChainOnce(t *testing.T) {
	calls := []string{}
	continuation := successfulFakePostRuntimeContinuation()
	orchestration := &FullRunOrchestration{
		PreRuntime: successfulPreRuntimeOrchestration(&calls),
		BindPostRuntime: func(_ context.Context, prefix PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			calls = append(calls, "bind-post-runtime")
			if prefix.State != "SUCCEEDED" || len(prefix.Checkpoints) != 7 {
				t.Fatal("post-runtime binder did not receive the completed prefix")
			}
			return continuation, nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := append(append([]string(nil), preRuntimeStageOrder...), "bind-post-runtime")
	if !reflect.DeepEqual(calls, wantCalls) || continuation.calls.Load() != 1 {
		t.Fatalf("unexpected full-run calls: prefix=%v suffix=%d", calls, continuation.calls.Load())
	}
	if receipt.Format != FullRunOrchestrationReceiptFormat || receipt.State != "SUCCEEDED" || receipt.PlanDigest != runnerStageSHA("a") || receipt.StoppedAt != "" || len(receipt.Checkpoints) != 12 {
		t.Fatalf("unexpected full-run receipt: %#v", receipt)
	}
	wantOrder := append(append([]string(nil), preRuntimeStageOrder...), postRuntimeStageOrder...)
	for index, checkpoint := range receipt.Checkpoints {
		if checkpoint.StageID != wantOrder[index] || checkpoint.State != "COMPLETED_SUCCEEDED" {
			t.Fatalf("unexpected checkpoint %d: %#v", index, checkpoint)
		}
	}
	if second, err := orchestration.Run(context.Background()); err == nil || second.State != "STOPPED" || len(calls) != 8 || continuation.calls.Load() != 1 {
		t.Fatalf("single-use full run executed twice: %#v calls=%v suffix=%d err=%v", second, calls, continuation.calls.Load(), err)
	}
}

func TestFullRunOrchestrationAllowsExactlyOneConcurrentInvocation(t *testing.T) {
	continuation := successfulFakePostRuntimeContinuation()
	orchestration := &FullRunOrchestration{
		PreRuntime: successfulPreRuntimeOrchestration(nil),
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			return continuation, nil
		},
	}
	const attempts = 24
	results := make(chan error, attempts)
	var group sync.WaitGroup
	for index := 0; index < attempts; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := orchestration.Run(context.Background())
			results <- err
		}()
	}
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 || continuation.calls.Load() != 1 {
		t.Fatalf("full-run single use was not atomic: succeeded=%d continuationCalls=%d", succeeded, continuation.calls.Load())
	}
}

func TestFullRunOrchestrationStopsBeforeContinuationWhenPrefixStops(t *testing.T) {
	calls := []string{}
	prefix := successfulPreRuntimeOrchestration(&calls)
	prefix.RunProviderPrerequisites = func(context.Context) (execution.StagedOperationReceipt, error) {
		return execution.StagedOperationReceipt{}, errors.New("private failure")
	}
	bindCalls := 0
	orchestration := &FullRunOrchestration{
		PreRuntime: prefix,
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			bindCalls++
			return successfulFakePostRuntimeContinuation(), nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "provider-prerequisites" || len(receipt.Checkpoints) != 0 || bindCalls != 0 {
		t.Fatalf("stopped prefix reached continuation: %#v bindCalls=%d err=%v", receipt, bindCalls, err)
	}
	if !strings.Contains(err.Error(), "private failure") {
		t.Fatalf("prefix failure cause was not preserved: %v", err)
	}
}

func TestFullRunOrchestrationPropagatesPrefixStopCategory(t *testing.T) {
	prefix := successfulPreRuntimeOrchestration(nil)
	prefix.RunNetworkObservation = func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
		return execution.ObservationStageRunReceipt{
			Format: execution.ObservationStageReceiptFormat,
			State:  "PREOBSERVATION", PlanDigest: runnerStageSHA("a"), StageID: "network-observation",
		}, newRedactedObservationError("OBSERVATION_SOURCE_ERROR", "redacted source failure")
	}
	orchestration := &FullRunOrchestration{
		PreRuntime: prefix,
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			t.Fatal("stopped prefix reached continuation")
			return nil, nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.StoppedAt != "network-observation" || receipt.StopCategory != "OBSERVATION_SOURCE_ERROR" || len(receipt.Checkpoints) != 4 {
		t.Fatalf("full-run stop category was not propagated: %#v err=%v", receipt, err)
	}
}

func TestFullRunOrchestrationRejectsUnboundedPrefixStopCategory(t *testing.T) {
	prefix := &fakePreRuntimeContinuation{
		receipt: PreRuntimeOrchestrationReceipt{
			Format: PreRuntimeOrchestrationReceiptFormat, State: "STOPPED", PlanDigest: runnerStageSHA("a"),
			StoppedAt: "provider-prerequisites", StopCategory: "sensitive arbitrary detail",
			Checkpoints: []PreRuntimeStageCheckpoint{},
		},
	}
	orchestration := &FullRunOrchestration{
		PreRuntime: prefix,
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			t.Fatal("invalid prefix reached continuation")
			return nil, nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || strings.Contains(receipt.StopCategory, "sensitive") {
		t.Fatalf("unbounded prefix category was accepted: %#v err=%v", receipt, err)
	}
}

func TestFullRunOrchestrationPreservesCompletedPrefixCheckpointWhenBridgeStops(t *testing.T) {
	prefix := successfulPreRuntimeOrchestration(nil)
	runProvider := prefix.RunProviderPrerequisites
	prefix.RunProviderPrerequisites = func(ctx context.Context) (execution.StagedOperationReceipt, error) {
		receipt, err := runProvider(ctx)
		if err != nil {
			return receipt, err
		}
		return receipt, errors.New("private receipt bridge failure")
	}
	bindCalls := 0
	orchestration := &FullRunOrchestration{
		PreRuntime: prefix,
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			bindCalls++
			return successfulFakePostRuntimeContinuation(), nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "provider-prerequisites" ||
		len(receipt.Checkpoints) != 1 || bindCalls != 0 {
		t.Fatalf("completed prefix checkpoint was not preserved: %#v bindCalls=%d err=%v", receipt, bindCalls, err)
	}
}

func TestFullRunOrchestrationRejectsForeignContinuationBeforeRun(t *testing.T) {
	for name, mutate := range map[string]func(*PostRuntimeContinuationBinding){
		"foreign plan": func(binding *PostRuntimeContinuationBinding) { binding.PlanDigest = runnerStageSHA("f") },
		"foreign receipt": func(binding *PostRuntimeContinuationBinding) {
			binding.Predecessors[6].StageReceiptDigest = runnerStageSHA("f")
		},
		"missing receipt": func(binding *PostRuntimeContinuationBinding) {
			binding.Predecessors = binding.Predecessors[:6]
		},
	} {
		t.Run(name, func(t *testing.T) {
			continuation := successfulFakePostRuntimeContinuation()
			mutate(&continuation.binding)
			orchestration := &FullRunOrchestration{
				PreRuntime: successfulPreRuntimeOrchestration(nil),
				BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
					return continuation, nil
				},
			}
			receipt, err := orchestration.Run(context.Background())
			if err == nil || receipt.StoppedAt != "target-credential" || len(receipt.Checkpoints) != 7 || continuation.calls.Load() != 0 {
				t.Fatalf("foreign continuation ran: %#v calls=%d err=%v", receipt, continuation.calls.Load(), err)
			}
		})
	}
}

func TestFullRunOrchestrationPreservesBoundedSuffixStop(t *testing.T) {
	continuation := successfulFakePostRuntimeContinuation()
	continuation.receipt.State = "STOPPED"
	continuation.receipt.StoppedAt = "platform-applications"
	continuation.receipt.Checkpoints = continuation.receipt.Checkpoints[:2]
	continuation.err = errors.New("private suffix failure")
	orchestration := &FullRunOrchestration{
		PreRuntime: successfulPreRuntimeOrchestration(nil),
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			return continuation, nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "platform-applications" || len(receipt.Checkpoints) != 9 || continuation.calls.Load() != 1 {
		t.Fatalf("suffix stop was not preserved: %#v calls=%d err=%v", receipt, continuation.calls.Load(), err)
	}
}

func TestFullRunOrchestrationPreservesCompletedSuffixCheckpointWhenBridgeStops(t *testing.T) {
	continuation := successfulFakePostRuntimeContinuation()
	continuation.receipt.State = "STOPPED"
	continuation.receipt.StoppedAt = "target-credential"
	continuation.receipt.Checkpoints = continuation.receipt.Checkpoints[:1]
	continuation.err = errors.New("private receipt bridge failure")
	orchestration := &FullRunOrchestration{
		PreRuntime: successfulPreRuntimeOrchestration(nil),
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			return continuation, nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" ||
		len(receipt.Checkpoints) != 8 || continuation.calls.Load() != 1 {
		t.Fatalf("completed suffix checkpoint was not preserved: %#v calls=%d err=%v", receipt, continuation.calls.Load(), err)
	}
}

func TestFullRunOrchestrationRejectsMalformedSuffix(t *testing.T) {
	continuation := successfulFakePostRuntimeContinuation()
	continuation.receipt.Checkpoints[0].StageReceiptDigest = "bad"
	orchestration := &FullRunOrchestration{
		PreRuntime: successfulPreRuntimeOrchestration(nil),
		BindPostRuntime: func(context.Context, PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			return continuation, nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" || len(receipt.Checkpoints) != 7 {
		t.Fatalf("malformed suffix was accepted: %#v err=%v", receipt, err)
	}
}

func TestPostRuntimeExecutionExposesExactVerifiedContinuationBinding(t *testing.T) {
	config, factories, _, _ := postRuntimeExecutionFixture(t)
	executor, err := openPostRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := executor.ContinuationBinding()
	if err != nil {
		t.Fatal(err)
	}
	plan, _, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: config.TargetCredential.PlanPath, PlanExpected: config.TargetCredential.PlanExpected,
		Receipts: config.TargetCredential.Receipts,
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := newPostRuntimeContinuationBinding(plan.PlanDigest, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(binding, want) {
		t.Fatalf("post-runtime binding differs: got=%#v want=%#v", binding, want)
	}
	binding.Predecessors[0].StageID = "changed"
	again, err := executor.ContinuationBinding()
	if err != nil || again.Predecessors[0].StageID != "provider-prerequisites" {
		t.Fatalf("post-runtime binding was not defensively copied: %#v %v", again, err)
	}
}

func successfulFakePostRuntimeContinuation() *fakePostRuntimeContinuation {
	predecessors := make([]PreRuntimeStageCheckpoint, len(preRuntimeStageOrder))
	for index, stageID := range preRuntimeStageOrder {
		predecessors[index] = PreRuntimeStageCheckpoint{
			StageID: stageID, State: "COMPLETED_SUCCEEDED", StageReceiptDigest: runnerStageSHA(string(rune('1' + index))),
		}
	}
	checkpoints := make([]PostRuntimeStageCheckpoint, len(postRuntimeStageOrder))
	digestValues := []string{"8", "9", "b", "c", "d"}
	for index, stageID := range postRuntimeStageOrder {
		checkpoints[index] = PostRuntimeStageCheckpoint{
			StageID: stageID, State: "COMPLETED_SUCCEEDED", StageReceiptDigest: runnerStageSHA(digestValues[index]),
		}
	}
	return &fakePostRuntimeContinuation{
		binding: PostRuntimeContinuationBinding{
			Format: PostRuntimeContinuationBindingFormat, State: postRuntimeContinuationBindingState,
			PlanDigest: runnerStageSHA("a"), Predecessors: predecessors,
		},
		receipt: PostRuntimeExecutionReceipt{
			Format: PostRuntimeExecutionReceiptFormat, State: "SUCCEEDED", PlanDigest: runnerStageSHA("a"),
			Checkpoints: checkpoints, ResolvedAuthorizations: []ResolvedStageAuthorizationReceipt{},
		},
	}
}
