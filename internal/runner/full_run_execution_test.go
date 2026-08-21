package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeConcretePreRuntimeExecution struct {
	receipt     PreRuntimeExecutionReceipt
	prefix      []StageReceiptSource
	runErr      error
	prefixErr   error
	runs        int
	prefixCalls int
}

func (execution *fakeConcretePreRuntimeExecution) Run(context.Context) (PreRuntimeExecutionReceipt, error) {
	execution.runs++
	return execution.receipt, execution.runErr
}

func (execution *fakeConcretePreRuntimeExecution) ReceiptPrefix() ([]StageReceiptSource, error) {
	execution.prefixCalls++
	return append([]StageReceiptSource(nil), execution.prefix...), execution.prefixErr
}

func TestFullRunExecutionComposesConcreteAdaptersWithExactPrivatePrefix(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	postRuntime := successfulFakePostRuntimeContinuation()
	postCalls := 0
	config := testFullRunExecutionConfig()
	execution, err := openFullRunExecution(config, fullRunExecutionFactories{
		preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) {
			return preRuntime, nil
		},
		postRuntime: func(bound PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			postCalls++
			if preRuntime.runs != 1 || preRuntime.prefixCalls != 1 || !reflect.DeepEqual(bound.TargetCredential.Receipts, preRuntime.prefix) {
				t.Fatalf("post-runtime suffix did not receive the completed private prefix: %#v", bound.TargetCredential.Receipts)
			}
			return postRuntime, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != FullRunOrchestrationReceiptFormat || receipt.State != "SUCCEEDED" || len(receipt.Checkpoints) != 12 ||
		preRuntime.runs != 1 || preRuntime.prefixCalls != 1 || postCalls != 1 || postRuntime.calls.Load() != 1 {
		t.Fatalf("unexpected concrete full-run result: %#v pre=%d prefix=%d post=%d suffix=%d", receipt, preRuntime.runs, preRuntime.prefixCalls, postCalls, postRuntime.calls.Load())
	}
	if second, secondErr := execution.Run(context.Background()); secondErr == nil || second.State != "STOPPED" ||
		preRuntime.runs != 1 || postCalls != 1 || postRuntime.calls.Load() != 1 {
		t.Fatalf("concrete full-run execution was replayed: %#v err=%v", second, secondErr)
	}
}

func TestFullRunExecutionRunsRealPreRuntimeAdapterBeforeOpeningSuffix(t *testing.T) {
	preConfig, preFactories, calls, _ := preRuntimeExecutionFixture(t)
	config := FullRunExecutionConfig{PreRuntime: preConfig}
	config.PostRuntime.TargetCredential.PlanPath = preConfig.PlanPath
	config.PostRuntime.TargetCredential.PlanExpected = preConfig.PlanExpected
	postCalls := 0
	execution, err := openFullRunExecution(config, fullRunExecutionFactories{
		preRuntime: func(config PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) {
			return openPreRuntimeExecution(config, preFactories)
		},
		postRuntime: func(bound PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			postCalls++
			plan, _, prefix, loadErr := loadStageResumeWithPrefix(StageResumeConfig{
				PlanPath: bound.TargetCredential.PlanPath, PlanExpected: bound.TargetCredential.PlanExpected,
				Receipts: bound.TargetCredential.Receipts,
			})
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			binding, bindErr := newPostRuntimeContinuationBinding(plan.PlanDigest, prefix)
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			continuation := successfulFakePostRuntimeContinuation()
			continuation.binding = binding
			continuation.receipt.PlanDigest = binding.PlanDigest
			return continuation, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err != nil || receipt.State != "SUCCEEDED" || len(receipt.Checkpoints) != 12 ||
		!reflect.DeepEqual(*calls, preRuntimeStageOrder) || postCalls != 1 {
		t.Fatalf("real pre-runtime adapter did not compose: %#v calls=%v post=%d err=%v", receipt, *calls, postCalls, err)
	}
}

func TestFullRunExecutionDoesNotOpenSuffixAfterStoppedPrefix(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	preRuntime.receipt.State = "STOPPED"
	preRuntime.receipt.StoppedAt = "enablement"
	preRuntime.receipt.Checkpoints = preRuntime.receipt.Checkpoints[:3]
	preRuntime.runErr = errors.New("private prefix failure")
	postCalls := 0
	execution, err := openFullRunExecution(testFullRunExecutionConfig(), fullRunExecutionFactories{
		preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) { return preRuntime, nil },
		postRuntime: func(PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			postCalls++
			return successfulFakePostRuntimeContinuation(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "enablement" || len(receipt.Checkpoints) != 3 ||
		preRuntime.prefixCalls != 0 || postCalls != 0 {
		t.Fatalf("stopped concrete prefix opened the suffix: %#v prefix=%d post=%d err=%v", receipt, preRuntime.prefixCalls, postCalls, err)
	}
}

func TestFullRunExecutionRejectsPrivatePrefixDifferentFromPublicCheckpoints(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	preRuntime.prefix[6].Digest = runnerStageSHA("f")
	postCalls := 0
	execution, err := openFullRunExecution(testFullRunExecutionConfig(), fullRunExecutionFactories{
		preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) { return preRuntime, nil },
		postRuntime: func(PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			postCalls++
			return successfulFakePostRuntimeContinuation(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" || len(receipt.Checkpoints) != 7 || postCalls != 0 {
		t.Fatalf("foreign private prefix opened the suffix: %#v post=%d err=%v", receipt, postCalls, err)
	}
}

func TestOpenFullRunExecutionRejectsHistoricalSuffixState(t *testing.T) {
	for name, mutate := range map[string]func(*FullRunExecutionConfig){
		"prebound receipts": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetCredential.Receipts = []StageReceiptSource{{Path: "/private/receipt.json", Digest: runnerStageSHA("1")}}
		},
		"credential recovery": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetCredentialRecovery = &PostRuntimeTargetCredentialRecoveryConfig{}
		},
		"registration recovery": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetRegistrationRecovery = &PostRuntimeTargetRegistrationRecoveryConfig{}
		},
		"foreign plan": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetCredential.PlanPath = "/private/foreign-plan.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := testFullRunExecutionConfig()
			mutate(&config)
			preCalls := 0
			if _, err := openFullRunExecution(config, fullRunExecutionFactories{
				preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) {
					preCalls++
					return successfulFakeConcretePreRuntimeExecution(t), nil
				},
				postRuntime: func(PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
					return successfulFakePostRuntimeContinuation(), nil
				},
			}); err == nil || preCalls != 0 {
				t.Fatalf("unsafe full-run suffix was accepted: preCalls=%d err=%v", preCalls, err)
			}
		})
	}
}

func successfulFakeConcretePreRuntimeExecution(t *testing.T) *fakeConcretePreRuntimeExecution {
	t.Helper()
	orchestrationReceipt, err := successfulPreRuntimeOrchestration(nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt := PreRuntimeExecutionReceipt{
		Format: PreRuntimeExecutionReceiptFormat, State: orchestrationReceipt.State, PlanDigest: orchestrationReceipt.PlanDigest,
		StoppedAt: orchestrationReceipt.StoppedAt, Checkpoints: append([]PreRuntimeStageCheckpoint(nil), orchestrationReceipt.Checkpoints...),
		ResolvedAuthorizations: []ResolvedStageAuthorizationReceipt{},
	}
	prefix := make([]StageReceiptSource, len(receipt.Checkpoints))
	for index, checkpoint := range receipt.Checkpoints {
		prefix[index] = StageReceiptSource{Path: "/private/" + checkpoint.StageID + ".json", Digest: checkpoint.StageReceiptDigest}
	}
	return &fakeConcretePreRuntimeExecution{receipt: receipt, prefix: prefix}
}

func testFullRunExecutionConfig() FullRunExecutionConfig {
	config := FullRunExecutionConfig{}
	config.PreRuntime.PlanPath = "/private/ok147-plan.json"
	config.PostRuntime.TargetCredential.PlanPath = config.PreRuntime.PlanPath
	config.PostRuntime.TargetCredential.PlanExpected = config.PreRuntime.PlanExpected
	return config
}
