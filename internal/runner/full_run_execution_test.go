package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeConcretePreRuntimeExecution struct {
	receipt     PreRuntimeExecutionReceipt
	prefix      []StageReceiptSource
	runErr      error
	prefixErr   error
	runs        int
	prefixCalls int
	target      string
	targetErr   error
	workload    WorkloadAuthorityFileResolverConfig
	workloadErr error
}

func (execution *fakeConcretePreRuntimeExecution) RuntimeTargetIdentity() (string, error) {
	return execution.target, execution.targetErr
}

func (execution *fakeConcretePreRuntimeExecution) RuntimeWorkloadAuthority() (WorkloadAuthorityFileResolverConfig, error) {
	return execution.workload, execution.workloadErr
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
			if bound.TargetRegistration.Expected.TargetIdentityDigest == "" ||
				bound.PlatformApplications.Expected.TargetIdentityDigest != bound.TargetRegistration.Expected.TargetIdentityDigest {
				t.Fatalf("post-runtime suffix did not receive one lifecycle-derived target identity: %#v", bound)
			}
			if bound.TargetCredentialRun.Workload != preRuntime.workload ||
				bound.AggregateEvidence.Runtime.WorkloadTokenFile != preRuntime.workload.TokenFile ||
				bound.AggregateEvidence.Runtime.WorkloadCAFile != preRuntime.workload.CAFile {
				t.Fatalf("post-runtime suffix did not receive one lifecycle-derived workload authority: %#v", bound)
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

func TestFullRunExecutionBindsCapabilityAuthorityBeforeOpeningSuffix(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	binder := &recordingFullRunWorkloadAuthorityBinder{}
	config := testFullRunExecutionConfig()
	config.WorkloadAuthorityBinder = binder
	postCalls := 0
	execution, err := openFullRunExecution(config, fullRunExecutionFactories{
		preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) { return preRuntime, nil },
		postRuntime: func(PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			postCalls++
			if binder.calls != 1 || binder.bound != preRuntime.workload {
				t.Fatalf("suffix opened before exact capability authority binding: %#v", binder)
			}
			return successfulFakePostRuntimeContinuation(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err != nil || receipt.State != "SUCCEEDED" || binder.calls != 1 || postCalls != 1 {
		t.Fatalf("full run did not bind capability authority once: receipt=%#v binder=%#v post=%d err=%v", receipt, binder, postCalls, err)
	}
}

func TestFullRunExecutionStopsBeforeSuffixWhenCapabilityAuthorityBindingFails(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	binder := &recordingFullRunWorkloadAuthorityBinder{err: errors.New("binding rejected")}
	config := testFullRunExecutionConfig()
	config.WorkloadAuthorityBinder = binder
	postCalls := 0
	execution, err := openFullRunExecution(config, fullRunExecutionFactories{
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
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" || len(receipt.Checkpoints) != 7 || binder.calls != 1 || postCalls != 0 {
		t.Fatalf("failed capability binding opened suffix: receipt=%#v binder=%#v post=%d err=%v", receipt, binder, postCalls, err)
	}
}

func TestFullRunExecutionBindsEvidenceIdentityFromExactSixStagePrefix(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	binder := &recordingFullRunEvidenceIdentityBinder{}
	config := testFullRunExecutionConfig()
	config.EvidenceIdentityBinder = binder
	postCalls := 0
	execution, err := openFullRunExecution(config, fullRunExecutionFactories{
		preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) { return preRuntime, nil },
		postRuntime: func(PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			postCalls++
			if binder.calls != 1 || !reflect.DeepEqual(binder.prefix, preRuntime.prefix[:6]) {
				t.Fatalf("suffix opened before exact evidence identity binding: %#v", binder)
			}
			return successfulFakePostRuntimeContinuation(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err != nil || receipt.State != "SUCCEEDED" || binder.calls != 1 || postCalls != 1 {
		t.Fatalf("full run did not bind evidence identity once: receipt=%#v binder=%#v post=%d err=%v", receipt, binder, postCalls, err)
	}
}

func TestFullRunExecutionStopsBeforeSuffixWhenEvidenceIdentityBindingFails(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	binder := &recordingFullRunEvidenceIdentityBinder{err: errors.New("identity rejected")}
	config := testFullRunExecutionConfig()
	config.EvidenceIdentityBinder = binder
	postCalls := 0
	execution, err := openFullRunExecution(config, fullRunExecutionFactories{
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
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" ||
		len(receipt.Checkpoints) != 7 || binder.calls != 1 || postCalls != 0 {
		t.Fatalf("failed evidence identity binding opened suffix: receipt=%#v binder=%#v post=%d err=%v", receipt, binder, postCalls, err)
	}
}

type recordingFullRunWorkloadAuthorityBinder struct {
	bound WorkloadAuthorityFileResolverConfig
	calls int
	err   error
}

type recordingFullRunEvidenceIdentityBinder struct {
	prefix []StageReceiptSource
	calls  int
	err    error
}

func (binder *recordingFullRunEvidenceIdentityBinder) BindFullRunEvidenceIdentity(prefix []StageReceiptSource) error {
	binder.calls++
	binder.prefix = append([]StageReceiptSource(nil), prefix...)
	return binder.err
}

func (binder *recordingFullRunWorkloadAuthorityBinder) BindFullRunWorkloadAuthority(config WorkloadAuthorityFileResolverConfig) error {
	binder.calls++
	binder.bound = config
	return binder.err
}

func TestFullRunExecutionRunsRealPreRuntimeAdapterBeforeOpeningSuffix(t *testing.T) {
	preConfig, preFactories, calls, _ := preRuntimeExecutionFixture(t)
	config := FullRunExecutionConfig{PreRuntime: preConfig}
	config.PostRuntime.TargetCredential.PlanPath = preConfig.PlanPath
	config.PostRuntime.TargetCredential.PlanExpected = preConfig.PlanExpected
	config.PostRuntime.RuntimeBinding.MaterialPath = preConfig.RuntimeBinding.OutputPath
	config.PostRuntime.RuntimeBinding.ReceiptPath = preConfig.RuntimeBindingReceiptPath
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

func TestFullRunExecutionDoesNotOpenSuffixWithoutLifecycleTargetIdentity(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	preRuntime.target = ""
	preRuntime.targetErr = errors.New("missing lifecycle identity")
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
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" ||
		len(receipt.Checkpoints) != 7 || postCalls != 0 {
		t.Fatalf("missing lifecycle identity opened suffix: %#v post=%d err=%v", receipt, postCalls, err)
	}
}

func TestFullRunExecutionDoesNotOpenSuffixWithoutLifecycleWorkloadAuthority(t *testing.T) {
	preRuntime := successfulFakeConcretePreRuntimeExecution(t)
	preRuntime.workload = WorkloadAuthorityFileResolverConfig{}
	preRuntime.workloadErr = errors.New("missing lifecycle workload authority")
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
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-credential" ||
		len(receipt.Checkpoints) != 7 || postCalls != 0 {
		t.Fatalf("missing workload authority opened suffix: %#v post=%d err=%v", receipt, postCalls, err)
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
		"prebound Stage-8 authorization": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetCredential.GrantPath = "/private/stage8-grant.json"
			config.PostRuntime.TargetCredential.GrantPublicKeyPath = "/private/stage8-authority.pub"
			config.PostRuntime.TargetCredential.EvaluationTime = time.Date(2026, 8, 21, 8, 0, 0, 0, time.UTC)
		},
		"foreign plan": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetCredential.PlanPath = "/private/foreign-plan.json"
		},
		"foreign runtime material": func(config *FullRunExecutionConfig) {
			config.PostRuntime.RuntimeBinding.MaterialPath = "/private/foreign-runtime.json"
		},
		"foreign runtime receipt": func(config *FullRunExecutionConfig) {
			config.PostRuntime.RuntimeBinding.ReceiptPath = "/private/foreign-runtime-receipt.json"
		},
		"prefilled registration target": func(config *FullRunExecutionConfig) {
			config.PostRuntime.TargetRegistration.Expected.TargetIdentityDigest = runnerStageSHA("1")
		},
		"prefilled applications target": func(config *FullRunExecutionConfig) {
			config.PostRuntime.PlatformApplications.Expected.TargetIdentityDigest = runnerStageSHA("1")
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
	return &fakeConcretePreRuntimeExecution{
		receipt: receipt, prefix: prefix, target: runnerStageSHA("7"),
		workload: WorkloadAuthorityFileResolverConfig{
			Path: "/private/workload-authority.json", ExpectedBindingDigest: runnerStageSHA("8"),
			TokenFile: "/private/workload-token", CAFile: "/private/workload-ca.crt",
		},
	}
}

func testFullRunExecutionConfig() FullRunExecutionConfig {
	config := FullRunExecutionConfig{}
	config.PreRuntime.PlanPath = "/private/ok147-plan.json"
	config.PreRuntime.RuntimeBinding.OutputPath = "/private/runtime-binding.json"
	config.PreRuntime.RuntimeBindingReceiptPath = "/private/runtime-binding-receipt.json"
	config.PostRuntime.TargetCredential.PlanPath = config.PreRuntime.PlanPath
	config.PostRuntime.TargetCredential.PlanExpected = config.PreRuntime.PlanExpected
	config.PostRuntime.RuntimeBinding.MaterialPath = config.PreRuntime.RuntimeBinding.OutputPath
	config.PostRuntime.RuntimeBinding.ReceiptPath = config.PreRuntime.RuntimeBindingReceiptPath
	return config
}
