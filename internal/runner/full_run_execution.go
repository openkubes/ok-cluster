package runner

import (
	"context"
	"errors"

	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/projection"
)

// FullRunExecutionConfig binds the two existing concrete execution adapters.
// PostRuntime must not carry a historical receipt prefix or recovery mode: the
// exact seven private sources are supplied only by the completed PreRuntime
// execution in this same single-use run.
type FullRunExecutionConfig struct {
	PreRuntime  PreRuntimeExecutionConfig
	PostRuntime PostRuntimeExecutionConfig
}

type fullRunPreRuntimeExecution interface {
	Run(context.Context) (PreRuntimeExecutionReceipt, error)
	ReceiptPrefix() ([]StageReceiptSource, error)
	RuntimeTargetIdentity() (string, error)
}

type fullRunExecutionFactories struct {
	preRuntime  func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error)
	postRuntime func(PostRuntimeExecutionConfig) (PostRuntimeContinuation, error)
}

type concretePreRuntimeContinuation struct {
	executor fullRunPreRuntimeExecution
}

// FullRunExecution is the concrete, single-use in-process composition of the
// Stage 1-7 and Stage 8-12 adapters. It adds no CLI, Job, retry, rollback or
// cleanup surface.
type FullRunExecution struct {
	orchestration *FullRunOrchestration
}

// OpenFullRunExecution performs bounded local opening of the Stage 1-7
// adapter. The Stage 8-12 adapter is deliberately opened only after all seven
// predecessor receipts have completed and become durable.
func OpenFullRunExecution(config FullRunExecutionConfig) (*FullRunExecution, error) {
	return openFullRunExecution(config, defaultFullRunExecutionFactories())
}

func openFullRunExecution(config FullRunExecutionConfig, factories fullRunExecutionFactories) (*FullRunExecution, error) {
	if factories.preRuntime == nil || factories.postRuntime == nil {
		return nil, errors.New("full-run execution factories are incomplete")
	}
	if config.PreRuntime.PlanPath == "" || config.PostRuntime.TargetCredential.PlanPath != config.PreRuntime.PlanPath ||
		config.PostRuntime.TargetCredential.PlanExpected != config.PreRuntime.PlanExpected {
		return nil, errors.New("full-run execution plan binding differs")
	}
	if config.PreRuntime.RuntimeBinding.OutputPath == "" || config.PreRuntime.RuntimeBindingReceiptPath == "" ||
		config.PostRuntime.RuntimeBinding.MaterialPath != config.PreRuntime.RuntimeBinding.OutputPath ||
		config.PostRuntime.RuntimeBinding.ReceiptPath != config.PreRuntime.RuntimeBindingReceiptPath {
		return nil, errors.New("full-run runtime binding handoff differs")
	}
	if config.PostRuntime.TargetRegistration.Expected.TargetIdentityDigest != "" ||
		config.PostRuntime.PlatformApplications.Expected.TargetIdentityDigest != "" {
		return nil, errors.New("full-run target identity must originate at lifecycle execution")
	}
	if len(config.PostRuntime.TargetCredential.Receipts) != 0 || config.PostRuntime.TargetCredentialRecovery != nil ||
		config.PostRuntime.TargetRegistrationRecovery != nil {
		return nil, errors.New("full-run execution requires a fresh unbound post-runtime suffix")
	}

	preRuntime, err := factories.preRuntime(config.PreRuntime)
	if err != nil || preRuntime == nil {
		return nil, errors.New("open full-run pre-runtime execution")
	}
	postRuntime := clonePostRuntimeExecutionConfigForFullRun(config.PostRuntime)
	prefix := &concretePreRuntimeContinuation{executor: preRuntime}
	orchestration := &FullRunOrchestration{
		PreRuntime: prefix,
		BindPostRuntime: func(completed PreRuntimeOrchestrationReceipt) (PostRuntimeContinuation, error) {
			privatePrefix, prefixErr := preRuntime.ReceiptPrefix()
			if prefixErr != nil || len(privatePrefix) != len(completed.Checkpoints) || len(privatePrefix) != len(preRuntimeStageOrder) {
				return nil, errors.New("load full-run private receipt prefix")
			}
			for index := range privatePrefix {
				if privatePrefix[index].Digest != completed.Checkpoints[index].StageReceiptDigest {
					return nil, errors.New("full-run private receipt prefix differs from completed execution")
				}
			}
			targetIdentity, targetErr := preRuntime.RuntimeTargetIdentity()
			if targetErr != nil || !stageReceiptPrefixDigestPattern.MatchString(targetIdentity) {
				return nil, errors.New("full-run lifecycle target identity is unavailable")
			}
			bound := clonePostRuntimeExecutionConfigForFullRun(postRuntime)
			bound.TargetCredential.Receipts = append([]StageReceiptSource(nil), privatePrefix...)
			bound.TargetRegistration.Expected.TargetIdentityDigest = targetIdentity
			bound.PlatformApplications.Expected.TargetIdentityDigest = targetIdentity
			continuation, openErr := factories.postRuntime(bound)
			if openErr != nil || continuation == nil {
				return nil, errors.New("open full-run post-runtime execution")
			}
			return continuation, nil
		},
	}
	return &FullRunExecution{orchestration: orchestration}, nil
}

func (execution *FullRunExecution) Run(ctx context.Context) (FullRunOrchestrationReceipt, error) {
	if execution == nil || execution.orchestration == nil {
		receipt := FullRunOrchestrationReceipt{
			Format: FullRunOrchestrationReceiptFormat, State: "RUNNING", Checkpoints: []FullRunStageCheckpoint{},
		}
		return stopFullRunOrchestration(receipt, fullRunOrchestrationInitialStoppedStage)
	}
	return execution.orchestration.Run(ctx)
}

func (continuation *concretePreRuntimeContinuation) Run(ctx context.Context) (PreRuntimeOrchestrationReceipt, error) {
	if continuation == nil || continuation.executor == nil {
		return PreRuntimeOrchestrationReceipt{}, errors.New("concrete pre-runtime execution is unavailable")
	}
	receipt, err := continuation.executor.Run(ctx)
	converted := PreRuntimeOrchestrationReceipt{
		Format: receipt.Format, State: receipt.State, PlanDigest: receipt.PlanDigest, StoppedAt: receipt.StoppedAt,
		Checkpoints: append([]PreRuntimeStageCheckpoint(nil), receipt.Checkpoints...),
	}
	if receipt.Format == PreRuntimeExecutionReceiptFormat {
		converted.Format = PreRuntimeOrchestrationReceiptFormat
	}
	return converted, err
}

func defaultFullRunExecutionFactories() fullRunExecutionFactories {
	return fullRunExecutionFactories{
		preRuntime: func(config PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) {
			return OpenPreRuntimeExecution(config)
		},
		postRuntime: func(config PostRuntimeExecutionConfig) (PostRuntimeContinuation, error) {
			return OpenPostRuntimeExecution(config)
		},
	}
}

func clonePostRuntimeExecutionConfigForFullRun(config PostRuntimeExecutionConfig) PostRuntimeExecutionConfig {
	config.TargetCredential.Receipts = append([]StageReceiptSource(nil), config.TargetCredential.Receipts...)
	config.TargetCredential.TargetAccessExpectedObjects = append([]projection.ResourceIdentity(nil), config.TargetCredential.TargetAccessExpectedObjects...)
	config.TargetRegistration.Expected.TargetNamespaces = append([]string(nil), config.TargetRegistration.Expected.TargetNamespaces...)
	config.PlatformApplications.Expected.Profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), config.PlatformApplications.Expected.Profile.RequiredApplications...)
	config.PlatformObservation.Profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), config.PlatformObservation.Profile.RequiredApplications...)
	config.AggregateEvidence.Profile.Required = append([]string(nil), config.AggregateEvidence.Profile.Required...)
	return config
}
