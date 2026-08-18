package runner

import (
	"context"
	"errors"
	"path/filepath"
	"sync"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const PostRuntimeExecutionReceiptFormat = "ok147-post-runtime-execution-receipt/v1"

var postRuntimeReceiptFiles = map[string]string{
	"target-credential":     "08-target-credential.json",
	"target-registration":   "09-target-registration.json",
	"platform-applications": "10-platform-applications.json",
	"platform-observation":  "11-platform-observation.json",
}

type PostRuntimeTargetRegistrationConfig struct {
	ArtifactPath string
	Expected     submission.TargetRegistrationExpected
	Runtime      TargetRegistrationStageHandoffRuntimeConfig
}

type PostRuntimePlatformApplicationsConfig struct {
	ArtifactPath string
	Expected     submission.PlatformApplicationsExpected
	Runtime      PlatformApplicationsStageRuntimeConfig
}

type PostRuntimePlatformObservationConfig struct {
	Profile observation.PlatformProfile
	Runtime PlatformObservationStageFileRuntimeConfig
}

type PostRuntimeAggregateEvidenceConfig struct {
	Profile AggregateEvidenceProfile
	Runtime AggregateEvidenceStageFileRuntimeConfig
}

// PostRuntimeExecutionConfig supplies immutable artifacts and private runtime
// bindings for exactly Stage 8-12. The Stage-8 grant is already part of its
// verified bundle; later mutating grants are resolved only after their direct
// predecessor receipt is durable.
type PostRuntimeExecutionConfig struct {
	TargetCredential     TargetCredentialStageBundleConfig
	TargetCredentialRun  TargetCredentialStageRuntimeConfig
	Authorization        StageAuthorizationResolver
	TargetRegistration   PostRuntimeTargetRegistrationConfig
	PlatformApplications PostRuntimePlatformApplicationsConfig
	PlatformObservation  PostRuntimePlatformObservationConfig
	AggregateEvidence    PostRuntimeAggregateEvidenceConfig
	RuntimeBinding       RuntimeBindingMaterialFileConfig
	ReceiptDirectory     string
}

type PostRuntimeExecutionReceipt struct {
	Format                 string                              `json:"format"`
	State                  string                              `json:"state"`
	PlanDigest             string                              `json:"planDigest,omitempty"`
	StoppedAt              string                              `json:"stoppedAt,omitempty"`
	Checkpoints            []PostRuntimeStageCheckpoint        `json:"checkpoints"`
	ResolvedAuthorizations []ResolvedStageAuthorizationReceipt `json:"resolvedAuthorizations"`
}

type postRuntimeCredentialInvocation struct {
	run    func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error)
	ledger *ledger.Ledger
}

type postRuntimeStagedInvocation struct {
	run    func(context.Context) (execution.StagedOperationReceipt, error)
	ledger *ledger.Ledger
}

type postRuntimeObservationInvocation struct {
	run    func(context.Context) (execution.ObservationStageRunReceipt, error)
	ledger *ledger.Ledger
}

type postRuntimeEvaluationInvocation struct {
	run func(context.Context) (execution.EvaluationStageRunReceipt, error)
}

type postRuntimeExecutionFactories struct {
	credential   func(TargetCredentialStageBundleConfig, TargetCredentialStageRuntimeConfig) (postRuntimeCredentialInvocation, error)
	registration func(StageResumeConfig, *VerifiedTargetCredentialStageHandoff, StageAuthorizationSource, PostRuntimeTargetRegistrationConfig, VerifiedRuntimeBindingMaterial) (postRuntimeStagedInvocation, error)
	applications func(StageResumeConfig, StageAuthorizationSource, PostRuntimePlatformApplicationsConfig) (postRuntimeStagedInvocation, error)
	observation  func(StageResumeConfig, PostRuntimePlatformObservationConfig) (postRuntimeObservationInvocation, error)
	aggregate    func(StageResumeConfig, PostRuntimeAggregateEvidenceConfig, VerifiedRuntimeBindingMaterial) (postRuntimeEvaluationInvocation, error)
}

type PostRuntimeExecution struct {
	config     PostRuntimeExecutionConfig
	initial    StageResumeConfig
	runtime    VerifiedRuntimeBindingMaterial
	credential postRuntimeCredentialInvocation
	factories  postRuntimeExecutionFactories
	mu         sync.Mutex
	used       bool
}

// OpenPostRuntimeExecution performs bounded local loading only. It opens
// credential clients but performs no ledger or Kubernetes request and writes
// no receipt.
func OpenPostRuntimeExecution(config PostRuntimeExecutionConfig) (*PostRuntimeExecution, error) {
	return openPostRuntimeExecution(config, defaultPostRuntimeExecutionFactories())
}

func openPostRuntimeExecution(config PostRuntimeExecutionConfig, factories postRuntimeExecutionFactories) (*PostRuntimeExecution, error) {
	if config.Authorization == nil || config.ReceiptDirectory == "" || factories.credential == nil || factories.registration == nil ||
		factories.applications == nil || factories.observation == nil || factories.aggregate == nil {
		return nil, errors.New("post-runtime execution configuration is incomplete")
	}
	initial := StageResumeConfig{
		PlanPath: config.TargetCredential.PlanPath, PlanExpected: config.TargetCredential.PlanExpected,
		Receipts: append([]StageReceiptSource(nil), config.TargetCredential.Receipts...),
	}
	decision, err := InspectStageResume(initial)
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-credential" || len(initial.Receipts) != 7 {
		return nil, errors.New("post-runtime execution requires the exact Stage-8 cursor")
	}
	for _, stageID := range postRuntimeStageOrder[:4] {
		if err := validateRuntimeBindingOutputPath(filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles[stageID])); err != nil {
			return nil, errors.New("post-runtime receipt destination is invalid")
		}
	}
	runtimeConfig := config.RuntimeBinding
	runtimeConfig.Bundle = initial
	runtime, err := LoadRuntimeBindingMaterialFiles(runtimeConfig)
	if err != nil {
		return nil, errors.New("load post-runtime execution binding")
	}
	credential, err := factories.credential(config.TargetCredential, config.TargetCredentialRun)
	if err != nil || credential.run == nil || credential.ledger == nil {
		return nil, errors.New("open post-runtime target credential stage")
	}
	config.TargetCredential.Receipts = append([]StageReceiptSource(nil), initial.Receipts...)
	config.PlatformObservation.Profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), config.PlatformObservation.Profile.RequiredApplications...)
	config.PlatformObservation.Runtime.RuntimeMaterialPath = config.RuntimeBinding.MaterialPath
	config.PlatformObservation.Runtime.RuntimeReceiptPath = config.RuntimeBinding.ReceiptPath
	config.AggregateEvidence.Profile.Required = append([]string(nil), config.AggregateEvidence.Profile.Required...)
	config.AggregateEvidence.Runtime.RuntimeMaterialPath = config.RuntimeBinding.MaterialPath
	config.AggregateEvidence.Runtime.RuntimeReceiptPath = config.RuntimeBinding.ReceiptPath
	return &PostRuntimeExecution{
		config: config, initial: initial, runtime: runtime, credential: credential, factories: factories,
	}, nil
}

// Run executes exactly one Stage 8-12 suffix. It persists only canonical
// redaction-safe Stage 8-11 receipts and has no retry, rollback or cleanup
// path. A second invocation is rejected before any stage or authority call.
func (executor *PostRuntimeExecution) Run(ctx context.Context) (PostRuntimeExecutionReceipt, error) {
	if executor == nil {
		return stoppedPostRuntimeExecutionReceipt("target-credential", nil, nil), errors.New("post-runtime execution is required")
	}
	executor.mu.Lock()
	if executor.used {
		executor.mu.Unlock()
		return stoppedPostRuntimeExecutionReceipt("target-credential", nil, nil), errors.New("post-runtime execution is single-use")
	}
	executor.used = true
	executor.mu.Unlock()

	receipts := append([]StageReceiptSource(nil), executor.initial.Receipts...)
	authorizations := []ResolvedStageAuthorizationReceipt{}
	orchestration := PostRuntimeOrchestration{}
	orchestration.RunTargetCredential = func(ctx context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
		runReceipt, handoff, err := executor.credential.run(ctx)
		if err != nil {
			return runReceipt, handoff, err
		}
		source, err := executor.bridgeStagedReceipt(ctx, receipts, executor.credential.ledger, runReceipt)
		if err != nil {
			return runReceipt, handoff, err
		}
		receipts = append(receipts, source)
		return runReceipt, handoff, nil
	}
	orchestration.RunTargetRegistration = func(ctx context.Context, handoff *VerifiedTargetCredentialStageHandoff, _ execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
		resolved, err := ResolveStageAuthorization(ctx, executor.resume(receipts), executor.config.Authorization)
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		source, err := resolved.Source()
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		invocation, err := executor.factories.registration(executor.resume(receipts), handoff, source, executor.config.TargetRegistration, executor.runtime)
		if err != nil || invocation.run == nil || invocation.ledger == nil {
			return execution.StagedOperationReceipt{}, errors.New("open post-runtime target registration stage")
		}
		runReceipt, err := invocation.run(ctx)
		if err != nil {
			return runReceipt, err
		}
		persisted, err := executor.bridgeStagedReceipt(ctx, receipts, invocation.ledger, runReceipt)
		if err != nil {
			return runReceipt, err
		}
		receipt, _ := resolved.Receipt()
		authorizations = append(authorizations, receipt)
		receipts = append(receipts, persisted)
		return runReceipt, nil
	}
	orchestration.RunPlatformApplications = func(ctx context.Context, _ execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
		resolved, err := ResolveStageAuthorization(ctx, executor.resume(receipts), executor.config.Authorization)
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		source, err := resolved.Source()
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		invocation, err := executor.factories.applications(executor.resume(receipts), source, executor.config.PlatformApplications)
		if err != nil || invocation.run == nil || invocation.ledger == nil {
			return execution.StagedOperationReceipt{}, errors.New("open post-runtime platform Applications stage")
		}
		runReceipt, err := invocation.run(ctx)
		if err != nil {
			return runReceipt, err
		}
		persisted, err := executor.bridgeStagedReceipt(ctx, receipts, invocation.ledger, runReceipt)
		if err != nil {
			return runReceipt, err
		}
		receipt, _ := resolved.Receipt()
		authorizations = append(authorizations, receipt)
		receipts = append(receipts, persisted)
		return runReceipt, nil
	}
	orchestration.RunPlatformObservation = func(ctx context.Context, _ execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
		invocation, err := executor.factories.observation(executor.resume(receipts), executor.config.PlatformObservation)
		if err != nil || invocation.run == nil || invocation.ledger == nil {
			return execution.ObservationStageRunReceipt{}, errors.New("open post-runtime platform observation stage")
		}
		runReceipt, err := invocation.run(ctx)
		if err != nil {
			return runReceipt, err
		}
		persisted, err := executor.bridgeObservationReceipt(ctx, receipts, invocation.ledger, runReceipt)
		if err != nil {
			return runReceipt, err
		}
		receipts = append(receipts, persisted)
		return runReceipt, nil
	}
	orchestration.RunAggregateEvidence = func(ctx context.Context, _ execution.ObservationStageRunReceipt) (execution.EvaluationStageRunReceipt, error) {
		invocation, err := executor.factories.aggregate(executor.resume(receipts), executor.config.AggregateEvidence, executor.runtime)
		if err != nil || invocation.run == nil {
			return execution.EvaluationStageRunReceipt{}, errors.New("open post-runtime aggregate evidence stage")
		}
		return invocation.run(ctx)
	}

	orchestrationReceipt, err := orchestration.Run(ctx)
	result := PostRuntimeExecutionReceipt{
		Format: PostRuntimeExecutionReceiptFormat, State: orchestrationReceipt.State,
		PlanDigest: orchestrationReceipt.PlanDigest, StoppedAt: orchestrationReceipt.StoppedAt,
		Checkpoints:            append([]PostRuntimeStageCheckpoint(nil), orchestrationReceipt.Checkpoints...),
		ResolvedAuthorizations: append([]ResolvedStageAuthorizationReceipt(nil), authorizations...),
	}
	return result, err
}

func (executor *PostRuntimeExecution) resume(receipts []StageReceiptSource) StageResumeConfig {
	return StageResumeConfig{
		PlanPath: executor.initial.PlanPath, PlanExpected: executor.initial.PlanExpected,
		Receipts: append([]StageReceiptSource(nil), receipts...),
	}
}

func (executor *PostRuntimeExecution) bridgeStagedReceipt(ctx context.Context, receipts []StageReceiptSource, store *ledger.Ledger, receipt execution.StagedOperationReceipt) (StageReceiptSource, error) {
	return executor.bridgeReceipt(ctx, receipts, store, StagedOperationReceiptReference(receipt))
}

func (executor *PostRuntimeExecution) bridgeObservationReceipt(ctx context.Context, receipts []StageReceiptSource, store *ledger.Ledger, receipt execution.ObservationStageRunReceipt) (StageReceiptSource, error) {
	return executor.bridgeReceipt(ctx, receipts, store, ObservationStageReceiptReference(receipt))
}

func (executor *PostRuntimeExecution) bridgeReceipt(ctx context.Context, receipts []StageReceiptSource, store *ledger.Ledger, reference StageRunReceiptReference) (StageReceiptSource, error) {
	material, err := LoadStageReceiptMaterial(ctx, StageReceiptBridgeConfig{Bundle: executor.resume(receipts), Ledger: store, Run: reference})
	if err != nil {
		return StageReceiptSource{}, err
	}
	name, ok := postRuntimeReceiptFiles[reference.StageID]
	if !ok {
		return StageReceiptSource{}, errors.New("post-runtime receipt stage is not persistable")
	}
	return material.Persist(filepath.Join(executor.config.ReceiptDirectory, name))
}

func stoppedPostRuntimeExecutionReceipt(stageID string, checkpoints []PostRuntimeStageCheckpoint, authorizations []ResolvedStageAuthorizationReceipt) PostRuntimeExecutionReceipt {
	return PostRuntimeExecutionReceipt{
		Format: PostRuntimeExecutionReceiptFormat, State: "STOPPED", StoppedAt: stageID,
		Checkpoints:            append([]PostRuntimeStageCheckpoint(nil), checkpoints...),
		ResolvedAuthorizations: append([]ResolvedStageAuthorizationReceipt(nil), authorizations...),
	}
}

func defaultPostRuntimeExecutionFactories() postRuntimeExecutionFactories {
	return postRuntimeExecutionFactories{
		credential: func(bundleConfig TargetCredentialStageBundleConfig, runtimeConfig TargetCredentialStageRuntimeConfig) (postRuntimeCredentialInvocation, error) {
			bundle, err := LoadTargetCredentialStageBundle(bundleConfig)
			if err != nil {
				return postRuntimeCredentialInvocation{}, err
			}
			opened, err := bundle.Open(runtimeConfig)
			if err != nil {
				return postRuntimeCredentialInvocation{}, err
			}
			return postRuntimeCredentialInvocation{run: opened.RunHandoff, ledger: opened.operation.Ledger}, nil
		},
		registration: func(_ StageResumeConfig, handoff *VerifiedTargetCredentialStageHandoff, grant StageAuthorizationSource, config PostRuntimeTargetRegistrationConfig, runtime VerifiedRuntimeBindingMaterial) (postRuntimeStagedInvocation, error) {
			bundle, err := LoadTargetRegistrationStageBundleFromHandoff(TargetRegistrationStageHandoffConfig{
				Handoff: handoff, GrantPath: grant.GrantPath, GrantPublicKeyPath: grant.PublicKeyPath, EvaluationTime: grant.EvaluationTime,
				ArtifactPath: config.ArtifactPath, Expected: config.Expected,
			})
			if err != nil {
				return postRuntimeStagedInvocation{}, err
			}
			runtimeConfig := config.Runtime
			runtimeConfig.Runtime = runtime
			opened, err := bundle.OpenHandoff(runtimeConfig)
			if err != nil {
				return postRuntimeStagedInvocation{}, err
			}
			return postRuntimeStagedInvocation{run: opened.Run, ledger: opened.operation.Ledger}, nil
		},
		applications: func(resume StageResumeConfig, grant StageAuthorizationSource, config PostRuntimePlatformApplicationsConfig) (postRuntimeStagedInvocation, error) {
			bundle, err := LoadPlatformApplicationsStageBundle(PlatformApplicationsStageBundleConfig{
				PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
				GrantPath: grant.GrantPath, GrantPublicKeyPath: grant.PublicKeyPath, EvaluationTime: grant.EvaluationTime,
				ArtifactPath: config.ArtifactPath, Expected: config.Expected,
			})
			if err != nil {
				return postRuntimeStagedInvocation{}, err
			}
			opened, err := bundle.Open(config.Runtime)
			if err != nil {
				return postRuntimeStagedInvocation{}, err
			}
			return postRuntimeStagedInvocation{run: opened.Run, ledger: opened.operation.Ledger}, nil
		},
		observation: func(resume StageResumeConfig, config PostRuntimePlatformObservationConfig) (postRuntimeObservationInvocation, error) {
			profileDigest, err := observation.PlatformProfileDigest(config.Profile)
			if err != nil {
				return postRuntimeObservationInvocation{}, err
			}
			bundle, err := LoadPlatformObservationStageBundle(PlatformObservationStageBundleConfig{
				StageResumeConfig: resume, Profile: config.Profile, ExpectedProfileDigest: profileDigest,
			})
			if err != nil {
				return postRuntimeObservationInvocation{}, err
			}
			runtimeConfig := config.Runtime
			runtimeConfig.Bundle, runtimeConfig.Profile = resume, config.Profile
			runtime, err := LoadPlatformObservationStageFileRuntime(runtimeConfig)
			if err != nil {
				return postRuntimeObservationInvocation{}, err
			}
			opened, err := bundle.Open(runtime)
			if err != nil {
				return postRuntimeObservationInvocation{}, err
			}
			return postRuntimeObservationInvocation{run: opened.Run, ledger: opened.operation.Ledger}, nil
		},
		aggregate: func(resume StageResumeConfig, config PostRuntimeAggregateEvidenceConfig, runtimeBinding VerifiedRuntimeBindingMaterial) (postRuntimeEvaluationInvocation, error) {
			profileDigest, err := AggregateEvidenceProfileDigest(config.Profile)
			if err != nil {
				return postRuntimeEvaluationInvocation{}, err
			}
			bundle, err := LoadAggregateEvidenceStageBundle(AggregateEvidenceStageBundleConfig{
				StageResumeConfig: resume, Profile: config.Profile, ExpectedProfileDigest: profileDigest,
			})
			if err != nil {
				return postRuntimeEvaluationInvocation{}, err
			}
			runtimeConfig := config.Runtime
			runtimeConfig.Bundle = resume
			runtimeConfig.ExpectedWorkloadEndpoint = runtimeBinding.material.Target.WorkloadAPIEndpoint
			runtime, err := LoadAggregateEvidenceStageFileRuntime(runtimeConfig)
			if err != nil {
				return postRuntimeEvaluationInvocation{}, err
			}
			opened, err := bundle.Open(runtime)
			if err != nil {
				return postRuntimeEvaluationInvocation{}, err
			}
			return postRuntimeEvaluationInvocation{run: opened.Run}, nil
		},
	}
}
