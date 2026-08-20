package runner

import (
	"context"
	"errors"
	"path/filepath"
	"sync"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
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

// PostRuntimeTargetCredentialRecoveryConfig selects the explicit crash-only
// continuation path after Stage 8 succeeded durably but its memory-only
// credential handoff was lost. It never replaces the normal first attempt.
type PostRuntimeTargetCredentialRecoveryConfig struct {
	StageReceipt  StageReceiptSource
	Authorization TargetCredentialRecoveryAuthorizationResolver
}

// PostRuntimeTargetRegistrationRecoveryConfig selects the explicit crash-only
// continuation path after Stage 9 succeeded durably but the short-lived target
// credential embedded in the Argo registration has expired. It is valid only
// together with target-credential recovery and never replaces a first attempt.
type PostRuntimeTargetRegistrationRecoveryConfig struct {
	StageReceipt  StageReceiptSource
	Authorization TargetRegistrationRecoveryAuthorizationResolver
}

// PostRuntimeExecutionConfig supplies immutable artifacts and private runtime
// bindings for exactly Stage 8-12. The Stage-8 grant is already part of its
// verified bundle; later mutating grants are resolved only after their direct
// predecessor receipt is durable.
type PostRuntimeExecutionConfig struct {
	TargetCredential           TargetCredentialStageBundleConfig
	TargetCredentialRun        TargetCredentialStageRuntimeConfig
	TargetCredentialRecovery   *PostRuntimeTargetCredentialRecoveryConfig
	TargetRegistrationRecovery *PostRuntimeTargetRegistrationRecoveryConfig
	Authorization              StageAuthorizationResolver
	TargetRegistration         PostRuntimeTargetRegistrationConfig
	PlatformApplications       PostRuntimePlatformApplicationsConfig
	PlatformObservation        PostRuntimePlatformObservationConfig
	AggregateEvidence          PostRuntimeAggregateEvidenceConfig
	RuntimeBinding             RuntimeBindingMaterialFileConfig
	ReceiptDirectory           string
}

type PostRuntimeExecutionReceipt struct {
	Format                                    string                                                  `json:"format"`
	State                                     string                                                  `json:"state"`
	PlanDigest                                string                                                  `json:"planDigest,omitempty"`
	StoppedAt                                 string                                                  `json:"stoppedAt,omitempty"`
	Checkpoints                               []PostRuntimeStageCheckpoint                            `json:"checkpoints"`
	ResolvedAuthorizations                    []ResolvedStageAuthorizationReceipt                     `json:"resolvedAuthorizations"`
	ResolvedRecoveryAuthorization             *ResolvedTargetCredentialRecoveryAuthorizationReceipt   `json:"resolvedRecoveryAuthorization,omitempty"`
	TargetCredentialRecovery                  *TargetCredentialRecoveryReceipt                        `json:"targetCredentialRecovery,omitempty"`
	ResolvedRegistrationRecoveryAuthorization *ResolvedTargetRegistrationRecoveryAuthorizationReceipt `json:"resolvedRegistrationRecoveryAuthorization,omitempty"`
	TargetRegistrationRecovery                *TargetRegistrationRecoveryReceipt                      `json:"targetRegistrationRecovery,omitempty"`
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
	credential           func(TargetCredentialStageBundleConfig, TargetCredentialStageRuntimeConfig) (postRuntimeCredentialInvocation, error)
	registration         func(StageResumeConfig, *VerifiedTargetCredentialStageHandoff, StageAuthorizationSource, PostRuntimeTargetRegistrationConfig, VerifiedRuntimeBindingMaterial) (postRuntimeStagedInvocation, error)
	applications         func(StageResumeConfig, StageAuthorizationSource, PostRuntimePlatformApplicationsConfig) (postRuntimeStagedInvocation, error)
	observation          func(StageResumeConfig, PostRuntimePlatformObservationConfig) (postRuntimeObservationInvocation, error)
	aggregate            func(StageResumeConfig, PostRuntimeAggregateEvidenceConfig, VerifiedRuntimeBindingMaterial) (postRuntimeEvaluationInvocation, error)
	registrationRecovery func(context.Context, TargetRegistrationRecoveryConfig) (TargetRegistrationRecoveryReceipt, error)
}

type PostRuntimeExecution struct {
	config               PostRuntimeExecutionConfig
	initial              StageResumeConfig
	runtime              VerifiedRuntimeBindingMaterial
	credential           postRuntimeCredentialInvocation
	recoveryBundle       *VerifiedTargetCredentialStageBundle
	recovery             *PostRuntimeTargetCredentialRecoveryConfig
	registrationRecovery *PostRuntimeTargetRegistrationRecoveryConfig
	factories            postRuntimeExecutionFactories
	mu                   sync.Mutex
	used                 bool
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
	persistedStages := postRuntimeStageOrder[:4]
	if config.TargetCredentialRecovery != nil {
		persistedStages = postRuntimeStageOrder[1:4]
	}
	if config.TargetRegistrationRecovery != nil {
		persistedStages = postRuntimeStageOrder[2:4]
	}
	for _, stageID := range persistedStages {
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
	var credential postRuntimeCredentialInvocation
	var recoveryBundle *VerifiedTargetCredentialStageBundle
	if config.TargetCredentialRecovery == nil {
		credential, err = factories.credential(config.TargetCredential, config.TargetCredentialRun)
		if err != nil || credential.run == nil || credential.ledger == nil {
			return nil, errors.New("open post-runtime target credential stage")
		}
	} else {
		retainedRecovery := *config.TargetCredentialRecovery
		config.TargetCredentialRecovery = &retainedRecovery
		if config.TargetCredentialRecovery.Authorization == nil {
			return nil, errors.New("post-runtime target-credential recovery authorization is required")
		}
		bundle, loadErr := LoadTargetCredentialStageBundle(config.TargetCredential)
		if loadErr != nil {
			return nil, errors.New("load post-runtime target-credential recovery bundle")
		}
		if _, loadErr = loadSuccessfulTargetCredentialReceipt(bundle, config.TargetCredentialRecovery.StageReceipt); loadErr != nil {
			return nil, errors.New("verify post-runtime target-credential recovery receipt")
		}
		recoveryBundle = &bundle
	}
	var registrationRecovery *PostRuntimeTargetRegistrationRecoveryConfig
	if config.TargetRegistrationRecovery != nil {
		if config.TargetCredentialRecovery == nil || config.TargetRegistrationRecovery.Authorization == nil || recoveryBundle == nil || factories.registrationRecovery == nil {
			return nil, errors.New("post-runtime target-registration recovery requires credential recovery and independent authorization")
		}
		retained := *config.TargetRegistrationRecovery
		config.TargetRegistrationRecovery = &retained
		stageEight, loadErr := loadSuccessfulTargetCredentialReceipt(*recoveryBundle, config.TargetCredentialRecovery.StageReceipt)
		if loadErr != nil {
			return nil, errors.New("verify post-runtime target-credential recovery receipt for registration recovery")
		}
		prefix := append(append([]stagereceipt.Verified(nil), recoveryBundle.prefix...), stageEight)
		cursor, loadErr := stagecursor.Evaluate(recoveryBundle.plan, prefix)
		if loadErr != nil {
			return nil, errors.New("evaluate post-runtime target-registration recovery prefix")
		}
		if _, loadErr = loadSuccessfulTargetRegistrationReceipt(recoveryBundle.plan, cursor, prefix, retained.StageReceipt); loadErr != nil {
			return nil, errors.New("verify post-runtime target-registration recovery receipt")
		}
		registrationRecovery = config.TargetRegistrationRecovery
	}
	config.TargetCredential.Receipts = append([]StageReceiptSource(nil), initial.Receipts...)
	config.PlatformObservation.Profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), config.PlatformObservation.Profile.RequiredApplications...)
	config.PlatformObservation.Runtime.RuntimeMaterialPath = config.RuntimeBinding.MaterialPath
	config.PlatformObservation.Runtime.RuntimeReceiptPath = config.RuntimeBinding.ReceiptPath
	config.AggregateEvidence.Profile.Required = append([]string(nil), config.AggregateEvidence.Profile.Required...)
	config.AggregateEvidence.Runtime.RuntimeMaterialPath = config.RuntimeBinding.MaterialPath
	config.AggregateEvidence.Runtime.RuntimeReceiptPath = config.RuntimeBinding.ReceiptPath
	return &PostRuntimeExecution{
		config: config, initial: initial, runtime: runtime, credential: credential,
		recoveryBundle: recoveryBundle, recovery: config.TargetCredentialRecovery, factories: factories,
		registrationRecovery: registrationRecovery,
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
	var recoveryAuthorization *ResolvedTargetCredentialRecoveryAuthorizationReceipt
	var recoveryReceipt *TargetCredentialRecoveryReceipt
	var registrationRecoveryAuthorization *ResolvedTargetRegistrationRecoveryAuthorizationReceipt
	var registrationRecoveryReceipt *TargetRegistrationRecoveryReceipt
	orchestration := PostRuntimeOrchestration{}
	orchestration.RunTargetCredential = func(ctx context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
		if executor.recovery != nil {
			if executor.recoveryBundle == nil {
				return execution.StagedOperationReceipt{}, nil, errors.New("post-runtime recovery bundle is unavailable")
			}
			resolved, err := ResolveTargetCredentialRecoveryAuthorization(ctx, *executor.recoveryBundle, executor.recovery.StageReceipt, executor.recovery.Authorization)
			if err != nil {
				return execution.StagedOperationReceipt{}, nil, err
			}
			resolvedReceipt, err := resolved.Receipt()
			if err != nil {
				return execution.StagedOperationReceipt{}, nil, err
			}
			recovered, handoff, err := RecoverTargetCredential(ctx, TargetCredentialRecoveryConfig{
				Bundle: *executor.recoveryBundle, StageReceipt: executor.recovery.StageReceipt, Authorization: resolved,
				Ledger: executor.config.TargetCredentialRun.Ledger, Workload: executor.config.TargetCredentialRun.Workload,
				Clock: executor.config.TargetCredentialRun.Clock,
			})
			recoveryAuthorization, recoveryReceipt = &resolvedReceipt, &recovered
			runReceipt := execution.StagedOperationReceipt{
				Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED",
				PlanDigest: executor.recoveryBundle.plan.PlanDigest, StageID: "target-credential",
				StageReceiptDigest: executor.recovery.StageReceipt.Digest,
			}
			if err != nil {
				return runReceipt, nil, err
			}
			receipts = append(receipts, executor.recovery.StageReceipt)
			return runReceipt, handoff, nil
		}
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
		if executor.registrationRecovery != nil {
			resolved, err := ResolveTargetRegistrationRecoveryAuthorization(ctx, handoff, executor.registrationRecovery.StageReceipt, executor.registrationRecovery.Authorization)
			if err != nil {
				return execution.StagedOperationReceipt{}, err
			}
			resolvedReceipt, err := resolved.Receipt()
			if err != nil {
				return execution.StagedOperationReceipt{}, err
			}
			recovered, err := executor.factories.registrationRecovery(ctx, TargetRegistrationRecoveryConfig{
				Handoff: handoff, PriorStageReceipt: executor.registrationRecovery.StageReceipt, Authorization: resolved,
				ArtifactPath: executor.config.TargetRegistration.ArtifactPath, Expected: executor.config.TargetRegistration.Expected,
				Ledger: executor.config.TargetRegistration.Runtime.Ledger, GitOps: executor.config.TargetRegistration.Runtime.GitOps,
				Runtime: executor.runtime, MaterializationTime: executor.config.TargetRegistration.Runtime.MaterializationTime,
				Clock: executor.config.TargetRegistration.Runtime.Clock,
			})
			registrationRecoveryAuthorization, registrationRecoveryReceipt = &resolvedReceipt, &recovered
			runReceipt := execution.StagedOperationReceipt{
				Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: executor.recoveryBundle.plan.PlanDigest,
				StageID: "target-registration", StageReceiptDigest: executor.registrationRecovery.StageReceipt.Digest,
			}
			if err != nil {
				return runReceipt, err
			}
			receipts = append(receipts, executor.registrationRecovery.StageReceipt)
			return runReceipt, nil
		}
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
		Checkpoints:                   append([]PostRuntimeStageCheckpoint(nil), orchestrationReceipt.Checkpoints...),
		ResolvedAuthorizations:        append([]ResolvedStageAuthorizationReceipt(nil), authorizations...),
		ResolvedRecoveryAuthorization: recoveryAuthorization, TargetCredentialRecovery: recoveryReceipt,
		ResolvedRegistrationRecoveryAuthorization: registrationRecoveryAuthorization,
		TargetRegistrationRecovery:                registrationRecoveryReceipt,
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
		registrationRecovery: RecoverTargetRegistration,
	}
}
