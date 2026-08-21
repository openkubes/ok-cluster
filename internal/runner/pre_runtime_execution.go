package runner

import (
	"context"
	"errors"
	"path/filepath"
	"sync"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const PreRuntimeExecutionReceiptFormat = "ok147-pre-runtime-execution-receipt/v1"

var preRuntimeReceiptFiles = map[string]string{
	"provider-prerequisites": "01-provider-prerequisites.json",
	"cluster-lifecycle":      "02-cluster-lifecycle.json",
	"lifecycle-observation":  "03-lifecycle-observation.json",
	"enablement":             "04-enablement.json",
	"network-observation":    "05-network-observation.json",
	"runtime-binding":        "06-runtime-binding.json",
	"target-access":          "07-target-access.json",
}

type PreRuntimeEnablementExecutionConfig struct {
	ArtifactPath   string
	ExpectedObject projection.ResourceIdentity
	Runtime        SubmissionStageRuntimeConfig
}

type PreRuntimeTargetAccessExecutionConfig struct {
	ArtifactPath    string
	ExpectedObjects []projection.ResourceIdentity
	Runtime         TargetAccessStageRuntimeConfig
}

// PreRuntimeExecutionConfig binds all immutable artifacts and private runtime
// capabilities for Stage 1-7. Mutating grants are resolved only after the
// exact direct predecessor receipt is durable.
type PreRuntimeExecutionConfig struct {
	PlanPath                  string
	PlanExpected              stageplan.Expected
	ProjectionManifestPath    string
	ProjectionRoot            string
	Authorization             StageAuthorizationResolver
	ProviderPrerequisites     SubmissionStageRuntimeConfig
	ClusterLifecycle          SubmissionStageRuntimeConfig
	LifecycleObservation      LifecycleObservationStageRuntimeConfig
	Enablement                PreRuntimeEnablementExecutionConfig
	NetworkObservation        NetworkObservationStageRuntimeConfig
	RuntimeBinding            RuntimeBindingStageRuntimeConfig
	RuntimeBindingReceiptPath string
	TargetAccess              PreRuntimeTargetAccessExecutionConfig
	ReceiptDirectory          string
}

type PreRuntimeExecutionReceipt struct {
	Format                 string                              `json:"format"`
	State                  string                              `json:"state"`
	PlanDigest             string                              `json:"planDigest,omitempty"`
	StoppedAt              string                              `json:"stoppedAt,omitempty"`
	Checkpoints            []PreRuntimeStageCheckpoint         `json:"checkpoints"`
	ResolvedAuthorizations []ResolvedStageAuthorizationReceipt `json:"resolvedAuthorizations"`
}

type preRuntimeStagedInvocation struct {
	run   func(context.Context) (execution.StagedOperationReceipt, error)
	store *ledger.Ledger
}

type preRuntimeObservationInvocation struct {
	run   func(context.Context) (execution.ObservationStageRunReceipt, error)
	store *ledger.Ledger
}

type preRuntimeBindingInvocation struct {
	run             func(context.Context) (execution.BindingStageRunReceipt, error)
	materialReceipt func() (RuntimeBindingMaterialReceipt, error)
	store           *ledger.Ledger
}

type preRuntimeExecutionFactories struct {
	submission func(StageResumeConfig, string, StageAuthorizationSource, PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error)
	lifecycle  func(StageResumeConfig, PreRuntimeExecutionConfig) (preRuntimeObservationInvocation, error)
	enablement func(StageResumeConfig, StageAuthorizationSource, PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error)
	network    func(StageResumeConfig, PreRuntimeExecutionConfig) (preRuntimeObservationInvocation, error)
	binding    func(StageResumeConfig, PreRuntimeExecutionConfig) (preRuntimeBindingInvocation, error)
	target     func(StageResumeConfig, StageAuthorizationSource, PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error)
	persist    func(context.Context, StageResumeConfig, *ledger.Ledger, StageRunReceiptReference, string) (StageReceiptSource, error)
}

type PreRuntimeExecution struct {
	config    PreRuntimeExecutionConfig
	initial   StageResumeConfig
	factories preRuntimeExecutionFactories

	mu        sync.Mutex
	used      bool
	completed bool
	prefix    []StageReceiptSource
}

// OpenPreRuntimeExecution verifies the empty Stage-1 cursor and every future
// receipt destination. It does not resolve a grant, read a credential, contact
// Kubernetes or create a file.
func OpenPreRuntimeExecution(config PreRuntimeExecutionConfig) (*PreRuntimeExecution, error) {
	return openPreRuntimeExecution(config, defaultPreRuntimeExecutionFactories())
}

func openPreRuntimeExecution(config PreRuntimeExecutionConfig, factories preRuntimeExecutionFactories) (*PreRuntimeExecution, error) {
	if config.Authorization == nil || config.ReceiptDirectory == "" || config.PlanPath == "" ||
		factories.submission == nil || factories.lifecycle == nil || factories.enablement == nil ||
		factories.network == nil || factories.binding == nil || factories.target == nil || factories.persist == nil {
		return nil, errors.New("pre-runtime execution configuration is incomplete")
	}
	initial := StageResumeConfig{PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: []StageReceiptSource{}}
	decision, err := InspectStageResume(initial)
	if err != nil || decision.State != "NEXT" || decision.StageID != "provider-prerequisites" {
		return nil, errors.New("pre-runtime execution requires the exact Stage-1 cursor")
	}
	for _, stageID := range preRuntimeStageOrder {
		name, ok := preRuntimeReceiptFiles[stageID]
		if !ok || validateRuntimeBindingOutputPath(filepath.Join(config.ReceiptDirectory, name)) != nil {
			return nil, errors.New("pre-runtime receipt destination is invalid")
		}
	}
	if config.RuntimeBinding.OutputPath == config.RuntimeBindingReceiptPath ||
		validateRuntimeBindingOutputPath(config.RuntimeBinding.OutputPath) != nil ||
		validateRuntimeBindingOutputPath(config.RuntimeBindingReceiptPath) != nil {
		return nil, errors.New("pre-runtime binding handoff destination is invalid")
	}
	config.TargetAccess.ExpectedObjects = append([]projection.ResourceIdentity(nil), config.TargetAccess.ExpectedObjects...)
	return &PreRuntimeExecution{config: config, initial: initial, factories: factories}, nil
}

// Run executes exactly one Stage 1-7 prefix. Every successful stage receipt
// is reloaded from its authoritative ledger and persisted create-only as a
// private 0600 source before a later stage can be opened.
func (executor *PreRuntimeExecution) Run(ctx context.Context) (PreRuntimeExecutionReceipt, error) {
	if executor == nil {
		return stoppedPreRuntimeExecutionReceipt("provider-prerequisites", nil, nil), errors.New("pre-runtime execution is required")
	}
	executor.mu.Lock()
	if executor.used {
		executor.mu.Unlock()
		return stoppedPreRuntimeExecutionReceipt("provider-prerequisites", nil, nil), errors.New("pre-runtime execution is single-use")
	}
	executor.used = true
	executor.mu.Unlock()

	receipts := []StageReceiptSource{}
	authorizations := []ResolvedStageAuthorizationReceipt{}
	orchestration := PreRuntimeOrchestration{}

	resolve := func(ctx context.Context) (StageAuthorizationSource, error) {
		resolved, err := ResolveStageAuthorization(ctx, executor.resume(receipts), executor.config.Authorization)
		if err != nil {
			return StageAuthorizationSource{}, err
		}
		source, err := resolved.Source()
		if err != nil {
			return StageAuthorizationSource{}, err
		}
		public, err := resolved.Receipt()
		if err != nil {
			return StageAuthorizationSource{}, err
		}
		authorizations = append(authorizations, public)
		return source, nil
	}
	persist := func(ctx context.Context, store *ledger.Ledger, reference StageRunReceiptReference) error {
		name, ok := preRuntimeReceiptFiles[reference.StageID]
		if !ok {
			return errors.New("pre-runtime receipt stage is not persistable")
		}
		source, err := executor.factories.persist(ctx, executor.resume(receipts), store, reference, filepath.Join(executor.config.ReceiptDirectory, name))
		if err != nil {
			return err
		}
		receipts = append(receipts, source)
		return nil
	}

	orchestration.RunProviderPrerequisites = func(ctx context.Context) (execution.StagedOperationReceipt, error) {
		source, err := resolve(ctx)
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		invocation, err := executor.factories.submission(executor.resume(receipts), "provider-prerequisites", source, executor.config)
		if err != nil || invocation.run == nil || invocation.store == nil {
			return execution.StagedOperationReceipt{}, errors.New("open provider-prerequisites stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		return run, persist(ctx, invocation.store, StagedOperationReceiptReference(run))
	}
	orchestration.RunClusterLifecycle = func(ctx context.Context, _ execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
		source, err := resolve(ctx)
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		invocation, err := executor.factories.submission(executor.resume(receipts), "cluster-lifecycle", source, executor.config)
		if err != nil || invocation.run == nil || invocation.store == nil {
			return execution.StagedOperationReceipt{}, errors.New("open cluster-lifecycle stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		return run, persist(ctx, invocation.store, StagedOperationReceiptReference(run))
	}
	orchestration.RunLifecycleObservation = func(ctx context.Context, _ execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
		invocation, err := executor.factories.lifecycle(executor.resume(receipts), executor.config)
		if err != nil || invocation.run == nil || invocation.store == nil {
			return execution.ObservationStageRunReceipt{}, errors.New("open lifecycle-observation stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		return run, persist(ctx, invocation.store, ObservationStageReceiptReference(run))
	}
	orchestration.RunEnablement = func(ctx context.Context, _ execution.ObservationStageRunReceipt) (execution.StagedOperationReceipt, error) {
		source, err := resolve(ctx)
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		invocation, err := executor.factories.enablement(executor.resume(receipts), source, executor.config)
		if err != nil || invocation.run == nil || invocation.store == nil {
			return execution.StagedOperationReceipt{}, errors.New("open enablement stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		return run, persist(ctx, invocation.store, StagedOperationReceiptReference(run))
	}
	orchestration.RunNetworkObservation = func(ctx context.Context, _ execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
		invocation, err := executor.factories.network(executor.resume(receipts), executor.config)
		if err != nil || invocation.run == nil || invocation.store == nil {
			return execution.ObservationStageRunReceipt{}, errors.New("open network-observation stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		return run, persist(ctx, invocation.store, ObservationStageReceiptReference(run))
	}
	orchestration.RunRuntimeBinding = func(ctx context.Context, _ execution.ObservationStageRunReceipt) (execution.BindingStageRunReceipt, error) {
		invocation, err := executor.factories.binding(executor.resume(receipts), executor.config)
		if err != nil || invocation.run == nil || invocation.materialReceipt == nil || invocation.store == nil {
			return execution.BindingStageRunReceipt{}, errors.New("open runtime-binding stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		materialReceipt, err := invocation.materialReceipt()
		if err != nil {
			return run, errors.New("read runtime-binding material receipt")
		}
		if err := persistRuntimeBindingMaterialReceipt(
			materialReceipt,
			executor.config.RuntimeBinding.OutputPath,
			executor.config.RuntimeBindingReceiptPath,
			run.PlanDigest,
		); err != nil {
			return run, errors.New("persist runtime-binding material receipt")
		}
		return run, persist(ctx, invocation.store, BindingStageReceiptReference(run))
	}
	orchestration.RunTargetAccess = func(ctx context.Context, _ execution.BindingStageRunReceipt) (execution.StagedOperationReceipt, error) {
		source, err := resolve(ctx)
		if err != nil {
			return execution.StagedOperationReceipt{}, err
		}
		invocation, err := executor.factories.target(executor.resume(receipts), source, executor.config)
		if err != nil || invocation.run == nil || invocation.store == nil {
			return execution.StagedOperationReceipt{}, errors.New("open target-access stage")
		}
		run, err := invocation.run(ctx)
		if err != nil {
			return run, err
		}
		return run, persist(ctx, invocation.store, StagedOperationReceiptReference(run))
	}

	orchestrationReceipt, runErr := orchestration.Run(ctx)
	result := PreRuntimeExecutionReceipt{
		Format: PreRuntimeExecutionReceiptFormat, State: orchestrationReceipt.State,
		PlanDigest: orchestrationReceipt.PlanDigest, StoppedAt: orchestrationReceipt.StoppedAt,
		Checkpoints:            append([]PreRuntimeStageCheckpoint(nil), orchestrationReceipt.Checkpoints...),
		ResolvedAuthorizations: append([]ResolvedStageAuthorizationReceipt(nil), authorizations...),
	}
	if runErr == nil && result.State == "SUCCEEDED" && len(receipts) == len(preRuntimeStageOrder) {
		executor.mu.Lock()
		executor.prefix = append([]StageReceiptSource(nil), receipts...)
		executor.completed = true
		executor.mu.Unlock()
	}
	return result, runErr
}

// ReceiptPrefix returns the exact private receipt sources only after all seven
// stages completed. It is intended for the receipt-bound full-run adapter and
// must never be serialized into public evidence.
func (executor *PreRuntimeExecution) ReceiptPrefix() ([]StageReceiptSource, error) {
	if executor == nil {
		return nil, errors.New("pre-runtime execution is required")
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if !executor.completed || len(executor.prefix) != len(preRuntimeStageOrder) {
		return nil, errors.New("pre-runtime receipt prefix is unavailable")
	}
	return append([]StageReceiptSource(nil), executor.prefix...), nil
}

// RuntimeTargetIdentity reloads the completed private prefix and returns only
// the lifecycle-derived CAPI Cluster UID digest. Raw target identity remains
// private and no file path is exposed.
func (executor *PreRuntimeExecution) RuntimeTargetIdentity() (string, error) {
	prefix, err := executor.ReceiptPrefix()
	if err != nil {
		return "", err
	}
	plan, _, verifiedPrefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: executor.config.PlanPath, PlanExpected: executor.config.PlanExpected, Receipts: prefix,
	})
	if err != nil || len(verifiedPrefix) != len(preRuntimeStageOrder) {
		return "", errors.New("verify completed pre-runtime target identity")
	}
	lifecycle, err := verifiedPrefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || lifecycle.State != "SUCCEEDED" ||
		lifecycle.PlanDigest != plan.PlanDigest || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return "", errors.New("completed pre-runtime target identity is unavailable")
	}
	return lifecycle.TargetClusterUIDDigest, nil
}

func (executor *PreRuntimeExecution) resume(receipts []StageReceiptSource) StageResumeConfig {
	prefix := make([]StageReceiptSource, len(receipts))
	copy(prefix, receipts)
	return StageResumeConfig{
		PlanPath: executor.initial.PlanPath, PlanExpected: executor.initial.PlanExpected,
		Receipts: prefix,
	}
}

func defaultPreRuntimeExecutionFactories() preRuntimeExecutionFactories {
	return preRuntimeExecutionFactories{
		submission: func(resume StageResumeConfig, stageID string, grant StageAuthorizationSource, config PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error) {
			bundle, err := LoadSubmissionStageBundle(SubmissionStageBundleConfig{
				ExpectedStageID: stageID, PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
				GrantPath: grant.GrantPath, GrantPublicKeyPath: grant.PublicKeyPath, EvaluationTime: grant.EvaluationTime,
				ProjectionManifestPath: config.ProjectionManifestPath, ProjectionRoot: config.ProjectionRoot,
			})
			if err != nil {
				return preRuntimeStagedInvocation{}, err
			}
			runtime := config.ProviderPrerequisites
			if stageID == "cluster-lifecycle" {
				runtime = config.ClusterLifecycle
			}
			opened, err := bundle.Open(runtime)
			if err != nil {
				return preRuntimeStagedInvocation{}, err
			}
			return preRuntimeStagedInvocation{run: opened.Run, store: opened.operation.Ledger}, nil
		},
		lifecycle: func(resume StageResumeConfig, config PreRuntimeExecutionConfig) (preRuntimeObservationInvocation, error) {
			bundle, err := LoadLifecycleObservationStageBundle(resume)
			if err != nil {
				return preRuntimeObservationInvocation{}, err
			}
			opened, err := bundle.Open(config.LifecycleObservation)
			if err != nil {
				return preRuntimeObservationInvocation{}, err
			}
			return preRuntimeObservationInvocation{run: opened.Run, store: opened.operation.Ledger}, nil
		},
		enablement: func(resume StageResumeConfig, grant StageAuthorizationSource, config PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error) {
			bundle, err := LoadEnablementStageBundle(EnablementStageBundleConfig{
				PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
				GrantPath: grant.GrantPath, GrantPublicKeyPath: grant.PublicKeyPath, EvaluationTime: grant.EvaluationTime,
				ArtifactPath: config.Enablement.ArtifactPath, ExpectedObject: config.Enablement.ExpectedObject,
			})
			if err != nil {
				return preRuntimeStagedInvocation{}, err
			}
			opened, err := bundle.Open(config.Enablement.Runtime)
			if err != nil {
				return preRuntimeStagedInvocation{}, err
			}
			return preRuntimeStagedInvocation{run: opened.Run, store: opened.operation.Ledger}, nil
		},
		network: func(resume StageResumeConfig, config PreRuntimeExecutionConfig) (preRuntimeObservationInvocation, error) {
			bundle, err := LoadNetworkObservationStageBundle(resume)
			if err != nil {
				return preRuntimeObservationInvocation{}, err
			}
			opened, err := bundle.Open(config.NetworkObservation)
			if err != nil {
				return preRuntimeObservationInvocation{}, err
			}
			return preRuntimeObservationInvocation{run: opened.Run, store: opened.operation.Ledger}, nil
		},
		binding: func(resume StageResumeConfig, config PreRuntimeExecutionConfig) (preRuntimeBindingInvocation, error) {
			bundle, err := LoadRuntimeBindingStageBundle(resume)
			if err != nil {
				return preRuntimeBindingInvocation{}, err
			}
			opened, err := bundle.Open(config.RuntimeBinding)
			if err != nil {
				return preRuntimeBindingInvocation{}, err
			}
			return preRuntimeBindingInvocation{
				run: opened.Run, materialReceipt: func() (RuntimeBindingMaterialReceipt, error) {
					evidence, evidenceErr := opened.EvidenceReceipt()
					if evidenceErr != nil || evidence.State != "SUCCEEDED" || evidence.Material == nil {
						return RuntimeBindingMaterialReceipt{}, errors.New("runtime-binding material evidence is unavailable")
					}
					return *evidence.Material, nil
				},
				store: opened.operation.Ledger,
			}, nil
		},
		target: func(resume StageResumeConfig, grant StageAuthorizationSource, config PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error) {
			bundle, err := LoadTargetAccessStageBundle(TargetAccessStageBundleConfig{
				PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
				GrantPath: grant.GrantPath, GrantPublicKeyPath: grant.PublicKeyPath, EvaluationTime: grant.EvaluationTime,
				ArtifactPath: config.TargetAccess.ArtifactPath, ExpectedObjects: config.TargetAccess.ExpectedObjects,
			})
			if err != nil {
				return preRuntimeStagedInvocation{}, err
			}
			opened, err := bundle.Open(config.TargetAccess.Runtime)
			if err != nil {
				return preRuntimeStagedInvocation{}, err
			}
			return preRuntimeStagedInvocation{run: opened.Run, store: opened.operation.Ledger}, nil
		},
		persist: func(ctx context.Context, resume StageResumeConfig, store *ledger.Ledger, reference StageRunReceiptReference, path string) (StageReceiptSource, error) {
			material, err := LoadStageReceiptMaterial(ctx, StageReceiptBridgeConfig{Bundle: resume, Ledger: store, Run: reference})
			if err != nil {
				return StageReceiptSource{}, err
			}
			return material.Persist(path)
		},
	}
}

func stoppedPreRuntimeExecutionReceipt(stageID string, checkpoints []PreRuntimeStageCheckpoint, authorizations []ResolvedStageAuthorizationReceipt) PreRuntimeExecutionReceipt {
	return PreRuntimeExecutionReceipt{
		Format: PreRuntimeExecutionReceiptFormat, State: "STOPPED", StoppedAt: stageID,
		Checkpoints:            append([]PreRuntimeStageCheckpoint(nil), checkpoints...),
		ResolvedAuthorizations: append([]ResolvedStageAuthorizationReceipt(nil), authorizations...),
	}
}
