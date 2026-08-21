package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const (
	ledgerNamespace                 = "openkubes-execution-system"
	stageRunTimeout                 = 10 * time.Minute
	stageLaunchTimeout              = 5 * time.Minute
	lifecycleObservationRunOverhead = time.Minute
	runtimeBindingRunTimeout        = 2 * time.Minute
)

var (
	version                 = "0.0.0-dev"
	revision                = "unknown"
	sha256DigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	stageReceiptFlagPattern = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
)

var materializeSubmissionStagePackage = func(config runner.SubmissionStagePackageConfig) ([]byte, runner.SubmissionStagePackageReceipt, error) {
	packaged, err := runner.BuildSubmissionStagePackage(config)
	if err != nil {
		return nil, runner.SubmissionStagePackageReceipt{}, err
	}
	raw, err := packaged.Bytes()
	if err != nil {
		return nil, runner.SubmissionStagePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var materializeLifecycleObservationStagePackage = func(config runner.LifecycleObservationStagePackageConfig) ([]byte, runner.LifecycleObservationStagePackageReceipt, error) {
	packaged, err := runner.BuildLifecycleObservationStagePackage(config)
	if err != nil {
		return nil, runner.LifecycleObservationStagePackageReceipt{}, err
	}
	raw, err := packaged.Bytes()
	if err != nil {
		return nil, runner.LifecycleObservationStagePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var materializeNetworkObservationStagePackage = func(config runner.NetworkObservationStagePackageConfig) ([]byte, runner.NetworkObservationStagePackageReceipt, error) {
	packaged, err := runner.BuildNetworkObservationStagePackage(config)
	if err != nil {
		return nil, runner.NetworkObservationStagePackageReceipt{}, err
	}
	raw, err := packaged.Bytes()
	if err != nil {
		return nil, runner.NetworkObservationStagePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var materializeEnablementStagePackage = func(config runner.EnablementStagePackageConfig) ([]byte, runner.EnablementStagePackageReceipt, error) {
	packaged, err := runner.BuildEnablementStagePackage(config)
	if err != nil {
		return nil, runner.EnablementStagePackageReceipt{}, err
	}
	raw, err := packaged.Bytes()
	if err != nil {
		return nil, runner.EnablementStagePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var materializeTargetAccessStagePackage = func(config runner.TargetAccessStagePackageConfig) ([]byte, runner.TargetAccessStagePackageReceipt, error) {
	packaged, err := runner.BuildTargetAccessStagePackage(config)
	if err != nil {
		return nil, runner.TargetAccessStagePackageReceipt{}, err
	}
	raw, err := packaged.Bytes()
	if err != nil {
		return nil, runner.TargetAccessStagePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var prepareSubmissionStageLaunch = func(config runner.SubmissionStageLaunchMaterialConfig) (stageLaunchPreparation, error) {
	material, err := runner.BuildSubmissionStageLaunchMaterial(config)
	if err != nil {
		return stageLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return stageLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return stageLaunchPreparation{}, err
	}
	return stageLaunchPreparation{
		Format: "ok147-submission-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var prepareLifecycleObservationStageLaunch = func(config runner.LifecycleObservationStageLaunchMaterialConfig) (lifecycleObservationLaunchPreparation, error) {
	material, err := runner.BuildLifecycleObservationStageLaunchMaterial(config)
	if err != nil {
		return lifecycleObservationLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return lifecycleObservationLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return lifecycleObservationLaunchPreparation{}, err
	}
	return lifecycleObservationLaunchPreparation{
		Format: "ok147-lifecycle-observation-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var prepareNetworkObservationStageLaunch = func(config runner.NetworkObservationStageLaunchMaterialConfig) (networkObservationLaunchPreparation, error) {
	material, err := runner.BuildNetworkObservationStageLaunchMaterial(config)
	if err != nil {
		return networkObservationLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return networkObservationLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return networkObservationLaunchPreparation{}, err
	}
	return networkObservationLaunchPreparation{
		Format: "ok147-network-observation-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var executeSubmissionStageLaunch = func(ctx context.Context, config runner.SubmissionStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.SubmissionStageLaunchReceipt, error) {
	material, err := runner.BuildSubmissionStageLaunchMaterial(config)
	if err != nil {
		return runner.SubmissionStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.SubmissionStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.SubmissionStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.SubmissionStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

var executeLifecycleObservationStageLaunch = func(ctx context.Context, config runner.LifecycleObservationStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.LifecycleObservationStageLaunchReceipt, error) {
	material, err := runner.BuildLifecycleObservationStageLaunchMaterial(config)
	if err != nil {
		return runner.LifecycleObservationStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.LifecycleObservationStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.LifecycleObservationStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.LifecycleObservationStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

var executeNetworkObservationStageLaunch = func(ctx context.Context, config runner.NetworkObservationStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.NetworkObservationStageLaunchReceipt, error) {
	material, err := runner.BuildNetworkObservationStageLaunchMaterial(config)
	if err != nil {
		return runner.NetworkObservationStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.NetworkObservationStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.NetworkObservationStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.NetworkObservationStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

type createPlan struct {
	Format                  string                  `json:"format"`
	Operation               string                  `json:"operation"`
	ContractIdentity        contract.Identity       `json:"contractIdentity"`
	ContractRevision        string                  `json:"contractRevision"`
	CanonicalizationProfile string                  `json:"canonicalizationProfile"`
	RawArtifactDigest       string                  `json:"rawArtifactDigest"`
	SchemaDigest            string                  `json:"schemaDigest"`
	AuthorizationState      string                  `json:"authorizationState"`
	MutationAllowed         bool                    `json:"mutationAllowed"`
	Request                 *executor.CreateRequest `json:"request,omitempty"`
	RequestDigest           string                  `json:"requestDigest,omitempty"`
	Authorization           *authorization.Receipt  `json:"authorization,omitempty"`
	Ledger                  *ledger.Inspection      `json:"ledger,omitempty"`
}

type stageInspection struct {
	Format             string               `json:"format"`
	Decision           stagecursor.Decision `json:"decision"`
	AuthorizationState string               `json:"authorizationState"`
	MutationAllowed    bool                 `json:"mutationAllowed"`
}

type stageResumeInspection struct {
	Format          string               `json:"format"`
	Decision        stagecursor.Decision `json:"decision"`
	MutationAllowed bool                 `json:"mutationAllowed"`
}

type stageLaunchPreparation struct {
	Format          string                                       `json:"format"`
	State           string                                       `json:"state"`
	Material        runner.SubmissionStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.SubmissionStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                         `json:"mutationAllowed"`
}

type lifecycleObservationLaunchPreparation struct {
	Format          string                                                 `json:"format"`
	State           string                                                 `json:"state"`
	Material        runner.LifecycleObservationStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.LifecycleObservationStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                                   `json:"mutationAllowed"`
}

type networkObservationLaunchPreparation struct {
	Format          string                                               `json:"format"`
	State           string                                               `json:"state"`
	Material        runner.NetworkObservationStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.NetworkObservationStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                                 `json:"mutationAllowed"`
}

type runtimeBindingExecution struct {
	Format   string                                     `json:"format"`
	Receipt  execution.BindingStageRunReceipt           `json:"receipt"`
	Evidence *runner.RuntimeBindingStageEvidenceReceipt `json:"evidence,omitempty"`
}

type receiptFlags []string

func (values *receiptFlags) String() string { return strings.Join(*values, ",") }

func (values *receiptFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type stageBundleFlags struct {
	expectedStage                                                 *string
	planPath, contractNamespace, contractName                     *string
	intentRevision, enablementRevision, platformRevision          *string
	executionFixture                                              *string
	infrastructureAuthority, managementAuthority, gitOpsAuthority *string
	grantPath, grantKeyPath, projectionManifest, projectionRoot   *string
	evaluationTime                                                *string
	receipts                                                      receiptFlags
	receiptPrefix, receiptPrefixDigest                            *string
}

type stageResumeFlags struct {
	planPath, contractNamespace, contractName                     *string
	intentRevision, enablementRevision, platformRevision          *string
	executionFixture                                              *string
	infrastructureAuthority, managementAuthority, gitOpsAuthority *string
	receipts                                                      receiptFlags
	receiptPrefix, receiptPrefixDigest                            *string
}

func addStageResumeFlags(flags *flag.FlagSet) *stageResumeFlags {
	values := &stageResumeFlags{}
	values.planPath = flags.String("plan", "", "path to the bounded staged execution plan")
	values.contractNamespace = flags.String("contract-namespace", "", "expected Contract namespace")
	values.contractName = flags.String("contract-name", "", "expected Contract name")
	values.intentRevision = flags.String("intent-revision", "", "expected normalized Contract revision R")
	values.enablementRevision = flags.String("enablement-revision", "", "expected Enablement revision E")
	values.platformRevision = flags.String("platform-revision", "", "expected Platform revision P")
	values.executionFixture = flags.String("execution-fixture", "", "expected execution FixtureDigest")
	values.infrastructureAuthority = flags.String("infrastructure-authority", "", "expected infrastructure authority identity")
	values.managementAuthority = flags.String("management-authority", "", "expected management authority identity")
	values.gitOpsAuthority = flags.String("gitops-authority", "", "expected GitOps authority identity")
	flags.Var(&values.receipts, "receipt", "ordered canonical receipt as PATH@sha256:<digest>; repeat for each completed stage")
	values.receiptPrefix = flags.String("receipt-prefix", "", "path to a digest-bound ordered receipt-prefix manifest")
	values.receiptPrefixDigest = flags.String("receipt-prefix-digest", "", "expected SHA-256 digest of the receipt-prefix manifest")
	return values
}

func (values *stageResumeFlags) config() (runner.StageResumeConfig, error) {
	required := []struct{ name, value string }{
		{"--plan", *values.planPath}, {"--contract-namespace", *values.contractNamespace}, {"--contract-name", *values.contractName},
		{"--intent-revision", *values.intentRevision}, {"--enablement-revision", *values.enablementRevision}, {"--platform-revision", *values.platformRevision},
		{"--execution-fixture", *values.executionFixture}, {"--infrastructure-authority", *values.infrastructureAuthority},
		{"--management-authority", *values.managementAuthority}, {"--gitops-authority", *values.gitOpsAuthority},
	}
	for _, input := range required {
		if input.value == "" {
			return runner.StageResumeConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	providedPrefix := countNonEmpty(*values.receiptPrefix, *values.receiptPrefixDigest)
	if providedPrefix != 0 && (providedPrefix != 2 || len(values.receipts) != 0) {
		return runner.StageResumeConfig{}, errors.New("--receipt-prefix and --receipt-prefix-digest must be provided together and cannot be combined with --receipt")
	}
	receipts := make([]runner.StageReceiptSource, 0, len(values.receipts))
	var err error
	if providedPrefix == 2 {
		receipts, err = runner.LoadStageReceiptPrefix(*values.receiptPrefix, *values.receiptPrefixDigest)
		if err != nil {
			return runner.StageResumeConfig{}, err
		}
	} else {
		for _, value := range values.receipts {
			if !stageReceiptFlagPattern.MatchString(value) {
				return runner.StageResumeConfig{}, errors.New("receipt must use PATH@sha256:<64 lowercase hex> format")
			}
			separator := strings.LastIndex(value, "@sha256:")
			receipts = append(receipts, runner.StageReceiptSource{Path: value[:separator], Digest: value[separator+1:]})
		}
	}
	return runner.StageResumeConfig{
		PlanPath: *values.planPath,
		PlanExpected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: *values.contractNamespace, Name: *values.contractName},
			IntentRevision:   *values.intentRevision, EnablementRevision: *values.enablementRevision,
			PlatformRevision: *values.platformRevision, ExecutionFixture: *values.executionFixture,
			InfrastructureAuthority: *values.infrastructureAuthority, ManagementAuthority: *values.managementAuthority, GitOpsAuthority: *values.gitOpsAuthority,
		},
		Receipts: receipts,
	}, nil
}

func addStageBundleFlags(flags *flag.FlagSet) *stageBundleFlags {
	values := &stageBundleFlags{}
	values.expectedStage = flags.String("expected-stage", "", "independently expected Contract-to-CAPI stage")
	values.planPath = flags.String("plan", "", "path to the bounded staged execution plan")
	values.contractNamespace = flags.String("contract-namespace", "", "expected Contract namespace")
	values.contractName = flags.String("contract-name", "", "expected Contract name")
	values.intentRevision = flags.String("intent-revision", "", "expected normalized Contract revision R")
	values.enablementRevision = flags.String("enablement-revision", "", "expected Enablement revision E")
	values.platformRevision = flags.String("platform-revision", "", "expected Platform revision P")
	values.executionFixture = flags.String("execution-fixture", "", "expected execution FixtureDigest")
	values.infrastructureAuthority = flags.String("infrastructure-authority", "", "expected infrastructure authority identity")
	values.managementAuthority = flags.String("management-authority", "", "expected management authority identity")
	values.gitOpsAuthority = flags.String("gitops-authority", "", "expected GitOps authority identity")
	flags.Var(&values.receipts, "receipt", "ordered canonical predecessor receipt as PATH@sha256:<digest>; repeat for each receipt")
	values.receiptPrefix = flags.String("receipt-prefix", "", "path to a digest-bound ordered receipt-prefix manifest")
	values.receiptPrefixDigest = flags.String("receipt-prefix-digest", "", "expected SHA-256 digest of the receipt-prefix manifest")
	values.grantPath = flags.String("grant", "", "path to the signed single-stage grant")
	values.grantKeyPath = flags.String("grant-key", "", "path to the trusted stage-authority public key")
	values.projectionManifest = flags.String("projection-manifest", "", "path to the immutable projection manifest")
	values.projectionRoot = flags.String("projection-root", "", "directory containing projection artifacts (defaults to manifest directory)")
	values.evaluationTime = flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	return values
}

func (values *stageBundleFlags) config() (runner.SubmissionStageBundleConfig, error) {
	required := []struct {
		name  string
		value string
	}{
		{"--expected-stage", *values.expectedStage},
		{"--plan", *values.planPath}, {"--contract-namespace", *values.contractNamespace}, {"--contract-name", *values.contractName},
		{"--intent-revision", *values.intentRevision}, {"--enablement-revision", *values.enablementRevision}, {"--platform-revision", *values.platformRevision},
		{"--execution-fixture", *values.executionFixture}, {"--infrastructure-authority", *values.infrastructureAuthority},
		{"--management-authority", *values.managementAuthority}, {"--gitops-authority", *values.gitOpsAuthority},
		{"--grant", *values.grantPath}, {"--grant-key", *values.grantKeyPath}, {"--projection-manifest", *values.projectionManifest}, {"--evaluation-time", *values.evaluationTime},
	}
	for _, input := range required {
		if input.value == "" {
			return runner.SubmissionStageBundleConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	at, err := time.Parse(time.RFC3339, *values.evaluationTime)
	if err != nil {
		return runner.SubmissionStageBundleConfig{}, fmt.Errorf("parse evaluation time: %w", err)
	}
	providedPrefix := countNonEmpty(*values.receiptPrefix, *values.receiptPrefixDigest)
	if providedPrefix != 0 && (providedPrefix != 2 || len(values.receipts) != 0) {
		return runner.SubmissionStageBundleConfig{}, errors.New("--receipt-prefix and --receipt-prefix-digest must be provided together and cannot be combined with --receipt")
	}
	var receipts []runner.StageReceiptSource
	if providedPrefix == 2 {
		receipts, err = runner.LoadStageReceiptPrefix(*values.receiptPrefix, *values.receiptPrefixDigest)
		if err != nil {
			return runner.SubmissionStageBundleConfig{}, err
		}
	} else {
		receipts = make([]runner.StageReceiptSource, 0, len(values.receipts))
		for _, value := range values.receipts {
			if !stageReceiptFlagPattern.MatchString(value) {
				return runner.SubmissionStageBundleConfig{}, errors.New("receipt must use PATH@sha256:<64 lowercase hex> format")
			}
			separator := strings.LastIndex(value, "@sha256:")
			receipts = append(receipts, runner.StageReceiptSource{Path: value[:separator], Digest: value[separator+1:]})
		}
	}
	return runner.SubmissionStageBundleConfig{
		ExpectedStageID: *values.expectedStage, PlanPath: *values.planPath,
		PlanExpected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: *values.contractNamespace, Name: *values.contractName},
			IntentRevision:   *values.intentRevision, EnablementRevision: *values.enablementRevision,
			PlatformRevision: *values.platformRevision, ExecutionFixture: *values.executionFixture,
			InfrastructureAuthority: *values.infrastructureAuthority, ManagementAuthority: *values.managementAuthority, GitOpsAuthority: *values.gitOpsAuthority,
		},
		Receipts: receipts, GrantPath: *values.grantPath, GrantPublicKeyPath: *values.grantKeyPath,
		ProjectionManifestPath: *values.projectionManifest, ProjectionRoot: *values.projectionRoot, EvaluationTime: at,
	}, nil
}

var inspectSubmissionStage = func(config runner.SubmissionStageBundleConfig) (stageInspection, error) {
	bundle, err := runner.LoadSubmissionStageBundle(config)
	if err != nil {
		return stageInspection{}, err
	}
	decision, err := bundle.Decision()
	if err != nil {
		return stageInspection{}, err
	}
	return stageInspection{
		Format: "ok147-stage-inspection/v1", Decision: decision,
		AuthorizationState: "VERIFIED", MutationAllowed: false,
	}, nil
}

var inspectStageResume = func(config runner.StageResumeConfig) (stageResumeInspection, error) {
	decision, err := runner.InspectStageResume(config)
	if err != nil {
		return stageResumeInspection{}, err
	}
	return stageResumeInspection{Format: "ok147-stage-resume-inspection/v1", Decision: decision, MutationAllowed: false}, nil
}

var executeSubmissionStage = func(ctx context.Context, bundleConfig runner.SubmissionStageBundleConfig, runtimeConfig runner.SubmissionStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
	bundle, err := runner.LoadSubmissionStageBundle(bundleConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	decision, err := bundle.Decision()
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	authorityIdentity, err := submissionStageAuthority(decision, bundleConfig.PlanExpected)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	runtimeConfig.Authority.AuthorityIdentity = authorityIdentity
	bound, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	return bound.Run(ctx)
}

var executeEnablementStage = func(ctx context.Context, bundleConfig runner.EnablementStageBundleConfig, runtimeConfig runner.SubmissionStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
	bundle, err := runner.LoadEnablementStageBundle(bundleConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	bound, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	return bound.Run(ctx)
}

var executeTargetAccessStage = func(ctx context.Context, bundleConfig runner.TargetAccessStageBundleConfig, runtimeConfig runner.TargetAccessStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
	bundle, err := runner.LoadTargetAccessStageBundle(bundleConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	bound, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	return bound.Run(ctx)
}

var executeLifecycleObservationStage = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.LifecycleObservationStageRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
	bundle, err := runner.LoadLifecycleObservationStageBundle(bundleConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	runtimeConfig.Management.AuthorityIdentity = bundleConfig.PlanExpected.ManagementAuthority
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	return opened.Run(ctx)
}

var executeLifecycleObservationStageRetry = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.LifecycleObservationStageRuntimeConfig, failedReceiptDigest string) (execution.ObservationStageRunReceipt, error) {
	bundle, err := runner.LoadLifecycleObservationStageBundle(bundleConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	runtimeConfig.Management.AuthorityIdentity = bundleConfig.PlanExpected.ManagementAuthority
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	return opened.Retry(ctx, failedReceiptDigest)
}

var executeNetworkObservationStage = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.NetworkObservationStageRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
	bundle, err := runner.LoadNetworkObservationStageBundle(bundleConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	runtimeConfig.Management.AuthorityIdentity = bundleConfig.PlanExpected.ManagementAuthority
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	return opened.Run(ctx)
}

var executeNetworkObservationStageRetry = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.NetworkObservationStageRuntimeConfig, failedReceiptDigest string) (execution.ObservationStageRunReceipt, error) {
	bundle, err := runner.LoadNetworkObservationStageBundle(bundleConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	runtimeConfig.Management.AuthorityIdentity = bundleConfig.PlanExpected.ManagementAuthority
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	return opened.Retry(ctx, failedReceiptDigest)
}

var executeRuntimeBindingStage = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.RuntimeBindingStageRuntimeConfig) (execution.BindingStageRunReceipt, *runner.RuntimeBindingStageEvidenceReceipt, error) {
	bundle, err := runner.LoadRuntimeBindingStageBundle(bundleConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	receipt, runErr := opened.Run(ctx)
	evidence, evidenceErr := opened.EvidenceReceipt()
	if evidenceErr == nil {
		return receipt, &evidence, runErr
	}
	return receipt, nil, runErr
}

var executeKubernetesRuntimeBindingStage = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.RuntimeBindingStageKubernetesRuntimeConfig) (execution.BindingStageRunReceipt, *runner.RuntimeBindingStageEvidenceReceipt, error) {
	bundle, err := runner.LoadRuntimeBindingStageBundle(bundleConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	opened, err := bundle.OpenKubernetes(runtimeConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	receipt, runErr := opened.Run(ctx)
	evidence, evidenceErr := opened.EvidenceReceipt()
	if evidenceErr == nil {
		return receipt, &evidence, runErr
	}
	return receipt, nil, runErr
}

var executeRuntimeBindingStageRetry = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.RuntimeBindingStageRuntimeConfig, terminalReceiptDigest string) (execution.BindingStageRunReceipt, *runner.RuntimeBindingStageEvidenceReceipt, error) {
	bundle, err := runner.LoadRuntimeBindingStageBundle(bundleConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	receipt, runErr := opened.Retry(ctx, terminalReceiptDigest)
	evidence, evidenceErr := opened.EvidenceReceipt()
	if evidenceErr == nil {
		return receipt, &evidence, runErr
	}
	return receipt, nil, runErr
}

var executeKubernetesRuntimeBindingStageRetry = func(ctx context.Context, bundleConfig runner.StageResumeConfig, runtimeConfig runner.RuntimeBindingStageKubernetesRuntimeConfig, terminalReceiptDigest string) (execution.BindingStageRunReceipt, *runner.RuntimeBindingStageEvidenceReceipt, error) {
	bundle, err := runner.LoadRuntimeBindingStageBundle(bundleConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	opened, err := bundle.OpenKubernetes(runtimeConfig)
	if err != nil {
		return execution.BindingStageRunReceipt{}, nil, err
	}
	receipt, runErr := opened.Retry(ctx, terminalReceiptDigest)
	evidence, evidenceErr := opened.EvidenceReceipt()
	if evidenceErr == nil {
		return receipt, &evidence, runErr
	}
	return receipt, nil, runErr
}

func submissionStageAuthority(decision stagecursor.Decision, expected stageplan.Expected) (string, error) {
	switch decision.Authority {
	case "infrastructure":
		return expected.InfrastructureAuthority, nil
	case "management":
		return expected.ManagementAuthority, nil
	default:
		return "", errors.New("selected stage has no supported Kubernetes submission authority")
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	return runContext(context.Background(), arguments, stdout, stderr)
}

func runContext(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 1 && arguments[0] == "version" {
		fmt.Fprintf(stdout, "%s %s\n", version, revision)
		return nil
	}
	if len(arguments) >= 2 && arguments[0] == "cluster" && arguments[1] == "create" {
		return runClusterCreate(arguments[2:], stdout, stderr)
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "inspect" {
		return runClusterStageInspect(arguments[3:], stdout, stderr)
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "resume" {
		return runClusterStageResume(arguments[3:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "receipt" && arguments[3] == "materialize" {
		return runClusterStageReceiptMaterialize(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "lifecycle" && arguments[4] == "package" {
		return runClusterStageObserveLifecyclePackage(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "lifecycle" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageObserveLifecycleLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "lifecycle" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageObserveLifecycleLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "lifecycle" {
		return runClusterStageObserveLifecycle(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "network" && arguments[4] == "package" {
		return runClusterStageObserveNetworkPackage(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "network" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageObserveNetworkLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "network" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageObserveNetworkLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "network" {
		return runClusterStageObserveNetwork(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && arguments[3] == "platform" {
		return runClusterStageObservePlatform(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "evaluate" && arguments[3] == "aggregate" {
		return runClusterStageEvaluateAggregate(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "bind" && arguments[3] == "runtime" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageBindRuntimeLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "bind" && arguments[3] == "runtime" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageBindRuntimeLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "bind" && arguments[3] == "runtime" {
		return runClusterStageBindRuntime(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "enablement" && arguments[4] == "package" {
		return runClusterStageRunEnablementPackage(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "enablement" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageRunEnablementLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "enablement" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageRunEnablementLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "enablement" {
		return runClusterStageRunEnablement(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "target-access" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageRunTargetAccessLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "target-access" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageRunTargetAccessLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "target-access" && arguments[4] == "package" {
		return runClusterStageRunTargetAccessPackage(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "target-access" {
		return runClusterStageRunTargetAccess(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "platform-applications" {
		return runClusterStageRunPlatformApplications(ctx, arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "full" && arguments[4] == "prepare" {
		return runClusterStageRunFullPrepare(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "full" && arguments[4] == "execute" {
		return runClusterStageRunFullExecute(ctx, arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "post-runtime" && arguments[4] == "materialize" {
		return runClusterStageRunPostRuntimeMaterialize(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "post-runtime" && arguments[4] == "package" {
		return runClusterStageRunPostRuntimePackage(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "post-runtime" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageRunPostRuntimeLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "post-runtime" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageRunPostRuntimeLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "post-runtime" && arguments[4] == "prepare" {
		return runClusterStageRunPostRuntimePrepare(arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "post-runtime" && arguments[4] == "execute" {
		return runClusterStageRunPostRuntimeExecute(ctx, arguments[5:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "aggregate-evidence" && arguments[4] == "launch" && arguments[5] == "prepare" {
		return runClusterStageRunAggregateEvidenceLaunchPrepare(arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 6 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "aggregate-evidence" && arguments[4] == "launch" && arguments[5] == "execute" {
		return runClusterStageRunAggregateEvidenceLaunchExecute(ctx, arguments[6:], stdout, stderr)
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" {
		return runClusterStageRun(ctx, arguments[3:], stdout, stderr)
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "package" {
		return runClusterStagePackage(arguments[3:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "launch" && arguments[3] == "prepare" {
		return runClusterStageLaunchPrepare(arguments[4:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "launch" && arguments[3] == "execute" {
		return runClusterStageLaunchExecute(ctx, arguments[4:], stdout, stderr)
	}
	return errors.New("usage: ok cluster create ... | ok cluster stage inspect ... | ok cluster stage resume ... | ok cluster stage receipt materialize ... | ok cluster stage observe lifecycle ... | ok cluster stage observe network ... | ok cluster stage observe platform ... | ok cluster stage evaluate aggregate ... | ok cluster stage bind runtime ... | ok cluster stage bind runtime launch prepare ... | ok cluster stage bind runtime launch execute ... | ok cluster stage observe network package ... | ok cluster stage observe network launch prepare ... | ok cluster stage observe network launch execute ... | ok cluster stage observe lifecycle package ... | ok cluster stage observe lifecycle launch prepare ... | ok cluster stage observe lifecycle launch execute ... | ok cluster stage run ... | ok cluster stage run full prepare ... | ok cluster stage run full execute ... | ok cluster stage run enablement ... | ok cluster stage run target-access ... | ok cluster stage run platform-applications ... | ok cluster stage run post-runtime package ... | ok cluster stage run post-runtime materialize ... | ok cluster stage run post-runtime launch prepare ... | ok cluster stage run post-runtime launch execute ... | ok cluster stage run post-runtime prepare ... | ok cluster stage run post-runtime execute ... | ok cluster stage run aggregate-evidence launch prepare ... | ok cluster stage run aggregate-evidence launch execute ... | ok cluster stage run enablement package ... | ok cluster stage run enablement launch prepare ... | ok cluster stage run enablement launch execute ... | ok cluster stage package ... | ok cluster stage launch prepare ... | ok cluster stage launch execute ...")
}

func runClusterCreate(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to the versioned cluster contract")
	schemaPath := flags.String("schema", "", "path to the contract test schema")
	dryRun := flags.Bool("dry-run", false, "validate and emit an immutable create plan without mutation")
	projectionManifest := flags.String("projection-manifest", "", "path to an immutable projection manifest produced by the authoritative renderer")
	projectionRoot := flags.String("projection-root", "", "directory containing projection artifacts (defaults to manifest directory)")
	authorizationPath := flags.String("authorization", "", "path to a signed create authorization JSON document")
	authorizationKeyPath := flags.String("authorization-key", "", "path to the trusted base64-encoded raw Ed25519 public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 authorization evaluation time")
	ledgerInspect := flags.Bool("ledger-inspect", false, "read the exact durable grant state without claiming it")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to a projected short-lived ledger ServiceAccount token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the projected Kubernetes API CA bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*dryRun {
		return errors.New("ok cluster create remains dry-run-only; mutating submission is available only through explicitly authorized ok cluster stage commands")
	}
	if *contractPath == "" || *schemaPath == "" {
		return errors.New("--contract and --schema are required")
	}
	if *projectionRoot != "" && *projectionManifest == "" {
		return errors.New("--projection-root requires --projection-manifest")
	}
	raw, err := os.ReadFile(*contractPath)
	if err != nil {
		return fmt.Errorf("read contract: %w", err)
	}
	schema, err := os.ReadFile(*schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	result, err := contract.Canonicalize(raw, schema)
	if err != nil {
		return err
	}
	identity, err := contract.ContractIdentity(result.Normalized)
	if err != nil {
		return err
	}
	plan := createPlan{
		Format:                  "ok147-create-plan/v1",
		Operation:               "CreateCluster",
		ContractIdentity:        identity,
		ContractRevision:        result.NormalizedDigest,
		CanonicalizationProfile: result.CanonicalizationProfile,
		RawArtifactDigest:       result.RawArtifactDigest,
		SchemaDigest:            result.SchemaDigest,
		AuthorizationState:      "NOT_EVALUATED",
		MutationAllowed:         false,
	}
	if *projectionManifest != "" {
		binding, err := projection.Verify(*projectionManifest, *projectionRoot, result.NormalizedDigest, identity)
		if err != nil {
			return err
		}
		request, err := executor.NewCreateRequest(result, identity, binding)
		if err != nil {
			return err
		}
		requestDigest, err := executor.Digest(request)
		if err != nil {
			return fmt.Errorf("digest create request: %w", err)
		}
		plan.Format = "ok147-create-plan/v2"
		plan.Request = &request
		plan.RequestDigest = requestDigest
	}
	providedAuthorizationInputs := countNonEmpty(*authorizationPath, *authorizationKeyPath, *evaluationTime)
	var verifiedGrant authorization.VerifiedGrant
	if providedAuthorizationInputs != 0 {
		if plan.Request == nil {
			return errors.New("--authorization requires --projection-manifest")
		}
		if providedAuthorizationInputs != 3 {
			return errors.New("--authorization, --authorization-key, and --evaluation-time must be provided together")
		}
		authorizationRaw, err := os.ReadFile(*authorizationPath)
		if err != nil {
			return fmt.Errorf("read authorization: %w", err)
		}
		keyRaw, err := os.ReadFile(*authorizationKeyPath)
		if err != nil {
			return fmt.Errorf("read authorization key: %w", err)
		}
		at, err := time.Parse(time.RFC3339, *evaluationTime)
		if err != nil {
			return fmt.Errorf("parse evaluation time: %w", err)
		}
		grant, err := authorization.Verify(authorizationRaw, keyRaw, *plan.Request, at)
		if err != nil {
			return err
		}
		verifiedGrant = grant
		receipt := grant.Receipt()
		plan.AuthorizationState = "VERIFIED"
		plan.Authorization = &receipt
	}
	providedLedgerInputs := countNonEmpty(*ledgerAPIEndpoint, *ledgerTokenFile, *ledgerCAFile)
	if !*ledgerInspect && providedLedgerInputs != 0 {
		return errors.New("Kubernetes ledger inputs require --ledger-inspect")
	}
	if *ledgerInspect {
		if plan.Authorization == nil {
			return errors.New("--ledger-inspect requires a verified authorization")
		}
		if providedLedgerInputs != 3 {
			return errors.New("--ledger-api-endpoint, --ledger-token-file, and --ledger-ca-file must be provided together")
		}
		inspection, err := runner.InspectKubernetesLedger(context.Background(), verifiedGrant, runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		})
		if err != nil {
			return fmt.Errorf("inspect durable grant ledger: %w", err)
		}
		plan.Format = "ok147-create-plan/v3"
		plan.Ledger = &inspection
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}

func runClusterStageInspect(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleFlags := addStageBundleFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	inspection, err := inspectSubmissionStage(bundleConfig)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inspection)
}

func runClusterStageResume(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage resume", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := resumeFlags.config()
	if err != nil {
		return err
	}
	inspection, err := inspectStageResume(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inspection)
}

func runClusterStageReceiptMaterialize(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage receipt materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	execute := flags.Bool("execute", false, "materialize exactly one verified durable stage receipt")
	runFormat := flags.String("run-format", "", "exact successful stage run receipt format")
	planDigest := flags.String("plan-digest", "", "exact staged plan digest from the successful run")
	stageID := flags.String("stage-id", "", "exact successful stage ID selected by the cursor")
	stageReceiptDigest := flags.String("stage-receipt-digest", "", "exact durable successful stage receipt digest")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	output := flags.String("output", "", "exclusive private absolute output path for the verified receipt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("stage receipt materialization requires explicit --execute")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--run-format", *runFormat}, {"--plan-digest", *planDigest}, {"--stage-id", *stageID},
		{"--stage-receipt-digest", *stageReceiptDigest}, {"--ledger-api-endpoint", *ledgerAPIEndpoint},
		{"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile}, {"--output", *output},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*planDigest) || !sha256DigestPattern.MatchString(*stageReceiptDigest) {
		return errors.New("stage receipt materialization requires exact SHA-256 identities")
	}
	boundedContext, cancel := context.WithTimeout(ctx, runtimeBindingRunTimeout)
	defer cancel()
	store, err := runner.OpenKubernetesLedger(runner.KubernetesLedgerConfig{
		Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
	})
	if err != nil {
		return errors.New("open durable stage receipt ledger")
	}
	material, err := runner.LoadStageReceiptMaterial(boundedContext, runner.StageReceiptBridgeConfig{
		Bundle: resume, Ledger: store,
		Run: runner.StageRunReceiptReference{
			Format: *runFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: *planDigest,
			StageID: *stageID, StageReceiptDigest: *stageReceiptDigest,
		},
	})
	if err != nil {
		return err
	}
	source, err := material.Persist(*output)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(struct {
		Format string `json:"format"`
		State  string `json:"state"`
		Stage  string `json:"stageId"`
		Path   string `json:"path"`
		Digest string `json:"digest"`
	}{
		Format: "ok147-stage-receipt-materialization/v1", State: "MATERIALIZED",
		Stage: *stageID, Path: source.Path, Digest: source.Digest,
	})
}

func runClusterStageObserveLifecycle(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe lifecycle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	execute := flags.Bool("execute", false, "perform exactly the selected read-only observation and persist its receipt")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	managementAPIEndpoint := flags.String("management-api-endpoint", "", "TLS Kubernetes API endpoint for exact CAPI observation")
	managementTokenFile := flags.String("management-token-file", "", "path to the short-lived read-only management token")
	managementCAFile := flags.String("management-ca-file", "", "path to the management Kubernetes API CA bundle")
	pollInterval := flags.Duration("poll-interval", 0, "bounded interval between verified Unknown observations")
	pollTimeout := flags.Duration("poll-timeout", 0, "maximum bounded lifecycle observation duration")
	retryAfterReceipt := flags.String("retry-after-failed-receipt-digest", "", "retry only after the exact immutable FAILED observation receipt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("lifecycle observation requires explicit --execute")
	}
	bundleConfig, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--management-api-endpoint", *managementAPIEndpoint}, {"--management-token-file", *managementTokenFile}, {"--management-ca-file", *managementCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if *pollInterval < time.Second || *pollInterval > 5*time.Minute || *pollTimeout < *pollInterval || *pollTimeout > 6*time.Hour {
		return errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	if *retryAfterReceipt != "" && !sha256DigestPattern.MatchString(*retryAfterReceipt) {
		return errors.New("--retry-after-failed-receipt-digest must be an exact SHA-256 identity")
	}
	runTimeout := *pollTimeout + lifecycleObservationRunOverhead
	boundedContext, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	runtimeConfig := runner.LifecycleObservationStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		},
		Management: runner.KubernetesAuthorityConfig{
			Endpoint: *managementAPIEndpoint, TokenFile: *managementTokenFile, CAFile: *managementCAFile,
		},
		PollInterval: *pollInterval, PollTimeout: *pollTimeout,
		Clock: func() time.Time { return time.Now().UTC() }, Wait: runner.WaitWithTimer,
	}
	var receipt execution.ObservationStageRunReceipt
	var runErr error
	if *retryAfterReceipt == "" {
		receipt, runErr = executeLifecycleObservationStage(boundedContext, bundleConfig, runtimeConfig)
	} else {
		receipt, runErr = executeLifecycleObservationStageRetry(boundedContext, bundleConfig, runtimeConfig, *retryAfterReceipt)
	}
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStageObserveNetwork(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe network", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	execute := flags.Bool("execute", false, "perform exactly the selected read-only network observation and persist its receipt")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	managementAPIEndpoint := flags.String("management-api-endpoint", "", "TLS Kubernetes API endpoint for exact HCP/HRP observation")
	managementTokenFile := flags.String("management-token-file", "", "path to the short-lived read-only management token")
	managementCAFile := flags.String("management-ca-file", "", "path to the management Kubernetes API CA bundle")
	workloadBinding := flags.String("workload-binding", "", "path to the private runtime workload-authority binding")
	workloadBindingDigest := flags.String("workload-binding-digest", "", "expected workload-authority binding digest")
	workloadTokenFile := flags.String("workload-token-file", "", "path to the short-lived read-only workload token")
	workloadCAFile := flags.String("workload-ca-file", "", "path to the workload Kubernetes API CA bundle")
	networkProfile := flags.String("network-profile", "", "path to the immutable NetworkReady profile")
	networkProfileDigest := flags.String("network-profile-digest", "", "expected NetworkReady profile digest")
	pollInterval := flags.Duration("poll-interval", 0, "bounded interval between verified Unknown observations")
	pollTimeout := flags.Duration("poll-timeout", 0, "maximum bounded network observation duration")
	retryAfterReceipt := flags.String("retry-after-failed-receipt-digest", "", "retry only after the exact immutable FAILED observation receipt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("network observation requires explicit --execute")
	}
	bundleConfig, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--management-api-endpoint", *managementAPIEndpoint}, {"--management-token-file", *managementTokenFile}, {"--management-ca-file", *managementCAFile},
		{"--workload-binding", *workloadBinding}, {"--workload-binding-digest", *workloadBindingDigest},
		{"--workload-token-file", *workloadTokenFile}, {"--workload-ca-file", *workloadCAFile},
		{"--network-profile", *networkProfile}, {"--network-profile-digest", *networkProfileDigest},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*workloadBindingDigest) || !sha256DigestPattern.MatchString(*networkProfileDigest) {
		return errors.New("workload binding and network profile digests must be lowercase SHA-256 identities")
	}
	if *pollInterval < time.Second || *pollInterval > 5*time.Minute || *pollTimeout < *pollInterval || *pollTimeout > 6*time.Hour {
		return errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	if *retryAfterReceipt != "" && !sha256DigestPattern.MatchString(*retryAfterReceipt) {
		return errors.New("--retry-after-failed-receipt-digest must be an exact SHA-256 identity")
	}
	boundedContext, cancel := context.WithTimeout(ctx, *pollTimeout+lifecycleObservationRunOverhead)
	defer cancel()
	runtimeConfig := runner.NetworkObservationStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		},
		Management: runner.KubernetesAuthorityConfig{
			Endpoint: *managementAPIEndpoint, TokenFile: *managementTokenFile, CAFile: *managementCAFile,
		},
		Workload: runner.WorkloadAuthorityFileResolverConfig{
			Path: *workloadBinding, ExpectedBindingDigest: *workloadBindingDigest,
			TokenFile: *workloadTokenFile, CAFile: *workloadCAFile,
		},
		NetworkProfilePath: *networkProfile, ExpectedNetworkProfileDigest: *networkProfileDigest,
		PollInterval: *pollInterval, PollTimeout: *pollTimeout,
		Clock: func() time.Time { return time.Now().UTC() }, Wait: runner.WaitWithTimer,
	}
	var receipt execution.ObservationStageRunReceipt
	var runErr error
	if *retryAfterReceipt == "" {
		receipt, runErr = executeNetworkObservationStage(boundedContext, bundleConfig, runtimeConfig)
	} else {
		receipt, runErr = executeNetworkObservationStageRetry(boundedContext, bundleConfig, runtimeConfig, *retryAfterReceipt)
	}
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStageBindRuntime(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage bind runtime", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	execute := flags.Bool("execute", false, "perform exactly the selected runtime binding and persist its receipts")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable management ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	workloadBinding := flags.String("workload-binding", "", "path to the private workload-authority binding")
	workloadBindingDigest := flags.String("workload-binding-digest", "", "expected workload-authority binding digest")
	workloadTokenFile := flags.String("workload-token-file", "", "path to the short-lived read-only workload token")
	workloadCAFile := flags.String("workload-ca-file", "", "path to the workload Kubernetes API CA bundle")
	persistenceMode := flags.String("persistence-mode", "local-file", "exact persistence mode: local-file or immutable-secret")
	persistenceTokenFile := flags.String("persistence-token-file", "", "path to the distinct short-lived runtime-binding Secret writer token")
	persistenceCAFile := flags.String("persistence-ca-file", "", "path to the runtime-binding Secret writer Kubernetes API CA bundle")
	output := flags.String("output", "", "absent absolute path in a private directory for the runtime binding")
	retryAfterReceipt := flags.String("retry-after-terminal-receipt-digest", "", "retry only after the exact immutable FAILED or STOPPED binding receipt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("runtime binding requires explicit --execute")
	}
	bundleConfig, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--workload-binding", *workloadBinding}, {"--workload-binding-digest", *workloadBindingDigest},
		{"--workload-token-file", *workloadTokenFile}, {"--workload-ca-file", *workloadCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*workloadBindingDigest) {
		return errors.New("workload binding digest must be a lowercase SHA-256 identity")
	}
	if *retryAfterReceipt != "" && !sha256DigestPattern.MatchString(*retryAfterReceipt) {
		return errors.New("--retry-after-terminal-receipt-digest must be an exact SHA-256 identity")
	}
	switch *persistenceMode {
	case "local-file":
		if *persistenceTokenFile != "" || *persistenceCAFile != "" {
			return errors.New("local-file persistence cannot accept Kubernetes persistence credentials")
		}
		if *output == "" || !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
			return errors.New("--output must be a clean absolute path for local-file persistence")
		}
	case "immutable-secret":
		if *output != "" {
			return errors.New("immutable-secret persistence cannot accept --output")
		}
		if *persistenceTokenFile == "" || *persistenceCAFile == "" {
			return errors.New("immutable-secret persistence requires token and CA files")
		}
	default:
		return errors.New("unsupported runtime binding persistence mode")
	}
	boundedContext, cancel := context.WithTimeout(ctx, runtimeBindingRunTimeout)
	defer cancel()
	ledgerConfig := runner.KubernetesLedgerConfig{Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile}
	workloadConfig := runner.WorkloadAuthorityFileResolverConfig{
		Path: *workloadBinding, ExpectedBindingDigest: *workloadBindingDigest,
		TokenFile: *workloadTokenFile, CAFile: *workloadCAFile,
	}
	var receipt execution.BindingStageRunReceipt
	var evidence *runner.RuntimeBindingStageEvidenceReceipt
	var runErr error
	outputFormat := "ok147-runtime-binding-execution/v1"
	if *persistenceMode == "immutable-secret" {
		outputFormat = "ok147-runtime-binding-execution/v2"
		runtimeConfig := runner.RuntimeBindingStageKubernetesRuntimeConfig{
			Ledger: ledgerConfig, Workload: workloadConfig,
			Persistence: runner.KubernetesAuthorityConfig{
				Endpoint: *ledgerAPIEndpoint, AuthorityIdentity: bundleConfig.PlanExpected.ManagementAuthority,
				TokenFile: *persistenceTokenFile, CAFile: *persistenceCAFile,
			},
			Clock: func() time.Time { return time.Now().UTC() },
		}
		if *retryAfterReceipt == "" {
			receipt, evidence, runErr = executeKubernetesRuntimeBindingStage(boundedContext, bundleConfig, runtimeConfig)
		} else {
			receipt, evidence, runErr = executeKubernetesRuntimeBindingStageRetry(boundedContext, bundleConfig, runtimeConfig, *retryAfterReceipt)
		}
	} else {
		runtimeConfig := runner.RuntimeBindingStageRuntimeConfig{
			Ledger: ledgerConfig, Workload: workloadConfig, OutputPath: *output,
			Clock: func() time.Time { return time.Now().UTC() },
		}
		if *retryAfterReceipt == "" {
			receipt, evidence, runErr = executeRuntimeBindingStage(boundedContext, bundleConfig, runtimeConfig)
		} else {
			receipt, evidence, runErr = executeRuntimeBindingStageRetry(boundedContext, bundleConfig, runtimeConfig, *retryAfterReceipt)
		}
	}
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(runtimeBindingExecution{Format: outputFormat, Receipt: receipt, Evidence: evidence}); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStageObserveNetworkPackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe network package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	jobTemplate := flags.String("job-template", "", "path to the bounded network-observation Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new local file for the verified ConfigMap/Job/NetworkPolicy package")
	runID := flags.String("run-id", "", "bounded OK-147 network observation Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable network observation input ConfigMap name")
	networkProfile := flags.String("network-profile", "", "path to the immutable NetworkReady profile")
	networkProfileDigest := flags.String("network-profile-digest", "", "expected NetworkReady profile digest")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "externally materialized ledger credential Secret name")
	managementAPIURL := flags.String("management-api-url", "", "exact management-observer HTTPS IP endpoint")
	managementAPICIDR := flags.String("management-api-cidr", "", "single-address management-observer CIDR")
	managementCredentialSecret := flags.String("management-credential-secret", "", "externally materialized management credential Secret name")
	workloadAPIURL := flags.String("workload-api-url", "", "exact workload-observer HTTPS IP endpoint")
	workloadAPICIDR := flags.String("workload-api-cidr", "", "single-address workload-observer CIDR")
	workloadCredentialSecret := flags.String("workload-credential-secret", "", "externally materialized workload credential Secret name")
	workloadBinding := flags.String("workload-binding", "", "path to the private workload-authority binding")
	workloadBindingDigest := flags.String("workload-binding-digest", "", "expected workload-authority binding digest")
	pollInterval := flags.Duration("poll-interval", 0, "bounded interval between verified Unknown observations")
	pollTimeout := flags.Duration("poll-timeout", 0, "maximum bounded network observation duration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--output", *output},
		{"--run-id", *runID}, {"--image", *imageDigest}, {"--input-configmap", *inputConfigMap},
		{"--network-profile", *networkProfile}, {"--network-profile-digest", *networkProfileDigest},
		{"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR}, {"--ledger-credential-secret", *ledgerCredentialSecret},
		{"--management-api-url", *managementAPIURL}, {"--management-api-cidr", *managementAPICIDR}, {"--management-credential-secret", *managementCredentialSecret},
		{"--workload-api-url", *workloadAPIURL}, {"--workload-api-cidr", *workloadAPICIDR}, {"--workload-credential-secret", *workloadCredentialSecret},
		{"--workload-binding", *workloadBinding}, {"--workload-binding-digest", *workloadBindingDigest},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{*jobTemplateDigest, *networkProfileDigest, *workloadBindingDigest} {
		if !sha256DigestPattern.MatchString(value) {
			return errors.New("template, network profile, and workload binding digests must be lowercase SHA-256 identities")
		}
	}
	if *pollInterval < time.Second || *pollInterval > 5*time.Minute || *pollTimeout < *pollInterval || *pollTimeout > 6*time.Hour {
		return errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read network observation Job template: %w", err)
	}
	raw, receipt, err := materializeNetworkObservationStagePackage(runner.NetworkObservationStagePackageConfig{
		Input: runner.NetworkObservationStageInputConfig{
			Bundle: bundleConfig, NetworkProfilePath: *networkProfile,
			ExpectedNetworkProfileDigest: *networkProfileDigest, ConfigMapName: *inputConfigMap,
		},
		JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest,
		LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
		ManagementAPIURL: *managementAPIURL, ManagementAPICIDR: *managementAPICIDR, ManagementCredentialSecret: *managementCredentialSecret,
		WorkloadAPIURL: *workloadAPIURL, WorkloadAPICIDR: *workloadAPICIDR, WorkloadCredentialSecret: *workloadCredentialSecret,
		WorkloadBindingPath: *workloadBinding, ExpectedWorkloadBindingDigest: *workloadBindingDigest,
		PollInterval: *pollInterval, PollTimeout: *pollTimeout,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return fmt.Errorf("write network observation stage package: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runClusterStageObserveLifecyclePackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe lifecycle package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	jobTemplate := flags.String("job-template", "", "path to the bounded lifecycle-observation Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new local file for the verified ConfigMap/Job/NetworkPolicy package")
	runID := flags.String("run-id", "", "bounded OK-147 observation Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable observation input ConfigMap name")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "externally materialized ledger credential Secret name")
	managementAPIURL := flags.String("management-api-url", "", "exact management-observer HTTPS IP endpoint")
	managementAPICIDR := flags.String("management-api-cidr", "", "single-address management-observer CIDR")
	managementCredentialSecret := flags.String("management-credential-secret", "", "externally materialized read-only management credential Secret name")
	pollInterval := flags.Duration("poll-interval", 0, "bounded interval between verified Unknown observations")
	pollTimeout := flags.Duration("poll-timeout", 0, "maximum bounded lifecycle observation duration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--output", *output},
		{"--run-id", *runID}, {"--image", *imageDigest}, {"--input-configmap", *inputConfigMap},
		{"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR}, {"--ledger-credential-secret", *ledgerCredentialSecret},
		{"--management-api-url", *managementAPIURL}, {"--management-api-cidr", *managementAPICIDR}, {"--management-credential-secret", *managementCredentialSecret},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if *pollInterval < time.Second || *pollInterval > 5*time.Minute || *pollTimeout < *pollInterval || *pollTimeout > 6*time.Hour {
		return errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read lifecycle observation Job template: %w", err)
	}
	raw, receipt, err := materializeLifecycleObservationStagePackage(runner.LifecycleObservationStagePackageConfig{
		Bundle: bundleConfig, JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, InputConfigMap: *inputConfigMap,
		LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
		ManagementAPIURL: *managementAPIURL, ManagementAPICIDR: *managementAPICIDR, ManagementCredentialSecret: *managementCredentialSecret,
		PollInterval: *pollInterval, PollTimeout: *pollTimeout,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return fmt.Errorf("write lifecycle observation stage package: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

type lifecycleObservationLaunchMaterialFlags struct {
	resume                                                                                       *stageResumeFlags
	jobTemplate, jobTemplateDigest, runID, imageDigest, inputConfigMap                           *string
	ledgerAPIURL, ledgerAPICIDR, ledgerCredentialSecret                                          *string
	managementAPIURL, managementAPICIDR, managementCredentialSecret                              *string
	pollInterval, pollTimeout                                                                    *time.Duration
	materializedAt, runtimeManifest, runtimeManifestDigest                                       *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt *string
	ledgerCredential, managementCredential                                                       *stageLaunchCredentialFlags
}

func addLifecycleObservationLaunchMaterialFlags(flags *flag.FlagSet) *lifecycleObservationLaunchMaterialFlags {
	values := &lifecycleObservationLaunchMaterialFlags{resume: addStageResumeFlags(flags)}
	values.jobTemplate = flags.String("job-template", "", "path to the bounded lifecycle-observation Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 observation Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable observation input ConfigMap name")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerCredentialSecret = flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	values.managementAPIURL = flags.String("management-api-url", "", "exact management-observer HTTPS IP endpoint")
	values.managementAPICIDR = flags.String("management-api-cidr", "", "single-address management-observer CIDR")
	values.managementCredentialSecret = flags.String("management-credential-secret", "", "read-only management credential Secret name")
	values.pollInterval = flags.Duration("poll-interval", 0, "bounded interval between Unknown observations")
	values.pollTimeout = flags.Duration("poll-timeout", 0, "maximum bounded lifecycle observation duration")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	values.managementCredential = addStageLaunchCredentialFlags(flags, "management-observer-job", "read-only management observer Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected management installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected management installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *lifecycleObservationLaunchMaterialFlags) config() (runner.LifecycleObservationStageLaunchMaterialConfig, error) {
	resumeConfig, err := values.resume.config()
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest}, {"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--input-configmap", *values.inputConfigMap}, {"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR},
		{"--ledger-credential-secret", *values.ledgerCredentialSecret}, {"--management-api-url", *values.managementAPIURL},
		{"--management-api-cidr", *values.managementAPICIDR}, {"--management-credential-secret", *values.managementCredentialSecret},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest},
		{"--runtime-manifest-digest", *values.runtimeManifestDigest}, {"--installer-api-endpoint", *values.installerAPIEndpoint},
		{"--installer-ca-digest", *values.installerCADigest}, {"--installer-token-digest", *values.installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.LifecycleObservationStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	if *values.pollInterval < time.Second || *values.pollInterval > 5*time.Minute || *values.pollTimeout < *values.pollInterval || *values.pollTimeout > 6*time.Hour {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	materializedAt, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	preparedAt, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledgerSource, err := values.ledgerCredential.source("ledger-job")
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, err
	}
	managementSource, err := values.managementCredential.source("management-observer-job")
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, err
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, fmt.Errorf("read lifecycle observation Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.LifecycleObservationStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	return runner.LifecycleObservationStageLaunchMaterialConfig{
		Package: runner.LifecycleObservationStagePackageConfig{
			Bundle: resumeConfig, JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest,
			RunID: *values.runID, ImageDigest: *values.imageDigest, InputConfigMap: *values.inputConfigMap,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerCredentialSecret,
			ManagementAPIURL: *values.managementAPIURL, ManagementAPICIDR: *values.managementAPICIDR, ManagementCredentialSecret: *values.managementCredentialSecret,
			PollInterval: *values.pollInterval, PollTimeout: *values.pollTimeout,
		},
		MaterializationTime: materializedAt, Ledger: ledgerSource, ManagementObserver: managementSource,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence,
			PreparedAt: preparedAt,
		},
	}, nil
}

func runClusterStageObserveLifecycleLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe lifecycle launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addLifecycleObservationLaunchMaterialFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	preparation, err := prepareLifecycleObservationStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageObserveLifecycleLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe lifecycle launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addLifecycleObservationLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use lifecycle observation launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by lifecycle observation launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("lifecycle observation launch mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-candidate-digest", *expectedCandidateDigest}, {"--installer-token-file", *installerTokenFile}, {"--installer-ca-file", *installerCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedCandidateDigest) {
		return errors.New("--expected-candidate-digest must be sha256:<64 lowercase hex>")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeLifecycleObservationStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
		Endpoint: config.Candidate.AuthorityEndpoint, TokenFile: *installerTokenFile,
		CAFile: *installerCAFile, CABundleDigest: config.Candidate.CABundleDigest,
	}, *expectedCandidateDigest)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return launchErr
}

type networkObservationLaunchMaterialFlags struct {
	resume                                                                                       *stageResumeFlags
	jobTemplate, jobTemplateDigest, runID, imageDigest, inputConfigMap                           *string
	networkProfile, networkProfileDigest                                                         *string
	ledgerAPIURL, ledgerAPICIDR, ledgerCredentialSecret                                          *string
	managementAPIURL, managementAPICIDR, managementCredentialSecret                              *string
	workloadAPIURL, workloadAPICIDR, workloadCredentialSecret                                    *string
	workloadBinding, workloadBindingDigest                                                       *string
	pollInterval, pollTimeout                                                                    *time.Duration
	materializedAt, runtimeManifest, runtimeManifestDigest                                       *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt *string
	ledgerCredential, managementCredential, workloadCredential                                   *stageLaunchCredentialFlags
}

func addNetworkObservationLaunchMaterialFlags(flags *flag.FlagSet) *networkObservationLaunchMaterialFlags {
	values := &networkObservationLaunchMaterialFlags{resume: addStageResumeFlags(flags)}
	values.jobTemplate = flags.String("job-template", "", "path to the bounded network-observation Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 network observation Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable network observation input ConfigMap name")
	values.networkProfile = flags.String("network-profile", "", "path to the immutable NetworkReady profile")
	values.networkProfileDigest = flags.String("network-profile-digest", "", "expected NetworkReady profile digest")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerCredentialSecret = flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	values.managementAPIURL = flags.String("management-api-url", "", "exact management-observer HTTPS IP endpoint")
	values.managementAPICIDR = flags.String("management-api-cidr", "", "single-address management-observer CIDR")
	values.managementCredentialSecret = flags.String("management-credential-secret", "", "read-only management credential Secret name")
	values.workloadAPIURL = flags.String("workload-api-url", "", "exact workload-observer HTTPS IP endpoint")
	values.workloadAPICIDR = flags.String("workload-api-cidr", "", "single-address workload-observer CIDR")
	values.workloadCredentialSecret = flags.String("workload-credential-secret", "", "read-only workload credential Secret name")
	values.workloadBinding = flags.String("workload-binding", "", "path to the private workload-authority binding")
	values.workloadBindingDigest = flags.String("workload-binding-digest", "", "expected workload-authority binding digest")
	values.pollInterval = flags.Duration("poll-interval", 0, "bounded interval between Unknown observations")
	values.pollTimeout = flags.Duration("poll-timeout", 0, "maximum bounded network observation duration")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	values.managementCredential = addStageLaunchCredentialFlags(flags, "management-observer-job", "read-only management observer Job credential")
	values.workloadCredential = addStageLaunchCredentialFlags(flags, "workload-observer-job", "read-only workload observer Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected management installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected management installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *networkObservationLaunchMaterialFlags) config() (runner.NetworkObservationStageLaunchMaterialConfig, error) {
	resumeConfig, err := values.resume.config()
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest}, {"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--input-configmap", *values.inputConfigMap}, {"--network-profile", *values.networkProfile}, {"--network-profile-digest", *values.networkProfileDigest},
		{"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR}, {"--ledger-credential-secret", *values.ledgerCredentialSecret},
		{"--management-api-url", *values.managementAPIURL}, {"--management-api-cidr", *values.managementAPICIDR}, {"--management-credential-secret", *values.managementCredentialSecret},
		{"--workload-api-url", *values.workloadAPIURL}, {"--workload-api-cidr", *values.workloadAPICIDR}, {"--workload-credential-secret", *values.workloadCredentialSecret},
		{"--workload-binding", *values.workloadBinding}, {"--workload-binding-digest", *values.workloadBindingDigest},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest},
		{"--runtime-manifest-digest", *values.runtimeManifestDigest}, {"--installer-api-endpoint", *values.installerAPIEndpoint},
		{"--installer-ca-digest", *values.installerCADigest}, {"--installer-token-digest", *values.installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.NetworkObservationStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{*values.jobTemplateDigest, *values.networkProfileDigest, *values.workloadBindingDigest, *values.runtimeManifestDigest, *values.installerCADigest, *values.installerTokenDigest, *values.installerEvidence} {
		if !sha256DigestPattern.MatchString(value) {
			return runner.NetworkObservationStageLaunchMaterialConfig{}, errors.New("network observation launch digests must be lowercase SHA-256 identities")
		}
	}
	if *values.pollInterval < time.Second || *values.pollInterval > 5*time.Minute || *values.pollTimeout < *values.pollInterval || *values.pollTimeout > 6*time.Hour {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	materializedAt, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	preparedAt, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledgerSource, err := values.ledgerCredential.source("ledger-job")
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, err
	}
	managementSource, err := values.managementCredential.source("management-observer-job")
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, err
	}
	workloadSource, err := values.workloadCredential.source("workload-observer-job")
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, err
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, fmt.Errorf("read network observation Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.NetworkObservationStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	return runner.NetworkObservationStageLaunchMaterialConfig{
		Package: runner.NetworkObservationStagePackageConfig{
			Input:       runner.NetworkObservationStageInputConfig{Bundle: resumeConfig, NetworkProfilePath: *values.networkProfile, ExpectedNetworkProfileDigest: *values.networkProfileDigest, ConfigMapName: *values.inputConfigMap},
			JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest, RunID: *values.runID, ImageDigest: *values.imageDigest,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerCredentialSecret,
			ManagementAPIURL: *values.managementAPIURL, ManagementAPICIDR: *values.managementAPICIDR, ManagementCredentialSecret: *values.managementCredentialSecret,
			WorkloadAPIURL: *values.workloadAPIURL, WorkloadAPICIDR: *values.workloadAPICIDR, WorkloadCredentialSecret: *values.workloadCredentialSecret,
			WorkloadBindingPath: *values.workloadBinding, ExpectedWorkloadBindingDigest: *values.workloadBindingDigest,
			PollInterval: *values.pollInterval, PollTimeout: *values.pollTimeout,
		},
		MaterializationTime: materializedAt, Ledger: ledgerSource, ManagementObserver: managementSource, WorkloadObserver: workloadSource,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence, PreparedAt: preparedAt,
		},
	}, nil
}

func runClusterStageObserveNetworkLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe network launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addNetworkObservationLaunchMaterialFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	preparation, err := prepareNetworkObservationStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageObserveNetworkLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe network launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addNetworkObservationLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use network observation launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by network observation launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("network observation launch mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-candidate-digest", *expectedCandidateDigest}, {"--installer-token-file", *installerTokenFile}, {"--installer-ca-file", *installerCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedCandidateDigest) {
		return errors.New("--expected-candidate-digest must be sha256:<64 lowercase hex>")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeNetworkObservationStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
		Endpoint: config.Candidate.AuthorityEndpoint, TokenFile: *installerTokenFile,
		CAFile: *installerCAFile, CABundleDigest: config.Candidate.CABundleDigest,
	}, *expectedCandidateDigest)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return launchErr
}

func runClusterStageRun(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleFlags := addStageBundleFlags(flags)
	execute := flags.Bool("execute", false, "claim and execute exactly the selected authorized stage")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	authorityAPIEndpoint := flags.String("authority-api-endpoint", "", "TLS Kubernetes API endpoint for the selected write authority")
	authorityTokenFile := flags.String("authority-token-file", "", "path to the selected short-lived write-authority token")
	authorityCAFile := flags.String("authority-ca-file", "", "path to the selected authority Kubernetes API CA bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("stage mutation requires explicit --execute")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct {
		name, value string
	}{
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--authority-api-endpoint", *authorityAPIEndpoint}, {"--authority-token-file", *authorityTokenFile}, {"--authority-ca-file", *authorityCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageRunTimeout)
	defer cancel()
	receipt, runErr := executeSubmissionStage(boundedContext, bundleConfig, runner.SubmissionStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		},
		Authority: runner.KubernetesAuthorityConfig{
			Endpoint: *authorityAPIEndpoint, TokenFile: *authorityTokenFile, CAFile: *authorityCAFile,
		},
		Clock: func() time.Time { return time.Now().UTC() },
	})
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStageRunEnablement(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run enablement", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	grantPath := flags.String("grant", "", "path to the signed single-stage grant")
	grantKeyPath := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	artifactPath := flags.String("enablement-artifact", "", "path to the exact externally rendered HelmChartProxy")
	objectName := flags.String("helmchartproxy-name", "", "independently expected HelmChartProxy name")
	execute := flags.Bool("execute", false, "claim and execute exactly the selected enablement stage")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	managementAPIEndpoint := flags.String("management-api-endpoint", "", "TLS Kubernetes API endpoint for the management writer")
	managementTokenFile := flags.String("management-token-file", "", "path to the short-lived management writer token")
	managementCAFile := flags.String("management-ca-file", "", "path to the management Kubernetes API CA bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("enablement mutation requires explicit --execute")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *grantPath}, {"--grant-key", *grantKeyPath}, {"--evaluation-time", *evaluationTime},
		{"--enablement-artifact", *artifactPath}, {"--helmchartproxy-name", *objectName},
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--management-api-endpoint", *managementAPIEndpoint}, {"--management-token-file", *managementTokenFile}, {"--management-ca-file", *managementCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	at, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return fmt.Errorf("parse evaluation time: %w", err)
	}
	bundleConfig := runner.EnablementStageBundleConfig{
		PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
		GrantPath: *grantPath, GrantPublicKeyPath: *grantKeyPath, EvaluationTime: at, ArtifactPath: *artifactPath,
		ExpectedObject: projection.ResourceIdentity{
			APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy",
			Namespace: resume.PlanExpected.ContractIdentity.Namespace, Name: *objectName,
		},
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageRunTimeout)
	defer cancel()
	receipt, runErr := executeEnablementStage(boundedContext, bundleConfig, runner.SubmissionStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile},
		Authority: runner.KubernetesAuthorityConfig{
			Endpoint: *managementAPIEndpoint, AuthorityIdentity: resume.PlanExpected.ManagementAuthority,
			TokenFile: *managementTokenFile, CAFile: *managementCAFile,
		},
		Clock: func() time.Time { return time.Now().UTC() },
	})
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStageRunTargetAccess(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run target-access", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	grantPath := flags.String("grant", "", "path to the signed single-stage grant")
	grantKeyPath := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	artifactPath := flags.String("target-access-artifact", "", "path to the exact externally rendered eight-object target-access set")
	observabilityNamespace := flags.String("observability-namespace", "", "independently expected observability namespace")
	managerServiceAccount := flags.String("manager-serviceaccount", "", "independently expected kube-system manager ServiceAccount")
	clusterRole := flags.String("cluster-role", "", "independently expected cluster role")
	clusterRoleBinding := flags.String("cluster-rolebinding", "", "independently expected cluster role binding")
	platformRole := flags.String("platform-role", "", "independently expected observability namespace role")
	platformRoleBinding := flags.String("platform-rolebinding", "", "independently expected observability namespace role binding")
	kubeSystemRole := flags.String("kube-system-role", "", "independently expected kube-system role")
	kubeSystemRoleBinding := flags.String("kube-system-rolebinding", "", "independently expected kube-system role binding")
	execute := flags.Bool("execute", false, "claim and execute exactly the selected target-access stage")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	workloadBinding := flags.String("workload-binding", "", "path to the private runtime-bound workload authority record")
	workloadBindingDigest := flags.String("workload-binding-digest", "", "expected digest of the private workload authority record")
	workloadTokenFile := flags.String("workload-token-file", "", "path to the short-lived workload writer token")
	workloadCAFile := flags.String("workload-ca-file", "", "path to the runtime-bound workload Kubernetes API CA bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("target-access mutation requires explicit --execute")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *grantPath}, {"--grant-key", *grantKeyPath}, {"--evaluation-time", *evaluationTime}, {"--target-access-artifact", *artifactPath},
		{"--observability-namespace", *observabilityNamespace}, {"--manager-serviceaccount", *managerServiceAccount},
		{"--cluster-role", *clusterRole}, {"--cluster-rolebinding", *clusterRoleBinding},
		{"--platform-role", *platformRole}, {"--platform-rolebinding", *platformRoleBinding},
		{"--kube-system-role", *kubeSystemRole}, {"--kube-system-rolebinding", *kubeSystemRoleBinding},
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--workload-binding", *workloadBinding}, {"--workload-binding-digest", *workloadBindingDigest},
		{"--workload-token-file", *workloadTokenFile}, {"--workload-ca-file", *workloadCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	at, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return fmt.Errorf("parse evaluation time: %w", err)
	}
	expectedObjects := targetAccessExpectedObjects(*observabilityNamespace, *managerServiceAccount, *clusterRole, *clusterRoleBinding, *platformRole, *platformRoleBinding, *kubeSystemRole, *kubeSystemRoleBinding)
	bundleConfig := runner.TargetAccessStageBundleConfig{
		PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
		GrantPath: *grantPath, GrantPublicKeyPath: *grantKeyPath, EvaluationTime: at,
		ArtifactPath: *artifactPath, ExpectedObjects: expectedObjects,
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageRunTimeout)
	defer cancel()
	receipt, runErr := executeTargetAccessStage(boundedContext, bundleConfig, runner.TargetAccessStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		},
		Workload: runner.WorkloadAuthorityFileResolverConfig{
			Path: *workloadBinding, ExpectedBindingDigest: *workloadBindingDigest,
			TokenFile: *workloadTokenFile, CAFile: *workloadCAFile,
		},
		Clock: func() time.Time { return time.Now().UTC() },
	})
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStageRunEnablementPackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run enablement package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	grantPath := flags.String("grant", "", "path to the signed single-stage grant")
	grantKeyPath := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	artifactPath := flags.String("enablement-artifact", "", "path to the exact externally rendered HelmChartProxy")
	objectName := flags.String("helmchartproxy-name", "", "independently expected HelmChartProxy name")
	jobTemplate := flags.String("job-template", "", "path to the bounded enablement Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new local file for the verified enablement package")
	runID := flags.String("run-id", "", "bounded OK-147 enablement Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable enablement input ConfigMap name")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "externally materialized ledger credential Secret name")
	managementAPIURL := flags.String("management-api-url", "", "exact management-writer HTTPS IP endpoint")
	managementAPICIDR := flags.String("management-api-cidr", "", "single-address management-writer CIDR")
	managementCredentialSecret := flags.String("management-credential-secret", "", "externally materialized management-writer credential Secret name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *grantPath}, {"--grant-key", *grantKeyPath}, {"--evaluation-time", *evaluationTime},
		{"--enablement-artifact", *artifactPath}, {"--helmchartproxy-name", *objectName},
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--output", *output},
		{"--run-id", *runID}, {"--image", *imageDigest}, {"--input-configmap", *inputConfigMap},
		{"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR}, {"--ledger-credential-secret", *ledgerCredentialSecret},
		{"--management-api-url", *managementAPIURL}, {"--management-api-cidr", *managementAPICIDR}, {"--management-credential-secret", *managementCredentialSecret},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	at, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return fmt.Errorf("parse evaluation time: %w", err)
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read enablement Job template: %w", err)
	}
	raw, receipt, err := materializeEnablementStagePackage(runner.EnablementStagePackageConfig{
		Bundle: runner.EnablementStageBundleConfig{
			PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
			GrantPath: *grantPath, GrantPublicKeyPath: *grantKeyPath, EvaluationTime: at, ArtifactPath: *artifactPath,
			ExpectedObject: projection.ResourceIdentity{
				APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy",
				Namespace: resume.PlanExpected.ContractIdentity.Namespace, Name: *objectName,
			},
		},
		JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, InputConfigMap: *inputConfigMap, HelmChartProxyName: *objectName,
		LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
		ManagementAPIURL: *managementAPIURL, ManagementAPICIDR: *managementAPICIDR, ManagementCredentialSecret: *managementCredentialSecret,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return fmt.Errorf("write enablement stage package: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runClusterStagePackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleFlags := addStageBundleFlags(flags)
	jobTemplate := flags.String("job-template", "", "path to the bounded submission-stage Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new local file for the verified ConfigMap/Job/NetworkPolicy package")
	runID := flags.String("run-id", "", "bounded OK-147 Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable input ConfigMap name")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "externally materialized ledger credential Secret name")
	authorityAPIURL := flags.String("authority-api-url", "", "exact selected-authority HTTPS IP endpoint")
	authorityAPICIDR := flags.String("authority-api-cidr", "", "single-address selected-authority CIDR")
	authorityCredentialSecret := flags.String("authority-credential-secret", "", "externally materialized authority credential Secret name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--output", *output}, {"--run-id", *runID}, {"--image", *imageDigest},
		{"--input-configmap", *inputConfigMap}, {"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR},
		{"--ledger-credential-secret", *ledgerCredentialSecret}, {"--authority-api-url", *authorityAPIURL},
		{"--authority-api-cidr", *authorityAPICIDR}, {"--authority-credential-secret", *authorityCredentialSecret},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read Job template: %w", err)
	}
	raw, receipt, err := materializeSubmissionStagePackage(runner.SubmissionStagePackageConfig{
		Bundle: bundleConfig, JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, InputConfigMap: *inputConfigMap,
		LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
		AuthorityAPIURL: *authorityAPIURL, AuthorityAPICIDR: *authorityAPICIDR, AuthorityCredentialSecret: *authorityCredentialSecret,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return fmt.Errorf("write stage package: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

type stageLaunchCredentialFlags struct {
	authority, tokenFile, tokenDigest, caFile, caDigest, evidenceDigest *string
	issuer, subject, audiences, issuedAt, expiresAt                     *string
}

func addStageLaunchCredentialFlags(flags *flag.FlagSet, prefix, description string) *stageLaunchCredentialFlags {
	values := &stageLaunchCredentialFlags{}
	values.authority = flags.String(prefix+"-authority", "", description+" authority identity")
	values.tokenFile = flags.String(prefix+"-token-file", "", description+" bounded token file")
	values.tokenDigest = flags.String(prefix+"-token-digest", "", description+" expected token digest")
	values.caFile = flags.String(prefix+"-ca-file", "", description+" bounded CA file")
	values.caDigest = flags.String(prefix+"-ca-digest", "", description+" expected CA digest")
	values.evidenceDigest = flags.String(prefix+"-tokenrequest-evidence-digest", "", description+" TokenRequest evidence digest")
	values.issuer = flags.String(prefix+"-issuer", "", description+" expected token issuer")
	values.subject = flags.String(prefix+"-subject", "", description+" expected ServiceAccount subject")
	values.audiences = flags.String(prefix+"-audiences", "", description+" comma-separated exact token audiences")
	values.issuedAt = flags.String(prefix+"-issued-at", "", description+" exact token issued-at time")
	values.expiresAt = flags.String(prefix+"-expires-at", "", description+" exact token expiration time")
	return values
}

func (values *stageLaunchCredentialFlags) source(prefix string) (runner.SubmissionStageCredentialSource, error) {
	required := []struct{ name, value string }{
		{"--" + prefix + "-authority", *values.authority}, {"--" + prefix + "-token-file", *values.tokenFile},
		{"--" + prefix + "-token-digest", *values.tokenDigest}, {"--" + prefix + "-ca-file", *values.caFile},
		{"--" + prefix + "-ca-digest", *values.caDigest}, {"--" + prefix + "-tokenrequest-evidence-digest", *values.evidenceDigest},
		{"--" + prefix + "-issuer", *values.issuer}, {"--" + prefix + "-subject", *values.subject},
		{"--" + prefix + "-audiences", *values.audiences}, {"--" + prefix + "-issued-at", *values.issuedAt},
		{"--" + prefix + "-expires-at", *values.expiresAt},
	}
	for _, input := range required {
		if input.value == "" {
			return runner.SubmissionStageCredentialSource{}, fmt.Errorf("%s is required", input.name)
		}
	}
	issuedAt, err := time.Parse(time.RFC3339, *values.issuedAt)
	if err != nil {
		return runner.SubmissionStageCredentialSource{}, fmt.Errorf("parse %s issued-at: %w", prefix, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, *values.expiresAt)
	if err != nil {
		return runner.SubmissionStageCredentialSource{}, fmt.Errorf("parse %s expires-at: %w", prefix, err)
	}
	audiences := strings.Split(*values.audiences, ",")
	for _, audience := range audiences {
		if audience == "" || strings.TrimSpace(audience) != audience {
			return runner.SubmissionStageCredentialSource{}, fmt.Errorf("--%s-audiences must contain exact non-empty values", prefix)
		}
	}
	return runner.SubmissionStageCredentialSource{
		AuthorityIdentity: *values.authority, TokenFile: *values.tokenFile, TokenDigest: *values.tokenDigest,
		CAFile: *values.caFile, CABundleDigest: *values.caDigest, TokenRequestEvidenceDigest: *values.evidenceDigest,
		ExpectedIssuer: *values.issuer, ExpectedSubject: *values.subject, ExpectedAudiences: audiences,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}, nil
}

type stageLaunchMaterialFlags struct {
	bundle                                                                                       *stageBundleFlags
	jobTemplate, jobTemplateDigest, runID, imageDigest, inputConfigMap                           *string
	ledgerAPIURL, ledgerAPICIDR, ledgerCredentialSecret                                          *string
	authorityAPIURL, authorityAPICIDR, authorityCredentialSecret                                 *string
	materializedAt, runtimeManifest, runtimeManifestDigest                                       *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt *string
	ledgerCredential, authorityCredential                                                        *stageLaunchCredentialFlags
}

func addStageLaunchMaterialFlags(flags *flag.FlagSet) *stageLaunchMaterialFlags {
	values := &stageLaunchMaterialFlags{bundle: addStageBundleFlags(flags)}
	values.jobTemplate = flags.String("job-template", "", "path to the bounded submission-stage Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable input ConfigMap name")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerCredentialSecret = flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	values.authorityAPIURL = flags.String("authority-api-url", "", "exact selected-authority HTTPS IP endpoint")
	values.authorityAPICIDR = flags.String("authority-api-cidr", "", "single-address selected-authority CIDR")
	values.authorityCredentialSecret = flags.String("authority-credential-secret", "", "authority credential Secret name")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	values.authorityCredential = addStageLaunchCredentialFlags(flags, "authority-job", "selected-authority Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected management installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected management installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *stageLaunchMaterialFlags) config() (runner.SubmissionStageLaunchMaterialConfig, error) {
	bundleConfig, err := values.bundle.config()
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest}, {"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--input-configmap", *values.inputConfigMap}, {"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR},
		{"--ledger-credential-secret", *values.ledgerCredentialSecret}, {"--authority-api-url", *values.authorityAPIURL},
		{"--authority-api-cidr", *values.authorityAPICIDR}, {"--authority-credential-secret", *values.authorityCredentialSecret},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest},
		{"--runtime-manifest-digest", *values.runtimeManifestDigest}, {"--installer-api-endpoint", *values.installerAPIEndpoint},
		{"--installer-ca-digest", *values.installerCADigest}, {"--installer-token-digest", *values.installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.SubmissionStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	materializationTime, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	candidateTime, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledgerSource, err := values.ledgerCredential.source("ledger-job")
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, err
	}
	authoritySource, err := values.authorityCredential.source("authority-job")
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, err
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, fmt.Errorf("read Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.SubmissionStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	return runner.SubmissionStageLaunchMaterialConfig{
		Package: runner.SubmissionStagePackageConfig{
			Bundle: bundleConfig, JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest,
			RunID: *values.runID, ImageDigest: *values.imageDigest, InputConfigMap: *values.inputConfigMap,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerCredentialSecret,
			AuthorityAPIURL: *values.authorityAPIURL, AuthorityAPICIDR: *values.authorityAPICIDR, AuthorityCredentialSecret: *values.authorityCredentialSecret,
		},
		MaterializationTime: materializationTime, Ledger: ledgerSource, SelectedAuthority: authoritySource,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence,
			PreparedAt: candidateTime,
		},
	}, nil
}

func runClusterStageLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addStageLaunchMaterialFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	preparation, err := prepareSubmissionStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addStageLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use six-object launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("stage launch mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-candidate-digest", *expectedCandidateDigest}, {"--installer-token-file", *installerTokenFile}, {"--installer-ca-file", *installerCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedCandidateDigest) {
		return errors.New("--expected-candidate-digest must be sha256:<64 lowercase hex>")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeSubmissionStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
		Endpoint: config.Candidate.AuthorityEndpoint, TokenFile: *installerTokenFile,
		CAFile: *installerCAFile, CABundleDigest: config.Candidate.CABundleDigest,
	}, *expectedCandidateDigest)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return launchErr
}

func readBoundedLocalFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("local file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > maximum {
		return nil, errors.New("local file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("read bounded local file")
	}
	return raw, nil
}

func writeNewLocalFile(path string, raw []byte) (err error) {
	if path == "" || len(raw) == 0 {
		return errors.New("non-empty output path and package are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func countNonEmpty(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}
