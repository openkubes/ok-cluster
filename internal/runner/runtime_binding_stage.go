package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const RuntimeBindingStageEvidenceFormat = "ok147-runtime-binding-stage-evidence/v1"

const RuntimeBindingStageKubernetesEvidenceFormat = "ok147-runtime-binding-stage-evidence/v2"

type VerifiedRuntimeBindingStageBundle struct {
	config   StageResumeConfig
	plan     stageplan.Binding
	cursor   stagecursor.Cursor
	prefix   []stagereceipt.Verified
	verified bool
}

type RuntimeBindingStageRuntimeConfig struct {
	Ledger     KubernetesLedgerConfig
	Workload   WorkloadAuthorityFileResolverConfig
	OutputPath string
	Clock      func() time.Time
}

// RuntimeBindingStageKubernetesRuntimeConfig selects the durable immutable
// Secret persistence path. Its credential is distinct from both ledger and
// workload credentials and carries no lifecycle authority.
type RuntimeBindingStageKubernetesRuntimeConfig struct {
	Ledger      KubernetesLedgerConfig
	Workload    WorkloadAuthorityFileResolverConfig
	Persistence KubernetesAuthorityConfig
	Clock       func() time.Time
}

type RuntimeBindingStageEvidenceReceipt struct {
	Format                    string                                      `json:"format"`
	State                     string                                      `json:"state"`
	PlanDigest                string                                      `json:"planDigest"`
	StageID                   string                                      `json:"stageId"`
	FailureCategory           string                                      `json:"failureCategory,omitempty"`
	Material                  *RuntimeBindingMaterialReceipt              `json:"material,omitempty"`
	Persistence               *RuntimeBindingPersistenceReceipt           `json:"persistence,omitempty"`
	KubernetesPersistence     *KubernetesRuntimeBindingPersistenceReceipt `json:"kubernetesPersistence,omitempty"`
	KubernetesMutationAllowed bool                                        `json:"kubernetesMutationAllowed"`
	LifecycleMutationAllowed  *bool                                       `json:"lifecycleMutationAllowed,omitempty"`
}

type OpenedRuntimeBindingStage struct {
	operation execution.BindingStageOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	binder    *runtimeBindingStageBinder
	verified  bool
}

// LoadRuntimeBindingStageBundle verifies the exact five-receipt prefix and
// retains the runner-owned local binding cursor without opening credentials.
func LoadRuntimeBindingStageBundle(config StageResumeConfig) (VerifiedRuntimeBindingStageBundle, error) {
	plan, cursor, prefix, err := loadStageResumeWithPrefix(config)
	if err != nil {
		return VerifiedRuntimeBindingStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "runtime-binding" || decision.Kind != "Binding" || decision.Authority != "runner" || decision.RequiresAuthorization || decision.Operation != "" {
		return VerifiedRuntimeBindingStageBundle{}, errors.New("verified prefix does not select runtime binding")
	}
	if len(prefix) != 5 {
		return VerifiedRuntimeBindingStageBundle{}, errors.New("runtime binding receipt prefix is incomplete")
	}
	retained := config
	retained.Receipts = append([]StageReceiptSource(nil), config.Receipts...)
	return VerifiedRuntimeBindingStageBundle{config: retained, plan: plan, cursor: cursor, prefix: prefix, verified: true}, nil
}

func (bundle VerifiedRuntimeBindingStageBundle) Decision() (stagecursor.Decision, error) {
	if !bundle.verified {
		return stagecursor.Decision{}, errors.New("runtime binding stage bundle is not verified")
	}
	return bundle.cursor.Decision()
}

// Open binds the exact ledger, workload source and private output path. It
// reads bounded credential material but performs neither API requests nor file
// creation.
func (bundle VerifiedRuntimeBindingStageBundle) Open(config RuntimeBindingStageRuntimeConfig) (OpenedRuntimeBindingStage, error) {
	if !bundle.verified || config.Clock == nil {
		return OpenedRuntimeBindingStage{}, errors.New("verified runtime binding bundle and clock are required")
	}
	if err := validateRuntimeBindingOutputPath(config.OutputPath); err != nil {
		return OpenedRuntimeBindingStage{}, err
	}
	return bundle.open(config.Ledger, config.Workload, config.Clock, config.OutputPath, nil, "")
}

// OpenKubernetes binds the exact immutable Secret persistence capability. It
// reads three bounded credentials but performs no API request.
func (bundle VerifiedRuntimeBindingStageBundle) OpenKubernetes(config RuntimeBindingStageKubernetesRuntimeConfig) (OpenedRuntimeBindingStage, error) {
	if !bundle.verified || config.Clock == nil {
		return OpenedRuntimeBindingStage{}, errors.New("verified runtime binding bundle and clock are required")
	}
	if config.Ledger.Namespace != submissionStageInputNamespace || !sameRuntimeBindingEndpoint(config.Ledger.Endpoint, config.Persistence.Endpoint) {
		return OpenedRuntimeBindingStage{}, errors.New("runtime binding persistence must share the exact management API and namespace")
	}
	name, err := runtimeBindingSecretName(bundle.plan.PlanDigest)
	if err != nil {
		return OpenedRuntimeBindingStage{}, err
	}
	store, persistenceToken, err := openKubernetesRuntimeBindingStore(
		config.Persistence, bundle.plan.Authorities.Management, submissionStageInputNamespace, name,
	)
	if err != nil {
		return OpenedRuntimeBindingStage{}, errors.New("open runtime binding Kubernetes persistence")
	}
	return bundle.open(config.Ledger, config.Workload, config.Clock, "", store, persistenceToken)
}

func (bundle VerifiedRuntimeBindingStageBundle) open(ledgerConfig KubernetesLedgerConfig, workloadConfig WorkloadAuthorityFileResolverConfig, clock func() time.Time, outputPath string, kubernetesStore *KubernetesRuntimeBindingStore, persistenceToken string) (OpenedRuntimeBindingStage, error) {
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil {
		return OpenedRuntimeBindingStage{}, errors.New("read durable runtime target correlation")
	}
	binding, authority, err := loadWorkloadAuthorityFiles(workloadConfig)
	if err != nil {
		return OpenedRuntimeBindingStage{}, errors.New("open runtime binding workload authority")
	}
	if binding.IntentRevision != bundle.plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return OpenedRuntimeBindingStage{}, errors.New("runtime binding workload authority differs from durable lifecycle target")
	}
	if sameRuntimeBindingEndpoint(ledgerConfig.Endpoint, binding.Endpoint) {
		return OpenedRuntimeBindingStage{}, errors.New("ledger and runtime observation endpoints must be distinct")
	}
	store, ledgerToken, err := openKubernetesLedger(ledgerConfig)
	if err != nil {
		return OpenedRuntimeBindingStage{}, errors.New("open runtime binding ledger")
	}
	source, workloadToken, err := openKubernetesRuntimeBindingSource(authority, binding)
	if err != nil {
		return OpenedRuntimeBindingStage{}, errors.New("open bounded runtime binding source")
	}
	if sameSecret(ledgerToken, workloadToken) || persistenceToken != "" && (sameSecret(persistenceToken, ledgerToken) || sameSecret(persistenceToken, workloadToken)) {
		return OpenedRuntimeBindingStage{}, errors.New("runtime binding stage credentials must be pairwise distinct")
	}
	decision, _ := bundle.cursor.Decision()
	binder := &runtimeBindingStageBinder{
		binding: execution.StageBinderBinding{
			PlanDigest: bundle.plan.PlanDigest, StageID: decision.StageID, StageDigest: decision.StageDigest,
			Authority: decision.Authority, ContractRevision: bundle.plan.IntentRevision,
		},
		bundle: bundle.config, workload: workloadConfig, outputPath: outputPath,
		source: source, kubernetesStore: kubernetesStore, clock: clock,
	}
	return OpenedRuntimeBindingStage{
		operation: execution.BindingStageOperation{Ledger: store, Binder: binder},
		plan:      bundle.plan, cursor: bundle.cursor, binder: binder, verified: true,
	}, nil
}

func (stage OpenedRuntimeBindingStage) Run(ctx context.Context) (execution.BindingStageRunReceipt, error) {
	if !stage.verified {
		return execution.BindingStageRunReceipt{}, errors.New("runtime binding stage is not opened")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor)
}

// Retry performs one digest-bound retry after an immutable terminal binding
// receipt while preserving every prior attempt.
func (stage OpenedRuntimeBindingStage) Retry(ctx context.Context, terminalReceiptDigest string) (execution.BindingStageRunReceipt, error) {
	if !stage.verified {
		return execution.BindingStageRunReceipt{}, errors.New("runtime binding stage is not opened")
	}
	return stage.operation.Retry(ctx, stage.plan, stage.cursor, terminalReceiptDigest)
}

// EvidenceReceipt exposes only the redaction-safe receipt from a binding call
// made by this opened stage. Private material and runtime identities remain in
// the selected private persistence implementation.
func (stage OpenedRuntimeBindingStage) EvidenceReceipt() (RuntimeBindingStageEvidenceReceipt, error) {
	if !stage.verified || stage.binder == nil {
		return RuntimeBindingStageEvidenceReceipt{}, errors.New("runtime binding stage is not opened")
	}
	return stage.binder.evidenceReceipt()
}

type runtimeBindingStageBinder struct {
	mu              sync.Mutex
	binding         execution.StageBinderBinding
	bundle          StageResumeConfig
	workload        WorkloadAuthorityFileResolverConfig
	outputPath      string
	source          *KubernetesRuntimeBindingSource
	kubernetesStore *KubernetesRuntimeBindingStore
	clock           func() time.Time
	evidence        RuntimeBindingStageEvidenceReceipt
	hasEvidence     bool
}

func (binder *runtimeBindingStageBinder) Binding() execution.StageBinderBinding {
	return binder.binding
}

func (binder *runtimeBindingStageBinder) Bind(ctx context.Context) (execution.StageBindingResult, error) {
	if binder == nil || binder.source == nil || binder.clock == nil {
		return execution.StageBindingResult{}, errors.New("runtime binding stage binder is invalid")
	}
	at := binder.clock().UTC()
	if at.IsZero() {
		return execution.StageBindingResult{}, errors.New("runtime binding completion time is invalid")
	}
	observation, err := binder.source.Observe(ctx)
	if err != nil {
		return binder.stop("SOURCE_STOPPED", nil, nil, nil, at)
	}
	material, err := BuildRuntimeBindingMaterial(RuntimeBindingMaterialConfig{
		Bundle: binder.bundle, WorkloadBindingPath: binder.workload.Path,
		ExpectedWorkloadBindingDigest: binder.workload.ExpectedBindingDigest,
		WorkloadCAFile:                binder.workload.CAFile, Observation: observation,
	})
	if err != nil {
		return binder.stop("MATERIALIZATION_STOPPED", nil, nil, nil, at)
	}
	materialReceipt, err := material.Receipt()
	if err != nil || materialReceipt.PlanDigest != binder.binding.PlanDigest {
		return binder.stop("MATERIAL_VERIFICATION_STOPPED", nil, nil, nil, at)
	}
	if binder.kubernetesStore != nil {
		persistence, persistErr := binder.kubernetesStore.Store(ctx, material)
		if persistErr != nil {
			return binder.stop("PERSISTENCE_STOPPED", &materialReceipt, nil, &persistence, at)
		}
		evidence := RuntimeBindingStageEvidenceReceipt{
			Format: RuntimeBindingStageKubernetesEvidenceFormat, State: "SUCCEEDED", PlanDigest: binder.binding.PlanDigest,
			StageID: binder.binding.StageID, Material: &materialReceipt, KubernetesPersistence: &persistence,
			KubernetesMutationAllowed: true, LifecycleMutationAllowed: runtimeBindingBool(false),
		}
		return binder.finish(evidence, "SUCCEEDED", at)
	}
	writer, err := OpenRuntimeBindingWriter(material, binder.outputPath)
	if err != nil {
		return binder.stop("WRITER_OPEN_STOPPED", &materialReceipt, nil, nil, at)
	}
	persistence, writeErr := writer.Write()
	if writeErr != nil {
		return binder.stop("PERSISTENCE_STOPPED", &materialReceipt, &persistence, nil, at)
	}
	evidence := RuntimeBindingStageEvidenceReceipt{
		Format: RuntimeBindingStageEvidenceFormat, State: "SUCCEEDED", PlanDigest: binder.binding.PlanDigest,
		StageID: binder.binding.StageID, Material: &materialReceipt, Persistence: &persistence,
		KubernetesMutationAllowed: false,
	}
	return binder.finish(evidence, "SUCCEEDED", at)
}

func (binder *runtimeBindingStageBinder) stop(category string, material *RuntimeBindingMaterialReceipt, persistence *RuntimeBindingPersistenceReceipt, kubernetesPersistence *KubernetesRuntimeBindingPersistenceReceipt, at time.Time) (execution.StageBindingResult, error) {
	format, kubernetesMutationAllowed := RuntimeBindingStageEvidenceFormat, false
	if binder.kubernetesStore != nil {
		format, kubernetesMutationAllowed = RuntimeBindingStageKubernetesEvidenceFormat, true
	}
	evidence := RuntimeBindingStageEvidenceReceipt{
		Format: format, State: "STOPPED", PlanDigest: binder.binding.PlanDigest,
		StageID: binder.binding.StageID, FailureCategory: category, Material: material, Persistence: persistence,
		KubernetesPersistence: kubernetesPersistence, KubernetesMutationAllowed: kubernetesMutationAllowed,
	}
	if binder.kubernetesStore != nil {
		evidence.LifecycleMutationAllowed = runtimeBindingBool(false)
	}
	return binder.finish(evidence, "STOPPED", at)
}

func (binder *runtimeBindingStageBinder) finish(evidence RuntimeBindingStageEvidenceReceipt, outcome string, at time.Time) (execution.StageBindingResult, error) {
	evidenceDigest, err := runtimeBindingStageEvidenceDigest(evidence)
	if err != nil {
		return execution.StageBindingResult{}, errors.New("encode runtime binding stage evidence")
	}
	binder.mu.Lock()
	binder.evidence, binder.hasEvidence = evidence, true
	binder.mu.Unlock()
	return execution.StageBindingResult{Outcome: outcome, EvidenceDigest: evidenceDigest, CompletedAt: at}, nil
}

func (binder *runtimeBindingStageBinder) evidenceReceipt() (RuntimeBindingStageEvidenceReceipt, error) {
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if !binder.hasEvidence {
		return RuntimeBindingStageEvidenceReceipt{}, errors.New("runtime binding evidence is not available")
	}
	return cloneRuntimeBindingStageEvidence(binder.evidence), nil
}

func runtimeBindingStageEvidenceDigest(evidence RuntimeBindingStageEvidenceReceipt) (string, error) {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}

func cloneRuntimeBindingStageEvidence(evidence RuntimeBindingStageEvidenceReceipt) RuntimeBindingStageEvidenceReceipt {
	clone := evidence
	if evidence.Material != nil {
		value := *evidence.Material
		clone.Material = &value
	}
	if evidence.Persistence != nil {
		value := *evidence.Persistence
		clone.Persistence = &value
	}
	if evidence.KubernetesPersistence != nil {
		value := *evidence.KubernetesPersistence
		clone.KubernetesPersistence = &value
	}
	if evidence.LifecycleMutationAllowed != nil {
		value := *evidence.LifecycleMutationAllowed
		clone.LifecycleMutationAllowed = &value
	}
	return clone
}

func runtimeBindingBool(value bool) *bool { return &value }

func runtimeBindingSecretName(planDigest string) (string, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(planDigest) {
		return "", errors.New("runtime binding plan digest is invalid")
	}
	return "ok147-runtime-binding-" + strings.TrimPrefix(planDigest, "sha256:")[:24], nil
}

func sameRuntimeBindingEndpoint(first, second string) bool {
	left, leftErr := url.Parse(first)
	right, rightErr := url.Parse(second)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftPath, rightPath := strings.TrimSuffix(left.Path, "/"), strings.TrimSuffix(right.Path, "/")
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host) && leftPath == rightPath
}

var _ execution.StageBinder = (*runtimeBindingStageBinder)(nil)
