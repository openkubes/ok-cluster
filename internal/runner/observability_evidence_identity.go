package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityIndependentEvidenceIdentityFormat        = "ok147-observability-independent-evidence-identity/v1"
	ObservabilityIndependentEvidenceIdentityReceiptFormat = "ok147-observability-independent-evidence-identity-receipt/v1"
	maximumObservabilityEvidenceIdentityBytes             = 32 * 1024
)

// ObservabilityIndependentEvidenceIdentityMaterial is a private handoff. The
// target UID must never be copied into public receipts or command arguments.
type ObservabilityIndependentEvidenceIdentityMaterial struct {
	Format               string `json:"format"`
	State                string `json:"state"`
	ManifestDigest       string `json:"manifestDigest"`
	RuntimeBindingDigest string `json:"runtimeBindingDigest"`
	RunID                string `json:"runId"`
	TargetClusterUID     string `json:"targetClusterUid"`
	FixtureDigest        string `json:"fixtureDigest"`
	ProfileDigest        string `json:"profileDigest"`
}

type ObservabilityIndependentEvidenceIdentityReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	ManifestDigest            string `json:"manifestDigest"`
	RuntimeBindingDigest      string `json:"runtimeBindingDigest"`
	TargetClusterUIDDigest    string `json:"targetClusterUidDigest"`
	IdentityDigest            string `json:"identityDigest"`
	FileMode                  string `json:"fileMode"`
	FileSize                  int    `json:"fileSize"`
	PersistentMutationAllowed bool   `json:"persistentMutationAllowed"`
}

type ObservabilityIndependentEvidenceIdentityMaterialConfig struct {
	ManifestPath                string
	ExpectedManifestDigest      string
	ReceiptPrefixPath           string
	ExpectedReceiptPrefixDigest string
	OutputPath                  string
}

type fullRunObservabilityEvidenceIdentityBinder struct {
	manifest     VerifiedFullRunExecutionManifest
	identityPath string
	receiptPath  string

	mu   sync.Mutex
	used bool
}

func newFullRunObservabilityEvidenceIdentityBinder(manifest VerifiedFullRunExecutionManifest, identityPath, receiptPath string) FullRunEvidenceIdentityBinder {
	return &fullRunObservabilityEvidenceIdentityBinder{manifest: manifest, identityPath: identityPath, receiptPath: receiptPath}
}

// BindFullRunEvidenceIdentity is invoked by the concrete full-run exactly
// after Stage 1-7 succeeds. It deliberately replays only Stage 1-6 because
// runtime binding, not target-access mutation, is the identity authority.
func (binder *fullRunObservabilityEvidenceIdentityBinder) BindFullRunEvidenceIdentity(prefix []StageReceiptSource) error {
	if binder == nil || !binder.manifest.verified || len(prefix) != 6 || binder.identityPath == "" || binder.receiptPath == "" || binder.identityPath == binder.receiptPath {
		return errors.New("full-run observability evidence identity binder is invalid")
	}
	binder.mu.Lock()
	if binder.used {
		binder.mu.Unlock()
		return errors.New("full-run observability evidence identity binder is single-use")
	}
	binder.used = true
	binder.mu.Unlock()
	document := binder.manifest.document
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle: StageResumeConfig{
			PlanPath: document.Plan.Path, PlanExpected: fullRunPlanExpected(document.Plan.Expected),
			Receipts: append([]StageReceiptSource(nil), prefix...),
		},
		MaterialPath: document.RuntimeBinding.MaterialPath, ReceiptPath: document.RuntimeBinding.ReceiptPath,
	})
	if err != nil {
		return errors.New("load full-run runtime binding for evidence identity")
	}
	material, err := deriveObservabilityIndependentEvidenceIdentity(binder.manifest, runtime)
	if err != nil {
		return err
	}
	receipt, err := persistObservabilityIndependentEvidenceIdentity(material, binder.identityPath)
	if err != nil || receipt.State != "WRITTEN_VERIFIED" {
		return errors.New("persist full-run observability evidence identity")
	}
	receiptRaw, err := canonicalObservabilityIndependentEvidenceIdentityReceipt(receipt)
	if err != nil {
		return errors.New("canonicalize full-run observability evidence identity receipt")
	}
	if err := writeExclusivePrivateMaterial(binder.receiptPath, receiptRaw); err != nil {
		return errors.New("persist full-run observability evidence identity receipt")
	}
	return nil
}

// MaterializeObservabilityIndependentEvidenceIdentity derives the evidence
// authority identity from the verified full-run contract and the durable
// lifecycle-produced runtime binding. It performs local reads and one
// create-only private file write; it contacts no API.
func MaterializeObservabilityIndependentEvidenceIdentity(config ObservabilityIndependentEvidenceIdentityMaterialConfig) (ObservabilityIndependentEvidenceIdentityReceipt, error) {
	receipt := ObservabilityIndependentEvidenceIdentityReceipt{
		Format: ObservabilityIndependentEvidenceIdentityReceiptFormat, State: "STOPPED_ZERO_WRITE",
		PersistentMutationAllowed: false,
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedReceiptPrefixDigest) || config.OutputPath == "" {
		return receipt, errors.New("observability evidence identity materialization input is invalid")
	}
	if err := validateRuntimeBindingOutputPath(config.OutputPath); err != nil {
		return receipt, errors.New("observability evidence identity destination is invalid")
	}
	manifest, manifestReceipt, err := LoadFullRunExecutionManifest(config.ManifestPath)
	if err != nil || manifestReceipt.ManifestDigest != config.ExpectedManifestDigest {
		return receipt, errors.New("load exact full-run manifest for evidence identity")
	}
	prefix, err := LoadStageReceiptPrefix(config.ReceiptPrefixPath, config.ExpectedReceiptPrefixDigest)
	if err != nil || len(prefix) != 6 {
		return receipt, errors.New("load exact six-stage receipt prefix for evidence identity")
	}
	document := manifest.document
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle:       StageResumeConfig{PlanPath: document.Plan.Path, PlanExpected: fullRunPlanExpected(document.Plan.Expected), Receipts: prefix},
		MaterialPath: document.RuntimeBinding.MaterialPath, ReceiptPath: document.RuntimeBinding.ReceiptPath,
	})
	if err != nil {
		return receipt, errors.New("load runtime binding for evidence identity")
	}
	material, err := deriveObservabilityIndependentEvidenceIdentity(manifest, runtime)
	if err != nil {
		return receipt, err
	}
	return persistObservabilityIndependentEvidenceIdentity(material, config.OutputPath)
}

func persistObservabilityIndependentEvidenceIdentity(material ObservabilityIndependentEvidenceIdentityMaterial, outputPath string) (ObservabilityIndependentEvidenceIdentityReceipt, error) {
	receipt := ObservabilityIndependentEvidenceIdentityReceipt{
		Format: ObservabilityIndependentEvidenceIdentityReceiptFormat, State: "STOPPED_ZERO_WRITE",
		PersistentMutationAllowed: false,
	}
	if err := validateRuntimeBindingOutputPath(outputPath); err != nil {
		return receipt, errors.New("observability evidence identity destination is invalid")
	}
	raw, err := canonicalObservabilityIndependentEvidenceIdentity(material)
	if err != nil || len(raw) == 0 || len(raw) > maximumObservabilityEvidenceIdentityBytes {
		return receipt, errors.New("canonicalize observability evidence identity")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	if err := writeExclusivePrivateMaterial(outputPath, raw); err != nil {
		return receipt, errors.New("materialize private observability evidence identity")
	}
	info, err := os.Lstat(outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(raw)) {
		return receipt, errors.New("observability evidence identity metadata differs after write")
	}
	receipt.State, receipt.ManifestDigest = "WRITTEN_VERIFIED", material.ManifestDigest
	receipt.RuntimeBindingDigest = material.RuntimeBindingDigest
	receipt.TargetClusterUIDDigest = digest.SHA256([]byte(material.TargetClusterUID))
	receipt.IdentityDigest, receipt.FileMode, receipt.FileSize = digest.SHA256(raw), "0600", len(raw)
	return receipt, nil
}

func deriveObservabilityIndependentEvidenceIdentity(manifest VerifiedFullRunExecutionManifest, runtime VerifiedRuntimeBindingMaterial) (ObservabilityIndependentEvidenceIdentityMaterial, error) {
	if !manifest.verified || verifyRuntimeBindingMaterial(runtime) != nil {
		return ObservabilityIndependentEvidenceIdentityMaterial{}, errors.New("evidence identity sources are not verified")
	}
	plan, document, material := manifest.plan, manifest.document, runtime.material
	if material.PlanDigest != plan.PlanDigest || material.IntentRevision != plan.IntentRevision || material.PlatformRevision != plan.PlatformRevision || material.ExecutionFixture != plan.ExecutionFixture {
		return ObservabilityIndependentEvidenceIdentityMaterial{}, errors.New("runtime binding differs from full-run identity")
	}
	request := PlatformCapabilityProbeRequest{
		Format: PlatformCapabilityProbeRequestFormat, TargetClusterUID: material.Target.CAPIClusterUID,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		ContractDigest: manifest.platform.CapabilityContractDigest, ExecutableDigest: manifest.platform.CapabilityExecutableDigest,
	}
	if err := validatePlatformCapabilityProbeRequest(request); err != nil {
		return ObservabilityIndependentEvidenceIdentityMaterial{}, errors.New("derive bounded capability request")
	}
	run, err := observabilityCapabilityRun(request, document.PlatformObservation.Capability.Namespace)
	if err != nil {
		return ObservabilityIndependentEvidenceIdentityMaterial{}, errors.New("derive bounded capability run")
	}
	fixture, err := BuildObservabilitySyntheticFixture(run, ObservabilitySyntheticFixtureConfig{
		PushgatewayImage: document.PlatformObservation.Capability.PushgatewayImage,
		LogEmitterImage:  document.PlatformObservation.Capability.LogEmitterImage,
	})
	if err != nil {
		return ObservabilityIndependentEvidenceIdentityMaterial{}, errors.New("derive exact observability fixture")
	}
	profile, err := StandardObservabilityCapabilityCheckProfile(document.PlatformObservation.Capability.Namespace)
	if err != nil {
		return ObservabilityIndependentEvidenceIdentityMaterial{}, errors.New("derive standard observability profile")
	}
	return ObservabilityIndependentEvidenceIdentityMaterial{
		Format: ObservabilityIndependentEvidenceIdentityFormat, State: "RUNTIME_BOUND",
		ManifestDigest: manifest.receipt.ManifestDigest, RuntimeBindingDigest: runtime.receipt.PrivateMaterialDigest,
		RunID: run.RunID, TargetClusterUID: material.Target.CAPIClusterUID,
		FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest(),
	}, nil
}

// LoadObservabilityIndependentEvidenceIdentity reads one private identity and
// returns only the typed producer input after canonical digest verification.
func LoadObservabilityIndependentEvidenceIdentity(path, expectedDigest string) (ObservabilityCapabilityObservationIdentity, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(expectedDigest) || validateObservabilityEvidenceFile(path, maximumObservabilityEvidenceIdentityBytes, true) != nil {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability evidence identity file is invalid")
	}
	raw, err := readBoundedRegular(path, maximumObservabilityEvidenceIdentityBytes)
	if err != nil || digest.SHA256(raw) != expectedDigest {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability evidence identity digest differs")
	}
	var material ObservabilityIndependentEvidenceIdentityMaterial
	if err := jsonstrict.Decode(raw, &material); err != nil {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("decode strict observability evidence identity")
	}
	canonical, err := canonicalObservabilityIndependentEvidenceIdentity(material)
	if err != nil || !bytes.Equal(canonical, raw) || material.Format != ObservabilityIndependentEvidenceIdentityFormat || material.State != "RUNTIME_BOUND" ||
		!stageReceiptPrefixDigestPattern.MatchString(material.ManifestDigest) || !stageReceiptPrefixDigestPattern.MatchString(material.RuntimeBindingDigest) {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability evidence identity is not canonical and bound")
	}
	identity := ObservabilityCapabilityObservationIdentity{
		RunID: material.RunID, TargetClusterUID: material.TargetClusterUID,
		FixtureDigest: material.FixtureDigest, ProfileDigest: material.ProfileDigest,
	}
	if !validObservabilityObservationIdentity(identity) {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability evidence producer identity is invalid")
	}
	return identity, nil
}

func canonicalObservabilityIndependentEvidenceIdentity(material ObservabilityIndependentEvidenceIdentityMaterial) ([]byte, error) {
	raw, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}

func canonicalObservabilityIndependentEvidenceIdentityReceipt(receipt ObservabilityIndependentEvidenceIdentityReceipt) ([]byte, error) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}

var _ FullRunEvidenceIdentityBinder = (*fullRunObservabilityEvidenceIdentityBinder)(nil)
