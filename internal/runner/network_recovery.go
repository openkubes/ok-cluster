package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const NetworkRecoveryFormat = "ok147-network-profile-recovery/v1"

type RecoveryReceiptSource struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// NetworkRecoveryDocument grants no authority. Its independently pinned
// digest binds a source STOP, exact successful prefix and successor identity.
type NetworkRecoveryDocument struct {
	Format                  string                  `json:"format"`
	AuthorizationState      string                  `json:"authorizationState"`
	SourceManifestPath      string                  `json:"sourceManifestPath"`
	SourceManifestDigest    string                  `json:"sourceManifestDigest"`
	SourcePlanDigest        string                  `json:"sourcePlanDigest"`
	SuccessorPlanDigest     string                  `json:"successorPlanDigest"`
	SourceStopReceiptPath   string                  `json:"sourceStopReceiptPath"`
	SourceStopReceiptDigest string                  `json:"sourceStopReceiptDigest"`
	SourceTerminalPath      string                  `json:"sourceTerminalPath"`
	SourceTerminalDigest    string                  `json:"sourceTerminalDigest"`
	SourceReceipts          []RecoveryReceiptSource `json:"sourceReceipts"`
	TargetClusterUIDDigest  string                  `json:"targetClusterUidDigest"`
	FormerClusterIdentity   contract.Identity       `json:"formerClusterIdentity"`
	CorrectedProfilePath    string                  `json:"correctedProfilePath"`
}

// VerifiedNetworkRecovery exposes an immutable successor Plan and the exact
// original receipt sources for offline consistency inspection only.
type VerifiedNetworkRecovery struct {
	Plan           stageplan.Binding
	SourceReceipts []StageReceiptSource
	prefix         []stagereceipt.Verified
	verified       bool
}

func readRecoveryArtifact(path, expected string) ([]byte, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(expected) {
		return nil, errors.New("recovery artifact digest is invalid")
	}
	raw, err := readBoundedRegular(path, maximumFullRunExecutionManifestBytes)
	if err != nil || digest.SHA256(raw) != expected {
		return nil, errors.New("recovery artifact identity differs")
	}
	return raw, nil
}

// VerifyNetworkRecovery is artifact consistency inspection, never execution
// authorization. Recovery execution is disabled pending an atomic ledger gate.
// It performs only bounded local reads and describes exactly
// one corrected HRP cluster reference, never a policy, authority or convergence
// change. It cannot enable execution or authority-policy generation.
func VerifyNetworkRecovery(config StageResumeConfig) (VerifiedNetworkRecovery, error) {
	raw, err := readRecoveryArtifact(config.RecoveryBindingPath, config.RecoveryBindingDigest)
	if err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	var doc NetworkRecoveryDocument
	if err := jsonstrict.Decode(raw, &doc); err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	if doc.Format != NetworkRecoveryFormat || doc.AuthorizationState != "NO-GO" || len(doc.SourceReceipts) != 4 || !stageReceiptPrefixDigestPattern.MatchString(doc.TargetClusterUIDDigest) {
		return VerifiedNetworkRecovery{}, errors.New("recovery binding has unsupported scope")
	}
	sourceManifest, sourceManifestDigest, err := loadFullRunExecutionManifest(doc.SourceManifestPath)
	if err != nil || sourceManifestDigest != doc.SourceManifestDigest || sourceManifest.Format != FullRunExecutionManifestFormat {
		return VerifiedNetworkRecovery{}, errors.New("recovery source manifest differs")
	}
	expected := config.PlanExpected
	if expected.RecoverySourcePlanDigest != "" {
		return VerifiedNetworkRecovery{}, errors.New("recovery source identity must come from the pinned binding")
	}
	source, err := stageplan.Load(sourceManifest.Plan.Path, expected)
	if err != nil || source.PlanDigest != doc.SourcePlanDigest || source.ExecutionAttempt != "" || source.RecoverySourcePlanDigest != "" {
		return VerifiedNetworkRecovery{}, errors.New("recovery source Plan differs")
	}
	if !reflect.DeepEqual(fullRunPlanExpected(sourceManifest.Plan.Expected), expected) {
		return VerifiedNetworkRecovery{}, errors.New("recovery expected Contract differs from source manifest")
	}
	expected.RecoverySourcePlanDigest = source.PlanDigest
	successor, err := stageplan.Load(config.PlanPath, expected)
	if err != nil || successor.PlanDigest != doc.SuccessorPlanDigest {
		return VerifiedNetworkRecovery{}, errors.New("recovery successor Plan differs")
	}
	previous := []stagereceipt.Verified{}
	originals := make([]stagereceipt.Verified, 0, 4)
	sources := make([]StageReceiptSource, 0, 4)
	for _, entry := range doc.SourceReceipts {
		v, err := stagereceipt.Load(entry.Path, entry.Digest, source, previous)
		if err != nil {
			return VerifiedNetworkRecovery{}, err
		}
		originals = append(originals, v)
		previous = []stagereceipt.Verified{v}
		sources = append(sources, StageReceiptSource{Path: entry.Path, Digest: entry.Digest})
	}
	decision, err := stagecursor.Evaluate(source, originals)
	if err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	d, err := decision.Decision()
	if err != nil || d.State != "NEXT" || d.StageOrder != 5 {
		return VerifiedNetworkRecovery{}, errors.New("recovery requires the exact successful Stage-1-4 prefix")
	}
	lifecycle, _ := originals[1].Receipt()
	if lifecycle.TargetClusterUIDDigest != doc.TargetClusterUIDDigest {
		return VerifiedNetworkRecovery{}, errors.New("recovery target differs from original lifecycle evidence")
	}
	stopRaw, err := readRecoveryArtifact(doc.SourceStopReceiptPath, doc.SourceStopReceiptDigest)
	if err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	var stop FullRunExecutionActivationReceipt
	if err := jsonstrict.Decode(stopRaw, &stop); err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	if stop.Format != FullRunExecutionActivationReceiptFormat || stop.State != "STOPPED" || stop.Manifest.State != "VERIFIED" ||
		stop.Manifest.ManifestDigest != doc.SourceManifestDigest || stop.Manifest.PlanDigest != source.PlanDigest || stop.Execution == nil ||
		stop.Execution.Format != FullRunOrchestrationReceiptFormat || stop.Execution.State != "STOPPED" || stop.Execution.PlanDigest != source.PlanDigest ||
		stop.Execution.CompletionMode != stageplan.CompletionModeBareClusterMVP || stop.Execution.StoppedAt != "network-observation" || stop.Execution.StopCategory != "OBSERVATION_SOURCE_ERROR" || len(stop.Execution.Checkpoints) != 4 {
		return VerifiedNetworkRecovery{}, errors.New("recovery does not bind the supported immutable source STOP")
	}
	for i, checkpoint := range stop.Execution.Checkpoints {
		if checkpoint.StageID != source.Stages[i].ID || checkpoint.State != "COMPLETED_SUCCEEDED" || checkpoint.StageReceiptDigest != doc.SourceReceipts[i].Digest {
			return VerifiedNetworkRecovery{}, errors.New("source STOP checkpoint differs from original prefix")
		}
	}
	terminal, err := readRecoveryArtifact(doc.SourceTerminalPath, doc.SourceTerminalDigest)
	if err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	if !bytes.Equal(terminal, []byte("TERMINAL\n")) {
		return VerifiedNetworkRecovery{}, errors.New("source executor terminal marker has unsupported content")
	}
	oldProfile, err := LoadNetworkProfileFile(NetworkProfileFileConfig{Path: sourceManifest.Profiles.Network.Path,
		ExpectedProfileDigest: sourceManifest.Profiles.Network.Digest, ExpectedIntentRevision: source.IntentRevision, ExpectedEnablementRevision: source.EnablementRevision})
	if err != nil || source.RequireInput("network-observation", "stage.network-observation", oldProfile.Digest) != nil {
		return VerifiedNetworkRecovery{}, errors.New("source Network profile differs")
	}
	stage, _, err := successor.Stage("network-observation")
	if err != nil || len(stage.Inputs) != 1 {
		return VerifiedNetworkRecovery{}, errors.New("successor Network profile input is invalid")
	}
	newProfile, err := LoadNetworkProfileFile(NetworkProfileFileConfig{Path: doc.CorrectedProfilePath, ExpectedProfileDigest: stage.Inputs[0].Digest,
		ExpectedIntentRevision: source.IntentRevision, ExpectedEnablementRevision: source.EnablementRevision})
	if err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	oldHrp := oldProfile.Profile.ExpectedHRPSpecDigest
	checkProfile := newProfile.Profile
	checkProfile.ExpectedHRPSpecDigest = oldHrp
	if !reflect.DeepEqual(checkProfile, oldProfile.Profile) || newProfile.Profile.ExpectedHRPSpecDigest == oldHrp {
		return VerifiedNetworkRecovery{}, errors.New("recovery changes requirements beyond the HRP identity")
	}
	enablement, err := submission.LoadEnablement(sourceManifest.Enablement.ArtifactPath, submission.EnablementExpected{
		ArtifactDigest: fullRunStageInputDigest(source, "enablement"), ContractIdentity: source.ContractIdentity,
		IntentRevision: source.IntentRevision, EnablementRevision: source.EnablementRevision, ExecutionFixture: source.ExecutionFixture,
		ManagementAuthority: source.Authorities.Management, ObjectIdentity: projection.ResourceIdentity{APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: source.ContractIdentity.Namespace, Name: source.ContractIdentity.Name + "-cilium"}})
	if err != nil || len(enablement.Management.Objects) != 1 {
		return VerifiedNetworkRecovery{}, errors.New("source enablement artifact differs")
	}
	var object struct {
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(enablement.Management.Objects[0].Raw, &object); err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	wantOld, err := observation.ExpectedLiteralReleaseSpecDigest(object.Spec, doc.FormerClusterIdentity.Namespace, doc.FormerClusterIdentity.Name)
	if err != nil || wantOld != oldHrp {
		return VerifiedNetworkRecovery{}, errors.New("old HRP identity is not reproduced by the former Cluster reference")
	}
	wantNew, err := observation.ExpectedLiteralReleaseSpecDigest(object.Spec, source.ContractIdentity.Namespace, source.ContractIdentity.Name)
	if err != nil || wantNew != newProfile.Profile.ExpectedHRPSpecDigest {
		return VerifiedNetworkRecovery{}, errors.New("corrected HRP identity is not derived from approved enablement and current Cluster reference")
	}
	prefix, err := stagereceipt.InheritFourStagePrefix(source, successor, originals, config.RecoveryBindingDigest)
	if err != nil {
		return VerifiedNetworkRecovery{}, err
	}
	return VerifiedNetworkRecovery{Plan: successor, SourceReceipts: sources, prefix: prefix, verified: true}, nil
}

func loadNetworkRecoveryResume(config StageResumeConfig) (stageplan.Binding, stagecursor.Cursor, []stagereceipt.Verified, error) {
	recovery, err := VerifyNetworkRecovery(config)
	if err != nil {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, err
	}
	if len(config.Receipts) < 4 || len(config.Receipts) > 7 {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, errors.New("recovery requires four original receipts and at most three successor outcomes")
	}
	for i, source := range recovery.SourceReceipts {
		if config.Receipts[i] != source {
			return stageplan.Binding{}, stagecursor.Cursor{}, nil, errors.New("recovery source receipt selection changed")
		}
	}
	prefix := append([]stagereceipt.Verified{}, recovery.prefix...)
	previous := []stagereceipt.Verified{prefix[3]}
	for _, source := range config.Receipts[4:] {
		v, err := stagereceipt.Load(source.Path, source.Digest, recovery.Plan, previous)
		if err != nil {
			return stageplan.Binding{}, stagecursor.Cursor{}, nil, err
		}
		prefix = append(prefix, v)
		previous = []stagereceipt.Verified{v}
	}
	cursor, err := stagecursor.Evaluate(recovery.Plan, prefix)
	return recovery.Plan, cursor, prefix, err
}
