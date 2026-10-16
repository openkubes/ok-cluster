package runner

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// Only existing connection/trust references are accepted. There is no plan,
// historical manifest, grant, policy deployment, output or runtime UID input.
type bareClusterRuntimeInputs struct {
	Format        string `json:"format"`
	Authorization struct {
		Endpoint      string `json:"endpoint"`
		TokenFile     string `json:"tokenFile"`
		CAFile        string `json:"caFile"`
		PublicKeyPath string `json:"publicKeyPath"`
	} `json:"authorization"`
	Ledger                           postRuntimeLedgerDocument    `json:"ledger"`
	Infrastructure                   postRuntimeAuthorityDocument `json:"infrastructure"`
	Management                       postRuntimeAuthorityDocument `json:"management"`
	ProviderAccessKubeconfigFile     string                       `json:"providerAccessKubeconfigFile"`
	IndependentEvidencePublicKeyPath string                       `json:"independentEvidencePublicKeyPath"`
}

// BareClusterManifestConfig contains fresh, already verified static inputs.
// Output directories are fixed below Root; existing credentials stay outside
// the CLI's authority to issue, copy, rotate or otherwise change them.
type BareClusterManifestConfig struct {
	Root                 string
	Expected             stageplan.Expected
	NetworkProfileDigest string
	EnablementObject     projection.ResourceIdentity
	TargetAccessObjects  []projection.ResourceIdentity
}

type BareClusterManifestDraft struct {
	Raw                      []byte
	RuntimeInputsDigest      string
	IndependentEvidenceKeyID string
}

// BuildBareClusterManifest creates private manifest bytes, not a verified
// manifest or an execution capability. The caller must create-only persist
// them and call LoadFullRunExecutionManifest before reporting preparation.
func BuildBareClusterManifest(runtimeInputsPath string, config BareClusterManifestConfig) (BareClusterManifestDraft, error) {
	info, err := os.Lstat(config.Root)
	if err != nil || !validFullRunAbsolutePath(config.Root) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return BareClusterManifestDraft{}, errors.New("fresh manifest root must be an existing private non-symlink directory")
	}
	plan, err := stageplan.Load(filepath.Join(config.Root, "staged-plan.json"), config.Expected)
	if err != nil || plan.CompletionMode != stageplan.CompletionModeBareClusterMVP || len(plan.Stages) != 7 || plan.ExecutionAttempt != "" || plan.RecoverySourcePlanDigest != "" || plan.NetworkObservationMode != "" {
		return BareClusterManifestDraft{}, errors.New("manifest handoff requires the exact fresh seven-stage plan")
	}
	raw, err := readBareClusterRuntimeInputs(runtimeInputsPath)
	if err != nil {
		return BareClusterManifestDraft{}, err
	}
	var inputs bareClusterRuntimeInputs
	if jsonstrict.Decode(raw, &inputs) != nil || inputs.Format != "ok-cli-cluster-runtime-inputs/v1" {
		return BareClusterManifestDraft{}, errors.New("decode strict private runtime inputs")
	}
	if err := verifyBareClusterCredentialReferences(inputs); err != nil {
		return BareClusterManifestDraft{}, err
	}
	if !validFullRunAbsolutePath(inputs.IndependentEvidencePublicKeyPath) {
		return BareClusterManifestDraft{}, errors.New("explicit independent evidence public key path is required")
	}
	key, err := readBoundedRegular(inputs.IndependentEvidencePublicKeyPath, 1024)
	if err != nil {
		return BareClusterManifestDraft{}, errors.New("read independent evidence public key")
	}
	keyID, err := fullRunBundleEvidenceKeyID(key)
	if err != nil {
		return BareClusterManifestDraft{}, err
	}
	stageKey, err := readBoundedRegular(inputs.Authorization.PublicKeyPath, 1024)
	if err != nil {
		return BareClusterManifestDraft{}, errors.New("read stage authority public key")
	}
	stageKeyID, err := fullRunBundleEvidenceKeyID(stageKey)
	if err != nil || stageKeyID == keyID {
		return BareClusterManifestDraft{}, errors.New("stage authority and independent evidence keys must be valid and distinct")
	}
	path := func(name string) string { return filepath.Join(config.Root, name) }
	ledger := inputs.Ledger
	infra := fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: inputs.Infrastructure}
	management := fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: inputs.Management}
	workload := fullRunWorkloadRuntimeDocument{BindingPath: path("runtime/workload-authority.json"), KubeconfigFile: path("runtime/workload.kubeconfig"), CAFile: path("runtime/workload-ca.crt")}
	expected := config.Expected
	doc := fullRunExecutionManifestDocument{
		Format: FullRunExecutionManifestFormat,
		Plan: fullRunPlanDocument{Path: path("staged-plan.json"), Expected: postRuntimePlanExpectedDocument{
			ContractIdentity: expected.ContractIdentity, IntentRevision: expected.IntentRevision, EnablementRevision: expected.EnablementRevision,
			PlatformRevision: expected.PlatformRevision, ExecutionFixture: expected.ExecutionFixture, InfrastructureAuthority: expected.InfrastructureAuthority,
			ManagementAuthority: expected.ManagementAuthority, GitOpsAuthority: expected.GitOpsAuthority, CompletionMode: expected.CompletionMode}},
		Projection: fullRunProjectionDocument{ManifestPath: path("projection/manifest.json"), Root: path("projection")},
		Authorization: postRuntimeAuthorizationDocument{Endpoint: inputs.Authorization.Endpoint, TokenFile: inputs.Authorization.TokenFile, CAFile: inputs.Authorization.CAFile,
			PublicKeyPath: inputs.Authorization.PublicKeyPath, OutputDirectory: path("authorizations")},
		Profiles:              postRuntimeProfilesDocument{Network: postRuntimeProfileReferenceDocument{Path: path("network-profile.json"), Digest: config.NetworkProfileDigest}},
		ProviderPrerequisites: infra, ProviderAccess: fullRunProviderAccessDocument{PolicyPath: path("provider-access-policy.json"), KubeconfigFile: inputs.ProviderAccessKubeconfigFile},
		ClusterLifecycle:     management,
		LifecycleObservation: fullRunLifecycleObservationDocument{Ledger: ledger, Management: inputs.Management, PollInterval: "15s", PollTimeout: "30m"},
		Enablement:           fullRunEnablementDocument{ArtifactPath: path("enablement.yaml"), ExpectedObject: config.EnablementObject, Runtime: management},
		NetworkObservation:   fullRunNetworkObservationDocument{Ledger: ledger, Management: inputs.Management, Workload: workload, PollInterval: "15s", PollTimeout: "30m"},
		RuntimeBinding:       fullRunRuntimeBindingDocument{Ledger: ledger, Workload: workload, MaterialPath: path("runtime/runtime-binding.json"), ReceiptPath: path("runtime/runtime-binding-receipt.json")},
		TargetAccess:         fullRunTargetAccessDocument{ArtifactPath: path("target-access.yaml"), ExpectedObjects: append([]projection.ResourceIdentity(nil), config.TargetAccessObjects...), Ledger: ledger, Workload: workload},
		ReceiptDirectory:     path("receipts"),
	}
	manifest, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return BareClusterManifestDraft{}, errors.New("encode fresh full-run manifest")
	}
	return BareClusterManifestDraft{Raw: append(manifest, '\n'), RuntimeInputsDigest: digest.SHA256(raw), IndependentEvidenceKeyID: keyID}, nil
}

func verifyBareClusterCredentialReferences(inputs bareClusterRuntimeInputs) error {
	seen := map[string]bool{}
	for _, ref := range []struct {
		token, ca, caDigest string
		trailingLF          bool
	}{
		{inputs.Infrastructure.TokenFile, inputs.Infrastructure.CAFile, inputs.Infrastructure.CABundleDigest, false},
		{inputs.Management.TokenFile, inputs.Management.CAFile, inputs.Management.CABundleDigest, false},
		{inputs.Ledger.TokenFile, inputs.Ledger.CAFile, "", false},
		{inputs.Authorization.TokenFile, inputs.Authorization.CAFile, "", true},
	} {
		if !validFullRunAbsolutePath(ref.token) || !validFullRunAbsolutePath(ref.ca) {
			return errors.New("credential references must be explicit absolute paths")
		}
		info, err := os.Lstat(ref.token)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("referenced token must be an existing private regular non-symlink file")
		}
		token, ca, _, err := readBoundedBearerMaterial(ref.token, ref.ca, ref.trailingLF)
		if err != nil {
			return errors.New("parse existing private credential/trust references")
		}
		if seen[token] {
			return errors.New("authority and ledger credentials must be distinct")
		}
		seen[token] = true
		if ref.caDigest != "" && digest.SHA256(ca) != ref.caDigest {
			return errors.New("authority CA differs from explicitly bound digest")
		}
	}
	return nil
}

func readBareClusterRuntimeInputs(path string) ([]byte, error) {
	const max = 64 * 1024
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > max {
		return nil, errors.New("runtime inputs must be a bounded private 0600 regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open private runtime inputs")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm() != 0o600 {
		return nil, errors.New("private runtime inputs changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || len(raw) > max {
		return nil, errors.New("read bounded private runtime inputs")
	}
	return raw, nil
}
