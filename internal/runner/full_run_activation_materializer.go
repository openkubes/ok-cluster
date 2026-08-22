package runner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const FullRunExecutionBundleMaterializationReceiptFormat = "ok147-full-run-execution-bundle-materialization-receipt/v1"

type FullRunExecutionBundleMaterializationConfig struct {
	SourceDirectory      string
	DestinationDirectory string
	HandoffDirectory     string
	ExpectedBundleDigest string
}

type FullRunExecutionBundleMaterializationReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	BundleDigest              string `json:"bundleDigest,omitempty"`
	ManifestDigest            string `json:"manifestDigest,omitempty"`
	EvidenceKeyID             string `json:"evidenceKeyId,omitempty"`
	FileCount                 int    `json:"fileCount,omitempty"`
	TotalBytes                int    `json:"totalBytes,omitempty"`
	KubernetesMutationAllowed bool   `json:"kubernetesMutationAllowed"`
}

// MaterializeFullRunExecutionBundle converts one immutable projected Secret
// into the only private workspace accepted by the full-run executor. The
// evidence handoff is a separate private emptyDir shared only with the
// independent authority process.
func MaterializeFullRunExecutionBundle(config FullRunExecutionBundleMaterializationConfig) (FullRunExecutionBundleMaterializationReceipt, error) {
	if config.DestinationDirectory != fullRunExecutionWorkspaceRoot || config.HandoffDirectory != fullRunExecutionHandoffRoot {
		return stoppedFullRunMaterializationReceipt(), errors.New("full-run bundle destinations differ from fixed runtime roots")
	}
	return materializeFullRunExecutionBundle(config)
}

func materializeFullRunExecutionBundle(config FullRunExecutionBundleMaterializationConfig) (FullRunExecutionBundleMaterializationReceipt, error) {
	receipt := stoppedFullRunMaterializationReceipt()
	if !absoluteCleanDirectory(config.SourceDirectory) || !absoluteCleanDirectory(config.DestinationDirectory) ||
		!absoluteCleanDirectory(config.HandoffDirectory) || !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedBundleDigest) ||
		directoriesOverlap(config.SourceDirectory, config.DestinationDirectory) || directoriesOverlap(config.SourceDirectory, config.HandoffDirectory) ||
		directoriesOverlap(config.DestinationDirectory, config.HandoffDirectory) {
		return receipt, errors.New("full-run bundle materialization configuration is invalid")
	}
	if _, err := os.Lstat(config.DestinationDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("full-run bundle destination must be absent")
	}
	handoffInfo, err := os.Lstat(config.HandoffDirectory)
	if err != nil || !handoffInfo.IsDir() || handoffInfo.Mode()&os.ModeSymlink != 0 || handoffInfo.Mode().Perm()&0o007 != 0 {
		return receipt, errors.New("full-run evidence handoff is not a private directory")
	}
	entries, err := os.ReadDir(config.HandoffDirectory)
	if err != nil || len(entries) != 0 {
		return receipt, errors.New("full-run evidence handoff must be empty before materialization")
	}
	indexRaw, err := readProjectedPostRuntimeBundleFile(config.SourceDirectory, fullRunExecutionBundleIndexName, 64*1024)
	if err != nil {
		return receipt, errors.New("read full-run bundle index")
	}
	var index fullRunExecutionBundleIndex
	if err := jsonstrict.Decode(indexRaw, &index); err != nil {
		return receipt, errors.New("decode full-run bundle index")
	}
	canonical, indexDigest, err := canonicalFullRunExecutionBundleIndex(index)
	if err != nil || !bytes.Equal(canonical, indexRaw) || indexDigest != config.ExpectedBundleDigest {
		return receipt, errors.New("full-run bundle index differs from expected identity")
	}
	receipt.BundleDigest, receipt.ManifestDigest = indexDigest, index.ManifestDigest
	contents := make(map[string][]byte, len(index.Files))
	for _, file := range index.Files {
		raw, readErr := readProjectedPostRuntimeBundleFile(config.SourceDirectory, file.Path, maximumFullRunExecutionBundleBytes)
		if readErr != nil || digest.SHA256(raw) != file.Digest {
			return receipt, errors.New("full-run bundle file differs from bound identity")
		}
		receipt.TotalBytes += len(raw)
		if receipt.TotalBytes > maximumFullRunExecutionBundleBytes {
			return receipt, errors.New("full-run bundle exceeds size limit")
		}
		contents[file.Path] = raw
	}
	var document fullRunExecutionManifestDocument
	if err := jsonstrict.Decode(contents[fullRunExecutionManifestPath], &document); err != nil ||
		digestFullRunExecutionManifest(document) != index.ManifestDigest || !validPackagedFullRunRuntimePaths(document) {
		return receipt, errors.New("full-run bundle manifest differs from packaged runtime identity")
	}
	publicKeyID, err := fullRunBundleEvidenceKeyID(contents["input/independent-evidence.pub"])
	if err != nil || publicKeyID != document.PlatformObservation.Capability.IndependentEvidenceKeyID {
		return receipt, errors.New("full-run bundle evidence key identity differs")
	}
	receipt.EvidenceKeyID = publicKeyID

	parentInfo, err := os.Lstat(filepath.Dir(config.DestinationDirectory))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return receipt, errors.New("full-run bundle destination parent is invalid")
	}
	if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
		return receipt, errors.New("create full-run bundle destination")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	for _, directory := range []string{
		"activation", "credentials", "input", "input/projection", "work", "work/authorizations", "work/receipts",
	} {
		if err := os.Mkdir(filepath.Join(config.DestinationDirectory, directory), 0o700); err != nil {
			return receipt, errors.New("create full-run bundle directory")
		}
	}
	for _, file := range index.Files {
		if err := writeExclusivePostRuntimeBundleFile(filepath.Join(config.DestinationDirectory, file.Path), contents[file.Path]); err != nil {
			return receipt, err
		}
	}
	receipt.State, receipt.FileCount = "MATERIALIZED_VERIFIED", len(index.Files)
	return receipt, nil
}

func stoppedFullRunMaterializationReceipt() FullRunExecutionBundleMaterializationReceipt {
	return FullRunExecutionBundleMaterializationReceipt{
		Format: FullRunExecutionBundleMaterializationReceiptFormat, State: "STOPPED_ZERO_WRITE", KubernetesMutationAllowed: false,
	}
}

func digestFullRunExecutionManifest(document fullRunExecutionManifestDocument) string {
	raw, err := json.Marshal(document)
	if err != nil {
		return ""
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return ""
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return ""
	}
	return digest.SHA256(canonical)
}

func validPackagedFullRunRuntimePaths(document fullRunExecutionManifestDocument) bool {
	path := func(relative string) string { return filepath.Join(fullRunExecutionWorkspaceRoot, relative) }
	ledger := postRuntimeLedgerDocument{Endpoint: document.ProviderPrerequisites.Ledger.Endpoint, Namespace: document.ProviderPrerequisites.Ledger.Namespace, TokenFile: path("credentials/ledger-token"), CAFile: path("credentials/ledger-ca.crt")}
	workload := fullRunWorkloadRuntimeDocument{BindingPath: path("work/workload-authority.json"), KubeconfigFile: path("work/workload-kubeconfig.yaml"), CAFile: path("work/workload-ca.crt")}
	return document.Plan.Path == path("input/staged-plan.json") && document.Projection.ManifestPath == path("input/projection-manifest.json") && document.Projection.Root == path("input/projection") &&
		document.Authorization.TokenFile == path("credentials/authorization-token") && document.Authorization.CAFile == path("credentials/authorization-ca.crt") &&
		document.Authorization.PublicKeyPath == path("input/authorization-authority.pub") && document.Authorization.OutputDirectory == path("work/authorizations") &&
		document.Profiles.Network.Path == path("input/network-profile.json") && document.Profiles.Platform.Path == path("input/platform-profile.json") && document.Profiles.Aggregate.Path == path("input/aggregate-profile.json") &&
		document.ProviderPrerequisites.Ledger == ledger && document.ProviderPrerequisites.Authority.TokenFile == path("credentials/infrastructure-token") && document.ProviderPrerequisites.Authority.CAFile == path("credentials/infrastructure-ca.crt") &&
		document.ProviderAccess.PolicyPath == path("input/provider-access-policy.json") && document.ProviderAccess.KubeconfigFile == path("credentials/provider-access-kubeconfig") &&
		document.ClusterLifecycle.Ledger == ledger && document.ClusterLifecycle.Authority.TokenFile == path("credentials/management-token") && document.ClusterLifecycle.Authority.CAFile == path("credentials/management-ca.crt") &&
		document.Enablement.ArtifactPath == path("input/enablement.yaml") && document.NetworkObservation.Workload == workload && document.RuntimeBinding.Workload == workload &&
		document.RuntimeBinding.MaterialPath == path("work/runtime-binding.json") && document.RuntimeBinding.ReceiptPath == path("work/runtime-binding-receipt.json") &&
		document.TargetAccess.ArtifactPath == path("input/target-access.yaml") && document.TargetAccess.Workload == workload &&
		document.TargetCredential.PolicyPath == path("input/target-credential-policy.json") && document.TargetCredential.Workload == workload &&
		document.TargetRegistration.ArtifactPath == path("input/target-registration.yaml") && document.TargetRegistration.GitOps.TokenFile == path("credentials/gitops-token") && document.TargetRegistration.GitOps.CAFile == path("credentials/gitops-ca.crt") &&
		document.PlatformApplications.ArtifactPath == path("input/platform-applications.yaml") && document.ReceiptDirectory == path("work/receipts") &&
		document.ObservabilityCollector.RuntimeAuthorityPath == path("input/collector-runtime-authority.yaml") &&
		document.ObservabilityCollector.JobTemplatePath == path("input/collector-job.yaml") &&
		document.ObservabilityCollector.WebhookTokenPath == path("credentials/collector-webhook-token") &&
		document.ObservabilityCollector.QueryTokenPath == path("credentials/collector-query-token") &&
		document.ObservabilityCollector.TLSCertificatePath == path("credentials/collector-tls.crt") &&
		document.ObservabilityCollector.TLSPrivateKeyPath == path("credentials/collector-tls.key") &&
		document.AggregateEvidence.WorkloadTokenFile == "" && document.AggregateEvidence.WorkloadKubeconfigFile == workload.KubeconfigFile && document.AggregateEvidence.WorkloadCAFile == workload.CAFile &&
		document.PlatformObservation.Capability.IndependentEvidenceIdentityPath == fullRunExecutionHandoffRoot+"/observability-evidence-identity.json" &&
		document.PlatformObservation.Capability.IndependentEvidenceIdentityReceiptPath == fullRunExecutionHandoffRoot+"/observability-evidence-identity-receipt.json" &&
		document.PlatformObservation.Capability.IndependentEvidencePath == fullRunExecutionHandoffRoot+"/observability-evidence.json"
}

func fullRunBundleEvidenceKeyID(raw []byte) (string, error) {
	encoded := strings.TrimSuffix(string(raw), "\n")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || strings.ContainsAny(encoded, " \t\r\n") {
		return "", errors.New("full-run evidence public key is invalid")
	}
	return digest.SHA256(key), nil
}
