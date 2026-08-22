package runner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	FullRunExecutionBundleFormat        = "ok147-full-run-execution-bundle/v1"
	FullRunExecutionBundleReceiptFormat = "ok147-full-run-execution-bundle-receipt/v1"
	fullRunExecutionBundleIndexName     = "bundle-index.json"
	fullRunExecutionManifestPath        = "activation/full-run-manifest.json"
	fullRunExecutionWorkspaceRoot       = "/var/run/openkubes/workspace"
	fullRunExecutionHandoffRoot         = "/var/run/openkubes/handoff"
	maximumFullRunExecutionBundleBytes  = 900 * 1024
	maximumFullRunExecutionBundleFiles  = 32
)

var fullRunExecutionBundleFiles = []string{
	"activation/full-run-manifest.json",
	"credentials/authorization-ca.crt",
	"credentials/authorization-token",
	"credentials/collector-query-token",
	"credentials/collector-tls.crt",
	"credentials/collector-tls.key",
	"credentials/collector-webhook-token",
	"credentials/gitops-ca.crt",
	"credentials/gitops-token",
	"credentials/infrastructure-ca.crt",
	"credentials/infrastructure-token",
	"credentials/ledger-ca.crt",
	"credentials/ledger-token",
	"credentials/management-ca.crt",
	"credentials/management-token",
	"input/aggregate-profile.json",
	"input/authorization-authority.pub",
	"input/collector-job.yaml",
	"input/collector-runtime-authority.yaml",
	"input/enablement.yaml",
	"input/independent-evidence.pub",
	"input/network-profile.json",
	"input/platform-applications.yaml",
	"input/platform-profile.json",
	"input/projection/authority-map.json",
	"input/projection/ok-infra-prerequisites.yaml",
	"input/projection/ok-mgmt-lifecycle.yaml",
	"input/projection-manifest.json",
	"input/staged-plan.json",
	"input/target-access.yaml",
	"input/target-credential-policy.json",
	"input/target-registration.yaml",
}

type FullRunExecutionBundleConfig struct {
	ManifestPath                 string
	IndependentEvidencePublicKey string
}

type FullRunExecutionBundleReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	BundleDigest              string `json:"bundleDigest"`
	SourceManifestDigest      string `json:"sourceManifestDigest"`
	ManifestDigest            string `json:"manifestDigest"`
	PlanDigest                string `json:"planDigest"`
	EvidenceKeyID             string `json:"evidenceKeyId"`
	FileCount                 int    `json:"fileCount"`
	TotalBytes                int    `json:"totalBytes"`
	KubernetesMutationAllowed bool   `json:"kubernetesMutationAllowed"`
}

type fullRunExecutionBundleIndex struct {
	Format               string                                `json:"format"`
	SourceManifestDigest string                                `json:"sourceManifestDigest"`
	ManifestDigest       string                                `json:"manifestDigest"`
	Files                []postRuntimeExecutionBundleIndexFile `json:"files"`
}

type VerifiedFullRunExecutionBundle struct {
	files    map[string][]byte
	indexRaw []byte
	receipt  FullRunExecutionBundleReceipt
	verified bool
}

// BuildFullRunExecutionBundle rewrites one verified local Stage 1-12 graph to
// fixed private in-Pod paths. R, E, P, the staged Plan and every artifact byte
// remain unchanged; only filesystem locations and the semantic manifest digest
// change. No file is created and no authority is contacted.
func BuildFullRunExecutionBundle(config FullRunExecutionBundleConfig) (VerifiedFullRunExecutionBundle, error) {
	manifest, sourceReceipt, err := LoadFullRunExecutionManifest(config.ManifestPath)
	if err != nil || !manifest.verified || sourceReceipt.State != "VERIFIED" || sourceReceipt.MutationAllowed {
		return VerifiedFullRunExecutionBundle{}, errors.New("verify source full-run execution manifest")
	}
	sources, evidenceKeyID, err := collectFullRunExecutionSources(manifest.document, config.IndependentEvidencePublicKey)
	if err != nil {
		return VerifiedFullRunExecutionBundle{}, fmt.Errorf("collect full-run execution sources: %w", err)
	}
	if evidenceKeyID != manifest.document.PlatformObservation.Capability.IndependentEvidenceKeyID {
		return VerifiedFullRunExecutionBundle{}, errors.New("collect full-run execution sources: evidence key differs")
	}
	files, manifestDigest, err := rewriteFullRunExecutionBundle(manifest.document, sources)
	if err != nil {
		return VerifiedFullRunExecutionBundle{}, err
	}
	index := fullRunExecutionBundleIndex{
		Format: FullRunExecutionBundleFormat, SourceManifestDigest: sourceReceipt.ManifestDigest, ManifestDigest: manifestDigest,
	}
	totalBytes := 0
	paths := append([]string(nil), fullRunExecutionBundleFiles...)
	sort.Strings(paths)
	for _, path := range paths {
		raw, ok := files[path]
		if !ok || len(raw) == 0 {
			return VerifiedFullRunExecutionBundle{}, errors.New("full-run execution bundle file set is incomplete")
		}
		totalBytes += len(raw)
		if totalBytes > maximumFullRunExecutionBundleBytes {
			return VerifiedFullRunExecutionBundle{}, errors.New("full-run execution bundle exceeds size limit")
		}
		index.Files = append(index.Files, postRuntimeExecutionBundleIndexFile{Path: path, Digest: digest.SHA256(raw)})
	}
	indexRaw, bundleDigest, err := canonicalFullRunExecutionBundleIndex(index)
	if err != nil {
		return VerifiedFullRunExecutionBundle{}, err
	}
	receipt := FullRunExecutionBundleReceipt{
		Format: FullRunExecutionBundleReceiptFormat, State: "VERIFIED", BundleDigest: bundleDigest,
		SourceManifestDigest: sourceReceipt.ManifestDigest, ManifestDigest: manifestDigest,
		PlanDigest: sourceReceipt.PlanDigest, EvidenceKeyID: evidenceKeyID,
		FileCount: len(files), TotalBytes: totalBytes, KubernetesMutationAllowed: false,
	}
	return VerifiedFullRunExecutionBundle{files: files, indexRaw: indexRaw, receipt: receipt, verified: true}, nil
}

func (bundle VerifiedFullRunExecutionBundle) Receipt() (FullRunExecutionBundleReceipt, error) {
	if err := verifyFullRunExecutionBundle(bundle); err != nil {
		return FullRunExecutionBundleReceipt{}, errors.New("full-run execution bundle was not produced by verification")
	}
	return bundle.receipt, nil
}

func verifyFullRunExecutionBundle(bundle VerifiedFullRunExecutionBundle) error {
	if !bundle.verified || bundle.receipt.Format != FullRunExecutionBundleReceiptFormat || bundle.receipt.State != "VERIFIED" ||
		bundle.receipt.KubernetesMutationAllowed || bundle.receipt.FileCount != len(fullRunExecutionBundleFiles) || len(bundle.files) != len(fullRunExecutionBundleFiles) ||
		!stageReceiptPrefixDigestPattern.MatchString(bundle.receipt.BundleDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(bundle.receipt.SourceManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(bundle.receipt.ManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(bundle.receipt.PlanDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(bundle.receipt.EvidenceKeyID) {
		return errors.New("full-run execution bundle identity is incomplete")
	}
	var index fullRunExecutionBundleIndex
	if err := json.Unmarshal(bundle.indexRaw, &index); err != nil {
		return errors.New("decode full-run execution bundle index")
	}
	canonical, bundleDigest, err := canonicalFullRunExecutionBundleIndex(index)
	if err != nil || !bytes.Equal(canonical, bundle.indexRaw) || bundleDigest != bundle.receipt.BundleDigest ||
		index.SourceManifestDigest != bundle.receipt.SourceManifestDigest || index.ManifestDigest != bundle.receipt.ManifestDigest ||
		len(index.Files) != len(fullRunExecutionBundleFiles) {
		return errors.New("full-run execution bundle index identity differs")
	}
	totalBytes := 0
	for _, file := range index.Files {
		raw, ok := bundle.files[file.Path]
		if !ok || digest.SHA256(raw) != file.Digest {
			return errors.New("full-run execution bundle content differs")
		}
		totalBytes += len(raw)
	}
	if totalBytes != bundle.receipt.TotalBytes {
		return errors.New("full-run execution bundle byte identity differs")
	}
	publicRaw := bundle.files["input/independent-evidence.pub"]
	publicKey, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(publicRaw), "\n"))
	if err != nil || len(publicKey) != ed25519.PublicKeySize || digest.SHA256(publicKey) != bundle.receipt.EvidenceKeyID {
		return errors.New("full-run execution evidence key identity differs")
	}
	var document fullRunExecutionManifestDocument
	if err := json.Unmarshal(bundle.files[fullRunExecutionManifestPath], &document); err != nil ||
		document.PlatformObservation.Capability.IndependentEvidenceKeyID != bundle.receipt.EvidenceKeyID {
		return errors.New("full-run execution manifest evidence key identity differs")
	}
	return nil
}

func collectFullRunExecutionSources(document fullRunExecutionManifestDocument, evidencePublicKeyPath string) (map[string][]byte, string, error) {
	paths := map[string]string{
		"credentials/authorization-ca.crt":             document.Authorization.CAFile,
		"credentials/authorization-token":              document.Authorization.TokenFile,
		"credentials/collector-query-token":            document.ObservabilityCollector.QueryTokenPath,
		"credentials/collector-tls.crt":                document.ObservabilityCollector.TLSCertificatePath,
		"credentials/collector-tls.key":                document.ObservabilityCollector.TLSPrivateKeyPath,
		"credentials/collector-webhook-token":          document.ObservabilityCollector.WebhookTokenPath,
		"credentials/gitops-ca.crt":                    document.TargetRegistration.GitOps.CAFile,
		"credentials/gitops-token":                     document.TargetRegistration.GitOps.TokenFile,
		"credentials/infrastructure-ca.crt":            document.ProviderPrerequisites.Authority.CAFile,
		"credentials/infrastructure-token":             document.ProviderPrerequisites.Authority.TokenFile,
		"credentials/ledger-ca.crt":                    document.ProviderPrerequisites.Ledger.CAFile,
		"credentials/ledger-token":                     document.ProviderPrerequisites.Ledger.TokenFile,
		"credentials/management-ca.crt":                document.ClusterLifecycle.Authority.CAFile,
		"credentials/management-token":                 document.ClusterLifecycle.Authority.TokenFile,
		"input/aggregate-profile.json":                 document.Profiles.Aggregate.Path,
		"input/authorization-authority.pub":            document.Authorization.PublicKeyPath,
		"input/collector-job.yaml":                     document.ObservabilityCollector.JobTemplatePath,
		"input/collector-runtime-authority.yaml":       document.ObservabilityCollector.RuntimeAuthorityPath,
		"input/enablement.yaml":                        document.Enablement.ArtifactPath,
		"input/independent-evidence.pub":               evidencePublicKeyPath,
		"input/network-profile.json":                   document.Profiles.Network.Path,
		"input/platform-applications.yaml":             document.PlatformApplications.ArtifactPath,
		"input/platform-profile.json":                  document.Profiles.Platform.Path,
		"input/projection/authority-map.json":          filepath.Join(document.Projection.Root, "authority-map.json"),
		"input/projection/ok-infra-prerequisites.yaml": filepath.Join(document.Projection.Root, "ok-infra-prerequisites.yaml"),
		"input/projection/ok-mgmt-lifecycle.yaml":      filepath.Join(document.Projection.Root, "ok-mgmt-lifecycle.yaml"),
		"input/projection-manifest.json":               document.Projection.ManifestPath,
		"input/staged-plan.json":                       document.Plan.Path,
		"input/target-access.yaml":                     document.TargetAccess.ArtifactPath,
		"input/target-credential-policy.json":          document.TargetCredential.PolicyPath,
		"input/target-registration.yaml":               document.TargetRegistration.ArtifactPath,
	}
	result := make(map[string][]byte, len(paths))
	totalBytes := 0
	for relative, source := range paths {
		raw, err := readBoundedRegular(source, maximumFullRunExecutionBundleBytes)
		if err != nil {
			return nil, "", fmt.Errorf("read full-run source %s", filepath.Base(relative))
		}
		totalBytes += len(raw)
		if totalBytes > maximumFullRunExecutionBundleBytes {
			return nil, "", errors.New("full-run execution sources exceed size limit")
		}
		result[relative] = raw
	}
	publicRaw := result["input/independent-evidence.pub"]
	encoded := strings.TrimSuffix(string(publicRaw), "\n")
	publicKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || strings.ContainsAny(encoded, " \t\r\n") {
		return nil, "", errors.New("full-run independent evidence public key is invalid")
	}
	authorizationToken, _, err := openBoundedKubernetesHTTP(document.Authorization.TokenFile, document.Authorization.CAFile)
	if err != nil || authorizationToken != string(result["credentials/authorization-token"]) {
		return nil, "", errors.New("full-run authorization credential is incomplete")
	}
	for name, bound := range map[string]struct {
		tokenPath string
		caPath    string
		caDigest  string
	}{
		"ledger":         {document.ProviderPrerequisites.Ledger.TokenFile, document.ProviderPrerequisites.Ledger.CAFile, digest.SHA256(result["credentials/ledger-ca.crt"])},
		"infrastructure": {document.ProviderPrerequisites.Authority.TokenFile, document.ProviderPrerequisites.Authority.CAFile, document.ProviderPrerequisites.Authority.CABundleDigest},
		"management":     {document.ClusterLifecycle.Authority.TokenFile, document.ClusterLifecycle.Authority.CAFile, document.ClusterLifecycle.Authority.CABundleDigest},
		"gitops":         {document.TargetRegistration.GitOps.TokenFile, document.TargetRegistration.GitOps.CAFile, document.TargetRegistration.GitOps.CABundleDigest},
	} {
		token, _, openErr := openBoundedKubernetesHTTP(bound.tokenPath, bound.caPath)
		if openErr != nil || token != string(result["credentials/"+name+"-token"]) ||
			digest.SHA256(result["credentials/"+name+"-ca.crt"]) != bound.caDigest {
			return nil, "", errors.New("full-run authority credential is incomplete")
		}
	}
	return result, digest.SHA256(publicKey), nil
}

func rewriteFullRunExecutionBundle(document fullRunExecutionManifestDocument, sources map[string][]byte) (map[string][]byte, string, error) {
	files := make(map[string][]byte, len(sources)+1)
	for path, raw := range sources {
		files[path] = append([]byte(nil), raw...)
	}
	path := func(relative string) string { return filepath.Join(fullRunExecutionWorkspaceRoot, relative) }
	ledger := document.ProviderPrerequisites.Ledger
	ledger.TokenFile, ledger.CAFile = path("credentials/ledger-token"), path("credentials/ledger-ca.crt")
	infrastructure := document.ProviderPrerequisites.Authority
	infrastructure.TokenFile, infrastructure.CAFile = path("credentials/infrastructure-token"), path("credentials/infrastructure-ca.crt")
	management := document.ClusterLifecycle.Authority
	management.TokenFile, management.CAFile = path("credentials/management-token"), path("credentials/management-ca.crt")
	gitOps := document.TargetRegistration.GitOps
	gitOps.TokenFile, gitOps.CAFile = path("credentials/gitops-token"), path("credentials/gitops-ca.crt")
	workload := fullRunWorkloadRuntimeDocument{
		BindingPath: path("work/workload-authority.json"), KubeconfigFile: path("work/workload-kubeconfig.yaml"),
		CAFile: path("work/workload-ca.crt"),
	}
	document.Plan.Path = path("input/staged-plan.json")
	document.Projection.ManifestPath, document.Projection.Root = path("input/projection-manifest.json"), path("input/projection")
	document.Authorization.TokenFile, document.Authorization.CAFile = path("credentials/authorization-token"), path("credentials/authorization-ca.crt")
	document.Authorization.PublicKeyPath, document.Authorization.OutputDirectory = path("input/authorization-authority.pub"), path("work/authorizations")
	document.Profiles.Network.Path, document.Profiles.Platform.Path, document.Profiles.Aggregate.Path = path("input/network-profile.json"), path("input/platform-profile.json"), path("input/aggregate-profile.json")
	document.ProviderPrerequisites = fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: infrastructure}
	document.ClusterLifecycle = fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: management}
	document.LifecycleObservation.Ledger, document.LifecycleObservation.Management = ledger, management
	document.Enablement.ArtifactPath, document.Enablement.Runtime = path("input/enablement.yaml"), fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: management}
	document.NetworkObservation.Ledger, document.NetworkObservation.Management, document.NetworkObservation.Workload = ledger, management, workload
	document.RuntimeBinding.Ledger, document.RuntimeBinding.Workload = ledger, workload
	document.RuntimeBinding.MaterialPath, document.RuntimeBinding.ReceiptPath = path("work/runtime-binding.json"), path("work/runtime-binding-receipt.json")
	document.TargetAccess.ArtifactPath, document.TargetAccess.Ledger, document.TargetAccess.Workload = path("input/target-access.yaml"), ledger, workload
	document.TargetCredential.PolicyPath, document.TargetCredential.Ledger, document.TargetCredential.Workload = path("input/target-credential-policy.json"), ledger, workload
	document.TargetRegistration.ArtifactPath, document.TargetRegistration.Ledger, document.TargetRegistration.GitOps = path("input/target-registration.yaml"), ledger, gitOps
	document.PlatformApplications.ArtifactPath, document.PlatformApplications.Ledger, document.PlatformApplications.GitOps = path("input/platform-applications.yaml"), ledger, gitOps
	document.PlatformObservation.Ledger, document.PlatformObservation.Argo = ledger, gitOps
	document.PlatformObservation.Capability.IndependentEvidenceIdentityPath = fullRunExecutionHandoffRoot + "/observability-evidence-identity.json"
	document.PlatformObservation.Capability.IndependentEvidenceIdentityReceiptPath = fullRunExecutionHandoffRoot + "/observability-evidence-identity-receipt.json"
	document.PlatformObservation.Capability.IndependentEvidencePath = fullRunExecutionHandoffRoot + "/observability-evidence.json"
	document.AggregateEvidence.Ledger, document.AggregateEvidence.Management, document.AggregateEvidence.Argo = ledger, management, gitOps
	document.AggregateEvidence.WorkloadTokenFile, document.AggregateEvidence.WorkloadKubeconfigFile, document.AggregateEvidence.WorkloadCAFile = "", workload.KubeconfigFile, workload.CAFile
	document.ObservabilityCollector.RuntimeAuthorityPath = path("input/collector-runtime-authority.yaml")
	document.ObservabilityCollector.JobTemplatePath = path("input/collector-job.yaml")
	document.ObservabilityCollector.WebhookTokenPath = path("credentials/collector-webhook-token")
	document.ObservabilityCollector.QueryTokenPath = path("credentials/collector-query-token")
	document.ObservabilityCollector.TLSCertificatePath = path("credentials/collector-tls.crt")
	document.ObservabilityCollector.TLSPrivateKeyPath = path("credentials/collector-tls.key")
	document.ReceiptDirectory = path("work/receipts")
	manifestRaw, err := json.Marshal(document)
	if err != nil {
		return nil, "", errors.New("encode rewritten full-run manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, "", errors.New("decode rewritten full-run manifest identity")
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return nil, "", errors.New("canonicalize rewritten full-run manifest")
	}
	files[fullRunExecutionManifestPath] = manifestRaw
	if len(files) != len(fullRunExecutionBundleFiles) {
		return nil, "", errors.New("rewritten full-run execution file set differs")
	}
	return files, digest.SHA256(canonical), nil
}

func canonicalFullRunExecutionBundleIndex(index fullRunExecutionBundleIndex) ([]byte, string, error) {
	if index.Format != FullRunExecutionBundleFormat || !stageReceiptPrefixDigestPattern.MatchString(index.SourceManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(index.ManifestDigest) || len(index.Files) != len(fullRunExecutionBundleFiles) ||
		len(index.Files) > maximumFullRunExecutionBundleFiles {
		return nil, "", errors.New("full-run execution bundle index is invalid")
	}
	want := append([]string(nil), fullRunExecutionBundleFiles...)
	sort.Strings(want)
	for i, file := range index.Files {
		if file.Path != want[i] || !stageReceiptPrefixDigestPattern.MatchString(file.Digest) {
			return nil, "", errors.New("full-run execution bundle index file set differs")
		}
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return nil, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return nil, "", err
	}
	return canonical, digest.SHA256(canonical), nil
}
