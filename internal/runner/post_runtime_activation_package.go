package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	PostRuntimeExecutionActivationPackageFormat = "ok147-post-runtime-execution-activation-package/v1"
	postRuntimeExecutionWorkspaceRoot           = "/var/run/openkubes/workspace"
	maximumPostRuntimeExecutionSecretBytes      = 950 * 1024
)

var postRuntimeReceiptBundlePaths = []string{
	"input/01-provider-prerequisites.json",
	"input/02-cluster-lifecycle.json",
	"input/03-lifecycle-observation.json",
	"input/04-enablement.json",
	"input/05-network-observation.json",
	"input/06-runtime-binding.json",
	"input/07-target-access.json",
}

type PostRuntimeExecutionActivationPackageConfig struct {
	ManifestPath         string
	ActivationSecret     string
	JobTemplate          []byte
	JobTemplateDigest    string
	RunID                string
	ImageDigest          string
	ManagementAPICIDR    string
	WorkloadAPICIDR      string
	ArgoAPICIDR          string
	AuthorizationAPICIDR string
}

type PostRuntimeExecutionActivationPackageReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	PackageDigest        string   `json:"packageDigest"`
	ActivationSecret     string   `json:"activationSecret"`
	SecretObjectDigest   string   `json:"secretObjectDigest"`
	BundleDigest         string   `json:"bundleDigest"`
	SourceManifestDigest string   `json:"sourceManifestDigest"`
	ManifestDigest       string   `json:"manifestDigest"`
	JobTemplateDigest    string   `json:"jobTemplateDigest"`
	JobEnvelopeDigest    string   `json:"jobEnvelopeDigest"`
	ManagementAuthority  string   `json:"managementAuthority"`
	PlanDigest           string   `json:"planDigest"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	RecoveryMode         string   `json:"recoveryMode,omitempty"`
	PrivateFileCount     int      `json:"privateFileCount"`
	ObjectKinds          []string `json:"objectKinds"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

type VerifiedPostRuntimeExecutionActivationPackage struct {
	raw                 []byte
	receipt             PostRuntimeExecutionActivationPackageReceipt
	managementAuthority string
	verified            bool
}

type postRuntimeActivationSecret struct {
	APIVersion string                              `json:"apiVersion"`
	Kind       string                              `json:"kind"`
	Metadata   postRuntimeActivationSecretMetadata `json:"metadata"`
	Immutable  bool                                `json:"immutable"`
	Type       string                              `json:"type"`
	Data       map[string]string                   `json:"data"`
}

type postRuntimeActivationSecretMetadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// BuildPostRuntimeExecutionActivationPackage converts one already verified
// local activation graph into a private immutable Secret plus the bounded Job
// envelope. It performs local reads only and does not contact Kubernetes.
func BuildPostRuntimeExecutionActivationPackage(config PostRuntimeExecutionActivationPackageConfig) (VerifiedPostRuntimeExecutionActivationPackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) || digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("post-runtime activation Job template differs from expected identity")
	}
	if !submissionStageInputNamePattern.MatchString(config.ActivationSecret) || len(config.ActivationSecret) > 63 || !strings.HasPrefix(config.ActivationSecret, "ok147-") {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("post-runtime activation Secret name is invalid")
	}
	executor, sourceReceipt, err := OpenPostRuntimeExecutionManifest(config.ManifestPath)
	if err != nil || executor == nil || sourceReceipt.State != "VERIFIED" || sourceReceipt.MutationAllowed {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("verify source post-runtime activation manifest")
	}
	document, _, err := loadPostRuntimeExecutionManifest(config.ManifestPath)
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("reload source post-runtime activation manifest")
	}
	workloadBinding, err := loadWorkloadAuthorityBinding(document.TargetCredential.Workload.Path, document.TargetCredential.Workload.ExpectedBindingDigest)
	if err != nil || workloadBinding.IntentRevision != executor.runtime.material.IntentRevision ||
		workloadBinding.TargetClusterUID != executor.runtime.material.Target.CAPIClusterUID ||
		workloadBinding.Endpoint != executor.runtime.material.Target.WorkloadAPIEndpoint ||
		workloadBinding.CABundleDigest != executor.runtime.material.Target.WorkloadAPICADigest {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("post-runtime activation workload source differs from runtime binding")
	}
	sources, err := collectPostRuntimeActivationSources(document)
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, err
	}
	files, manifestDigest, err := rewritePostRuntimeActivation(document, sources)
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, err
	}
	bundleFormat, recoveryMode, err := postRuntimeExecutionBundleIdentity(document)
	if err != nil || (sourceReceipt.RecoveryMode != "none" && sourceReceipt.RecoveryMode != recoveryMode) {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("post-runtime activation recovery identity differs")
	}
	bundleFiles, err := postRuntimeExecutionBundleFilesFor(bundleFormat, recoveryMode)
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, err
	}
	index := postRuntimeExecutionBundleIndex{Format: bundleFormat, ManifestDigest: manifestDigest, RecoveryMode: recoveryMode}
	for _, path := range bundleFiles {
		raw, ok := files[path]
		if !ok || len(raw) == 0 {
			return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("post-runtime activation file set is incomplete")
		}
		index.Files = append(index.Files, postRuntimeExecutionBundleIndexFile{Path: path, Digest: digest.SHA256(raw)})
	}
	if err := validatePostRuntimeExecutionBundleFiles(index.Files, bundleFiles); err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, err
	}
	bundleDigest, err := canonicalPostRuntimeExecutionBundleIndexDigest(index)
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("canonicalize post-runtime activation bundle")
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("encode post-runtime activation bundle index")
	}
	binaryData := map[string]string{postRuntimeExecutionBundleIndexName: base64.StdEncoding.EncodeToString(indexRaw)}
	for _, path := range bundleFiles {
		binaryData[strings.ReplaceAll(path, "/", ".")] = base64.StdEncoding.EncodeToString(files[path])
	}
	secret := postRuntimeActivationSecret{
		APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque", Data: binaryData,
		Metadata: postRuntimeActivationSecretMetadata{
			Name: config.ActivationSecret, Namespace: submissionStageInputNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/stage-id": "post-runtime",
			},
			Annotations: map[string]string{
				"openkubes.io/bundle-digest": bundleDigest, "openkubes.io/manifest-digest": manifestDigest,
			},
		},
	}
	secretRaw, err := json.Marshal(secret)
	if err != nil || len(secretRaw) > maximumPostRuntimeExecutionSecretBytes {
		return VerifiedPostRuntimeExecutionActivationPackage{}, errors.New("post-runtime activation Secret exceeds bounded object size")
	}
	jobRaw, err := RenderPostRuntimeExecutionJobTemplate(config.JobTemplate, PostRuntimeExecutionJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest, ActivationSecret: config.ActivationSecret,
		BundleDigest: bundleDigest, ManifestDigest: manifestDigest,
		ManagementAPIURL: document.TargetCredential.Ledger.Endpoint, ManagementAPICIDR: config.ManagementAPICIDR,
		WorkloadAPIURL: executor.runtime.material.Target.WorkloadAPIEndpoint, WorkloadAPICIDR: config.WorkloadAPICIDR,
		ArgoAPIURL: document.TargetRegistration.GitOps.Endpoint, ArgoAPICIDR: config.ArgoAPICIDR,
		AuthorizationAPIURL: document.Authorization.Endpoint, AuthorizationAPICIDR: config.AuthorizationAPICIDR,
		RecoveryMode: recoveryMode,
	})
	if err != nil {
		return VerifiedPostRuntimeExecutionActivationPackage{}, err
	}
	packageRaw := make([]byte, 0, len(secretRaw)+len(jobRaw)+6)
	packageRaw = append(packageRaw, secretRaw...)
	packageRaw = append(packageRaw, '\n', '-', '-', '-', '\n')
	packageRaw = append(packageRaw, jobRaw...)
	receipt := PostRuntimeExecutionActivationPackageReceipt{
		Format: PostRuntimeExecutionActivationPackageFormat, State: "VERIFIED", PackageDigest: digest.SHA256(packageRaw),
		ActivationSecret: config.ActivationSecret, SecretObjectDigest: digest.SHA256(secretRaw), BundleDigest: bundleDigest,
		SourceManifestDigest: sourceReceipt.ManifestDigest,
		ManifestDigest:       manifestDigest, JobTemplateDigest: config.JobTemplateDigest, JobEnvelopeDigest: digest.SHA256(jobRaw),
		ManagementAuthority: document.Plan.Expected.ManagementAuthority, PlanDigest: sourceReceipt.PlanDigest,
		TargetIdentityDigest: sourceReceipt.TargetIdentityDigest,
		RecoveryMode:         recoveryMode, PrivateFileCount: len(bundleFiles), ObjectKinds: []string{"Secret", "NetworkPolicy", "Job"}, MutationAllowed: false,
	}
	return VerifiedPostRuntimeExecutionActivationPackage{
		raw: packageRaw, receipt: receipt, managementAuthority: document.Plan.Expected.ManagementAuthority, verified: true,
	}, nil
}

// PrivateBytes returns the credential-bearing installation package. Callers
// must never write these bytes to a public receipt or Git history.
func (packaged VerifiedPostRuntimeExecutionActivationPackage) PrivateBytes() ([]byte, error) {
	if err := verifyPostRuntimeExecutionActivationPackage(packaged); err != nil {
		return nil, errors.New("post-runtime activation package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedPostRuntimeExecutionActivationPackage) Receipt() (PostRuntimeExecutionActivationPackageReceipt, error) {
	if err := verifyPostRuntimeExecutionActivationPackage(packaged); err != nil {
		return PostRuntimeExecutionActivationPackageReceipt{}, errors.New("post-runtime activation package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyPostRuntimeExecutionActivationPackage(packaged VerifiedPostRuntimeExecutionActivationPackage) error {
	if !packaged.verified || packaged.receipt.Format != PostRuntimeExecutionActivationPackageFormat || packaged.receipt.State != "VERIFIED" ||
		packaged.receipt.MutationAllowed || len(packaged.raw) == 0 || digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest ||
		!stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.BundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.ManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.SourceManifestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.SecretObjectDigest) || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.JobEnvelopeDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.PlanDigest) || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.TargetIdentityDigest) ||
		packaged.receipt.ManagementAuthority == "" || packaged.receipt.ManagementAuthority != packaged.managementAuthority {
		return errors.New("post-runtime activation package identity is incomplete")
	}
	bundleFormat := PostRuntimeExecutionBundleFormat
	if packaged.receipt.RecoveryMode != "" {
		bundleFormat = PostRuntimeExecutionRecoveryBundleFormat
	}
	expectedFiles, err := postRuntimeExecutionBundleFilesFor(bundleFormat, packaged.receipt.RecoveryMode)
	if err != nil || packaged.receipt.PrivateFileCount != len(expectedFiles) {
		return errors.New("post-runtime activation package file identity is incomplete")
	}
	parts := bytes.SplitN(packaged.raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || digest.SHA256(parts[0]) != packaged.receipt.SecretObjectDigest || digest.SHA256(parts[1]) != packaged.receipt.JobEnvelopeDigest {
		return errors.New("post-runtime activation package components changed")
	}
	return nil
}

func collectPostRuntimeActivationSources(document postRuntimeExecutionManifestDocument) (map[string][]byte, error) {
	if document.TargetCredential.Ledger != document.TargetRegistration.Ledger || document.TargetCredential.Ledger != document.PlatformApplications.Ledger ||
		document.TargetCredential.Ledger != document.PlatformObservation.Ledger || document.TargetCredential.Ledger != document.AggregateEvidence.Ledger {
		return nil, errors.New("post-runtime activation ledger sources differ")
	}
	if document.TargetRegistration.GitOps != document.PlatformApplications.GitOps || document.TargetRegistration.GitOps != document.PlatformObservation.Argo ||
		document.TargetRegistration.GitOps != document.AggregateEvidence.Argo {
		return nil, errors.New("post-runtime activation GitOps sources differ")
	}
	if document.AggregateEvidence.Management.Endpoint != document.TargetCredential.Ledger.Endpoint {
		return nil, errors.New("post-runtime activation management and ledger endpoints differ")
	}
	receipts, err := LoadStageReceiptPrefix(document.Plan.ReceiptPrefixPath, document.Plan.ReceiptPrefixDigest)
	if err != nil || len(receipts) != len(postRuntimeReceiptBundlePaths) {
		return nil, errors.New("post-runtime activation requires the exact seven-receipt prefix")
	}
	paths := map[string]string{
		"input/staged-plan.json":              document.Plan.Path,
		"input/target-credential-grant.json":  document.TargetCredential.GrantPath,
		"input/stage-authority.pub":           document.TargetCredential.GrantPublicKeyPath,
		"input/target-credential-policy.json": document.TargetCredential.PolicyPath,
		"input/target-access.yaml":            document.TargetCredential.TargetAccessArtifactPath,
		"input/workload-authority.json":       document.TargetCredential.Workload.Path,
		"credentials/ledger-token":            document.TargetCredential.Ledger.TokenFile,
		"credentials/ledger-ca.crt":           document.TargetCredential.Ledger.CAFile,
		"credentials/workload-token":          document.TargetCredential.Workload.TokenFile,
		"credentials/workload-ca.crt":         document.TargetCredential.Workload.CAFile,
		"credentials/authorization-token":     document.Authorization.TokenFile,
		"credentials/authorization-ca.crt":    document.Authorization.CAFile,
		"input/authorization-authority.pub":   document.Authorization.PublicKeyPath,
		"input/target-registration.yaml":      document.TargetRegistration.ArtifactPath,
		"credentials/gitops-token":            document.TargetRegistration.GitOps.TokenFile,
		"credentials/gitops-ca.crt":           document.TargetRegistration.GitOps.CAFile,
		"input/platform-applications.yaml":    document.PlatformApplications.ArtifactPath,
		"input/network-profile.json":          document.Profiles.Network.Path,
		"input/platform-profile.json":         document.Profiles.Platform.Path,
		"input/aggregate-profile.json":        document.Profiles.Aggregate.Path,
		"input/runtime-binding.json":          document.RuntimeBinding.MaterialPath,
		"input/runtime-binding-receipt.json":  document.RuntimeBinding.ReceiptPath,
		"input/platform-capability.json":      document.PlatformObservation.CapabilityPath,
		"credentials/management-token":        document.AggregateEvidence.Management.TokenFile,
		"credentials/management-ca.crt":       document.AggregateEvidence.Management.CAFile,
	}
	for index, receipt := range receipts {
		paths[postRuntimeReceiptBundlePaths[index]] = receipt.Path
	}
	if document.Recovery != nil {
		paths[postRuntimeExecutionRecoveryReceiptFiles[0]] = document.Recovery.TargetCredential.Path
		if document.Recovery.TargetRegistration != nil {
			paths[postRuntimeExecutionRecoveryReceiptFiles[1]] = document.Recovery.TargetRegistration.Path
		}
	}
	result := make(map[string][]byte, len(paths))
	total := 0
	for relative, source := range paths {
		raw, err := readBoundedRegular(source, maximumPostRuntimeExecutionBundleBytes)
		if err != nil {
			return nil, fmt.Errorf("read post-runtime activation source %s", filepath.Base(relative))
		}
		total += len(raw)
		if total > maximumPostRuntimeExecutionBundleBytes {
			return nil, errors.New("post-runtime activation sources exceed size limit")
		}
		result[relative] = raw
	}
	aggregateWorkloadToken, err := readBoundedRegular(document.AggregateEvidence.WorkloadTokenFile, maximumTokenBytes)
	if err != nil || !bytes.Equal(aggregateWorkloadToken, result["credentials/workload-token"]) {
		return nil, errors.New("post-runtime aggregate workload token differs from bound source")
	}
	aggregateWorkloadCA, err := readBoundedRegular(document.AggregateEvidence.WorkloadCAFile, maximumCABytes)
	if err != nil || !bytes.Equal(aggregateWorkloadCA, result["credentials/workload-ca.crt"]) {
		return nil, errors.New("post-runtime aggregate workload CA differs from bound source")
	}
	if _, _, err := loadWorkloadAuthorityFiles(WorkloadAuthorityFileResolverConfig{
		Path: document.TargetCredential.Workload.Path, ExpectedBindingDigest: document.TargetCredential.Workload.ExpectedBindingDigest,
		TokenFile: document.TargetCredential.Workload.TokenFile, CAFile: document.TargetCredential.Workload.CAFile,
	}); err != nil {
		return nil, errors.New("verify post-runtime activation workload authority")
	}
	for authority, bound := range map[string]struct {
		paths  [2]string
		digest string
	}{
		"gitops": {
			paths:  [2]string{document.TargetRegistration.GitOps.TokenFile, document.TargetRegistration.GitOps.CAFile},
			digest: document.TargetRegistration.GitOps.CABundleDigest,
		},
		"management": {
			paths:  [2]string{document.AggregateEvidence.Management.TokenFile, document.AggregateEvidence.Management.CAFile},
			digest: document.AggregateEvidence.Management.CABundleDigest,
		},
	} {
		token := result["credentials/"+authority+"-token"]
		ca := result["credentials/"+authority+"-ca.crt"]
		openedToken, _, openErr := openBoundedKubernetesHTTP(bound.paths[0], bound.paths[1])
		if len(token) == 0 || len(ca) == 0 || bound.paths[0] == "" || bound.paths[1] == "" || openErr != nil ||
			openedToken != string(token) || digest.SHA256(ca) != bound.digest {
			return nil, errors.New("post-runtime activation authority credential is incomplete")
		}
	}
	return result, nil
}

func rewritePostRuntimeActivation(document postRuntimeExecutionManifestDocument, sources map[string][]byte) (map[string][]byte, string, error) {
	files := make(map[string][]byte, len(sources)+2)
	for path, raw := range sources {
		files[path] = append([]byte(nil), raw...)
	}
	prefix := stageReceiptPrefixDocument{Format: StageReceiptPrefixFormat}
	for _, path := range postRuntimeReceiptBundlePaths {
		prefix.Receipts = append(prefix.Receipts, stageReceiptPrefixEntry{File: filepath.Base(path), Digest: digest.SHA256(files[path])})
	}
	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return nil, "", errors.New("encode rewritten post-runtime receipt prefix")
	}
	files["input/receipt-prefix.json"] = prefixRaw
	path := func(relative string) string { return filepath.Join(postRuntimeExecutionWorkspaceRoot, relative) }
	ledger := postRuntimeLedgerDocument{Endpoint: document.TargetCredential.Ledger.Endpoint, Namespace: document.TargetCredential.Ledger.Namespace, TokenFile: path("credentials/ledger-token"), CAFile: path("credentials/ledger-ca.crt")}
	gitOps := document.TargetRegistration.GitOps
	gitOps.TokenFile, gitOps.CAFile = path("credentials/gitops-token"), path("credentials/gitops-ca.crt")
	management := document.AggregateEvidence.Management
	management.TokenFile, management.CAFile = path("credentials/management-token"), path("credentials/management-ca.crt")
	document.Plan.Path, document.Plan.ReceiptPrefixPath, document.Plan.ReceiptPrefixDigest = path("input/staged-plan.json"), path("input/receipt-prefix.json"), digest.SHA256(prefixRaw)
	document.TargetCredential.GrantPath, document.TargetCredential.GrantPublicKeyPath = path("input/target-credential-grant.json"), path("input/stage-authority.pub")
	document.TargetCredential.PolicyPath, document.TargetCredential.TargetAccessArtifactPath = path("input/target-credential-policy.json"), path("input/target-access.yaml")
	document.TargetCredential.Ledger = ledger
	document.TargetCredential.Workload.Path, document.TargetCredential.Workload.TokenFile, document.TargetCredential.Workload.CAFile = path("input/workload-authority.json"), path("credentials/workload-token"), path("credentials/workload-ca.crt")
	document.Authorization.TokenFile, document.Authorization.CAFile, document.Authorization.PublicKeyPath = path("credentials/authorization-token"), path("credentials/authorization-ca.crt"), path("input/authorization-authority.pub")
	document.Authorization.OutputDirectory = path("work/authorizations")
	document.TargetRegistration.ArtifactPath, document.TargetRegistration.Ledger, document.TargetRegistration.GitOps = path("input/target-registration.yaml"), ledger, gitOps
	document.PlatformApplications.ArtifactPath, document.PlatformApplications.Ledger, document.PlatformApplications.GitOps = path("input/platform-applications.yaml"), ledger, gitOps
	document.Profiles.Network.Path, document.Profiles.Platform.Path, document.Profiles.Aggregate.Path = path("input/network-profile.json"), path("input/platform-profile.json"), path("input/aggregate-profile.json")
	document.RuntimeBinding.MaterialPath, document.RuntimeBinding.ReceiptPath = path("input/runtime-binding.json"), path("input/runtime-binding-receipt.json")
	document.PlatformObservation.Ledger, document.PlatformObservation.Argo, document.PlatformObservation.CapabilityPath = ledger, gitOps, path("input/platform-capability.json")
	document.AggregateEvidence.Ledger, document.AggregateEvidence.Management, document.AggregateEvidence.Argo = ledger, management, gitOps
	document.AggregateEvidence.WorkloadTokenFile, document.AggregateEvidence.WorkloadCAFile = path("credentials/workload-token"), path("credentials/workload-ca.crt")
	document.AggregateEvidence.CapabilityPath = path("input/platform-capability.json")
	if document.Recovery != nil {
		document.Recovery.TargetCredential.Path = path(postRuntimeExecutionRecoveryReceiptFiles[0])
		document.Recovery.TargetCredential.Digest = digest.SHA256(files[postRuntimeExecutionRecoveryReceiptFiles[0]])
		if document.Recovery.TargetRegistration != nil {
			document.Recovery.TargetRegistration.Path = path(postRuntimeExecutionRecoveryReceiptFiles[1])
			document.Recovery.TargetRegistration.Digest = digest.SHA256(files[postRuntimeExecutionRecoveryReceiptFiles[1]])
		}
	}
	document.ReceiptDirectory = path("work/receipts")
	manifestRaw, err := json.Marshal(document)
	if err != nil {
		return nil, "", errors.New("encode rewritten post-runtime manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, "", errors.New("decode rewritten post-runtime manifest identity")
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return nil, "", errors.New("canonicalize rewritten post-runtime manifest")
	}
	manifestDigest := digest.SHA256(canonical)
	files[postRuntimeExecutionManifestRelativePath] = manifestRaw
	expectedCount := len(postRuntimeExecutionBundleFiles)
	if document.Recovery != nil {
		expectedCount++
		if document.Recovery.TargetRegistration != nil {
			expectedCount++
		}
	}
	if len(files) != expectedCount {
		return nil, "", errors.New("rewritten post-runtime activation file set differs")
	}
	return files, manifestDigest, nil
}
