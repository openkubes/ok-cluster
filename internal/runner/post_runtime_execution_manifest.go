package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	PostRuntimeExecutionManifestFormat          = "ok147-post-runtime-execution-manifest/v1"
	PostRuntimeExecutionRecoveryManifestFormat  = "ok147-post-runtime-execution-manifest/v2"
	PostRuntimeExecutionManifestReceiptFormat   = "ok147-post-runtime-execution-manifest-receipt/v1"
	PostRuntimeExecutionManifestReceiptFormatV2 = "ok147-post-runtime-execution-manifest-receipt/v2"
	maximumPostRuntimeExecutionManifestBytes    = 512 * 1024
)

type postRuntimePlanExpectedDocument struct {
	ContractIdentity        contract.Identity `json:"contractIdentity"`
	IntentRevision          string            `json:"intentRevision"`
	EnablementRevision      string            `json:"enablementRevision"`
	PlatformRevision        string            `json:"platformRevision"`
	ExecutionFixture        string            `json:"executionFixture"`
	ExecutionAttemptDigest  string            `json:"executionAttemptDigest,omitempty"`
	InfrastructureAuthority string            `json:"infrastructureAuthority"`
	ManagementAuthority     string            `json:"managementAuthority"`
	GitOpsAuthority         string            `json:"gitOpsAuthority"`
	NetworkObservationMode  string            `json:"networkObservationMode,omitempty"`
}

type postRuntimePlanDocument struct {
	Path                string                          `json:"path"`
	Expected            postRuntimePlanExpectedDocument `json:"expected"`
	ReceiptPrefixPath   string                          `json:"receiptPrefixPath"`
	ReceiptPrefixDigest string                          `json:"receiptPrefixDigest"`
}

type postRuntimeLedgerDocument struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	TokenFile string `json:"tokenFile"`
	CAFile    string `json:"caFile"`
}

type postRuntimeAuthorityDocument struct {
	Endpoint          string `json:"endpoint"`
	AuthorityIdentity string `json:"authorityIdentity"`
	TokenFile         string `json:"tokenFile"`
	CAFile            string `json:"caFile"`
	CABundleDigest    string `json:"caBundleDigest"`
}

type postRuntimeWorkloadDocument struct {
	Path                  string `json:"path"`
	ExpectedBindingDigest string `json:"expectedBindingDigest"`
	TokenFile             string `json:"tokenFile"`
	CAFile                string `json:"caFile"`
}

type postRuntimeTargetCredentialDocument struct {
	GrantPath                   string                        `json:"grantPath"`
	GrantPublicKeyPath          string                        `json:"grantPublicKeyPath"`
	EvaluationTime              string                        `json:"evaluationTime"`
	PolicyPath                  string                        `json:"policyPath"`
	TargetAccessArtifactPath    string                        `json:"targetAccessArtifactPath"`
	TargetAccessExpectedObjects []projection.ResourceIdentity `json:"targetAccessExpectedObjects"`
	Ledger                      postRuntimeLedgerDocument     `json:"ledger"`
	Workload                    postRuntimeWorkloadDocument   `json:"workload"`
}

type postRuntimeAuthorizationDocument struct {
	Endpoint        string `json:"endpoint"`
	TokenFile       string `json:"tokenFile"`
	CAFile          string `json:"caFile"`
	PublicKeyPath   string `json:"publicKeyPath"`
	OutputDirectory string `json:"outputDirectory"`
}

type postRuntimeTargetRegistrationDocument struct {
	ArtifactPath        string                       `json:"artifactPath"`
	ArgoNamespace       string                       `json:"argoNamespace"`
	ProjectName         string                       `json:"projectName"`
	RegistrationName    string                       `json:"registrationName"`
	TargetName          string                       `json:"targetName"`
	SourceRepository    string                       `json:"sourceRepository"`
	TargetNamespaces    []string                     `json:"targetNamespaces"`
	Ledger              postRuntimeLedgerDocument    `json:"ledger"`
	GitOps              postRuntimeAuthorityDocument `json:"gitOps"`
	MaterializationTime string                       `json:"materializationTime"`
}

type postRuntimePlatformApplicationsDocument struct {
	ArtifactPath     string                       `json:"artifactPath"`
	ArgoNamespace    string                       `json:"argoNamespace"`
	ProjectName      string                       `json:"projectName"`
	RegistrationName string                       `json:"registrationName"`
	SourceRepository string                       `json:"sourceRepository"`
	Ledger           postRuntimeLedgerDocument    `json:"ledger"`
	GitOps           postRuntimeAuthorityDocument `json:"gitOps"`
}

type postRuntimeProfileReferenceDocument struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type postRuntimeProfilesDocument struct {
	Network   postRuntimeProfileReferenceDocument `json:"network"`
	Platform  postRuntimeProfileReferenceDocument `json:"platform"`
	Aggregate postRuntimeProfileReferenceDocument `json:"aggregate"`
}

type postRuntimeBindingDocument struct {
	MaterialPath string `json:"materialPath"`
	ReceiptPath  string `json:"receiptPath"`
}

type postRuntimeRecoveryReceiptDocument struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type postRuntimeRecoveryDocument struct {
	TargetCredential   *postRuntimeRecoveryReceiptDocument `json:"targetCredential,omitempty"`
	TargetRegistration *postRuntimeRecoveryReceiptDocument `json:"targetRegistration,omitempty"`
}

type postRuntimePlatformObservationDocument struct {
	Ledger                   postRuntimeLedgerDocument    `json:"ledger"`
	Argo                     postRuntimeAuthorityDocument `json:"argo"`
	CapabilityPath           string                       `json:"capabilityPath"`
	ExpectedCapabilityDigest string                       `json:"expectedCapabilityDigest"`
	PollInterval             string                       `json:"pollInterval"`
	PollTimeout              string                       `json:"pollTimeout"`
}

type postRuntimeAggregateEvidenceDocument struct {
	Ledger                   postRuntimeLedgerDocument    `json:"ledger"`
	Management               postRuntimeAuthorityDocument `json:"management"`
	Argo                     postRuntimeAuthorityDocument `json:"argo"`
	WorkloadTokenFile        string                       `json:"workloadTokenFile"`
	WorkloadCAFile           string                       `json:"workloadCAFile"`
	CapabilityPath           string                       `json:"capabilityPath"`
	ExpectedCapabilityDigest string                       `json:"expectedCapabilityDigest"`
}

type postRuntimeExecutionManifestDocument struct {
	Format               string                                  `json:"format"`
	Plan                 postRuntimePlanDocument                 `json:"plan"`
	TargetCredential     postRuntimeTargetCredentialDocument     `json:"targetCredential"`
	Authorization        postRuntimeAuthorizationDocument        `json:"authorization"`
	TargetRegistration   postRuntimeTargetRegistrationDocument   `json:"targetRegistration"`
	PlatformApplications postRuntimePlatformApplicationsDocument `json:"platformApplications"`
	Profiles             postRuntimeProfilesDocument             `json:"profiles"`
	RuntimeBinding       postRuntimeBindingDocument              `json:"runtimeBinding"`
	PlatformObservation  postRuntimePlatformObservationDocument  `json:"platformObservation"`
	AggregateEvidence    postRuntimeAggregateEvidenceDocument    `json:"aggregateEvidence"`
	Recovery             *postRuntimeRecoveryDocument            `json:"recovery,omitempty"`
	ReceiptDirectory     string                                  `json:"receiptDirectory"`
}

type PostRuntimeExecutionManifestReceipt struct {
	Format                 string `json:"format"`
	State                  string `json:"state"`
	ManifestDigest         string `json:"manifestDigest"`
	PlanDigest             string `json:"planDigest"`
	ExecutionAttemptDigest string `json:"executionAttemptDigest,omitempty"`
	InitialReceiptCount    int    `json:"initialReceiptCount"`
	TargetIdentityDigest   string `json:"targetIdentityDigest"`
	NetworkProfileDigest   string `json:"networkProfileDigest"`
	PlatformProfileDigest  string `json:"platformProfileDigest"`
	AggregateProfileDigest string `json:"aggregateProfileDigest"`
	AuthorizationMode      string `json:"authorizationMode"`
	RecoveryMode           string `json:"recoveryMode,omitempty"`
	MutationAllowed        bool   `json:"mutationAllowed"`
}

// OpenPostRuntimeExecutionManifest loads one private strict-JSON activation
// manifest and composes the existing Stage 8-12 executor. It performs bounded
// local reads and opens credential clients, but makes no network or ledger
// request and performs no mutation.
func OpenPostRuntimeExecutionManifest(path string) (*PostRuntimeExecution, PostRuntimeExecutionManifestReceipt, error) {
	return openPostRuntimeExecutionManifest(path, defaultPostRuntimeExecutionFactories())
}

func openPostRuntimeExecutionManifest(path string, factories postRuntimeExecutionFactories) (*PostRuntimeExecution, PostRuntimeExecutionManifestReceipt, error) {
	receipt := PostRuntimeExecutionManifestReceipt{Format: PostRuntimeExecutionManifestReceiptFormat, State: "STOPPED", MutationAllowed: false}
	document, manifestDigest, err := loadPostRuntimeExecutionManifest(path)
	if err != nil {
		return nil, receipt, err
	}
	receipt.ManifestDigest = manifestDigest
	expected := stageplan.Expected{
		ContractIdentity: document.Plan.Expected.ContractIdentity,
		IntentRevision:   document.Plan.Expected.IntentRevision, EnablementRevision: document.Plan.Expected.EnablementRevision,
		PlatformRevision: document.Plan.Expected.PlatformRevision, ExecutionFixture: document.Plan.Expected.ExecutionFixture,
		ExecutionAttemptDigest:  document.Plan.Expected.ExecutionAttemptDigest,
		InfrastructureAuthority: document.Plan.Expected.InfrastructureAuthority, ManagementAuthority: document.Plan.Expected.ManagementAuthority,
		GitOpsAuthority: document.Plan.Expected.GitOpsAuthority,
	}
	receipts, err := LoadStageReceiptPrefix(document.Plan.ReceiptPrefixPath, document.Plan.ReceiptPrefixDigest)
	if err != nil {
		return nil, receipt, errors.New("load post-runtime receipt prefix")
	}
	resume := StageResumeConfig{PlanPath: document.Plan.Path, PlanExpected: expected, Receipts: receipts}
	plan, cursor, prefix, err := loadStageResumeWithPrefix(resume)
	if err != nil {
		return nil, receipt, errors.New("verify post-runtime manifest plan")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-credential" || len(prefix) != 7 {
		return nil, receipt, errors.New("post-runtime manifest does not select the exact Stage-8 cursor")
	}
	receipt.PlanDigest, receipt.InitialReceiptCount = plan.PlanDigest, len(prefix)
	receipt.ExecutionAttemptDigest = plan.ExecutionAttempt
	if plan.Format == stageplan.BindingFormatV2 {
		receipt.Format = PostRuntimeExecutionManifestReceiptFormatV2
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return nil, receipt, errors.New("post-runtime manifest lacks durable target identity")
	}
	receipt.TargetIdentityDigest = lifecycle.TargetClusterUIDDigest

	loadedNetwork, err := LoadNetworkProfileFile(NetworkProfileFileConfig{
		Path: document.Profiles.Network.Path, ExpectedProfileDigest: document.Profiles.Network.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
	})
	if err != nil {
		return nil, receipt, errors.New("load post-runtime Network profile")
	}
	loadedPlatform, err := LoadPlatformProfileFile(PlatformProfileFileConfig{
		Path: document.Profiles.Platform.Path, ExpectedProfileDigest: document.Profiles.Platform.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedPlatformRevision: plan.PlatformRevision,
		ExpectedExecutionFixture: plan.ExecutionFixture,
	})
	if err != nil {
		return nil, receipt, errors.New("load post-runtime Platform profile")
	}
	loadedAggregate, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: document.Profiles.Aggregate.Path, ExpectedProfileDigest: document.Profiles.Aggregate.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
		ExpectedPlatformRevision: plan.PlatformRevision, ExpectedExecutionFixture: plan.ExecutionFixture,
	})
	if err != nil {
		return nil, receipt, errors.New("load post-runtime aggregate profile")
	}
	receipt.NetworkProfileDigest, receipt.PlatformProfileDigest, receipt.AggregateProfileDigest = loadedNetwork.Digest, loadedPlatform.Digest, loadedAggregate.Digest
	if err := bindPostRuntimeProfileInputs(plan, receipt); err != nil {
		return nil, receipt, err
	}

	evaluationTime, err := time.Parse(time.RFC3339, document.TargetCredential.EvaluationTime)
	if err != nil {
		return nil, receipt, errors.New("post-runtime target credential evaluation time is invalid")
	}
	materializationTime, err := time.Parse(time.RFC3339, document.TargetRegistration.MaterializationTime)
	if err != nil {
		return nil, receipt, errors.New("post-runtime registration materialization time is invalid")
	}
	pollInterval, pollTimeout, err := parsePostRuntimePolling(document.PlatformObservation.PollInterval, document.PlatformObservation.PollTimeout)
	if err != nil {
		return nil, receipt, err
	}
	clock := func() time.Time { return time.Now().UTC() }
	authorization, err := OpenStageAuthorizationHTTPResolver(StageAuthorizationHTTPResolverConfig{
		Endpoint: document.Authorization.Endpoint, TokenFile: document.Authorization.TokenFile, CAFile: document.Authorization.CAFile,
		PublicKeyPath: document.Authorization.PublicKeyPath, OutputDirectory: document.Authorization.OutputDirectory, Clock: clock,
	})
	if err != nil {
		return nil, receipt, errors.New("open post-runtime authorization resolver")
	}
	receipt.AuthorizationMode = "predecessor-bound-tls/v1"
	if document.Recovery == nil {
		receipt.RecoveryMode = "none"
	} else if document.Recovery.TargetRegistration == nil {
		receipt.RecoveryMode = "target-credential"
	} else {
		receipt.RecoveryMode = "target-registration"
	}

	targetRegistrationStage, _, err := plan.Stage("target-registration")
	if err != nil || len(targetRegistrationStage.Inputs) != 1 {
		return nil, receipt, errors.New("post-runtime target-registration input is invalid")
	}
	platformApplicationsStage, _, err := plan.Stage("platform-applications")
	if err != nil || len(platformApplicationsStage.Inputs) != 1 {
		return nil, receipt, errors.New("post-runtime platform-applications input is invalid")
	}
	if document.TargetRegistration.TargetName != plan.ContractIdentity.Name {
		return nil, receipt, errors.New("post-runtime target name differs from Contract identity")
	}
	runtimeBinding := RuntimeBindingMaterialFileConfig{Bundle: resume, MaterialPath: document.RuntimeBinding.MaterialPath, ReceiptPath: document.RuntimeBinding.ReceiptPath}
	verifiedRuntime, err := LoadRuntimeBindingMaterialFiles(runtimeBinding)
	if err != nil {
		return nil, receipt, errors.New("load post-runtime manifest runtime binding")
	}
	if digest.SHA256([]byte(verifiedRuntime.material.Target.CAPIClusterUID)) != lifecycle.TargetClusterUIDDigest {
		return nil, receipt, errors.New("post-runtime runtime target differs from lifecycle identity")
	}
	registrationExpected := submission.TargetRegistrationExpected{
		ArtifactDigest: targetRegistrationStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: lifecycle.TargetClusterUIDDigest, ArgoAuthority: plan.Authorities.GitOps,
		ArgoNamespace: document.TargetRegistration.ArgoNamespace, ProjectName: document.TargetRegistration.ProjectName,
		RegistrationName: document.TargetRegistration.RegistrationName, TargetName: document.TargetRegistration.TargetName,
		SourceRepository: document.TargetRegistration.SourceRepository, TargetNamespaces: append([]string(nil), document.TargetRegistration.TargetNamespaces...),
	}
	if _, err := submission.LoadTargetRegistration(document.TargetRegistration.ArtifactPath, registrationExpected); err != nil {
		return nil, receipt, errors.New("verify post-runtime target-registration artifact")
	}
	applicationsExpected := submission.PlatformApplicationsExpected{
		ArtifactDigest: platformApplicationsStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: lifecycle.TargetClusterUIDDigest, ArgoAuthority: plan.Authorities.GitOps,
		ArgoNamespace: document.PlatformApplications.ArgoNamespace, ProjectName: document.PlatformApplications.ProjectName,
		RegistrationName: document.PlatformApplications.RegistrationName, SourceRepository: document.PlatformApplications.SourceRepository,
		Profile: loadedPlatform.Profile,
	}
	if _, err := submission.LoadPlatformApplications(document.PlatformApplications.ArtifactPath, applicationsExpected); err != nil {
		return nil, receipt, errors.New("verify post-runtime platform Applications artifact")
	}
	if document.PlatformObservation.CapabilityPath != document.AggregateEvidence.CapabilityPath ||
		document.PlatformObservation.ExpectedCapabilityDigest != document.AggregateEvidence.ExpectedCapabilityDigest {
		return nil, receipt, errors.New("post-runtime stages must share one capability assertion")
	}
	if _, err := LoadPlatformCapabilityFile(PlatformCapabilityFileConfig{
		Path: document.PlatformObservation.CapabilityPath, ExpectedEvidenceDigest: document.PlatformObservation.ExpectedCapabilityDigest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedPlatformRevision: plan.PlatformRevision,
		ExpectedExecutionFixture: plan.ExecutionFixture, ExpectedTargetClusterUID: verifiedRuntime.material.Target.CAPIClusterUID,
		ExpectedContractDigest:   loadedPlatform.Profile.CapabilityContractDigest,
		ExpectedExecutableDigest: loadedPlatform.Profile.CapabilityExecutableDigest,
	}); err != nil {
		return nil, receipt, errors.New("verify post-runtime platform capability assertion")
	}

	config := PostRuntimeExecutionConfig{
		TargetCredential: TargetCredentialStageBundleConfig{
			PlanPath: document.Plan.Path, PlanExpected: expected, Receipts: receipts,
			GrantPath: document.TargetCredential.GrantPath, GrantPublicKeyPath: document.TargetCredential.GrantPublicKeyPath,
			EvaluationTime: evaluationTime, PolicyPath: document.TargetCredential.PolicyPath,
			TargetAccessArtifactPath:    document.TargetCredential.TargetAccessArtifactPath,
			TargetAccessExpectedObjects: append([]projection.ResourceIdentity(nil), document.TargetCredential.TargetAccessExpectedObjects...),
		},
		TargetCredentialRun: TargetCredentialStageRuntimeConfig{
			Ledger: ledgerConfig(document.TargetCredential.Ledger),
			Workload: WorkloadAuthorityFileResolverConfig{
				Path: document.TargetCredential.Workload.Path, ExpectedBindingDigest: document.TargetCredential.Workload.ExpectedBindingDigest,
				TokenFile: document.TargetCredential.Workload.TokenFile, CAFile: document.TargetCredential.Workload.CAFile,
			},
			Clock: clock,
		},
		Authorization: authorization,
		TargetRegistration: PostRuntimeTargetRegistrationConfig{
			ArtifactPath: document.TargetRegistration.ArtifactPath,
			Expected:     registrationExpected,
			Runtime: TargetRegistrationStageHandoffRuntimeConfig{
				Ledger: ledgerConfig(document.TargetRegistration.Ledger), GitOps: authorityConfig(document.TargetRegistration.GitOps),
				MaterializationTime: materializationTime, Clock: clock,
			},
		},
		PlatformApplications: PostRuntimePlatformApplicationsConfig{
			ArtifactPath: document.PlatformApplications.ArtifactPath,
			Expected:     applicationsExpected,
			Runtime: PlatformApplicationsStageRuntimeConfig{
				Ledger: ledgerConfig(document.PlatformApplications.Ledger), GitOps: authorityConfig(document.PlatformApplications.GitOps), Clock: clock,
			},
		},
		PlatformObservation: PostRuntimePlatformObservationConfig{
			Profile: loadedPlatform.Profile,
			Runtime: PlatformObservationStageFileRuntimeConfig{
				Ledger: ledgerConfig(document.PlatformObservation.Ledger), Argo: authorityConfig(document.PlatformObservation.Argo),
				CapabilityPath: document.PlatformObservation.CapabilityPath, ExpectedCapabilityDigest: document.PlatformObservation.ExpectedCapabilityDigest,
				PollInterval: pollInterval, PollTimeout: pollTimeout, Clock: clock, Wait: WaitWithTimer,
			},
		},
		AggregateEvidence: PostRuntimeAggregateEvidenceConfig{
			Profile: loadedAggregate.Profile,
			Runtime: AggregateEvidenceStageFileRuntimeConfig{
				NetworkProfile: loadedNetwork.Profile, PlatformProfile: loadedPlatform.Profile,
				Ledger: ledgerConfig(document.AggregateEvidence.Ledger), Management: authorityConfig(document.AggregateEvidence.Management),
				Argo: authorityConfig(document.AggregateEvidence.Argo), WorkloadTokenFile: document.AggregateEvidence.WorkloadTokenFile,
				WorkloadCAFile: document.AggregateEvidence.WorkloadCAFile, CapabilityPath: document.AggregateEvidence.CapabilityPath,
				ExpectedCapabilityDigest: document.AggregateEvidence.ExpectedCapabilityDigest, Clock: clock,
			},
		},
		RuntimeBinding: runtimeBinding, ReceiptDirectory: document.ReceiptDirectory,
	}
	if document.Recovery != nil {
		config.TargetCredentialRecovery = &PostRuntimeTargetCredentialRecoveryConfig{
			StageReceipt: recoveryStageReceiptSource(document.Recovery.TargetCredential), Authorization: authorization,
		}
		if document.Recovery.TargetRegistration != nil {
			config.TargetRegistrationRecovery = &PostRuntimeTargetRegistrationRecoveryConfig{
				StageReceipt: recoveryStageReceiptSource(document.Recovery.TargetRegistration), Authorization: authorization,
			}
		}
	}
	executor, err := openPostRuntimeExecution(config, factories)
	if err != nil {
		return nil, receipt, errors.New("open verified post-runtime execution")
	}
	receipt.State = "VERIFIED"
	return executor, receipt, nil
}

func loadPostRuntimeExecutionManifest(path string) (postRuntimeExecutionManifestDocument, string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("post-runtime execution manifest path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumPostRuntimeExecutionManifestBytes {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("post-runtime execution manifest metadata is invalid")
	}
	raw, err := readBoundedRegular(path, maximumPostRuntimeExecutionManifestBytes)
	if err != nil {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("read bounded post-runtime execution manifest")
	}
	return decodePostRuntimeExecutionManifest(raw)
}

func decodePostRuntimeExecutionManifest(raw []byte) (postRuntimeExecutionManifestDocument, string, error) {
	var document postRuntimeExecutionManifestDocument
	if err := jsonstrict.Decode(raw, &document); err != nil {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("decode strict post-runtime execution manifest")
	}
	if document.Format != PostRuntimeExecutionManifestFormat && document.Format != PostRuntimeExecutionRecoveryManifestFormat {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("post-runtime execution manifest format is not supported")
	}
	if err := validatePostRuntimeRecoveryDocument(document); err != nil {
		return postRuntimeExecutionManifestDocument{}, "", err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("encode post-runtime execution manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("decode post-runtime execution manifest identity")
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return postRuntimeExecutionManifestDocument{}, "", errors.New("canonicalize post-runtime execution manifest")
	}
	return document, digest.SHA256(canonical), nil
}

func validatePostRuntimeRecoveryDocument(document postRuntimeExecutionManifestDocument) error {
	if document.Recovery == nil {
		if document.Format != PostRuntimeExecutionManifestFormat {
			return errors.New("post-runtime recovery manifest requires recovery receipts")
		}
		return nil
	}
	if document.Format != PostRuntimeExecutionRecoveryManifestFormat || document.Recovery.TargetCredential == nil {
		return errors.New("post-runtime recovery manifest requires a target-credential receipt")
	}
	for _, source := range []*postRuntimeRecoveryReceiptDocument{document.Recovery.TargetCredential, document.Recovery.TargetRegistration} {
		if source == nil {
			continue
		}
		if source.Path == "" || !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path ||
			!stageReceiptPrefixDigestPattern.MatchString(source.Digest) {
			return errors.New("post-runtime recovery receipt source is invalid")
		}
	}
	return nil
}

func recoveryStageReceiptSource(document *postRuntimeRecoveryReceiptDocument) StageReceiptSource {
	if document == nil {
		return StageReceiptSource{}
	}
	return StageReceiptSource{Path: document.Path, Digest: document.Digest}
}

func bindPostRuntimeProfileInputs(plan stageplan.Binding, receipt PostRuntimeExecutionManifestReceipt) error {
	for stageID, expected := range map[string]struct{ name, digest string }{
		"network-observation":  {"stage.network-observation", receipt.NetworkProfileDigest},
		"platform-observation": {"stage.platform-observation", receipt.PlatformProfileDigest},
		"aggregate-evidence":   {"stage.aggregate-evidence", receipt.AggregateProfileDigest},
	} {
		stage, _, err := plan.Stage(stageID)
		if err != nil || len(stage.Inputs) != 1 || stage.Inputs[0].Name != expected.name || stage.Inputs[0].Digest != expected.digest {
			return errors.New("post-runtime profile differs from staged input")
		}
	}
	return nil
}

func parsePostRuntimePolling(intervalValue, timeoutValue string) (time.Duration, time.Duration, error) {
	interval, intervalErr := time.ParseDuration(intervalValue)
	timeout, timeoutErr := time.ParseDuration(timeoutValue)
	if intervalErr != nil || timeoutErr != nil || interval < time.Second || interval > 5*time.Minute || timeout < interval || timeout > 6*time.Hour {
		return 0, 0, errors.New("post-runtime polling bounds are invalid")
	}
	return interval, timeout, nil
}

func ledgerConfig(document postRuntimeLedgerDocument) KubernetesLedgerConfig {
	return KubernetesLedgerConfig{Endpoint: document.Endpoint, Namespace: document.Namespace, TokenFile: document.TokenFile, CAFile: document.CAFile}
}

func authorityConfig(document postRuntimeAuthorityDocument) KubernetesAuthorityConfig {
	return KubernetesAuthorityConfig{
		Endpoint: document.Endpoint, AuthorityIdentity: document.AuthorityIdentity,
		TokenFile: document.TokenFile, CAFile: document.CAFile, CABundleDigest: document.CABundleDigest,
	}
}
