package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	FullRunExecutionManifestFormat        = "ok147-full-run-execution-manifest/v1"
	FullRunExecutionManifestReceiptFormat = "ok147-full-run-execution-manifest-receipt/v1"
	maximumFullRunExecutionManifestBytes  = 1024 * 1024
)

type fullRunPlanDocument struct {
	Path     string                          `json:"path"`
	Expected postRuntimePlanExpectedDocument `json:"expected"`
}

type fullRunProjectionDocument struct {
	ManifestPath string `json:"manifestPath"`
	Root         string `json:"root"`
}

type fullRunSubmissionRuntimeDocument struct {
	Ledger    postRuntimeLedgerDocument    `json:"ledger"`
	Authority postRuntimeAuthorityDocument `json:"authority"`
}

type fullRunLifecycleObservationDocument struct {
	Ledger       postRuntimeLedgerDocument    `json:"ledger"`
	Management   postRuntimeAuthorityDocument `json:"management"`
	PollInterval string                       `json:"pollInterval"`
	PollTimeout  string                       `json:"pollTimeout"`
}

type fullRunEnablementDocument struct {
	ArtifactPath   string                           `json:"artifactPath"`
	ExpectedObject projection.ResourceIdentity      `json:"expectedObject"`
	Runtime        fullRunSubmissionRuntimeDocument `json:"runtime"`
}

type fullRunWorkloadRuntimeDocument struct {
	BindingPath    string `json:"bindingPath"`
	TokenFile      string `json:"tokenFile,omitempty"`
	KubeconfigFile string `json:"kubeconfigFile,omitempty"`
	CAFile         string `json:"caFile"`
}

type fullRunNetworkObservationDocument struct {
	Ledger       postRuntimeLedgerDocument      `json:"ledger"`
	Management   postRuntimeAuthorityDocument   `json:"management"`
	Workload     fullRunWorkloadRuntimeDocument `json:"workload"`
	PollInterval string                         `json:"pollInterval"`
	PollTimeout  string                         `json:"pollTimeout"`
}

type fullRunRuntimeBindingDocument struct {
	Ledger       postRuntimeLedgerDocument      `json:"ledger"`
	Workload     fullRunWorkloadRuntimeDocument `json:"workload"`
	MaterialPath string                         `json:"materialPath"`
	ReceiptPath  string                         `json:"receiptPath"`
}

type fullRunTargetAccessDocument struct {
	ArtifactPath    string                         `json:"artifactPath"`
	ExpectedObjects []projection.ResourceIdentity  `json:"expectedObjects"`
	Ledger          postRuntimeLedgerDocument      `json:"ledger"`
	Workload        fullRunWorkloadRuntimeDocument `json:"workload"`
}

type fullRunTargetCredentialDocument struct {
	PolicyPath string                         `json:"policyPath"`
	Ledger     postRuntimeLedgerDocument      `json:"ledger"`
	Workload   fullRunWorkloadRuntimeDocument `json:"workload"`
}

type fullRunTargetRegistrationDocument struct {
	ArtifactPath     string                       `json:"artifactPath"`
	ArgoNamespace    string                       `json:"argoNamespace"`
	ProjectName      string                       `json:"projectName"`
	RegistrationName string                       `json:"registrationName"`
	TargetName       string                       `json:"targetName"`
	SourceRepository string                       `json:"sourceRepository"`
	TargetNamespaces []string                     `json:"targetNamespaces"`
	Ledger           postRuntimeLedgerDocument    `json:"ledger"`
	GitOps           postRuntimeAuthorityDocument `json:"gitOps"`
}

type fullRunPlatformApplicationsDocument struct {
	ArtifactPath     string                       `json:"artifactPath"`
	ArgoNamespace    string                       `json:"argoNamespace"`
	ProjectName      string                       `json:"projectName"`
	RegistrationName string                       `json:"registrationName"`
	SourceRepository string                       `json:"sourceRepository"`
	Ledger           postRuntimeLedgerDocument    `json:"ledger"`
	GitOps           postRuntimeAuthorityDocument `json:"gitOps"`
}

type fullRunCapabilityDocument struct {
	Namespace                              string `json:"namespace"`
	Timeout                                string `json:"timeout"`
	CleanupTimeout                         string `json:"cleanupTimeout"`
	PollInterval                           string `json:"pollInterval"`
	PushgatewayImage                       string `json:"pushgatewayImage"`
	LogEmitterImage                        string `json:"logEmitterImage"`
	IndependentEvidenceIdentityPath        string `json:"independentEvidenceIdentityPath"`
	IndependentEvidenceIdentityReceiptPath string `json:"independentEvidenceIdentityReceiptPath"`
	IndependentEvidencePath                string `json:"independentEvidencePath"`
	IndependentEvidenceKeyID               string `json:"independentEvidenceKeyId"`
}

type fullRunPlatformObservationDocument struct {
	Ledger       postRuntimeLedgerDocument    `json:"ledger"`
	Argo         postRuntimeAuthorityDocument `json:"argo"`
	Capability   fullRunCapabilityDocument    `json:"capability"`
	PollInterval string                       `json:"pollInterval"`
	PollTimeout  string                       `json:"pollTimeout"`
}

type fullRunAggregateEvidenceDocument struct {
	Ledger                 postRuntimeLedgerDocument    `json:"ledger"`
	Management             postRuntimeAuthorityDocument `json:"management"`
	Argo                   postRuntimeAuthorityDocument `json:"argo"`
	WorkloadTokenFile      string                       `json:"workloadTokenFile"`
	WorkloadKubeconfigFile string                       `json:"workloadKubeconfigFile,omitempty"`
	WorkloadCAFile         string                       `json:"workloadCAFile"`
}

type fullRunExecutionManifestDocument struct {
	Format                string                              `json:"format"`
	Plan                  fullRunPlanDocument                 `json:"plan"`
	Projection            fullRunProjectionDocument           `json:"projection"`
	Authorization         postRuntimeAuthorizationDocument    `json:"authorization"`
	Profiles              postRuntimeProfilesDocument         `json:"profiles"`
	ProviderPrerequisites fullRunSubmissionRuntimeDocument    `json:"providerPrerequisites"`
	ClusterLifecycle      fullRunSubmissionRuntimeDocument    `json:"clusterLifecycle"`
	LifecycleObservation  fullRunLifecycleObservationDocument `json:"lifecycleObservation"`
	Enablement            fullRunEnablementDocument           `json:"enablement"`
	NetworkObservation    fullRunNetworkObservationDocument   `json:"networkObservation"`
	RuntimeBinding        fullRunRuntimeBindingDocument       `json:"runtimeBinding"`
	TargetAccess          fullRunTargetAccessDocument         `json:"targetAccess"`
	TargetCredential      fullRunTargetCredentialDocument     `json:"targetCredential"`
	TargetRegistration    fullRunTargetRegistrationDocument   `json:"targetRegistration"`
	PlatformApplications  fullRunPlatformApplicationsDocument `json:"platformApplications"`
	PlatformObservation   fullRunPlatformObservationDocument  `json:"platformObservation"`
	AggregateEvidence     fullRunAggregateEvidenceDocument    `json:"aggregateEvidence"`
	ReceiptDirectory      string                              `json:"receiptDirectory"`
}

type FullRunExecutionManifestReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	ManifestDigest            string `json:"manifestDigest"`
	PlanDigest                string `json:"planDigest"`
	ProjectionManifestDigest  string `json:"projectionManifestDigest"`
	ProjectionAuthorityDigest string `json:"projectionAuthorityDigest"`
	NetworkProfileDigest      string `json:"networkProfileDigest"`
	PlatformProfileDigest     string `json:"platformProfileDigest"`
	AggregateProfileDigest    string `json:"aggregateProfileDigest"`
	RuntimeIdentityMode       string `json:"runtimeIdentityMode"`
	AuthorizationMode         string `json:"authorizationMode"`
	CapabilityMode            string `json:"capabilityMode"`
	MutationAllowed           bool   `json:"mutationAllowed"`
}

type VerifiedFullRunExecutionManifest struct {
	document  fullRunExecutionManifestDocument
	receipt   FullRunExecutionManifestReceipt
	plan      stageplan.Binding
	network   observation.NetworkProfile
	platform  observation.PlatformProfile
	aggregate AggregateEvidenceProfile
	verified  bool
}

// FullRunPlatformCapabilityBinding is the complete serializable part of the
// first-run capability boundary. The factory receives no credential, endpoint,
// target UID, command or arbitrary payload.
type FullRunPlatformCapabilityBinding struct {
	Namespace                string
	Timeout                  time.Duration
	CleanupTimeout           time.Duration
	PollInterval             time.Duration
	PushgatewayImage         string
	LogEmitterImage          string
	IndependentEvidencePath  string
	IndependentEvidenceKeyID string
	IntentRevision           string
	PlatformRevision         string
	ExecutionFixture         string
	ContractDigest           string
	ExecutableDigest         string
}

// FullRunPlatformCapabilityFactory supplies the process-local fixed checks and
// transport adapter. It must return a lazy resolver; opening the factory must
// not execute the capability.
type FullRunPlatformCapabilityFactory interface {
	OpenFullRunPlatformCapability(FullRunPlatformCapabilityBinding) (PlatformCapabilityResolver, error)
}

type FullRunPlatformCapabilityFactoryFunc func(FullRunPlatformCapabilityBinding) (PlatformCapabilityResolver, error)

func (factory FullRunPlatformCapabilityFactoryFunc) OpenFullRunPlatformCapability(binding FullRunPlatformCapabilityBinding) (PlatformCapabilityResolver, error) {
	return factory(binding)
}

// FullRunExecutionManifestRuntime supplies the process-local dependencies
// that cannot be serialized in the private manifest. Capability construction
// is typed and runtime-bound; Clock and Wait make bounded polling testable.
type FullRunExecutionManifestRuntime struct {
	PlatformCapability  FullRunPlatformCapabilityFactory
	PostPrefixActivator FullRunPostPrefixActivator
	Clock               func() time.Time
	Wait                ObservationWaiter
}

// Receipt returns the already verified, redaction-safe manifest identity. The
// private activation document and its credential paths remain inaccessible.
func (manifest VerifiedFullRunExecutionManifest) Receipt() (FullRunExecutionManifestReceipt, error) {
	if !manifest.verified || manifest.receipt.State != "VERIFIED" {
		return FullRunExecutionManifestReceipt{}, errors.New("full-run execution manifest is not verified")
	}
	return manifest.receipt, nil
}

// ExecutionConfig converts one already verified private manifest into the
// concrete Stage 1-12 configuration. It performs bounded local credential
// reads while opening the authorization and lifecycle-authority adapters, but
// performs no API request, grant resolution, capability action or mutation.
func (manifest VerifiedFullRunExecutionManifest) ExecutionConfig(runtime FullRunExecutionManifestRuntime) (FullRunExecutionConfig, error) {
	if !manifest.verified || manifest.receipt.State != "VERIFIED" || runtime.PlatformCapability == nil || runtime.Clock == nil || runtime.Wait == nil {
		return FullRunExecutionConfig{}, errors.New("verified full-run manifest runtime is incomplete")
	}
	document, plan := manifest.document, manifest.plan
	expected := fullRunPlanExpected(document.Plan.Expected)
	if plan.PlanDigest != manifest.receipt.PlanDigest || plan.IntentRevision != expected.IntentRevision ||
		plan.EnablementRevision != expected.EnablementRevision || plan.PlatformRevision != expected.PlatformRevision ||
		plan.ExecutionFixture != expected.ExecutionFixture {
		return FullRunExecutionConfig{}, errors.New("verified full-run manifest plan changed after loading")
	}
	lifecycleInterval, lifecycleTimeout, err := parsePostRuntimePolling(document.LifecycleObservation.PollInterval, document.LifecycleObservation.PollTimeout)
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("parse full-run lifecycle polling")
	}
	networkInterval, networkTimeout, err := parsePostRuntimePolling(document.NetworkObservation.PollInterval, document.NetworkObservation.PollTimeout)
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("parse full-run network polling")
	}
	platformInterval, platformTimeout, err := parsePostRuntimePolling(document.PlatformObservation.PollInterval, document.PlatformObservation.PollTimeout)
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("parse full-run platform polling")
	}
	authorization, err := OpenStageAuthorizationHTTPResolver(StageAuthorizationHTTPResolverConfig{
		Endpoint: document.Authorization.Endpoint, TokenFile: document.Authorization.TokenFile, CAFile: document.Authorization.CAFile,
		PublicKeyPath: document.Authorization.PublicKeyPath, OutputDirectory: document.Authorization.OutputDirectory, Clock: runtime.Clock,
	})
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("open full-run authorization resolver")
	}
	workload := document.NetworkObservation.Workload
	if workload.KubeconfigFile == "" || workload.TokenFile != "" {
		return FullRunExecutionConfig{}, errors.New("full-run lifecycle workload authority requires a client-certificate kubeconfig destination")
	}
	materializer, err := OpenKubernetesLifecycleWorkloadAuthorityMaterializer(KubernetesLifecycleWorkloadAuthorityMaterializerConfig{
		Management: authorityConfig(document.LifecycleObservation.Management), ExpectedManagementAuthority: plan.Authorities.Management,
		BindingPath: workload.BindingPath, KubeconfigFile: workload.KubeconfigFile, CAFile: workload.CAFile,
	})
	if err != nil {
		return FullRunExecutionConfig{}, fmt.Errorf("open full-run lifecycle workload authority materializer: %w", err)
	}
	capabilityTimeout, err := time.ParseDuration(document.PlatformObservation.Capability.Timeout)
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("parse full-run capability timeout")
	}
	cleanupTimeout, err := time.ParseDuration(document.PlatformObservation.Capability.CleanupTimeout)
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("parse full-run capability cleanup timeout")
	}
	capabilityPollInterval, err := time.ParseDuration(document.PlatformObservation.Capability.PollInterval)
	if err != nil {
		return FullRunExecutionConfig{}, errors.New("parse full-run capability polling")
	}
	capabilityResolver, err := runtime.PlatformCapability.OpenFullRunPlatformCapability(FullRunPlatformCapabilityBinding{
		Namespace: document.PlatformObservation.Capability.Namespace, Timeout: capabilityTimeout, CleanupTimeout: cleanupTimeout,
		PollInterval: capabilityPollInterval, PushgatewayImage: document.PlatformObservation.Capability.PushgatewayImage,
		LogEmitterImage:          document.PlatformObservation.Capability.LogEmitterImage,
		IndependentEvidencePath:  document.PlatformObservation.Capability.IndependentEvidencePath,
		IndependentEvidenceKeyID: document.PlatformObservation.Capability.IndependentEvidenceKeyID,
		IntentRevision:           plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		ContractDigest: manifest.platform.CapabilityContractDigest, ExecutableDigest: manifest.platform.CapabilityExecutableDigest,
	})
	if err != nil || capabilityResolver == nil {
		return FullRunExecutionConfig{}, errors.New("open bound full-run Platform capability")
	}
	capability, err := newSharedPlatformCapabilityResolver(capabilityResolver)
	if err != nil {
		return FullRunExecutionConfig{}, err
	}
	ledger := ledgerConfig(document.ProviderPrerequisites.Ledger)
	workloadFiles := WorkloadAuthorityFileResolverConfig{
		Path: workload.BindingPath, KubeconfigFile: workload.KubeconfigFile, CAFile: workload.CAFile,
	}
	registrationExpected := submission.TargetRegistrationExpected{
		ArtifactDigest: fullRunStageInputDigest(plan, "target-registration"), ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		ArgoAuthority: plan.Authorities.GitOps, ArgoNamespace: document.TargetRegistration.ArgoNamespace,
		ProjectName: document.TargetRegistration.ProjectName, RegistrationName: document.TargetRegistration.RegistrationName,
		TargetName: document.TargetRegistration.TargetName, SourceRepository: document.TargetRegistration.SourceRepository,
		TargetNamespaces: append([]string(nil), document.TargetRegistration.TargetNamespaces...),
	}
	applicationsExpected := submission.PlatformApplicationsExpected{
		ArtifactDigest: fullRunStageInputDigest(plan, "platform-applications"), ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		ArgoAuthority: plan.Authorities.GitOps, ArgoNamespace: document.PlatformApplications.ArgoNamespace,
		ProjectName: document.PlatformApplications.ProjectName, RegistrationName: document.PlatformApplications.RegistrationName,
		SourceRepository: document.PlatformApplications.SourceRepository, Profile: clonePlatformProfile(manifest.platform),
	}
	config := FullRunExecutionConfig{
		PostPrefixActivator: runtime.PostPrefixActivator,
		EvidenceIdentityBinder: newFullRunObservabilityEvidenceIdentityBinder(
			manifest,
			document.PlatformObservation.Capability.IndependentEvidenceIdentityPath,
			document.PlatformObservation.Capability.IndependentEvidenceIdentityReceiptPath,
		),
		PreRuntime: PreRuntimeExecutionConfig{
			PlanPath: document.Plan.Path, PlanExpected: expected,
			ProjectionManifestPath: document.Projection.ManifestPath, ProjectionRoot: document.Projection.Root,
			Authorization:         authorization,
			ProviderPrerequisites: SubmissionStageRuntimeConfig{Ledger: ledger, Authority: authorityConfig(document.ProviderPrerequisites.Authority), Clock: runtime.Clock},
			ClusterLifecycle:      SubmissionStageRuntimeConfig{Ledger: ledger, Authority: authorityConfig(document.ClusterLifecycle.Authority), Clock: runtime.Clock},
			LifecycleObservation: LifecycleObservationStageRuntimeConfig{
				Ledger: ledger, Management: authorityConfig(document.LifecycleObservation.Management),
				PollInterval: lifecycleInterval, PollTimeout: lifecycleTimeout, Clock: runtime.Clock, Wait: runtime.Wait,
			},
			Enablement: PreRuntimeEnablementExecutionConfig{
				ArtifactPath: document.Enablement.ArtifactPath, ExpectedObject: document.Enablement.ExpectedObject,
				Runtime: SubmissionStageRuntimeConfig{Ledger: ledger, Authority: authorityConfig(document.Enablement.Runtime.Authority), Clock: runtime.Clock},
			},
			WorkloadAuthority: materializer,
			NetworkObservation: NetworkObservationStageRuntimeConfig{
				Ledger: ledger, Management: authorityConfig(document.NetworkObservation.Management), Workload: workloadFiles,
				NetworkProfilePath: document.Profiles.Network.Path, ExpectedNetworkProfileDigest: manifest.receipt.NetworkProfileDigest,
				PollInterval: networkInterval, PollTimeout: networkTimeout, Clock: runtime.Clock, Wait: runtime.Wait,
			},
			RuntimeBinding: RuntimeBindingStageRuntimeConfig{
				Ledger: ledger, Workload: workloadFiles, OutputPath: document.RuntimeBinding.MaterialPath, Clock: runtime.Clock,
			},
			RuntimeBindingReceiptPath: document.RuntimeBinding.ReceiptPath,
			TargetAccess: PreRuntimeTargetAccessExecutionConfig{
				ArtifactPath: document.TargetAccess.ArtifactPath, ExpectedObjects: append([]projection.ResourceIdentity(nil), document.TargetAccess.ExpectedObjects...),
				Runtime: TargetAccessStageRuntimeConfig{Ledger: ledger, Workload: workloadFiles, Clock: runtime.Clock},
			},
			ReceiptDirectory: document.ReceiptDirectory,
		},
		PostRuntime: PostRuntimeExecutionConfig{
			TargetCredential: TargetCredentialStageBundleConfig{
				PlanPath: document.Plan.Path, PlanExpected: expected, Receipts: []StageReceiptSource{}, PolicyPath: document.TargetCredential.PolicyPath,
				TargetAccessArtifactPath:    document.TargetAccess.ArtifactPath,
				TargetAccessExpectedObjects: append([]projection.ResourceIdentity(nil), document.TargetAccess.ExpectedObjects...),
			},
			TargetCredentialRun: TargetCredentialStageRuntimeConfig{Ledger: ledger, Workload: workloadFiles, Clock: runtime.Clock},
			Authorization:       authorization,
			TargetRegistration: PostRuntimeTargetRegistrationConfig{
				ArtifactPath: document.TargetRegistration.ArtifactPath, Expected: registrationExpected,
				Runtime: TargetRegistrationStageHandoffRuntimeConfig{Ledger: ledger, GitOps: authorityConfig(document.TargetRegistration.GitOps), Clock: runtime.Clock},
			},
			PlatformApplications: PostRuntimePlatformApplicationsConfig{
				ArtifactPath: document.PlatformApplications.ArtifactPath, Expected: applicationsExpected,
				Runtime: PlatformApplicationsStageRuntimeConfig{Ledger: ledger, GitOps: authorityConfig(document.PlatformApplications.GitOps), Clock: runtime.Clock},
			},
			PlatformObservation: PostRuntimePlatformObservationConfig{
				Profile: clonePlatformProfile(manifest.platform), Capability: capability,
				Runtime: PlatformObservationStageFileRuntimeConfig{
					Ledger: ledger, Argo: authorityConfig(document.PlatformObservation.Argo),
					RuntimeMaterialPath: document.RuntimeBinding.MaterialPath, RuntimeReceiptPath: document.RuntimeBinding.ReceiptPath,
					PollInterval: platformInterval, PollTimeout: platformTimeout, Clock: runtime.Clock, Wait: runtime.Wait,
				},
			},
			AggregateEvidence: PostRuntimeAggregateEvidenceConfig{
				Profile: cloneAggregateEvidenceProfile(manifest.aggregate), Capability: capability,
				Runtime: AggregateEvidenceStageFileRuntimeConfig{
					NetworkProfile: cloneNetworkProfile(manifest.network), PlatformProfile: clonePlatformProfile(manifest.platform),
					Ledger: ledger, Management: authorityConfig(document.AggregateEvidence.Management), Argo: authorityConfig(document.AggregateEvidence.Argo),
					WorkloadKubeconfigFile: workload.KubeconfigFile, WorkloadCAFile: workload.CAFile,
					RuntimeMaterialPath: document.RuntimeBinding.MaterialPath, RuntimeReceiptPath: document.RuntimeBinding.ReceiptPath, Clock: runtime.Clock,
				},
			},
			RuntimeBinding: RuntimeBindingMaterialFileConfig{
				Bundle:       StageResumeConfig{PlanPath: document.Plan.Path, PlanExpected: expected},
				MaterialPath: document.RuntimeBinding.MaterialPath, ReceiptPath: document.RuntimeBinding.ReceiptPath,
			},
			ReceiptDirectory: document.ReceiptDirectory,
		},
	}
	return config, nil
}

// Open composes the concrete single-use Stage 1-12 executor from this
// verified manifest. It remains a local open boundary; Run is the only method
// that may contact authorities or mutate authorized resources.
func (manifest VerifiedFullRunExecutionManifest) Open(runtime FullRunExecutionManifestRuntime) (*FullRunExecution, error) {
	config, err := manifest.ExecutionConfig(runtime)
	if err != nil {
		return nil, err
	}
	return OpenFullRunExecution(config)
}

// OpenFullRunExecutionManifest is the direct private manifest-to-executor
// activation seam. It performs only the same bounded local opening as Load,
// ExecutionConfig and Open; the returned executor remains inert until Run.
func OpenFullRunExecutionManifest(path string, runtime FullRunExecutionManifestRuntime) (*FullRunExecution, FullRunExecutionManifestReceipt, error) {
	manifest, receipt, err := LoadFullRunExecutionManifest(path)
	if err != nil {
		return nil, receipt, err
	}
	execution, err := manifest.Open(runtime)
	if err != nil {
		return nil, receipt, err
	}
	return execution, receipt, nil
}

// LoadFullRunExecutionManifest verifies the complete private first-run
// contract without opening a credential, resolving a grant, contacting an API
// or creating a file. Lifecycle-derived runtime identity and capability proof
// deliberately remain later in-memory handoffs.
func LoadFullRunExecutionManifest(path string) (VerifiedFullRunExecutionManifest, FullRunExecutionManifestReceipt, error) {
	receipt := FullRunExecutionManifestReceipt{
		Format: FullRunExecutionManifestReceiptFormat, State: "STOPPED", MutationAllowed: false,
	}
	document, manifestDigest, err := loadFullRunExecutionManifest(path)
	if err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, err
	}
	receipt.ManifestDigest = manifestDigest
	expected := stageplan.Expected{
		ContractIdentity: document.Plan.Expected.ContractIdentity,
		IntentRevision:   document.Plan.Expected.IntentRevision, EnablementRevision: document.Plan.Expected.EnablementRevision,
		PlatformRevision: document.Plan.Expected.PlatformRevision, ExecutionFixture: document.Plan.Expected.ExecutionFixture,
		InfrastructureAuthority: document.Plan.Expected.InfrastructureAuthority,
		ManagementAuthority:     document.Plan.Expected.ManagementAuthority, GitOpsAuthority: document.Plan.Expected.GitOpsAuthority,
	}
	plan, err := stageplan.Load(document.Plan.Path, expected)
	if err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, errors.New("load full-run staged plan")
	}
	decision, err := InspectStageResume(StageResumeConfig{PlanPath: document.Plan.Path, PlanExpected: expected, Receipts: []StageReceiptSource{}})
	if err != nil || decision.State != "NEXT" || decision.StageID != "provider-prerequisites" {
		return VerifiedFullRunExecutionManifest{}, receipt, errors.New("full-run manifest requires the exact empty Stage-1 cursor")
	}
	receipt.PlanDigest = plan.PlanDigest

	projected, err := projection.Verify(document.Projection.ManifestPath, document.Projection.Root, plan.IntentRevision, plan.ContractIdentity)
	if err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, errors.New("verify full-run Contract projection")
	}
	for stageID, artifactName := range map[string]string{
		"provider-prerequisites": "ok-infra-prerequisites.yaml", "cluster-lifecycle": "ok-mgmt-lifecycle.yaml",
	} {
		artifactDigest, artifactErr := verifiedProjectionArtifact(projected, artifactName)
		if artifactErr != nil || plan.RequireInput(stageID, "projection."+stageID, artifactDigest) != nil {
			return VerifiedFullRunExecutionManifest{}, receipt, errors.New("full-run projection differs from staged plan")
		}
	}
	receipt.ProjectionManifestDigest, receipt.ProjectionAuthorityDigest = projected.ManifestDigest, projected.AuthorityMapDigest

	network, err := LoadNetworkProfileFile(NetworkProfileFileConfig{
		Path: document.Profiles.Network.Path, ExpectedProfileDigest: document.Profiles.Network.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
	})
	if err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, errors.New("load full-run Network profile")
	}
	platform, err := LoadPlatformProfileFile(PlatformProfileFileConfig{
		Path: document.Profiles.Platform.Path, ExpectedProfileDigest: document.Profiles.Platform.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedPlatformRevision: plan.PlatformRevision,
		ExpectedExecutionFixture: plan.ExecutionFixture,
	})
	if err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, errors.New("load full-run Platform profile")
	}
	aggregate, err := LoadAggregateEvidenceProfileFile(AggregateEvidenceProfileFileConfig{
		Path: document.Profiles.Aggregate.Path, ExpectedProfileDigest: document.Profiles.Aggregate.Digest,
		ExpectedIntentRevision: plan.IntentRevision, ExpectedEnablementRevision: plan.EnablementRevision,
		ExpectedPlatformRevision: plan.PlatformRevision, ExpectedExecutionFixture: plan.ExecutionFixture,
	})
	if err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, errors.New("load full-run aggregate profile")
	}
	receipt.NetworkProfileDigest, receipt.PlatformProfileDigest, receipt.AggregateProfileDigest = network.Digest, platform.Digest, aggregate.Digest
	for stageID, input := range map[string]struct{ name, digest string }{
		"network-observation":  {"stage.network-observation", network.Digest},
		"platform-observation": {"stage.platform-observation", platform.Digest},
		"aggregate-evidence":   {"stage.aggregate-evidence", aggregate.Digest},
	} {
		if err := plan.RequireInput(stageID, input.name, input.digest); err != nil {
			return VerifiedFullRunExecutionManifest{}, receipt, errors.New("full-run profile differs from staged input")
		}
	}
	if err := verifyFullRunStaticArtifacts(document, plan, platform.Profile); err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, err
	}
	if err := validateFullRunRuntimeBoundary(document, plan); err != nil {
		return VerifiedFullRunExecutionManifest{}, receipt, err
	}
	receipt.State = "VERIFIED"
	receipt.RuntimeIdentityMode = "lifecycle-derived-private/v1"
	receipt.AuthorizationMode = "predecessor-bound-tls/v1"
	receipt.CapabilityMode = "runtime-bound-in-memory/v1"
	verified := VerifiedFullRunExecutionManifest{
		document: document, receipt: receipt, plan: plan,
		network: cloneNetworkProfile(network.Profile), platform: clonePlatformProfile(platform.Profile),
		aggregate: cloneAggregateEvidenceProfile(aggregate.Profile), verified: true,
	}
	return verified, receipt, nil
}

func fullRunPlanExpected(document postRuntimePlanExpectedDocument) stageplan.Expected {
	return stageplan.Expected{
		ContractIdentity: document.ContractIdentity, IntentRevision: document.IntentRevision,
		EnablementRevision: document.EnablementRevision, PlatformRevision: document.PlatformRevision,
		ExecutionFixture: document.ExecutionFixture, InfrastructureAuthority: document.InfrastructureAuthority,
		ManagementAuthority: document.ManagementAuthority, GitOpsAuthority: document.GitOpsAuthority,
	}
}

func fullRunStageInputDigest(plan stageplan.Binding, stageID string) string {
	stage, _, err := plan.Stage(stageID)
	if err != nil || len(stage.Inputs) != 1 {
		return ""
	}
	return stage.Inputs[0].Digest
}

func cloneNetworkProfile(profile observation.NetworkProfile) observation.NetworkProfile {
	return profile
}

func cloneAggregateEvidenceProfile(profile AggregateEvidenceProfile) AggregateEvidenceProfile {
	profile.Required = append([]string(nil), profile.Required...)
	return profile
}

func loadFullRunExecutionManifest(path string) (fullRunExecutionManifestDocument, string, error) {
	if !validFullRunAbsolutePath(path) {
		return fullRunExecutionManifestDocument{}, "", errors.New("full-run execution manifest path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > maximumFullRunExecutionManifestBytes {
		return fullRunExecutionManifestDocument{}, "", errors.New("full-run execution manifest metadata is invalid")
	}
	raw, err := readBoundedRegular(path, maximumFullRunExecutionManifestBytes)
	if err != nil {
		return fullRunExecutionManifestDocument{}, "", errors.New("read bounded full-run execution manifest")
	}
	var document fullRunExecutionManifestDocument
	if err := jsonstrict.Decode(raw, &document); err != nil {
		return fullRunExecutionManifestDocument{}, "", errors.New("decode strict full-run execution manifest")
	}
	if document.Format != FullRunExecutionManifestFormat {
		return fullRunExecutionManifestDocument{}, "", errors.New("full-run execution manifest format is not supported")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return fullRunExecutionManifestDocument{}, "", errors.New("encode full-run execution manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fullRunExecutionManifestDocument{}, "", errors.New("decode full-run execution manifest identity")
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return fullRunExecutionManifestDocument{}, "", errors.New("canonicalize full-run execution manifest")
	}
	return document, digest.SHA256(canonical), nil
}

func verifyFullRunStaticArtifacts(document fullRunExecutionManifestDocument, plan stageplan.Binding, platformProfile observation.PlatformProfile) error {
	enablementStage, _, err := plan.Stage("enablement")
	if err != nil || len(enablementStage.Inputs) != 1 || enablementStage.Inputs[0].Name != "stage.enablement" {
		return errors.New("full-run enablement input is invalid")
	}
	if _, err := submission.LoadEnablement(document.Enablement.ArtifactPath, submission.EnablementExpected{
		ArtifactDigest: enablementStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision, ExecutionFixture: plan.ExecutionFixture,
		ManagementAuthority: plan.Authorities.Management, ObjectIdentity: document.Enablement.ExpectedObject,
	}); err != nil {
		return errors.New("verify full-run enablement artifact")
	}
	targetIdentity := digest.SHA256([]byte("ok147-full-run-lifecycle-derived-target"))
	targetAccessStage, _, err := plan.Stage("target-access")
	if err != nil || len(targetAccessStage.Inputs) != 1 || targetAccessStage.Inputs[0].Name != "stage.target-access" {
		return errors.New("full-run target-access input is invalid")
	}
	access, err := submission.LoadTargetAccess(document.TargetAccess.ArtifactPath, submission.TargetAccessExpected{
		ArtifactDigest: targetAccessStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: targetIdentity, WorkloadAuthority: targetIdentity,
		Objects: append([]projection.ResourceIdentity(nil), document.TargetAccess.ExpectedObjects...),
	})
	if err != nil || len(access.Workload.Objects) != 11 || access.Workload.Objects[1].Identity.Kind != "ServiceAccount" || access.Workload.Objects[8].Identity.Kind != "ServiceAccount" {
		return errors.New("verify full-run target-access artifact")
	}
	targetCredentialStage, _, err := plan.Stage("target-credential")
	if err != nil || len(targetCredentialStage.Inputs) != 1 || targetCredentialStage.Inputs[0].Name != "stage.target-credential" {
		return errors.New("full-run target-credential input is invalid")
	}
	policyRaw, err := readBoundedRegular(document.TargetCredential.PolicyPath, maximumTargetCredentialPolicyBytes)
	if err != nil || digest.SHA256(policyRaw) != targetCredentialStage.Inputs[0].Digest {
		return errors.New("verify full-run target-credential policy identity")
	}
	var policy targetCredentialPolicyDocument
	if err := jsonstrict.Decode(policyRaw, &policy); err != nil ||
		validateTargetCredentialPolicy(policy, targetIdentity, access.Workload.Objects[1].Identity) != nil {
		return errors.New("verify full-run target-credential policy")
	}
	targetRegistrationStage, _, err := plan.Stage("target-registration")
	if err != nil || len(targetRegistrationStage.Inputs) != 1 || targetRegistrationStage.Inputs[0].Name != "stage.target-registration" {
		return errors.New("full-run target-registration input is invalid")
	}
	registrationExpected := submission.TargetRegistrationExpected{
		ArtifactDigest: targetRegistrationStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: targetIdentity, ArgoAuthority: plan.Authorities.GitOps,
		ArgoNamespace: document.TargetRegistration.ArgoNamespace, ProjectName: document.TargetRegistration.ProjectName,
		RegistrationName: document.TargetRegistration.RegistrationName, TargetName: document.TargetRegistration.TargetName,
		SourceRepository: document.TargetRegistration.SourceRepository,
		TargetNamespaces: append([]string(nil), document.TargetRegistration.TargetNamespaces...),
	}
	if _, err := submission.LoadTargetRegistration(document.TargetRegistration.ArtifactPath, registrationExpected); err != nil {
		return errors.New("verify full-run target-registration template")
	}
	applicationsStage, _, err := plan.Stage("platform-applications")
	if err != nil || len(applicationsStage.Inputs) != 1 || applicationsStage.Inputs[0].Name != "stage.platform-applications" {
		return errors.New("full-run platform-applications input is invalid")
	}
	applicationsExpected := submission.PlatformApplicationsExpected{
		ArtifactDigest: applicationsStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: targetIdentity, ArgoAuthority: plan.Authorities.GitOps,
		ArgoNamespace: document.PlatformApplications.ArgoNamespace, ProjectName: document.PlatformApplications.ProjectName,
		RegistrationName: document.PlatformApplications.RegistrationName,
		SourceRepository: document.PlatformApplications.SourceRepository, Profile: platformProfile,
	}
	if _, err := submission.LoadPlatformApplications(document.PlatformApplications.ArtifactPath, applicationsExpected); err != nil {
		return errors.New("verify full-run platform Applications template")
	}
	return nil
}

func validateFullRunRuntimeBoundary(document fullRunExecutionManifestDocument, plan stageplan.Binding) error {
	paths := []string{
		document.Plan.Path, document.Projection.ManifestPath, document.Projection.Root,
		document.Authorization.TokenFile, document.Authorization.CAFile, document.Authorization.PublicKeyPath, document.Authorization.OutputDirectory,
		document.Profiles.Network.Path, document.Profiles.Platform.Path, document.Profiles.Aggregate.Path,
		document.Enablement.ArtifactPath, document.TargetAccess.ArtifactPath, document.TargetCredential.PolicyPath,
		document.TargetRegistration.ArtifactPath, document.PlatformApplications.ArtifactPath, document.ReceiptDirectory,
	}
	for _, path := range paths {
		if !validFullRunAbsolutePath(path) {
			return errors.New("full-run manifest contains an invalid absolute path")
		}
	}
	if !validFullRunAuthorization(document.Authorization) {
		return errors.New("full-run authorization binding is invalid")
	}
	if !validFullRunLedger(document.ProviderPrerequisites.Ledger) {
		return errors.New("full-run ledger binding is invalid")
	}
	workload := document.NetworkObservation.Workload
	if workload != document.RuntimeBinding.Workload || workload != document.TargetAccess.Workload || workload != document.TargetCredential.Workload ||
		workload.TokenFile != document.AggregateEvidence.WorkloadTokenFile ||
		workload.KubeconfigFile != document.AggregateEvidence.WorkloadKubeconfigFile ||
		workload.CAFile != document.AggregateEvidence.WorkloadCAFile || workload.TokenFile != "" || workload.KubeconfigFile == "" {
		return errors.New("full-run workload runtime binding differs between stages")
	}
	workloadCredentialPath := workload.KubeconfigFile
	runtimeOutputs := []string{
		workload.BindingPath, workloadCredentialPath, workload.CAFile,
		document.RuntimeBinding.MaterialPath, document.RuntimeBinding.ReceiptPath,
		document.PlatformObservation.Capability.IndependentEvidenceIdentityPath,
		document.PlatformObservation.Capability.IndependentEvidenceIdentityReceiptPath,
	}
	seenOutputs := make(map[string]struct{}, len(runtimeOutputs)+len(preRuntimeStageOrder)+4)
	for _, path := range runtimeOutputs {
		if !validFullRunAbsolutePath(path) {
			return errors.New("full-run runtime output path is invalid")
		}
		if _, exists := seenOutputs[path]; exists {
			return errors.New("full-run private runtime outputs must be distinct")
		}
		seenOutputs[path] = struct{}{}
		if err := validateRuntimeBindingOutputPath(path); err != nil {
			return errors.New("full-run private runtime destination is invalid")
		}
	}
	for _, stageID := range preRuntimeStageOrder {
		path := filepath.Join(document.ReceiptDirectory, preRuntimeReceiptFiles[stageID])
		if _, exists := seenOutputs[path]; exists || validateRuntimeBindingOutputPath(path) != nil {
			return errors.New("full-run pre-runtime receipt destination is invalid")
		}
		seenOutputs[path] = struct{}{}
	}
	for _, stageID := range postRuntimeStageOrder[:4] {
		path := filepath.Join(document.ReceiptDirectory, postRuntimeReceiptFiles[stageID])
		if _, exists := seenOutputs[path]; exists || validateRuntimeBindingOutputPath(path) != nil {
			return errors.New("full-run post-runtime receipt destination is invalid")
		}
		seenOutputs[path] = struct{}{}
	}
	if document.ProviderPrerequisites.Authority.AuthorityIdentity != plan.Authorities.Infrastructure ||
		document.ClusterLifecycle.Authority.AuthorityIdentity != plan.Authorities.Management ||
		document.Enablement.Runtime.Authority.AuthorityIdentity != plan.Authorities.Management {
		return errors.New("full-run submission authority differs from staged plan")
	}
	if !validFullRunAuthority(document.ProviderPrerequisites.Authority) ||
		!validFullRunAuthority(document.ClusterLifecycle.Authority) ||
		!validFullRunAuthority(document.TargetRegistration.GitOps) ||
		document.ProviderPrerequisites.Authority.Endpoint == document.ClusterLifecycle.Authority.Endpoint ||
		document.ProviderPrerequisites.Authority.Endpoint == document.TargetRegistration.GitOps.Endpoint ||
		document.ClusterLifecycle.Authority.Endpoint == document.TargetRegistration.GitOps.Endpoint ||
		document.ProviderPrerequisites.Authority.TokenFile == document.ClusterLifecycle.Authority.TokenFile ||
		document.ProviderPrerequisites.Authority.TokenFile == document.TargetRegistration.GitOps.TokenFile ||
		document.ClusterLifecycle.Authority.TokenFile == document.TargetRegistration.GitOps.TokenFile {
		return errors.New("full-run authority isolation is invalid")
	}
	ledger := document.ProviderPrerequisites.Ledger
	ledgers := []postRuntimeLedgerDocument{
		document.ClusterLifecycle.Ledger, document.LifecycleObservation.Ledger, document.Enablement.Runtime.Ledger,
		document.NetworkObservation.Ledger, document.RuntimeBinding.Ledger, document.TargetAccess.Ledger,
		document.TargetCredential.Ledger, document.TargetRegistration.Ledger, document.PlatformApplications.Ledger,
		document.PlatformObservation.Ledger, document.AggregateEvidence.Ledger,
	}
	for _, candidate := range ledgers {
		if candidate != ledger {
			return errors.New("full-run ledger binding differs between stages")
		}
	}
	management := document.LifecycleObservation.Management
	if management != document.NetworkObservation.Management || management != document.AggregateEvidence.Management ||
		management.AuthorityIdentity != plan.Authorities.Management {
		return errors.New("full-run management observer binding differs between stages")
	}
	gitOps := document.TargetRegistration.GitOps
	if gitOps != document.PlatformApplications.GitOps || gitOps != document.PlatformObservation.Argo ||
		gitOps != document.AggregateEvidence.Argo || gitOps.AuthorityIdentity != plan.Authorities.GitOps {
		return errors.New("full-run GitOps binding differs between stages")
	}
	for _, pair := range [][2]string{
		{document.LifecycleObservation.PollInterval, document.LifecycleObservation.PollTimeout},
		{document.NetworkObservation.PollInterval, document.NetworkObservation.PollTimeout},
		{document.PlatformObservation.PollInterval, document.PlatformObservation.PollTimeout},
	} {
		if _, _, err := parsePostRuntimePolling(pair[0], pair[1]); err != nil {
			return errors.New("full-run polling bounds are invalid")
		}
	}
	capabilityTimeout, capabilityErr := time.ParseDuration(document.PlatformObservation.Capability.Timeout)
	cleanupTimeout, cleanupErr := time.ParseDuration(document.PlatformObservation.Capability.CleanupTimeout)
	capabilityPollInterval, capabilityPollErr := time.ParseDuration(document.PlatformObservation.Capability.PollInterval)
	if capabilityErr != nil || cleanupErr != nil || capabilityTimeout < time.Minute || capabilityTimeout > 30*time.Minute ||
		cleanupTimeout < 10*time.Second || cleanupTimeout > 2*time.Minute ||
		capabilityPollErr != nil || capabilityPollInterval < time.Millisecond || capabilityPollInterval > 30*time.Second ||
		document.PlatformObservation.Capability.Namespace != "ok-observability" ||
		!capabilityImageDigestPattern.MatchString(document.PlatformObservation.Capability.PushgatewayImage) ||
		!capabilityImageDigestPattern.MatchString(document.PlatformObservation.Capability.LogEmitterImage) ||
		!validFullRunAbsolutePath(document.PlatformObservation.Capability.IndependentEvidencePath) ||
		!platformInputDigestPattern.MatchString(document.PlatformObservation.Capability.IndependentEvidenceKeyID) {
		return errors.New("full-run capability execution bounds are invalid")
	}
	if _, exists := seenOutputs[document.PlatformObservation.Capability.IndependentEvidencePath]; exists {
		return errors.New("full-run capability evidence path collides with a private runtime output")
	}
	if document.TargetRegistration.TargetName != plan.ContractIdentity.Name ||
		document.TargetRegistration.ArgoNamespace != document.PlatformApplications.ArgoNamespace ||
		document.TargetRegistration.ProjectName != document.PlatformApplications.ProjectName ||
		document.TargetRegistration.TargetName != document.PlatformApplications.RegistrationName ||
		document.TargetRegistration.SourceRepository != document.PlatformApplications.SourceRepository {
		return errors.New("full-run GitOps projection identity differs between stages")
	}
	return nil
}

func validFullRunAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validFullRunLedger(document postRuntimeLedgerDocument) bool {
	return validFullRunKubernetesEndpoint(document.Endpoint) && document.Namespace == submissionStageInputNamespace &&
		validFullRunAbsolutePath(document.TokenFile) && validFullRunAbsolutePath(document.CAFile) && document.TokenFile != document.CAFile
}

func validFullRunAuthority(document postRuntimeAuthorityDocument) bool {
	return validFullRunKubernetesEndpoint(document.Endpoint) && document.AuthorityIdentity != "" &&
		validFullRunAbsolutePath(document.TokenFile) && validFullRunAbsolutePath(document.CAFile) &&
		document.TokenFile != document.CAFile && stageReceiptPrefixDigestPattern.MatchString(document.CABundleDigest)
}

func validFullRunAuthorization(document postRuntimeAuthorizationDocument) bool {
	endpoint, err := url.Parse(document.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Port() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/v1/stage-authorizations" {
		return false
	}
	if !validFullRunAbsolutePath(document.TokenFile) || !validFullRunAbsolutePath(document.CAFile) ||
		!validFullRunAbsolutePath(document.PublicKeyPath) || !validFullRunAbsolutePath(document.OutputDirectory) {
		return false
	}
	info, err := os.Lstat(document.OutputDirectory)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func validFullRunKubernetesEndpoint(raw string) bool {
	endpoint, err := url.Parse(raw)
	return err == nil && endpoint.Scheme == "https" && endpoint.Host != "" && endpoint.Port() != "" && endpoint.User == nil &&
		endpoint.RawQuery == "" && endpoint.Fragment == "" && (endpoint.Path == "" || endpoint.Path == "/")
}
