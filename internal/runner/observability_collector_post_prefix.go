package runner

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const ObservabilityCollectorPostPrefixReceiptFormat = "ok147-observability-collector-post-prefix-receipt/v1"

type ObservabilityCollectorPostPrefixConfig struct {
	Package          ObservabilityCollectorRuntimePackageConfig
	RuntimeAuthority ObservabilityCollectorRuntimeAuthorityPackageConfig
	Clock            func() time.Time
}

type ObservabilityCollectorPostPrefixReceipt struct {
	Format                          string `json:"format"`
	State                           string `json:"state"`
	PackageDigest                   string `json:"packageDigest,omitempty"`
	RuntimeBindingDigest            string `json:"runtimeBindingDigest,omitempty"`
	TargetIdentityDigest            string `json:"targetIdentityDigest,omitempty"`
	RuntimeAuthorityPackageDigest   string `json:"runtimeAuthorityPackageDigest,omitempty"`
	RuntimeAuthorityReceiptDigest   string `json:"runtimeAuthorityReceiptDigest,omitempty"`
	RuntimeAuthorityCreatedObjects  int    `json:"runtimeAuthorityCreatedObjects"`
	ObserverCredentialReceiptDigest string `json:"observerCredentialReceiptDigest,omitempty"`
	CredentialReceiptDigest         string `json:"credentialReceiptDigest,omitempty"`
	LaunchState                     string `json:"launchState,omitempty"`
	CreatedObjects                  int    `json:"createdObjects"`
}

type observabilityCollectorRuntimeLauncher interface {
	Launch(context.Context) (ObservabilityCollectorRuntimeLaunchReceipt, error)
}

type observabilityCollectorRuntimeAuthorityInstaller interface {
	Install(context.Context) (ObservabilityCollectorRuntimeAuthorityInstallationReceipt, error)
}

// KubernetesObservabilityCollectorPostPrefix builds and installs the exact
// collector only after the fresh seven-stage prefix exists. It is single-use
// and retains only a redaction-safe receipt.
type KubernetesObservabilityCollectorPostPrefix struct {
	mu             sync.Mutex
	used           bool
	config         ObservabilityCollectorPostPrefixConfig
	receipt        ObservabilityCollectorPostPrefixReceipt
	build          func(ObservabilityCollectorRuntimePackageConfig) (VerifiedObservabilityCollectorRuntimePackage, error)
	buildAuthority func(ObservabilityCollectorRuntimeAuthorityPackageConfig) (VerifiedObservabilityCollectorRuntimeAuthorityPackage, error)
	openAuthority  func(WorkloadAuthorityFileResolverConfig, VerifiedObservabilityCollectorRuntimeAuthorityPackage) (observabilityCollectorRuntimeAuthorityInstaller, error)
	issueObserver  func(context.Context, ObservabilityCollectorObserverCredentialConfig) (VerifiedObservabilityCollectorObserverCredential, error)
	issue          func(context.Context, ObservabilityCollectorInstallerCredentialConfig) (VerifiedObservabilityCollectorInstallerCredential, error)
	open           func(submissionStageInstallerClientConfig, VerifiedObservabilityCollectorRuntimePackage) (observabilityCollectorRuntimeLauncher, error)
	resolve        func(WorkloadAuthorityFileResolverConfig) (WorkloadAuthorityBinding, KubernetesAuthorityConfig, error)
}

func NewKubernetesObservabilityCollectorPostPrefix(config ObservabilityCollectorPostPrefixConfig) (*KubernetesObservabilityCollectorPostPrefix, error) {
	if config.Clock == nil || config.Package.Activation.RuntimeBinding.Bundle.PlanPath == "" ||
		config.Package.Activation.RuntimeBinding.MaterialPath == "" || config.Package.Activation.RuntimeBinding.ReceiptPath == "" ||
		config.Package.Activation.ObserverCredential.CAFile == "" || len(config.Package.Activation.ObserverToken) != 0 ||
		!stageReceiptPrefixDigestPattern.MatchString(config.Package.Activation.ObserverCredential.CABundleDigest) ||
		len(config.RuntimeAuthority.Manifest) == 0 || !stageReceiptPrefixDigestPattern.MatchString(config.RuntimeAuthority.ExpectedManifestDigest) ||
		digest.SHA256(config.RuntimeAuthority.Manifest) != config.RuntimeAuthority.ExpectedManifestDigest || config.RuntimeAuthority.TargetIdentityDigest != "" {
		return nil, errors.New("observability collector post-prefix configuration is incomplete")
	}
	return &KubernetesObservabilityCollectorPostPrefix{
		config:         config,
		receipt:        ObservabilityCollectorPostPrefixReceipt{Format: ObservabilityCollectorPostPrefixReceiptFormat, State: "PREPARED"},
		build:          BuildObservabilityCollectorRuntimePackage,
		buildAuthority: BuildObservabilityCollectorRuntimeAuthorityPackage,
		openAuthority: func(workload WorkloadAuthorityFileResolverConfig, packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) (observabilityCollectorRuntimeAuthorityInstaller, error) {
			return OpenKubernetesObservabilityCollectorRuntimeAuthorityInstaller(workload, packaged)
		},
		issueObserver: func(ctx context.Context, config ObservabilityCollectorObserverCredentialConfig) (VerifiedObservabilityCollectorObserverCredential, error) {
			issuer, err := OpenKubernetesObservabilityCollectorObserverCredentialIssuer(config)
			if err != nil {
				return VerifiedObservabilityCollectorObserverCredential{}, err
			}
			return issuer.Issue(ctx)
		},
		issue: func(ctx context.Context, config ObservabilityCollectorInstallerCredentialConfig) (VerifiedObservabilityCollectorInstallerCredential, error) {
			issuer, err := OpenKubernetesObservabilityCollectorInstallerCredentialIssuer(config)
			if err != nil {
				return VerifiedObservabilityCollectorInstallerCredential{}, err
			}
			return issuer.Issue(ctx)
		},
		open: func(config submissionStageInstallerClientConfig, packaged VerifiedObservabilityCollectorRuntimePackage) (observabilityCollectorRuntimeLauncher, error) {
			return newKubernetesObservabilityCollectorRuntimeLauncher(config, packaged)
		},
		resolve: loadWorkloadAuthorityFiles,
	}, nil
}

func (activation *KubernetesObservabilityCollectorPostPrefix) ActivateFullRunPostPrefix(ctx context.Context, prefix FullRunPostPrefixActivation) error {
	if activation == nil {
		return errors.New("observability collector post-prefix activation is required")
	}
	activation.mu.Lock()
	if activation.used {
		activation.mu.Unlock()
		return errors.New("observability collector post-prefix activation is single-use")
	}
	activation.used = true
	activation.mu.Unlock()
	if err := ctx.Err(); err != nil || len(prefix.ReceiptPrefix) != len(preRuntimeStageOrder) ||
		!stageReceiptPrefixDigestPattern.MatchString(prefix.TargetIdentity) {
		activation.stop()
		return errors.New("observability collector post-prefix binding is invalid")
	}
	binding, authority, err := activation.resolve(prefix.Workload)
	if err != nil || digest.SHA256([]byte(binding.TargetClusterUID)) != prefix.TargetIdentity ||
		authority.CABundleDigest != activation.config.Package.Activation.ObserverCredential.CABundleDigest ||
		prefix.Workload.CAFile != activation.config.Package.Activation.ObserverCredential.CAFile {
		activation.stop()
		return errors.New("observability collector installer differs from runtime workload authority")
	}
	authorityConfig := activation.config.RuntimeAuthority
	authorityConfig.TargetIdentityDigest = prefix.TargetIdentity
	authorityPackage, err := activation.buildAuthority(authorityConfig)
	if err != nil {
		activation.stop()
		return errors.New("build observability collector runtime authority package")
	}
	authorityPackageReceipt, err := authorityPackage.Receipt()
	if err != nil || authorityPackageReceipt.TargetIdentityDigest != prefix.TargetIdentity {
		activation.stop()
		return errors.New("verify observability collector runtime authority package")
	}
	authorityInstaller, err := activation.openAuthority(prefix.Workload, authorityPackage)
	if err != nil {
		activation.stop()
		return errors.New("open observability collector runtime authority installer")
	}
	authorityInstallReceipt, err := authorityInstaller.Install(ctx)
	authorityInstallReceiptRaw, encodeErr := json.Marshal(authorityInstallReceipt)
	activation.mu.Lock()
	activation.receipt.RuntimeAuthorityPackageDigest = authorityPackageReceipt.PackageDigest
	activation.receipt.RuntimeAuthorityCreatedObjects = len(authorityInstallReceipt.Results)
	if encodeErr == nil {
		activation.receipt.RuntimeAuthorityReceiptDigest = digest.SHA256(authorityInstallReceiptRaw)
	}
	activation.mu.Unlock()
	if err != nil || encodeErr != nil || authorityInstallReceipt.State != "INSTALLED" || len(authorityInstallReceipt.Results) != 5 ||
		authorityInstallReceipt.TargetIdentityDigest != prefix.TargetIdentity || authorityInstallReceipt.PackageDigest != authorityPackageReceipt.PackageDigest {
		activation.stop()
		return errors.New("install observability collector runtime authority")
	}
	observerCredential, err := activation.issueObserver(ctx, ObservabilityCollectorObserverCredentialConfig{
		Workload: prefix.Workload, ExpectedTargetDigest: prefix.TargetIdentity, Clock: activation.config.Clock,
	})
	if err != nil {
		activation.stop()
		return errors.New("issue observability collector observer credential")
	}
	observerSource, observerToken, observerReceipt, err := observerCredential.Material()
	if err != nil || observerSource.AuthorityIdentity != prefix.TargetIdentity || observerSource.CABundleDigest != authority.CABundleDigest {
		activation.stop()
		return errors.New("verify observability collector observer credential")
	}
	observerReceiptRaw, err := json.Marshal(observerReceipt)
	if err != nil {
		activation.stop()
		return errors.New("encode observability collector observer credential receipt")
	}
	packageConfig := activation.config.Package
	packageConfig.Activation.RuntimeBinding.Bundle.Receipts = append([]StageReceiptSource(nil), prefix.ReceiptPrefix[:6]...)
	packageConfig.Activation.MaterializationTime = activation.config.Clock().UTC().Truncate(time.Second)
	packageConfig.Activation.ObserverCredential = observerSource
	packageConfig.Activation.ObserverToken = observerToken
	packaged, err := activation.build(packageConfig)
	if err != nil {
		activation.stop()
		return errors.New("build observability collector post-prefix package")
	}
	packageReceipt, err := packaged.Receipt()
	if err != nil {
		activation.stop()
		return errors.New("verify observability collector post-prefix package")
	}
	plan, err := PlanObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil || plan.TargetIdentityDigest != prefix.TargetIdentity || plan.RuntimeBindingDigest != packageReceipt.RuntimeBindingDigest {
		activation.stop()
		return errors.New("observability collector package differs from fresh runtime prefix")
	}
	credential, err := activation.issue(ctx, ObservabilityCollectorInstallerCredentialConfig{
		Workload: prefix.Workload, ExpectedTargetDigest: prefix.TargetIdentity, Clock: activation.config.Clock,
	})
	if err != nil {
		activation.stop()
		return errors.New("issue observability collector installer credential")
	}
	credentialReceipt, err := credential.Receipt()
	if err != nil || credentialReceipt.TargetIdentityDigest != prefix.TargetIdentity || credentialReceipt.CABundleDigest != authority.CABundleDigest {
		activation.stop()
		return errors.New("verify observability collector installer credential")
	}
	credentialReceiptRaw, err := json.Marshal(credentialReceipt)
	if err != nil {
		activation.stop()
		return errors.New("encode observability collector installer credential receipt")
	}
	launcherConfig, err := credential.launcherConfig()
	if err != nil {
		activation.stop()
		return errors.New("bind observability collector installer credential")
	}
	launcher, err := activation.open(launcherConfig, packaged)
	if err != nil {
		activation.stop()
		return errors.New("open observability collector post-prefix launcher")
	}
	launchReceipt, err := launcher.Launch(ctx)
	activation.mu.Lock()
	activation.receipt.PackageDigest = packageReceipt.PackageDigest
	activation.receipt.RuntimeBindingDigest = packageReceipt.RuntimeBindingDigest
	activation.receipt.TargetIdentityDigest = prefix.TargetIdentity
	activation.receipt.ObserverCredentialReceiptDigest = digest.SHA256(observerReceiptRaw)
	activation.receipt.CredentialReceiptDigest = digest.SHA256(credentialReceiptRaw)
	activation.receipt.LaunchState = launchReceipt.State
	activation.receipt.CreatedObjects = len(launchReceipt.Results)
	if err == nil && launchReceipt.State == "ACTIVATED" && len(launchReceipt.Results) == 4 {
		activation.receipt.State = "ACTIVATED"
	} else {
		activation.receipt.State = "STOPPED"
	}
	activation.mu.Unlock()
	if err != nil || launchReceipt.State != "ACTIVATED" || len(launchReceipt.Results) != 4 {
		return errors.New("activate observability collector post-prefix package")
	}
	return nil
}

func (activation *KubernetesObservabilityCollectorPostPrefix) Receipt() ObservabilityCollectorPostPrefixReceipt {
	if activation == nil {
		return ObservabilityCollectorPostPrefixReceipt{Format: ObservabilityCollectorPostPrefixReceiptFormat, State: "STOPPED"}
	}
	activation.mu.Lock()
	defer activation.mu.Unlock()
	return activation.receipt
}

func (activation *KubernetesObservabilityCollectorPostPrefix) stop() {
	activation.mu.Lock()
	activation.receipt.State = "STOPPED"
	activation.mu.Unlock()
}

var _ FullRunPostPrefixActivator = (*KubernetesObservabilityCollectorPostPrefix)(nil)
