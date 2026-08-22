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
	Package ObservabilityCollectorRuntimePackageConfig
	Clock   func() time.Time
}

type ObservabilityCollectorPostPrefixReceipt struct {
	Format                  string `json:"format"`
	State                   string `json:"state"`
	PackageDigest           string `json:"packageDigest,omitempty"`
	RuntimeBindingDigest    string `json:"runtimeBindingDigest,omitempty"`
	TargetIdentityDigest    string `json:"targetIdentityDigest,omitempty"`
	CredentialReceiptDigest string `json:"credentialReceiptDigest,omitempty"`
	LaunchState             string `json:"launchState,omitempty"`
	CreatedObjects          int    `json:"createdObjects"`
}

type observabilityCollectorRuntimeLauncher interface {
	Launch(context.Context) (ObservabilityCollectorRuntimeLaunchReceipt, error)
}

// KubernetesObservabilityCollectorPostPrefix builds and installs the exact
// collector only after the fresh seven-stage prefix exists. It is single-use
// and retains only a redaction-safe receipt.
type KubernetesObservabilityCollectorPostPrefix struct {
	mu      sync.Mutex
	used    bool
	config  ObservabilityCollectorPostPrefixConfig
	receipt ObservabilityCollectorPostPrefixReceipt
	build   func(ObservabilityCollectorRuntimePackageConfig) (VerifiedObservabilityCollectorRuntimePackage, error)
	issue   func(context.Context, ObservabilityCollectorInstallerCredentialConfig) (VerifiedObservabilityCollectorInstallerCredential, error)
	open    func(submissionStageInstallerClientConfig, VerifiedObservabilityCollectorRuntimePackage) (observabilityCollectorRuntimeLauncher, error)
	resolve func(WorkloadAuthorityFileResolverConfig) (WorkloadAuthorityBinding, KubernetesAuthorityConfig, error)
}

func NewKubernetesObservabilityCollectorPostPrefix(config ObservabilityCollectorPostPrefixConfig) (*KubernetesObservabilityCollectorPostPrefix, error) {
	if config.Clock == nil || config.Package.Activation.RuntimeBinding.Bundle.PlanPath == "" ||
		config.Package.Activation.RuntimeBinding.MaterialPath == "" || config.Package.Activation.RuntimeBinding.ReceiptPath == "" ||
		config.Package.Activation.ObserverCredential.CAFile == "" ||
		!stageReceiptPrefixDigestPattern.MatchString(config.Package.Activation.ObserverCredential.CABundleDigest) {
		return nil, errors.New("observability collector post-prefix configuration is incomplete")
	}
	return &KubernetesObservabilityCollectorPostPrefix{
		config:  config,
		receipt: ObservabilityCollectorPostPrefixReceipt{Format: ObservabilityCollectorPostPrefixReceiptFormat, State: "PREPARED"},
		build:   BuildObservabilityCollectorRuntimePackage,
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
	packageConfig := activation.config.Package
	packageConfig.Activation.RuntimeBinding.Bundle.Receipts = append([]StageReceiptSource(nil), prefix.ReceiptPrefix[:6]...)
	packageConfig.Activation.MaterializationTime = activation.config.Clock().UTC().Truncate(time.Second)
	packageConfig.Activation.ObserverCredential.AuthorityIdentity = prefix.TargetIdentity
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
