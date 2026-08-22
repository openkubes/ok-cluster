package runner

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

// KubernetesObservabilityFullRunActivationConfig contains the only
// process-local input not carried by the private execution manifest: the
// pinned public key used to verify independent Observability evidence.
type KubernetesObservabilityFullRunActivationConfig struct {
	IndependentEvidencePublicKeyPath string
	PostPrefixActivator              FullRunPostPrefixActivator
	Clock                            func() time.Time
	Wait                             ObservationWaiter
}

// OpenKubernetesObservabilityFullRunActivation composes the verified private
// manifest, lifecycle-derived authority bridge and concrete Observability
// capability factory. It performs no API request or stage action; Run remains
// the only mutation boundary.
func OpenKubernetesObservabilityFullRunActivation(path string, runtime KubernetesObservabilityFullRunActivationConfig) (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
	receipt := FullRunExecutionActivationReceipt{Format: FullRunExecutionActivationReceiptFormat, State: "STOPPED"}
	if runtime.IndependentEvidencePublicKeyPath == "" || runtime.Clock == nil || runtime.Wait == nil {
		return nil, receipt, errors.New("Kubernetes observability full-run runtime is incomplete")
	}
	manifest, manifestReceipt, err := LoadFullRunExecutionManifest(path)
	receipt.Manifest = manifestReceipt
	if err != nil {
		return nil, receipt, errors.New("load Kubernetes observability full-run manifest")
	}
	document := manifest.document
	workload := NewDeferredFullRunWorkloadAuthorityResolver()
	evidence, err := OpenSignedObservabilityEvidenceFileSource(SignedObservabilityEvidenceFileConfig{
		Path:          document.PlatformObservation.Capability.IndependentEvidencePath,
		PublicKeyPath: runtime.IndependentEvidencePublicKeyPath,
		Clock:         runtime.Clock,
	})
	if err != nil {
		return nil, receipt, errors.New("open full-run independent Observability evidence")
	}
	profile, err := StandardObservabilityCapabilityCheckProfile(document.PlatformObservation.Capability.Namespace)
	if err != nil {
		return nil, receipt, errors.New("open full-run Observability profile")
	}
	pollInterval, err := time.ParseDuration(document.PlatformObservation.Capability.PollInterval)
	if err != nil {
		return nil, receipt, errors.New("parse full-run Observability polling")
	}
	capability, err := NewKubernetesObservabilityPlatformCapabilityFactory(KubernetesObservabilityPlatformCapabilityFactoryConfig{
		WorkloadAuthority: workload, IndependentEvidence: evidence,
		Fixture: ObservabilitySyntheticFixtureConfig{
			PushgatewayImage: document.PlatformObservation.Capability.PushgatewayImage,
			LogEmitterImage:  document.PlatformObservation.Capability.LogEmitterImage,
		},
		Profile: profile, PollInterval: pollInterval, Clock: runtime.Clock,
	})
	if err != nil {
		return nil, receipt, errors.New("open full-run Observability capability factory")
	}
	postPrefix := runtime.PostPrefixActivator
	if postPrefix == nil {
		postPrefix, err = manifest.openObservabilityCollectorPostPrefix(path, runtime.Clock)
		if err != nil {
			return nil, receipt, errors.New("open full-run Observability collector post-prefix")
		}
	}
	config, err := manifest.ExecutionConfig(FullRunExecutionManifestRuntime{
		PlatformCapability: capability, PostPrefixActivator: postPrefix,
		Clock: runtime.Clock, Wait: runtime.Wait,
	})
	if err != nil {
		return nil, receipt, errors.New("open concrete full-run execution configuration")
	}
	config.WorkloadAuthorityBinder = workload
	execution, err := OpenFullRunExecution(config)
	if err != nil {
		return nil, receipt, errors.New("open concrete Kubernetes observability full-run execution")
	}
	receipt.State = "PREPARED"
	return &FullRunExecutionActivation{execution: execution, manifest: manifestReceipt}, receipt, nil
}

func (manifest VerifiedFullRunExecutionManifest) openObservabilityCollectorPostPrefix(manifestPath string, clock func() time.Time) (FullRunPostPrefixActivator, error) {
	if !manifest.verified || clock == nil || manifestPath == "" {
		return nil, errors.New("verified collector manifest binding is incomplete")
	}
	document := manifest.document
	collector := document.ObservabilityCollector
	authority, err := readBoundedRegular(collector.RuntimeAuthorityPath, maximumFullRunExecutionManifestBytes)
	if err != nil || digest.SHA256(authority) != collector.RuntimeAuthorityDigest {
		return nil, errors.New("read bound collector runtime authority")
	}
	job, err := readBoundedRegular(collector.JobTemplatePath, maximumFullRunExecutionManifestBytes)
	if err != nil || digest.SHA256(job) != collector.JobTemplateDigest {
		return nil, errors.New("read bound collector Job template")
	}
	maximumRecordAge, err := time.ParseDuration(collector.MaximumRecordAge)
	if err != nil {
		return nil, errors.New("parse bound collector record age")
	}
	manifestReceipt := manifest.receipt
	manifestReceiptRaw, err := json.Marshal(manifestReceipt)
	if err != nil {
		return nil, errors.New("encode bound collector manifest receipt")
	}
	expected := fullRunPlanExpected(document.Plan.Expected)
	return NewKubernetesObservabilityCollectorPostPrefix(ObservabilityCollectorPostPrefixConfig{
		Package: ObservabilityCollectorRuntimePackageConfig{
			Activation: ObservabilityCollectorActivationPackageConfig{
				ManifestPath: manifestPath, ExpectedManifestDigest: manifest.receipt.ManifestDigest,
				ManifestReceipt: &manifestReceipt, ExpectedReceiptDigest: digest.SHA256(manifestReceiptRaw),
				RuntimeBinding: RuntimeBindingMaterialFileConfig{
					Bundle:       StageResumeConfig{PlanPath: document.Plan.Path, PlanExpected: expected},
					MaterialPath: document.RuntimeBinding.MaterialPath, ReceiptPath: document.RuntimeBinding.ReceiptPath,
				},
				ActivationSecret:   collector.ActivationSecret,
				ObserverCredential: SubmissionStageCredentialSource{CAFile: document.NetworkObservation.Workload.CAFile},
				WebhookTokenPath:   collector.WebhookTokenPath, QueryTokenPath: collector.QueryTokenPath,
				PublicEndpoint: collector.PublicEndpoint, ListenAddress: collector.ListenAddress,
				TLSCertificatePath: collector.TLSCertificatePath, TLSPrivateKeyPath: collector.TLSPrivateKeyPath,
				MaximumRecordAge: maximumRecordAge,
			},
			JobTemplate: job, JobTemplateDigest: collector.JobTemplateDigest,
			RunID: collector.RunID, ImageDigest: collector.ImageDigest,
			WorkloadAPICIDR: collector.WorkloadAPICIDR, AlertSourceCIDR: collector.AlertSourceCIDR,
		},
		RuntimeAuthority: ObservabilityCollectorRuntimeAuthorityPackageConfig{
			Manifest: authority, ExpectedManifestDigest: collector.RuntimeAuthorityDigest,
		},
		Clock: clock,
	})
}
