package runner

import "context"

// KubernetesLifecycleWorkloadAuthorityMaterializerConfig retains the legacy
// shape for an explicit rejection. No field authorizes admin bootstrap.
type KubernetesLifecycleWorkloadAuthorityMaterializerConfig struct {
	Management                  KubernetesAuthorityConfig
	ExpectedManagementAuthority string
	BindingPath                 string
	KubeconfigFile              string
	CAFile                      string
}

// KubernetesLifecycleWorkloadAuthorityMaterializer is disabled until a bounded
// bootstrap issuer contract exists. It must never read the CAPI admin Secret.
type KubernetesLifecycleWorkloadAuthorityMaterializer struct{}

func OpenKubernetesLifecycleWorkloadAuthorityMaterializer(KubernetesLifecycleWorkloadAuthorityMaterializerConfig) (*KubernetesLifecycleWorkloadAuthorityMaterializer, error) {
	return nil, ErrClientCertificateDisabled
}

func (*KubernetesLifecycleWorkloadAuthorityMaterializer) ResolvePreRuntimeWorkloadAuthority(context.Context, StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
	return WorkloadAuthorityFileResolverConfig{}, ErrClientCertificateDisabled
}
