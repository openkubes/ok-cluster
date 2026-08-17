package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

type AggregateEvidenceStageFileRuntimeConfig struct {
	Bundle                   StageResumeConfig
	NetworkProfile           observation.NetworkProfile
	PlatformProfile          observation.PlatformProfile
	Ledger                   KubernetesLedgerConfig
	Management               KubernetesAuthorityConfig
	Argo                     KubernetesAuthorityConfig
	ExpectedWorkloadEndpoint string
	WorkloadTokenFile        string
	WorkloadCAFile           string
	RuntimeMaterialPath      string
	RuntimeReceiptPath       string
	CapabilityPath           string
	ExpectedCapabilityDigest string
	Clock                    func() time.Time
}

// LoadAggregateEvidenceStageFileRuntime reconstructs the final evaluator from
// immutable public profiles and private restart material. It performs bounded
// local file reads only and contacts no authority.
func LoadAggregateEvidenceStageFileRuntime(config AggregateEvidenceStageFileRuntimeConfig) (AggregateEvidenceStageRuntimeConfig, error) {
	runtime, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle: config.Bundle, MaterialPath: config.RuntimeMaterialPath, ReceiptPath: config.RuntimeReceiptPath,
	})
	if err != nil {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("load verified aggregate runtime binding")
	}
	if config.ExpectedWorkloadEndpoint == "" || runtime.material.Target.WorkloadAPIEndpoint != config.ExpectedWorkloadEndpoint {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("aggregate workload endpoint differs from runtime binding")
	}
	if config.WorkloadTokenFile == "" || config.WorkloadCAFile == "" {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("aggregate workload credential files are required")
	}
	capability, err := OpenPlatformCapabilityFileResolver(PlatformCapabilityFileResolverConfig{
		Path: config.CapabilityPath, ExpectedEvidenceDigest: config.ExpectedCapabilityDigest,
	})
	if err != nil {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("open aggregate platform capability resolver")
	}
	argoCA, err := readBoundedRegular(config.Argo.CAFile, maximumCABytes)
	if err != nil {
		return AggregateEvidenceStageRuntimeConfig{}, errors.New("read bounded aggregate GitOps CA")
	}
	config.Argo.CABundleDigest = digest.SHA256(argoCA)
	workload := &runtimeBindingWorkloadAuthorityResolver{
		targetUID: runtime.material.Target.CAPIClusterUID, endpoint: runtime.material.Target.WorkloadAPIEndpoint,
		caDigest: runtime.material.Target.WorkloadAPICADigest, tokenFile: config.WorkloadTokenFile, caFile: config.WorkloadCAFile,
	}
	return AggregateEvidenceStageRuntimeConfig{
		Ledger: config.Ledger,
		Observer: KubernetesAggregateObserverConfig{
			Management: config.Management, ExpectedManagementAuthority: config.Bundle.PlanExpected.ManagementAuthority,
			Argo: config.Argo, ExpectedArgoAuthority: config.Bundle.PlanExpected.GitOpsAuthority,
			Namespace: config.Bundle.PlanExpected.ContractIdentity.Namespace, Name: config.Bundle.PlanExpected.ContractIdentity.Name,
			HCPName:        config.Bundle.PlanExpected.ContractIdentity.Name + "-cilium",
			NetworkProfile: config.NetworkProfile, PlatformProfile: config.PlatformProfile,
			WorkloadAuthority: workload, PlatformCapability: capability, Clock: config.Clock,
		},
		Runtime: runtime,
	}, nil
}

type runtimeBindingWorkloadAuthorityResolver struct {
	targetUID, endpoint, caDigest, tokenFile, caFile string
}

func (resolver *runtimeBindingWorkloadAuthorityResolver) ResolveWorkloadAuthority(ctx context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
	if resolver == nil {
		return KubernetesAuthorityConfig{}, errors.New("runtime-bound workload resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return KubernetesAuthorityConfig{}, errors.New("runtime-bound workload resolution cancelled")
	}
	if _, err := observation.PolicyDigest(policy); err != nil || policy.TargetClusterUID != resolver.targetUID {
		return KubernetesAuthorityConfig{}, errors.New("workload policy differs from runtime-bound target")
	}
	return KubernetesAuthorityConfig{
		Endpoint: resolver.endpoint, AuthorityIdentity: resolver.targetUID,
		TokenFile: resolver.tokenFile, CAFile: resolver.caFile, CABundleDigest: resolver.caDigest,
	}, nil
}

var _ WorkloadAuthorityResolver = (*runtimeBindingWorkloadAuthorityResolver)(nil)
