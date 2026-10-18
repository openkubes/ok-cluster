package runner

import (
	"context"
	"errors"
	"testing"
)

func TestPreRuntimeCredentialPolicyPrecedesFactoriesAndGrants(t *testing.T) {
	for _, mode := range []string{"network", "binding", "target", "zero-materializer", "nil-materializer"} {
		t.Run(mode, func(t *testing.T) {
			config, factories, calls, requests := preRuntimeExecutionFixture(t)
			switch mode {
			case "network":
				config.NetworkObservation.Workload.KubeconfigFile = "/must-not-read"
			case "binding":
				config.RuntimeBinding.Workload.KubeconfigFile = "/must-not-read"
			case "target":
				config.TargetAccess.Runtime.Workload.KubeconfigFile = "/must-not-read"
			case "zero-materializer":
				config.WorkloadAuthority = &KubernetesLifecycleWorkloadAuthorityMaterializer{}
			case "nil-materializer":
				config.WorkloadAuthority = (*KubernetesLifecycleWorkloadAuthorityMaterializer)(nil)
			}
			opened, err := openPreRuntimeExecution(config, factories)
			if opened != nil || !errors.Is(err, ErrClientCertificateDisabled) {
				t.Fatalf("open=%v err=%v", opened, err)
			}
			opened, err = OpenPreRuntimeExecution(config)
			if opened != nil || !errors.Is(err, ErrClientCertificateDisabled) {
				t.Fatalf("public open=%v err=%v", opened, err)
			}
			factoryCalls := 0
			full, err := openFullRunExecution(FullRunExecutionConfig{PreRuntime: config}, fullRunExecutionFactories{
				preRuntime: func(PreRuntimeExecutionConfig) (fullRunPreRuntimeExecution, error) {
					factoryCalls++
					return nil, errors.New("must not open")
				},
			})
			if full != nil || !errors.Is(err, ErrClientCertificateDisabled) || factoryCalls != 0 {
				t.Fatalf("full=%v err=%v factories=%d", full, err, factoryCalls)
			}
			full, err = OpenFullRunExecution(FullRunExecutionConfig{PreRuntime: config})
			if full != nil || !errors.Is(err, ErrClientCertificateDisabled) {
				t.Fatalf("public full=%v err=%v", full, err)
			}
			if len(*calls) != 0 || len(*requests) != 0 {
				t.Fatalf("stages=%v grants=%v", *calls, *requests)
			}
		})
	}
}

func TestPreRuntimeResolverPreservesCredentialPolicySentinel(t *testing.T) {
	config, factories, _, _ := preRuntimeExecutionFixture(t)
	config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(context.Context, StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
		return WorkloadAuthorityFileResolverConfig{}, ErrClientCertificateDisabled
	})
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Run(context.Background())
	if !errors.Is(err, ErrClientCertificateDisabled) {
		t.Fatalf("lost policy sentinel: %v", err)
	}
}
