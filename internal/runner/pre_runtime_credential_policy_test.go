package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type embeddedDisabledResolver struct {
	*KubernetesLifecycleWorkloadAuthorityMaterializer
}
type wrappedDisabledResolver struct {
	inner PreRuntimeWorkloadAuthorityResolver
}

func (r wrappedDisabledResolver) ResolvePreRuntimeWorkloadAuthority(ctx context.Context, resume StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
	return r.inner.ResolvePreRuntimeWorkloadAuthority(ctx, resume)
}

func TestPreRuntimeCredentialPolicyPrecedesFactoriesAndGrants(t *testing.T) {
	for _, mode := range []string{"network", "binding", "target", "zero-materializer", "nil-materializer",
		"wrapped", "embedded", "method-adapter", "function-adapter", "typed-nil-function",
		"provider-authority", "lifecycle-authority", "lifecycle-management", "network-management", "enablement-authority"} {
		t.Run(mode, func(t *testing.T) {
			config, factories, calls, requests := preRuntimeExecutionFixture(t)
			var apiCalls, connections, resolverCalls atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				apiCalls.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			// Isolate authority checks from the resolver denial, so each guard
			// must preserve its own policy sentinel rather than fail completeness.
			config.WorkloadAuthority = nil
			unsupported := KubernetesAuthorityConfig{KubeconfigFile: "/must-not-read", Endpoint: server.URL}
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
			case "wrapped":
				config.WorkloadAuthority = wrappedDisabledResolver{&KubernetesLifecycleWorkloadAuthorityMaterializer{}}
			case "embedded":
				config.WorkloadAuthority = &embeddedDisabledResolver{&KubernetesLifecycleWorkloadAuthorityMaterializer{}}
			case "method-adapter":
				config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc((&KubernetesLifecycleWorkloadAuthorityMaterializer{}).ResolvePreRuntimeWorkloadAuthority)
			case "function-adapter":
				config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(context.Context, StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
					resolverCalls.Add(1)
					return WorkloadAuthorityFileResolverConfig{}, nil
				})
			case "typed-nil-function":
				config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(nil)
			case "provider-authority":
				config.ProviderPrerequisites.Authority = unsupported
			case "lifecycle-authority":
				config.ClusterLifecycle.Authority = unsupported
			case "lifecycle-management":
				config.LifecycleObservation.Management = unsupported
			case "network-management":
				config.NetworkObservation.Management = unsupported
			case "enablement-authority":
				config.Enablement.Runtime.Authority = unsupported
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
			if apiCalls.Load() != 0 || connections.Load() != 0 || resolverCalls.Load() != 0 {
				t.Fatalf("pre-denial activity: API=%d connections=%d resolver=%d", apiCalls.Load(), connections.Load(), resolverCalls.Load())
			}
		})
	}
}

func TestPreRuntimeResolverPreservesCredentialPolicySentinel(t *testing.T) {
	config, factories, _, _ := preRuntimeExecutionFixture(t)
	config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(context.Context, StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
		return WorkloadAuthorityFileResolverConfig{}, ErrClientCertificateDisabled
	})
	executor, err := openSyntheticPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Run(context.Background())
	if !errors.Is(err, ErrClientCertificateDisabled) {
		t.Fatalf("lost policy sentinel: %v", err)
	}
}

func TestAuthorityOpenWrappersPreserveCredentialPolicySentinel(t *testing.T) {
	t.Run("submission", func(t *testing.T) {
		config := runnerStagedOperationConfig(t, runnerStagedPlan(t), "provider-prerequisites")
		config.Authority.KubeconfigFile, config.Authority.TokenFile = "/must-not-read", ""
		if _, err := OpenKubernetesSubmissionStageOperation(config); !errors.Is(err, ErrClientCertificateDisabled) {
			t.Fatalf("submission lost sentinel: %v", err)
		}
	})
	t.Run("lifecycle", func(t *testing.T) {
		bundle, err := LoadLifecycleObservationStageBundle(lifecycleObservationBundleConfig(t, true))
		if err != nil {
			t.Fatal(err)
		}
		runtime := lifecycleObservationRuntime(t, "ledger-token", "management-token")
		runtime.Management.KubeconfigFile, runtime.Management.TokenFile = "/must-not-read", ""
		if _, err := bundle.Open(runtime); !errors.Is(err, ErrClientCertificateDisabled) {
			t.Fatalf("lifecycle lost sentinel: %v", err)
		}
	})
	t.Run("network", func(t *testing.T) {
		bundle, err := LoadNetworkObservationStageBundle(networkObservationBundleConfig(t, true))
		if err != nil {
			t.Fatal(err)
		}
		runtime := networkObservationRuntime(t, bundle, "ledger-token", "management-token", "workload-token", "cluster-runtime-uid-147")
		runtime.Management.KubeconfigFile, runtime.Management.TokenFile = "/must-not-read", ""
		if _, err := bundle.Open(runtime); !errors.Is(err, ErrClientCertificateDisabled) {
			t.Fatalf("network lost sentinel: %v", err)
		}
	})
}
