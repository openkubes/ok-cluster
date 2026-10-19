package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/openkubes/ok-cluster/internal/observation"
)

// Keep this list at the adapter boundary: every entry consumes a
// KubernetesAuthorityConfig (directly or through its config) and has a
// dedicated certificate-policy guard before validating or opening anything
// else. A missing guard must not turn into a generic incomplete-input error.
func TestKubeconfigOnlyAndMixedCredentialsAreRejectedByAuthorityOpeners(t *testing.T) {
	var requests, connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	tests := []struct {
		name string
		open func(*testing.T, KubernetesAuthorityConfig) error
	}{
		{"authority transport", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := openBoundedKubernetesAuthorityTransport(a)
			return err
		}},
		{"submission client", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesSubmissionClient(a)
			return err
		}},
		{"submission stage operation", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesSubmissionStageOperation(KubernetesSubmissionStageOperationConfig{Authority: a})
			return err
		}},
		{"enablement stage operation", func(t *testing.T, a KubernetesAuthorityConfig) error {
			config := runnerEnablementOperationConfig(t, runnerStagedPlan(t))
			config.Authority = a
			config.Authority.AuthorityIdentity = config.Plan.Authorities.Management
			return assertNoCredentialFilesOpened(t, []string{config.Ledger.TokenFile, config.Ledger.CAFile}, func() error {
				_, err := OpenKubernetesEnablementStageOperation(config)
				return err
			})
		}},
		{"CAPI observer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesCAPILifecycleObserver(a, "management", "ns", "name")
			return err
		}},
		{"runtime binding source", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesRuntimeBindingSource(a, WorkloadAuthorityBinding{})
			return err
		}},
		{"runtime binding store", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesRuntimeBindingStore(a, "management", "ns", "name")
			return err
		}},
		{"submission runtime installer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesSubmissionStageRuntimeInstaller(a, VerifiedSubmissionStageRuntimePrerequisite{})
			return err
		}},
		{"submission package installer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesSubmissionStagePackageInstaller(a, VerifiedSubmissionStagePackage{})
			return err
		}},
		{"network source workload", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesNetworkSourceCollector(KubernetesNetworkObserverConfig{
				Management: KubernetesAuthorityConfig{}, Workload: a,
			})
			return err
		}},
		{"network source management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesNetworkSourceCollector(KubernetesNetworkObserverConfig{
				Management: a, Workload: KubernetesAuthorityConfig{},
			})
			return err
		}},
		{"platform source collector", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesPlatformSourceCollector(KubernetesPlatformObserverConfig{Argo: a})
			return err
		}},
		{"observability transport", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesObservabilityTransport(KubernetesObservabilityTransportConfig{Workload: a})
			return err
		}},
		{"submission launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesSubmissionStageLauncher(SubmissionStageLauncherConfig{Authority: a}, VerifiedSubmissionStagePackage{}, VerifiedSubmissionStageCredentialPackage{}, VerifiedSubmissionStageRuntimePrerequisite{})
			return err
		}},
		{"submission credential installer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesSubmissionStageCredentialInstaller(SubmissionStageCredentialInstallerConfig{Authority: a}, VerifiedSubmissionStageCredentialPackage{})
			return err
		}},
		{"target registration launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesTargetRegistrationLauncher(TargetRegistrationLauncherConfig{Authority: a}, VerifiedTargetRegistrationMaterial{})
			return err
		}},
		{"target registration recovery", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := RecoverTargetRegistration(context.Background(), TargetRegistrationRecoveryConfig{GitOps: a})
			return err
		}},
		{"enablement launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesEnablementStageLauncher(EnablementStageLauncherConfig{Authority: a}, VerifiedEnablementStagePackage{}, VerifiedEnablementStageCredentialPackage{}, VerifiedEnablementStageRuntimePrerequisite{})
			return err
		}},
		{"target access launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesTargetAccessStageLauncher(TargetAccessStageLauncherConfig{Authority: a}, VerifiedTargetAccessStagePackage{}, VerifiedTargetAccessStageCredentialPackage{}, VerifiedTargetAccessStageRuntimePrerequisite{})
			return err
		}},
		{"aggregate evidence launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesAggregateEvidenceStageLauncher(AggregateEvidenceStageLauncherConfig{Authority: a}, VerifiedAggregateEvidenceStagePackage{}, VerifiedAggregateEvidenceStageCredentialPackage{}, VerifiedAggregateEvidenceStagePrivateInputPackage{}, VerifiedAggregateEvidenceStageRuntimePrerequisite{})
			return err
		}},
		{"lifecycle observation launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesLifecycleObservationStageLauncher(LifecycleObservationStageLauncherConfig{Authority: a}, VerifiedLifecycleObservationStagePackage{}, VerifiedLifecycleObservationStageCredentialPackage{}, VerifiedLifecycleObservationStageRuntimePrerequisite{})
			return err
		}},
		{"network observation launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesNetworkObservationStageLauncher(NetworkObservationStageLauncherConfig{Authority: a}, VerifiedNetworkObservationStagePackage{}, VerifiedNetworkObservationStageCredentialPackage{}, VerifiedNetworkObservationStageRuntimePrerequisite{})
			return err
		}},
		{"runtime binding launch opener", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedRuntimeBindingStageLaunchMaterial{}).Open(RuntimeBindingStageLaunchOpenConfig{Authority: a})
			return err
		}},
		{"full-run activation launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesFullRunExecutionActivationLauncher(FullRunExecutionActivationLauncherConfig{Authority: a}, VerifiedFullRunExecutionActivationPackage{})
			return err
		}},
		{"post-runtime activation launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesPostRuntimeExecutionActivationLauncher(PostRuntimeExecutionActivationLauncherConfig{Authority: a}, VerifiedPostRuntimeExecutionActivationPackage{})
			return err
		}},
		{"platform applications launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesPlatformApplicationsLauncher(PlatformApplicationsLauncherConfig{Authority: a}, VerifiedPlatformApplicationsStageBundle{})
			return err
		}},
		{"observability collector runtime launcher", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesObservabilityCollectorRuntimeLauncher(ObservabilityCollectorRuntimeLauncherConfig{Authority: a}, VerifiedObservabilityCollectorRuntimePackage{})
			return err
		}},
		{"observability credentials installer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenObservabilityCredentialInstaller(ObservabilityCredentialInstallationConfig{Authority: a})
			return err
		}},
		{"aggregate observer management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesAggregateObserver(KubernetesAggregateObserverConfig{Management: a})
			return err
		}},
		{"aggregate observer GitOps", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesAggregateObserver(KubernetesAggregateObserverConfig{Argo: a})
			return err
		}},
		{"lifecycle stage observer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesLifecycleStageObserver(KubernetesLifecycleStageObserverConfig{Management: a})
			return err
		}},
		{"submission bundle open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedSubmissionStageBundle{}).Open(SubmissionStageRuntimeConfig{Authority: a})
			return err
		}},
		{"enablement bundle open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedEnablementStageBundle{}).Open(SubmissionStageRuntimeConfig{Authority: a})
			return err
		}},
		{"lifecycle observation bundle open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedLifecycleObservationStageBundle{}).Open(LifecycleObservationStageRuntimeConfig{Management: a})
			return err
		}},
		{"network observation bundle management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedNetworkObservationStageBundle{}).Open(NetworkObservationStageRuntimeConfig{Management: a})
			return err
		}},
		{"network observation bundle workload", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedNetworkObservationStageBundle{}).Open(NetworkObservationStageRuntimeConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"platform observation bundle open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedPlatformObservationStageBundle{}).Open(PlatformObservationStageRuntimeConfig{Argo: a})
			return err
		}},
		{"platform applications bundle open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedPlatformApplicationsStageBundle{}).Open(PlatformApplicationsStageRuntimeConfig{GitOps: a})
			return err
		}},
		{"target registration bundle open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedTargetRegistrationStageBundle{}).Open(TargetRegistrationStageRuntimeConfig{GitOps: a})
			return err
		}},
		{"target registration handoff open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedTargetRegistrationStageBundle{}).OpenHandoff(TargetRegistrationStageHandoffRuntimeConfig{GitOps: a})
			return err
		}},
		{"aggregate evidence bundle open management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedAggregateEvidenceStageBundle{}).Open(AggregateEvidenceStageRuntimeConfig{Observer: KubernetesAggregateObserverConfig{Management: a}})
			return err
		}},
		{"aggregate evidence bundle open GitOps", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedAggregateEvidenceStageBundle{}).Open(AggregateEvidenceStageRuntimeConfig{Observer: KubernetesAggregateObserverConfig{Argo: a}})
			return err
		}},
		{"target access stage operation", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesTargetAccessStageOperation(KubernetesTargetAccessStageOperationConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"execution operation infrastructure", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesExecutionOperation(KubernetesExecutionOperationConfig{Infrastructure: a})
			return err
		}},
		{"execution operation management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesExecutionOperation(KubernetesExecutionOperationConfig{Management: a})
			return err
		}},
		{"execution operation observer management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesExecutionOperation(KubernetesExecutionOperationConfig{Observer: KubernetesAggregateObserverConfig{Management: a}})
			return err
		}},
		{"execution operation observer GitOps", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesExecutionOperation(KubernetesExecutionOperationConfig{Observer: KubernetesAggregateObserverConfig{Argo: a}})
			return err
		}},
		{"workload authority resolver static open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenWorkloadAuthorityFileResolver(workloadResolverConfigForTest(a))
			return err
		}},
		{"deferred full-run authority binding", func(t *testing.T, a KubernetesAuthorityConfig) error {
			return NewDeferredFullRunWorkloadAuthorityResolver().BindFullRunWorkloadAuthority(workloadResolverConfigForTest(a))
		}},
		{"workload authority resolver load", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, _, err := loadWorkloadAuthorityFiles(workloadResolverConfigForTest(a))
			return err
		}},
		{"target credential issuer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenTargetCredentialIssuer(VerifiedTargetCredentialStageBundle{}, TargetCredentialIssuerConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"collector observer credential issuer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesObservabilityCollectorObserverCredentialIssuer(ObservabilityCollectorObserverCredentialConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"collector installer credential issuer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesObservabilityCollectorInstallerCredentialIssuer(ObservabilityCollectorInstallerCredentialConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"collector runtime authority installer", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := OpenKubernetesObservabilityCollectorRuntimeAuthorityInstaller(workloadResolverConfigForTest(a), VerifiedObservabilityCollectorRuntimeAuthorityPackage{})
			return err
		}},
		{"collector post-prefix activation", func(t *testing.T, a KubernetesAuthorityConfig) error {
			return (&KubernetesObservabilityCollectorPostPrefix{}).ActivateFullRunPostPrefix(context.Background(), FullRunPostPrefixActivation{Workload: workloadResolverConfigForTest(a)})
		}},
		{"target credential recovery", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, _, err := RecoverTargetCredential(context.Background(), TargetCredentialRecoveryConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"runtime binding stage open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedRuntimeBindingStageBundle{}).Open(RuntimeBindingStageRuntimeConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"runtime binding Kubernetes stage open", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedRuntimeBindingStageBundle{}).OpenKubernetes(RuntimeBindingStageKubernetesRuntimeConfig{Workload: workloadResolverConfigForTest(a)})
			return err
		}},
		{"runtime binding Kubernetes stage persistence", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := (VerifiedRuntimeBindingStageBundle{}).OpenKubernetes(RuntimeBindingStageKubernetesRuntimeConfig{Persistence: a})
			return err
		}},
		{"aggregate evidence file runtime load", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := LoadAggregateEvidenceStageFileRuntime(AggregateEvidenceStageFileRuntimeConfig{Management: a})
			return err
		}},
		{"aggregate evidence file runtime GitOps", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := LoadAggregateEvidenceStageFileRuntime(AggregateEvidenceStageFileRuntimeConfig{Argo: a})
			return err
		}},
		{"aggregate evidence file runtime workload", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := LoadAggregateEvidenceStageFileRuntime(AggregateEvidenceStageFileRuntimeConfig{WorkloadKubeconfigFile: a.KubeconfigFile, WorkloadTokenFile: a.TokenFile, WorkloadCAFile: a.CAFile, RuntimeMaterialPath: a.CAFile, RuntimeReceiptPath: a.CAFile})
			return err
		}},
		{"platform observation file runtime", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := LoadPlatformObservationStageFileRuntime(PlatformObservationStageFileRuntimeConfig{Argo: a, RuntimeMaterialPath: a.CAFile, RuntimeReceiptPath: a.CAFile})
			return err
		}},
		{"first-run platform observation runtime", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := loadFirstRunPlatformObservationRuntime(PlatformObservationStageFileRuntimeConfig{Argo: a, RuntimeMaterialPath: a.CAFile, RuntimeReceiptPath: a.CAFile}, nil)
			return err
		}},
		{"first-run aggregate runtime GitOps", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := loadFirstRunAggregateEvidenceRuntime(AggregateEvidenceStageFileRuntimeConfig{Argo: a}, nil)
			return err
		}},
		{"first-run aggregate runtime management", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := loadFirstRunAggregateEvidenceRuntime(AggregateEvidenceStageFileRuntimeConfig{Management: a}, nil)
			return err
		}},
		{"first-run aggregate runtime workload", func(t *testing.T, a KubernetesAuthorityConfig) error {
			_, err := loadFirstRunAggregateEvidenceRuntime(AggregateEvidenceStageFileRuntimeConfig{WorkloadKubeconfigFile: a.KubeconfigFile, WorkloadTokenFile: a.TokenFile, WorkloadCAFile: a.CAFile, RuntimeMaterialPath: a.CAFile, RuntimeReceiptPath: a.CAFile}, nil)
			return err
		}},
		{"derived workload authority resolver", func(t *testing.T, a KubernetesAuthorityConfig) error {
			policy := observation.Policy{
				Format: observation.PolicyFormat, IntentRevision: runnerStageSHA("a"),
				EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"),
				TargetClusterUID: "cluster-runtime-uid-147", Required: []string{"NetworkReady"},
			}
			_, err := (&runtimeBindingWorkloadAuthorityResolver{
				targetUID: policy.TargetClusterUID, endpoint: "https://192.0.2.22:6443", caDigest: runnerStageSHA("d"),
				kubeconfigFile: a.KubeconfigFile, tokenFile: a.TokenFile,
			}).ResolveWorkloadAuthority(context.Background(), policy)
			return err
		}},
	}
	for _, tc := range tests {
		for _, mode := range []string{"kubeconfig-only", "token-and-kubeconfig"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				root := t.TempDir()
				tokenPath := filepath.Join(root, "token")
				caPath := filepath.Join(root, "ca.crt")
				kubeconfigPath := filepath.Join(root, "kubeconfig")
				for path, value := range map[string][]byte{
					tokenPath: []byte("short-lived-token"), caPath: testCA(t), kubeconfigPath: []byte("client-certificate: never-read"),
				} {
					if err := os.WriteFile(path, value, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				a := KubernetesAuthorityConfig{Endpoint: server.URL, AuthorityIdentity: "management", CAFile: caPath, CABundleDigest: runnerStageSHA("authority-ca"), KubeconfigFile: kubeconfigPath}
				if mode == "token-and-kubeconfig" {
					a.TokenFile = tokenPath
				}
				err := assertNoCredentialFilesOpened(t, []string{tokenPath, caPath, kubeconfigPath}, func() error { return tc.open(t, a) })
				if !errors.Is(err, ErrClientCertificateDisabled) {
					t.Fatalf("got %v, want ErrClientCertificateDisabled", err)
				}
			})
		}
	}
	if requests.Load() != 0 || connections.Load() != 0 {
		t.Fatalf("rejected kubeconfig authority contacted API: requests=%d connections=%d", requests.Load(), connections.Load())
	}
}

func workloadResolverConfigForTest(authority KubernetesAuthorityConfig) WorkloadAuthorityFileResolverConfig {
	return WorkloadAuthorityFileResolverConfig{
		Path: authority.CAFile, ExpectedBindingDigest: authority.CABundleDigest,
		TokenFile: authority.TokenFile, KubeconfigFile: authority.KubeconfigFile, CAFile: authority.CAFile,
	}
}
