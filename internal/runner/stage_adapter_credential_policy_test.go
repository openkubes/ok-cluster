package runner

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

// Empty package/candidate values are deliberate: credential rejection must
// precede even package verification, file loading, or a usable adapter result.
// These are open-boundary tests, not evidence of stage/grant execution.
func TestStageAdapterCredentialPolicyBeforeOpen(t *testing.T) {
	openers := []struct {
		name string
		open func(KubernetesAuthorityConfig) (bool, error)
	}{
		{"submission_stage_installer", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesSubmissionStagePackageInstaller(a, VerifiedSubmissionStagePackage{})
			return opened == nil, err
		}},
		{"submission_stage_runtime_installer", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesSubmissionStageRuntimeInstaller(a, VerifiedSubmissionStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"submission_stage_credential_installer", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesSubmissionStageCredentialInstaller(SubmissionStageCredentialInstallerConfig{Authority: a}, VerifiedSubmissionStageCredentialPackage{})
			return opened == nil, err
		}},
		{"submission_stage_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesSubmissionStageLauncher(SubmissionStageLauncherConfig{Authority: a}, VerifiedSubmissionStagePackage{}, VerifiedSubmissionStageCredentialPackage{}, VerifiedSubmissionStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"lifecycle_observation_stage_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesLifecycleObservationStageLauncher(LifecycleObservationStageLauncherConfig{Authority: a}, VerifiedLifecycleObservationStagePackage{}, VerifiedLifecycleObservationStageCredentialPackage{}, VerifiedLifecycleObservationStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"enablement_stage_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesEnablementStageLauncher(EnablementStageLauncherConfig{Authority: a}, VerifiedEnablementStagePackage{}, VerifiedEnablementStageCredentialPackage{}, VerifiedEnablementStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"network_observation_stage_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesNetworkObservationStageLauncher(NetworkObservationStageLauncherConfig{Authority: a}, VerifiedNetworkObservationStagePackage{}, VerifiedNetworkObservationStageCredentialPackage{}, VerifiedNetworkObservationStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"target_access_stage_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesTargetAccessStageLauncher(TargetAccessStageLauncherConfig{Authority: a}, VerifiedTargetAccessStagePackage{}, VerifiedTargetAccessStageCredentialPackage{}, VerifiedTargetAccessStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"aggregate_evidence_stage_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesAggregateEvidenceStageLauncher(AggregateEvidenceStageLauncherConfig{Authority: a}, VerifiedAggregateEvidenceStagePackage{}, VerifiedAggregateEvidenceStageCredentialPackage{}, VerifiedAggregateEvidenceStagePrivateInputPackage{}, VerifiedAggregateEvidenceStageRuntimePrerequisite{})
			return opened == nil, err
		}},
		{"target_registration_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesTargetRegistrationLauncher(TargetRegistrationLauncherConfig{Authority: a}, VerifiedTargetRegistrationMaterial{})
			return opened == nil, err
		}},
		{"platform_applications_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesPlatformApplicationsLauncher(PlatformApplicationsLauncherConfig{Authority: a}, VerifiedPlatformApplicationsStageBundle{})
			return opened == nil, err
		}},
		{"observability_collector_runtime_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesObservabilityCollectorRuntimeLauncher(ObservabilityCollectorRuntimeLauncherConfig{Authority: a}, VerifiedObservabilityCollectorRuntimePackage{})
			return opened == nil, err
		}},
		{"post_runtime_activation_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesPostRuntimeExecutionActivationLauncher(PostRuntimeExecutionActivationLauncherConfig{Authority: a}, VerifiedPostRuntimeExecutionActivationPackage{})
			return opened == nil, err
		}},
		{"full_run_activation_launcher", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesFullRunExecutionActivationLauncher(FullRunExecutionActivationLauncherConfig{Authority: a}, VerifiedFullRunExecutionActivationPackage{})
			return opened == nil, err
		}},
		{"runtime_binding_stage_launch_open", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := (VerifiedRuntimeBindingStageLaunchMaterial{}).Open(RuntimeBindingStageLaunchOpenConfig{Authority: a})
			return opened == nil, err
		}},

		{"lifecycle_observer", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesLifecycleStageObserver(KubernetesLifecycleStageObserverConfig{Management: a})
			return opened == nil, err
		}},
		{"enablement_operation", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := OpenKubernetesEnablementStageOperation(KubernetesEnablementStageOperationConfig{Authority: a})
			return opened.Ledger == nil && opened.Mutator == nil && opened.Clock == nil, err
		}},
		{"authority_transport", func(a KubernetesAuthorityConfig) (bool, error) {
			opened, err := openBoundedKubernetesAuthorityTransport(a)
			return opened.client == nil && opened.credentialIdentity == "" && opened.bearerToken == "" && !opened.clientCertificate && len(opened.keyData) == 0 && len(opened.certificateData) == 0 && len(opened.caData) == 0, err
		}},
	}
	for _, opener := range openers {
		t.Run(opener.name, func(t *testing.T) {
			for _, mode := range []string{"kubeconfig_only", "both", "neither"} {
				t.Run(mode, func(t *testing.T) {
					var connections, requests atomic.Int32
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
					// Files do not exist: denial must not depend on loading any of them.
					root := t.TempDir()
					a := KubernetesAuthorityConfig{Endpoint: server.URL, AuthorityIdentity: "ok-mgmt", CAFile: filepath.Join(root, "must-not-read-ca")}
					if mode != "neither" {
						a.KubeconfigFile = filepath.Join(root, "must-not-read-kubeconfig")
					}
					if mode == "both" {
						a.TokenFile = filepath.Join(root, "must-not-read-token")
					}
					empty, err := opener.open(a)
					if !empty || err == nil {
						t.Fatalf("credential mode returned a usable adapter or no error: empty=%v err=%v", empty, err)
					}
					if mode != "neither" && !errors.Is(err, ErrClientCertificateDisabled) {
						t.Fatalf("unsupported credential lost policy sentinel: %v", err)
					}
					if mode == "neither" && (errors.Is(err, ErrClientCertificateDisabled) || !strings.Contains(err.Error(), "exactly one transport credential")) {
						t.Fatalf("missing credential mode not rejected explicitly: %v", err)
					}
					if strings.Contains(err.Error(), root) || connections.Load() != 0 || requests.Load() != 0 {
						t.Fatalf("denial leaked a path or contacted API: connections=%d requests=%d err=%v", connections.Load(), requests.Load(), err)
					}
				})
			}
		})
	}
}

func TestRuntimeInstallerCredentialPolicyWithValidPrerequisite(t *testing.T) {
	prerequisite := submissionStageRuntimePrerequisite(t)
	root := t.TempDir()
	tokenPath, caPath := filepath.Join(root, "token"), filepath.Join(root, "ca")
	ca := testCA(t)
	for path, raw := range map[string][]byte{tokenPath: []byte("synthetic-installer-token"), caPath: ca} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a := KubernetesAuthorityConfig{
		Endpoint: "https://192.0.2.10:6443", AuthorityIdentity: prerequisite.receipt.Authority,
		TokenFile: tokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
	}
	// Positive control: exact valid local prerequisites + token mode still open.
	if opened, err := OpenKubernetesSubmissionStageRuntimeInstaller(a, prerequisite); err != nil || opened == nil {
		t.Fatalf("token-only positive control failed: %v", err)
	}
	a.KubeconfigFile = filepath.Join(root, "must-not-read-kubeconfig")
	for _, mode := range []string{"both", "kubeconfig_only"} {
		t.Run(mode, func(t *testing.T) {
			config := a
			if mode == "kubeconfig_only" {
				config.TokenFile = ""
			}
			opened, err := OpenKubernetesSubmissionStageRuntimeInstaller(config, prerequisite)
			if opened != nil || !errors.Is(err, ErrClientCertificateDisabled) || strings.Contains(err.Error(), root) {
				t.Fatalf("otherwise-valid unsupported mode accepted or leaked: %v", err)
			}
		})
	}
}

func TestStageAdapterOpenErrorsRetainCause(t *testing.T) {
	t.Run("lifecycle source", func(t *testing.T) {
		plan := runnerStagedPlan(t)
		opened, err := OpenKubernetesLifecycleStageObserver(KubernetesLifecycleStageObserverConfig{
			Plan: plan,
			Management: KubernetesAuthorityConfig{
				Endpoint: "https://192.0.2.10:6443", AuthorityIdentity: plan.Authorities.Management,
				TokenFile: filepath.Join(t.TempDir(), "absent-token"), CAFile: filepath.Join(t.TempDir(), "absent-ca"),
			},
		})
		if opened != nil || err == nil || errors.Unwrap(err) == nil || !strings.HasPrefix(err.Error(), "open bounded lifecycle observation source: ") {
			t.Fatalf("source open discarded its cause: %v", err)
		}
	})
	for _, which := range []string{"ledger", "authority"} {
		t.Run("enablement "+which, func(t *testing.T) {
			config := runnerEnablementOperationConfig(t, runnerStagedPlan(t))
			prefix := "open enablement stage ledger: "
			if which == "ledger" {
				config.Ledger.TokenFile = filepath.Join(t.TempDir(), "absent-token")
			} else {
				config.Authority.TokenFile = filepath.Join(t.TempDir(), "absent-token")
				prefix = "open enablement submission authority: "
			}
			opened, err := OpenKubernetesEnablementStageOperation(config)
			if opened.Ledger != nil || opened.Mutator != nil || opened.Clock != nil || err == nil || errors.Unwrap(err) == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("operation open discarded its cause: %v", err)
			}
		})
	}
}
