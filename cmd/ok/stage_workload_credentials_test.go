package main

import (
	"bytes"
	"context"
	"flag"
	"testing"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestStageWorkloadCredentialSelection(t *testing.T) {
	oldNetwork := executeNetworkObservationStage
	oldBinding := executeRuntimeBindingStage
	oldSecretBinding := executeKubernetesRuntimeBindingStage
	oldAccess := executeTargetAccessStage
	t.Cleanup(func() {
		executeNetworkObservationStage = oldNetwork
		executeRuntimeBindingStage = oldBinding
		executeKubernetesRuntimeBindingStage = oldSecretBinding
		executeTargetAccessStage = oldAccess
	})
	var captured runner.WorkloadAuthorityFileResolverConfig
	var capturedResume runner.StageResumeConfig
	calls := 0
	record := func(value runner.WorkloadAuthorityFileResolverConfig) {
		captured = value
		calls++
	}
	executeNetworkObservationStage = func(_ context.Context, resume runner.StageResumeConfig, config runner.NetworkObservationStageRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
		capturedResume = resume
		record(config.Workload)
		return execution.ObservationStageRunReceipt{}, nil
	}
	executeRuntimeBindingStage = func(_ context.Context, resume runner.StageResumeConfig, config runner.RuntimeBindingStageRuntimeConfig) (execution.BindingStageRunReceipt, *runner.RuntimeBindingStageEvidenceReceipt, error) {
		capturedResume = resume
		record(config.Workload)
		return execution.BindingStageRunReceipt{}, nil, nil
	}
	executeKubernetesRuntimeBindingStage = func(_ context.Context, resume runner.StageResumeConfig, config runner.RuntimeBindingStageKubernetesRuntimeConfig) (execution.BindingStageRunReceipt, *runner.RuntimeBindingStageEvidenceReceipt, error) {
		capturedResume = resume
		record(config.Workload)
		return execution.BindingStageRunReceipt{}, nil, nil
	}
	executeTargetAccessStage = func(_ context.Context, resume runner.TargetAccessStageBundleConfig, config runner.TargetAccessStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
		capturedResume = runner.StageResumeConfig{RecoveryBindingPath: resume.RecoveryBindingPath, RecoveryBindingDigest: resume.RecoveryBindingDigest}
		record(config.Workload)
		return execution.StagedOperationReceipt{}, nil
	}
	for _, stage := range []struct {
		name string
		args func() []string
	}{
		{"network", stageObserveNetworkArguments},
		{"binding-local", stageBindRuntimeArguments},
		{"binding-secret", stageBindRuntimeKubernetesArguments},
		{"target-access", targetAccessStageRunArguments},
	} {
		t.Run(stage.name, func(t *testing.T) {
			for _, mode := range []string{"token", "kubeconfig", "both", "neither", "kubeconfig-no-execute", "kubeconfig-no-ca"} {
				t.Run(mode, func(t *testing.T) {
					args := stage.args()
					args = append(args, "--recovery-binding", "/private/recovery.json", "--recovery-binding-digest", testSHA("d"))
					if mode != "token" && mode != "both" {
						args = removeArgumentWithValue(args, "--workload-token-file")
					}
					if mode != "token" && mode != "neither" {
						args = append(args, "--workload-kubeconfig-file", "/private/guest.kubeconfig")
					}
					if mode == "kubeconfig-no-execute" {
						args = removeArgument(args, "--execute")
					}
					if mode == "kubeconfig-no-ca" {
						args = removeArgumentWithValue(args, "--workload-ca-file")
					}
					calls = 0
					var stdout, stderr bytes.Buffer
					err := run(args, &stdout, &stderr)
					if mode != "token" && mode != "kubeconfig" {
						if err == nil || calls != 0 || stdout.Len() != 0 {
							t.Fatalf("unsafe input reached execution: err=%v calls=%d stdout=%s", err, calls, stdout.String())
						}
						return
					}
					if err != nil || calls != 1 {
						t.Fatalf("credential route failed: err=%v calls=%d stderr=%s", err, calls, stderr.String())
					}
					if capturedResume.RecoveryBindingPath != "/private/recovery.json" || capturedResume.RecoveryBindingDigest != testSHA("d") {
						t.Fatal("explicit recovery binding lost in CLI routing")
					}
					if mode == "kubeconfig" && (captured.KubeconfigFile != "/private/guest.kubeconfig" || captured.TokenFile != "") {
						t.Fatalf("kubeconfig was not isolated: %#v", captured)
					}
					if mode == "token" && (captured.TokenFile == "" || captured.KubeconfigFile != "") {
						t.Fatalf("token compatibility changed: %#v", captured)
					}
					if captured.Path == "" || captured.ExpectedBindingDigest == "" || captured.CAFile == "" {
						t.Fatalf("runtime identity/CA binding lost: %#v", captured)
					}
				})
			}
		})
	}
}

func TestStageRecoveryFlagsMustBePaired(t *testing.T) {
	for _, name := range []string{"--recovery-binding", "--recovery-binding-digest"} {
		flags := flag.NewFlagSet("recovery", flag.ContinueOnError)
		values := addStageResumeFlags(flags)
		if err := flags.Parse([]string{name, "provided"}); err != nil {
			t.Fatal(err)
		}
		if _, err := values.config(); err == nil || err.Error() != "--recovery-binding and --recovery-binding-digest must be provided together" {
			t.Fatalf("incomplete recovery pair accepted: %v", err)
		}
	}
}
