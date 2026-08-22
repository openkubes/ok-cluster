package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestObservabilityCollectorLaunchPrepareEmitsNonAuthorizingPlan(t *testing.T) {
	original := prepareObservabilityCollectorLaunch
	defer func() { prepareObservabilityCollectorLaunch = original }()
	var captured runner.ObservabilityCollectorRuntimePackageFileConfig
	prepareObservabilityCollectorLaunch = func(config runner.ObservabilityCollectorRuntimePackageFileConfig) (observabilityCollectorLaunchPreparation, error) {
		captured = config
		return observabilityCollectorLaunchPreparation{
			Format: "ok147-observability-collector-launch-preparation/v1", State: "PREPARED",
			Plan:            runner.ObservabilityCollectorRuntimeInstallationPlan{Format: runner.ObservabilityCollectorRuntimeInstallationPlanFormat, State: "VERIFIED"},
			MutationAllowed: false,
		}, nil
	}
	var stdout, stderr bytes.Buffer
	receiptDigest := "sha256:" + string(bytes.Repeat([]byte("a"), 64))
	err := runClusterStageEvidenceObservabilityCollectorLaunchPrepare([]string{
		"--package", "/private/tmp/collector.yaml", "--package-receipt", "receipt.json",
		"--expected-package-receipt-digest", receiptDigest,
	}, &stdout, &stderr)
	if err != nil || captured.PackagePath != "/private/tmp/collector.yaml" || captured.ReceiptPath != "receipt.json" || captured.ExpectedReceiptDigest != receiptDigest {
		t.Fatalf("collector prepare inputs differ: %#v err=%v stderr=%s", captured, err, stderr.String())
	}
	var output observabilityCollectorLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || output.State != "PREPARED" || output.MutationAllowed {
		t.Fatalf("unexpected collector preparation: %#v %v", output, err)
	}
}

func TestObservabilityCollectorLaunchExecuteRequiresExplicitMutation(t *testing.T) {
	original := executeObservabilityCollectorLaunch
	defer func() { executeObservabilityCollectorLaunch = original }()
	called := false
	executeObservabilityCollectorLaunch = func(context.Context, runner.ObservabilityCollectorRuntimePackageFileConfig, runner.KubernetesAuthorityConfig, string) (runner.ObservabilityCollectorRuntimeLaunchReceipt, error) {
		called = true
		return runner.ObservabilityCollectorRuntimeLaunchReceipt{Format: runner.ObservabilityCollectorRuntimeLaunchReceiptFormat, State: "ACTIVATED"}, nil
	}
	var stdout, stderr bytes.Buffer
	digest := "sha256:" + string(bytes.Repeat([]byte("b"), 64))
	arguments := []string{
		"--package", "/private/tmp/collector.yaml", "--package-receipt", "receipt.json", "--expected-package-receipt-digest", digest,
		"--expected-package-digest", digest, "--installer-api-endpoint", "https://192.0.2.10:6443", "--installer-ca-digest", digest,
		"--installer-token-file", "/private/tmp/token", "--installer-ca-file", "/private/tmp/ca",
	}
	if err := runClusterStageEvidenceObservabilityCollectorLaunchExecute(context.Background(), arguments, &stdout, &stderr); err == nil || called {
		t.Fatalf("collector launch ran without --execute: called=%v err=%v", called, err)
	}
	arguments = append(arguments, "--execute")
	if err := runClusterStageEvidenceObservabilityCollectorLaunchExecute(context.Background(), arguments, &stdout, &stderr); err != nil || !called {
		t.Fatalf("collector launch did not execute: called=%v err=%v", called, err)
	}
}
