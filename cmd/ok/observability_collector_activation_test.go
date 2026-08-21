package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestObservabilityCollectorPackageBindsPostRuntimeInputs(t *testing.T) {
	original := materializeObservabilityCollectorRuntimePackage
	defer func() { materializeObservabilityCollectorRuntimePackage = original }()
	var captured runner.ObservabilityCollectorRuntimePackageConfig
	materializeObservabilityCollectorRuntimePackage = func(config runner.ObservabilityCollectorRuntimePackageConfig) ([]byte, runner.ObservabilityCollectorRuntimePackageReceipt, error) {
		captured = config
		return []byte("private-collector-package"), runner.ObservabilityCollectorRuntimePackageReceipt{
			Format: runner.ObservabilityCollectorRuntimePackageFormat, State: "VERIFIED",
			PackageDigest: testSHA("a"), MutationAllowed: false,
		}, nil
	}
	output := filepath.Join(t.TempDir(), "collector-package.yaml")
	stdout := &bytes.Buffer{}
	if err := run(observabilityCollectorPackageArguments(t, output), stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if captured.Activation.ManifestPath != "/private/full-run.json" || captured.Activation.ExpectedReceiptDigest != testSHA("b") ||
		captured.Activation.RuntimeBinding.MaterialPath != "/private/runtime-binding.json" ||
		captured.Activation.ObserverCredential.ExpectedSubject != "system:serviceaccount:ok-observability:ok147-observability-autonomy" ||
		len(captured.Activation.ObserverCredential.ExpectedAudiences) != 1 || captured.Activation.ObserverCredential.ExpectedAudiences[0] != "https://kubernetes.default.svc" ||
		captured.Activation.MaximumRecordAge != 10*time.Minute || captured.Activation.RuntimeBinding.Bundle.PlanExpected.ManagementAuthority != "ok-mgmt" ||
		captured.RunID != "ok147-evidence-collector-01" || captured.WorkloadAPICIDR != "192.0.2.147/32" || len(captured.JobTemplate) == 0 {
		t.Fatalf("collector package inputs differ: %#v", captured)
	}
	raw, err := os.ReadFile(output)
	if err != nil || string(raw) != "private-collector-package" {
		t.Fatalf("private collector package not written: %q %v", raw, err)
	}
	info, err := os.Lstat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("collector package is not private: %v %#v", err, info)
	}
	var receipt runner.ObservabilityCollectorRuntimePackageReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "VERIFIED" || receipt.MutationAllowed {
		t.Fatalf("unexpected collector package receipt: %#v err=%v", receipt, err)
	}
}

func TestObservabilityCollectorPackageFailsBeforeBuilder(t *testing.T) {
	original := materializeObservabilityCollectorRuntimePackage
	defer func() { materializeObservabilityCollectorRuntimePackage = original }()
	calls := 0
	materializeObservabilityCollectorRuntimePackage = func(runner.ObservabilityCollectorRuntimePackageConfig) ([]byte, runner.ObservabilityCollectorRuntimePackageReceipt, error) {
		calls++
		return nil, runner.ObservabilityCollectorRuntimePackageReceipt{}, nil
	}
	arguments := observabilityCollectorPackageArguments(t, filepath.Join(t.TempDir(), "collector.yaml"))
	arguments = replaceArgument(arguments, "--observer-token-digest", "sha256:bad")
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || calls != 0 {
		t.Fatal("unsafe collector package input reached the builder")
	}
}

func TestObservabilityCollectorMaterializeUsesExactDigests(t *testing.T) {
	original := materializeObservabilityCollectorActivation
	defer func() { materializeObservabilityCollectorActivation = original }()
	var captured runner.ObservabilityCollectorActivationMaterializationConfig
	materializeObservabilityCollectorActivation = func(config runner.ObservabilityCollectorActivationMaterializationConfig) (runner.ObservabilityCollectorActivationMaterializationReceipt, error) {
		captured = config
		return runner.ObservabilityCollectorActivationMaterializationReceipt{
			Format: runner.ObservabilityCollectorActivationMaterializationReceiptFormat,
			State:  "MATERIALIZED_VERIFIED", PrivateStateReady: true, KubernetesMutationAllowed: false,
		}, nil
	}
	stdout := &bytes.Buffer{}
	if err := run([]string{
		"cluster", "stage", "evidence", "observability", "collector", "materialize",
		"--source", "/var/run/openkubes/collector-source", "--destination", "/var/run/openkubes/collector",
		"--state-directory", "/var/lib/openkubes/observability-evidence",
		"--expected-activation-digest", testSHA("1"), "--expected-manifest-digest", testSHA("2"),
		"--expected-runtime-binding-digest", testSHA("3"), "--expected-public-endpoint-digest", testSHA("4"),
		"--materialize",
	}, stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if captured.ExpectedActivationDigest != testSHA("1") || captured.ExpectedRuntimeBinding != testSHA("3") ||
		captured.StateDirectory != "/var/lib/openkubes/observability-evidence" {
		t.Fatalf("collector materialization inputs differ: %#v", captured)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"state": "MATERIALIZED_VERIFIED"`)) {
		t.Fatal("collector materialization receipt missing")
	}
}

func observabilityCollectorPackageArguments(t *testing.T, output string) []string {
	t.Helper()
	template := "../../deploy/observability-evidence-collector-job.yaml.tpl"
	if _, err := os.Stat(template); err != nil {
		t.Fatal(err)
	}
	return []string{
		"cluster", "stage", "evidence", "observability", "collector", "package",
		"--manifest", "/private/full-run.json", "--expected-manifest-digest", testSHA("a"),
		"--manifest-receipt", "/private/full-run-receipt.json", "--expected-manifest-receipt-digest", testSHA("b"),
		"--plan", "/private/plan.json", "--contract-namespace", "openkubes-system", "--contract-name", "disposable-ok147",
		"--intent-revision", testSHA("1"), "--enablement-revision", testSHA("2"), "--platform-revision", testSHA("3"),
		"--execution-fixture", testSHA("4"), "--infrastructure-authority", "ok-infra", "--management-authority", "ok-mgmt",
		"--gitops-authority", "ok-shared",
		"--receipt", "/private/01.json@" + testSHA("a"), "--receipt", "/private/02.json@" + testSHA("b"),
		"--receipt", "/private/03.json@" + testSHA("c"), "--receipt", "/private/04.json@" + testSHA("d"),
		"--receipt", "/private/05.json@" + testSHA("e"), "--receipt", "/private/06.json@" + testSHA("f"),
		"--runtime-binding-material", "/private/runtime-binding.json", "--runtime-binding-receipt", "/private/runtime-binding-receipt.json",
		"--activation-secret", "ok147-observability-collector-activation", "--materialization-time", "2026-08-21T10:00:00Z",
		"--observer-authority", testSHA("6"), "--observer-token-file", "/private/observer-token", "--observer-token-digest", testSHA("7"),
		"--observer-ca-file", "/private/workload-ca.crt", "--observer-ca-digest", testSHA("8"),
		"--observer-tokenrequest-evidence-digest", testSHA("9"), "--observer-issuer", "https://kubernetes.default.svc.cluster.local",
		"--observer-subject", "system:serviceaccount:ok-observability:ok147-observability-autonomy",
		"--observer-audience", "https://kubernetes.default.svc", "--observer-issued-at", "2026-08-21T09:59:00Z",
		"--observer-expires-at", "2026-08-21T10:45:00Z", "--webhook-token-file", "/private/webhook-token",
		"--query-token-file", "/private/query-token", "--public-endpoint", "https://192.0.2.44:8443",
		"--listen", "0.0.0.0:8443", "--tls-cert", "/private/tls.crt", "--tls-key", "/private/tls.key",
		"--maximum-record-age", "10m", "--job-template", template, "--job-template-digest", testSHA("d"),
		"--run-id", "ok147-evidence-collector-01", "--image", "ghcr.io/openkubes/ok-cluster@" + testSHA("c"),
		"--workload-api-cidr", "192.0.2.147/32", "--alert-source-cidr", "10.244.0.0/16", "--output", output,
	}
}
