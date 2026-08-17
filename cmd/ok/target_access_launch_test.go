package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestTargetAccessStagePackageWritesVerifiedOfflineArtifact(t *testing.T) {
	previous := materializeTargetAccessStagePackage
	defer func() { materializeTargetAccessStagePackage = previous }()
	var captured runner.TargetAccessStagePackageConfig
	materializeTargetAccessStagePackage = func(config runner.TargetAccessStagePackageConfig) ([]byte, runner.TargetAccessStagePackageReceipt, error) {
		captured = config
		return []byte("verified-target-access-package\n"), runner.TargetAccessStagePackageReceipt{
			Format: runner.TargetAccessStagePackageFormat, State: "VERIFIED", StageID: "target-access",
			PackageDigest: testSHA("1"), InputConfigMapDigest: testSHA("2"), ReceiptPrefixDigest: testSHA("3"),
			TargetAccessDigest: testSHA("4"), TargetIdentityDigest: testSHA("5"), WorkloadBindingDigest: testSHA("6"),
			InstallationAuthority: "ok-shared", JobTemplateDigest: testSHA("7"), JobEnvelopeDigest: testSHA("8"),
			ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"}, AuthorizationState: "VERIFIED", MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template := filepath.Join(root, "target-access-job.yaml.tpl")
	if err := os.WriteFile(template, []byte("bounded-target-access-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "target-access-package.yaml")
	arguments := targetAccessStagePackageArguments(template, output)
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Bundle.PlanPath != "/tmp/plan.json" || len(captured.Bundle.Receipts) != 6 || len(captured.Bundle.ExpectedObjects) != 8 || captured.RunID != "ok147-target-access-20260817-01" {
		t.Fatalf("unexpected target-access package config: %#v", captured)
	}
	if captured.Bundle.ExpectedObjects[0].Name != "ok-observability" || captured.Bundle.ExpectedObjects[7].Namespace != "kube-system" || captured.Bundle.PlanExpected.GitOpsAuthority != "ok-shared" {
		t.Fatalf("target-access authority or object identities differ: %#v", captured.Bundle)
	}
	if string(captured.JobTemplate) != "bounded-target-access-template" || captured.JobTemplateDigest != digest.SHA256([]byte("bounded-target-access-template")) || captured.LedgerCredentialSecret == captured.WorkloadCredentialSecret || captured.WorkloadBindingPath != "/private/tmp/runtime-binding.json" {
		t.Fatalf("target-access private package inputs differ: %#v", captured)
	}
	written, err := os.ReadFile(output)
	if err != nil || string(written) != "verified-target-access-package\n" {
		t.Fatalf("unexpected target-access package: %q %v", written, err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("target-access package mode is not 0600: %v %v", info, err)
	}
	var receipt runner.TargetAccessStagePackageReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.AuthorizationState != "VERIFIED" || receipt.MutationAllowed || receipt.InstallationAuthority != "ok-shared" {
		t.Fatalf("unsafe target-access package receipt: %#v", receipt)
	}
	stdout.Reset()
	if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("existing target-access package was overwritten")
	}
}

func TestTargetAccessStagePackageRejectsIncompleteInputs(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "target-access-job.yaml.tpl")
	if err := os.WriteFile(template, []byte("bounded-target-access-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := targetAccessStagePackageArguments(template, filepath.Join(root, "target-access-package.yaml"))
	for name, arguments := range map[string][]string{
		"execute":                    append(append([]string{}, valid...), "--execute"),
		"missing template digest":    removeArgumentWithValue(valid, "--job-template-digest"),
		"missing workload secret":    removeArgumentWithValue(valid, "--workload-credential-secret"),
		"missing workload binding":   removeArgumentWithValue(valid, "--workload-binding"),
		"missing independent object": removeArgumentWithValue(valid, "--cluster-rolebinding"),
		"invalid time":               replaceArgument(valid, "--evaluation-time", "not-time"),
		"positional":                 append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe target-access package input was accepted: %v %s", err, stdout.String())
			}
		})
	}
}

func targetAccessStagePackageArguments(template, output string) []string {
	arguments := targetAccessStageRunArguments()
	arguments = removeArgument(arguments, "--execute")
	for _, name := range []string{
		"--ledger-api-endpoint", "--ledger-token-file", "--ledger-ca-file",
		"--workload-token-file", "--workload-ca-file",
	} {
		arguments = removeArgumentWithValue(arguments, name)
	}
	arguments = append(arguments[:4], append([]string{"package"}, arguments[4:]...)...)
	return append(arguments,
		"--job-template", template, "--job-template-digest", digest.SHA256([]byte("bounded-target-access-template")),
		"--output", output, "--run-id", "ok147-target-access-20260817-01",
		"--image", "ghcr.io/openkubes/ok-cluster@"+testSHA("a"), "--input-configmap", "ok147-target-access-input",
		"--ledger-api-url", "https://192.0.2.12:6443", "--ledger-api-cidr", "192.0.2.12/32", "--ledger-credential-secret", "ok147-ledger-target-access",
		"--workload-api-url", "https://192.0.2.13:6443", "--workload-api-cidr", "192.0.2.13/32", "--workload-credential-secret", "ok147-workload-target-access",
	)
}
