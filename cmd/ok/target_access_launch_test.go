package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if captured.Bundle.PlanPath != "/tmp/plan.json" || len(captured.Bundle.Receipts) != 6 || len(captured.Bundle.ExpectedObjects) != 11 || captured.RunID != "ok147-target-access-20260817-01" {
		t.Fatalf("unexpected target-access package config: %#v", captured)
	}
	if captured.Bundle.ExpectedObjects[0].Name != "ok-observability" || captured.Bundle.ExpectedObjects[7].Namespace != "kube-system" || captured.Bundle.ExpectedObjects[10].Name != "ok147-observability-autonomy" || captured.Bundle.PlanExpected.GitOpsAuthority != "ok-shared" {
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

func TestTargetAccessLaunchPrepareBuildsOneNonMutatingCandidate(t *testing.T) {
	previous := prepareTargetAccessStageLaunch
	defer func() { prepareTargetAccessStageLaunch = previous }()
	var captured runner.TargetAccessStageLaunchMaterialConfig
	prepareTargetAccessStageLaunch = func(config runner.TargetAccessStageLaunchMaterialConfig) (targetAccessLaunchPreparation, error) {
		captured = config
		return targetAccessLaunchPreparation{
			Format: "ok147-target-access-stage-launch-preparation/v1", State: "PREPARED",
			Material: runner.TargetAccessStageLaunchMaterialReceipt{
				Format: runner.TargetAccessStageLaunchMaterialFormat, State: "VERIFIED", StageID: "target-access",
				Authority: "ok-shared", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			Candidate: runner.TargetAccessStageLaunchCandidateReceipt{
				Format: runner.TargetAccessStageLaunchCandidateFormat, State: "PREPARED", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "target-access.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-target-access-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(targetAccessLaunchPrepareArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Package.Bundle.PlanExpected.GitOpsAuthority != "ok-shared" || len(captured.Package.Bundle.ExpectedObjects) != 11 || captured.Package.RunID != "ok147-target-access-20260817-01" {
		t.Fatalf("target-access package identity differs: %#v", captured.Package)
	}
	if string(captured.Package.JobTemplate) != "bounded-target-access-template" || string(captured.RuntimeManifest) != "bounded-runtime" {
		t.Fatalf("target-access private templates differ: %q %q", captured.Package.JobTemplate, captured.RuntimeManifest)
	}
	if captured.LedgerWriter.AuthorityIdentity != "ok-mgmt" || captured.WorkloadWriter.AuthorityIdentity != testSHA("f") || captured.LedgerWriter.TokenFile == captured.WorkloadWriter.TokenFile || captured.Candidate.AuthorityEndpoint != "https://192.0.2.14:6443" {
		t.Fatalf("target-access credential boundary differs: %#v %#v %#v", captured.LedgerWriter, captured.WorkloadWriter, captured.Candidate)
	}
	var preparation targetAccessLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.State != "PREPARED" || preparation.MutationAllowed || preparation.Material.MutationAllowed || preparation.Candidate.MutationAllowed {
		t.Fatalf("unsafe target-access launch preparation: %#v", preparation)
	}

	invalid := removeArgumentWithValue(targetAccessLaunchPrepareArguments(template, runtimeManifest), "--workload-writer-job-token-file")
	stdout.Reset()
	if err := run(invalid, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("incomplete private target-access material reached preparation")
	}
}

func TestTargetAccessLaunchExecuteUsesExactBoundary(t *testing.T) {
	previous := executeTargetAccessStageLaunch
	defer func() { executeTargetAccessStageLaunch = previous }()
	var calls int
	var candidate string
	executeTargetAccessStageLaunch = func(ctx context.Context, config runner.TargetAccessStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.TargetAccessStageLaunchReceipt, error) {
		calls++
		candidate = expectedCandidateDigest
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout {
			t.Fatal("target-access launch context is not bounded")
		}
		if config.Package.RunID != "ok147-target-access-20260817-01" || authority.Endpoint != "https://192.0.2.14:6443" || authority.TokenFile != "/private/tmp/installer-token" {
			t.Fatalf("execute boundary differs: %#v %#v", config, authority)
		}
		return runner.TargetAccessStageLaunchReceipt{
			Format: runner.TargetAccessStageLaunchReceiptFormat, StageID: "target-access", Authority: "ok-shared",
			State: "LAUNCHED", MutationState: "ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "target-access.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-target-access-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(targetAccessLaunchExecuteArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 || candidate != testSHA("9") {
		t.Fatalf("exact target-access candidate not used: calls=%d digest=%q", calls, candidate)
	}
	var receipt runner.TargetAccessStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("unexpected target-access launch receipt: %#v %v", receipt, err)
	}

	valid := targetAccessLaunchExecuteArguments(template, runtimeManifest)
	for name, arguments := range map[string][]string{
		"missing execute":         removeArgument(valid, "--execute"),
		"missing candidate":       removeArgumentWithValue(valid, "--expected-candidate-digest"),
		"malformed candidate":     replaceArgument(valid, "--expected-candidate-digest", "sha256:ABC"),
		"missing installer token": removeArgumentWithValue(valid, "--installer-token-file"),
		"missing workload source": removeArgumentWithValue(valid, "--workload-writer-job-authority"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			stdout.Reset()
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 || calls != before {
				t.Fatal("unsafe target-access launch input reached executor")
			}
		})
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

func targetAccessLaunchPrepareArguments(template, runtimeManifest string) []string {
	packaged := targetAccessStagePackageArguments(template, "/private/tmp/not-used-package")
	packaged = removeArgumentWithValue(packaged, "--output")
	arguments := append([]string{"cluster", "stage", "run", "target-access", "launch", "prepare"}, packaged[5:]...)
	arguments = append(arguments, "--credential-materialized-at", "2026-08-17T14:00:00Z")
	for _, credential := range []struct{ prefix, authority, tokenFile, tokenDigest, caFile, caDigest, evidence, subject string }{
		{"ledger-job", "ok-mgmt", "/private/tmp/ledger-target-token", testSHA("1"), "/private/tmp/ledger-target-ca", testSHA("2"), testSHA("3"), "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"},
		{"workload-writer-job", testSHA("f"), "/private/tmp/workload-writer-token", testSHA("4"), "/private/tmp/workload-writer-ca", testSHA("5"), testSHA("6"), "system:serviceaccount:kube-system:ok147-argocd-manager"},
	} {
		arguments = append(arguments,
			"--"+credential.prefix+"-authority", credential.authority,
			"--"+credential.prefix+"-token-file", credential.tokenFile, "--"+credential.prefix+"-token-digest", credential.tokenDigest,
			"--"+credential.prefix+"-ca-file", credential.caFile, "--"+credential.prefix+"-ca-digest", credential.caDigest,
			"--"+credential.prefix+"-tokenrequest-evidence-digest", credential.evidence,
			"--"+credential.prefix+"-issuer", "https://kubernetes.default.svc.cluster.local", "--"+credential.prefix+"-subject", credential.subject,
			"--"+credential.prefix+"-audiences", "https://kubernetes.default.svc",
			"--"+credential.prefix+"-issued-at", "2026-08-17T13:59:00Z", "--"+credential.prefix+"-expires-at", "2026-08-17T14:30:00Z",
		)
	}
	return append(arguments,
		"--runtime-manifest", runtimeManifest, "--runtime-manifest-digest", digest.SHA256([]byte("bounded-runtime")),
		"--installer-api-endpoint", "https://192.0.2.14:6443", "--installer-ca-digest", testSHA("7"),
		"--installer-token-digest", testSHA("8"), "--installer-tokenrequest-evidence-digest", testSHA("a"),
		"--prepared-at", "2026-08-17T14:01:00Z",
	)
}

func targetAccessLaunchExecuteArguments(template, runtimeManifest string) []string {
	arguments := targetAccessLaunchPrepareArguments(template, runtimeManifest)
	arguments[5] = "execute"
	return append(arguments,
		"--execute", "--expected-candidate-digest", testSHA("9"),
		"--installer-token-file", "/private/tmp/installer-token", "--installer-ca-file", "/private/tmp/installer-ca",
	)
}
