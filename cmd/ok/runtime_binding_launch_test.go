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

func TestRuntimeBindingLaunchPrepareBuildsOneNonMutatingCandidate(t *testing.T) {
	previous := prepareRuntimeBindingStageLaunch
	defer func() { prepareRuntimeBindingStageLaunch = previous }()
	var captured runner.RuntimeBindingStageLaunchMaterialConfig
	prepareRuntimeBindingStageLaunch = func(config runner.RuntimeBindingStageLaunchMaterialConfig) (runtimeBindingLaunchPreparation, error) {
		captured = config
		return runtimeBindingLaunchPreparation{
			Format: "ok147-runtime-binding-stage-launch-preparation/v1", State: "PREPARED",
			Material: runner.RuntimeBindingStageLaunchMaterialReceipt{
				Format: runner.RuntimeBindingStageLaunchMaterialFormat, State: "VERIFIED", StageID: "runtime-binding",
				Authority: "ok-mgmt", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			Candidate: runner.RuntimeBindingStageLaunchCandidateReceipt{
				Format: runner.RuntimeBindingStageLaunchCandidateFormat, State: "PREPARED", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "runtime-binding.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-runtime-binding-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(runtimeBindingLaunchPrepareArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Package.Bundle.PlanExpected.ManagementAuthority != "ok-mgmt" || captured.Package.RunID != "ok147-runtime-binding-20260817-01" {
		t.Fatalf("runtime-binding package identity differs: %#v", captured.Package)
	}
	if captured.Package.PersistenceCredentialSecret != "ok147-runtime-binding-persistence" || captured.Package.WorkloadBindingPath != "/private/tmp/ok147-workload-binding.json" {
		t.Fatalf("runtime-binding authority inputs differ: %#v", captured.Package)
	}
	if string(captured.Package.JobTemplate) != "bounded-runtime-binding-template" || string(captured.RuntimeManifest) != "bounded-runtime" {
		t.Fatalf("runtime-binding private templates differ: %q %q", captured.Package.JobTemplate, captured.RuntimeManifest)
	}
	if captured.LedgerWriter.TokenFile == captured.PersistenceWriter.TokenFile || captured.LedgerWriter.TokenFile == captured.WorkloadObserver.TokenFile || captured.PersistenceWriter.TokenFile == captured.WorkloadObserver.TokenFile {
		t.Fatalf("runtime-binding credentials are not distinct: %#v %#v %#v", captured.LedgerWriter, captured.PersistenceWriter, captured.WorkloadObserver)
	}
	var preparation runtimeBindingLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.State != "PREPARED" || preparation.MutationAllowed || preparation.Material.MutationAllowed || preparation.Candidate.MutationAllowed {
		t.Fatalf("unsafe runtime-binding launch preparation: %#v", preparation)
	}

	invalid := removeArgumentWithValue(runtimeBindingLaunchPrepareArguments(template, runtimeManifest), "--persistence-writer-job-token-file")
	stdout.Reset()
	if err := run(invalid, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("incomplete private material reached runtime-binding preparation")
	}
}

func TestRuntimeBindingLaunchExecuteUsesExactBoundary(t *testing.T) {
	previous := executeRuntimeBindingStageLaunch
	defer func() { executeRuntimeBindingStageLaunch = previous }()
	var calls int
	var candidate string
	executeRuntimeBindingStageLaunch = func(ctx context.Context, config runner.RuntimeBindingStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.RuntimeBindingStageLaunchReceipt, error) {
		calls++
		candidate = expectedCandidateDigest
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout {
			t.Fatal("runtime-binding launch context is not bounded")
		}
		if config.Package.RunID != "ok147-runtime-binding-20260817-01" || authority.Endpoint != "https://192.0.2.12:6443" || authority.TokenFile != "/private/tmp/installer-token" {
			t.Fatalf("execute boundary differs: %#v %#v", config, authority)
		}
		return runner.RuntimeBindingStageLaunchReceipt{
			Format: runner.RuntimeBindingStageLaunchReceiptFormat, StageID: "runtime-binding", Authority: "ok-mgmt",
			State: "LAUNCHED", MutationState: "ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "runtime-binding.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-runtime-binding-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(runtimeBindingLaunchExecuteArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 || candidate != testSHA("9") {
		t.Fatalf("exact runtime-binding candidate not used: calls=%d digest=%q", calls, candidate)
	}
	var receipt runner.RuntimeBindingStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("unexpected runtime-binding launch receipt: %#v %v", receipt, err)
	}

	valid := runtimeBindingLaunchExecuteArguments(template, runtimeManifest)
	for name, arguments := range map[string][]string{
		"missing execute":         removeArgument(valid, "--execute"),
		"missing candidate":       removeArgumentWithValue(valid, "--expected-candidate-digest"),
		"malformed candidate":     replaceArgument(valid, "--expected-candidate-digest", "sha256:ABC"),
		"missing installer token": removeArgumentWithValue(valid, "--installer-token-file"),
		"shared credential":       replaceArgument(valid, "--persistence-writer-job-token-file", "/private/tmp/ledger-runtime-binding-token"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			stdout.Reset()
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 || calls != before {
				t.Fatal("unsafe runtime-binding launch input reached executor")
			}
		})
	}
}

func runtimeBindingLaunchPrepareArguments(template, runtimeManifest string) []string {
	resume := stageResumeArguments()
	arguments := append([]string{"cluster", "stage", "bind", "runtime", "launch", "prepare"}, resume[3:]...)
	arguments = append(arguments,
		"--receipt", "/tmp/provider.json@"+testSHA("1"),
		"--receipt", "/tmp/lifecycle.json@"+testSHA("2"),
		"--receipt", "/tmp/lifecycle-observation.json@"+testSHA("3"),
		"--receipt", "/tmp/enablement.json@"+testSHA("4"),
		"--receipt", "/tmp/network-observation.json@"+testSHA("5"),
		"--job-template", template, "--job-template-digest", digest.SHA256([]byte("bounded-runtime-binding-template")),
		"--run-id", "ok147-runtime-binding-20260817-01", "--image", "ghcr.io/openkubes/ok-cluster@"+testSHA("a"),
		"--input-configmap", "ok147-runtime-binding-input",
		"--ledger-api-url", "https://192.0.2.12:6443", "--ledger-api-cidr", "192.0.2.12/32", "--ledger-credential-secret", "ok147-runtime-binding-ledger",
		"--persistence-credential-secret", "ok147-runtime-binding-persistence",
		"--workload-api-url", "https://192.0.2.20:6443", "--workload-api-cidr", "192.0.2.20/32", "--workload-credential-secret", "ok147-runtime-binding-workload",
		"--workload-binding", "/private/tmp/ok147-workload-binding.json", "--workload-binding-digest", testSHA("b"),
		"--credential-materialized-at", "2026-08-17T08:00:00Z",
	)
	for _, credential := range []struct{ prefix, authority, tokenFile, tokenDigest, caFile, caDigest, evidence, subject string }{
		{"ledger-writer-job", "ok-mgmt", "/private/tmp/ledger-runtime-binding-token", testSHA("1"), "/private/tmp/ledger-runtime-binding-ca", testSHA("2"), testSHA("3"), "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"},
		{"persistence-writer-job", "ok-mgmt", "/private/tmp/persistence-runtime-binding-token", testSHA("4"), "/private/tmp/persistence-runtime-binding-ca", testSHA("2"), testSHA("5"), "system:serviceaccount:openkubes-execution-system:ok147-runtime-binding-writer"},
		{"workload-observer-job", testSHA("b"), "/private/tmp/workload-runtime-binding-token", testSHA("6"), "/private/tmp/workload-runtime-binding-ca", testSHA("7"), testSHA("8"), "system:serviceaccount:openkubes-execution-system:ok147-runtime-binding-observer"},
	} {
		arguments = append(arguments,
			"--"+credential.prefix+"-authority", credential.authority,
			"--"+credential.prefix+"-token-file", credential.tokenFile, "--"+credential.prefix+"-token-digest", credential.tokenDigest,
			"--"+credential.prefix+"-ca-file", credential.caFile, "--"+credential.prefix+"-ca-digest", credential.caDigest,
			"--"+credential.prefix+"-tokenrequest-evidence-digest", credential.evidence,
			"--"+credential.prefix+"-issuer", "https://kubernetes.default.svc.cluster.local", "--"+credential.prefix+"-subject", credential.subject,
			"--"+credential.prefix+"-audiences", "https://kubernetes.default.svc",
			"--"+credential.prefix+"-issued-at", "2026-08-17T07:59:00Z", "--"+credential.prefix+"-expires-at", "2026-08-17T08:30:00Z",
		)
	}
	return append(arguments,
		"--runtime-manifest", runtimeManifest, "--runtime-manifest-digest", digest.SHA256([]byte("bounded-runtime")),
		"--installer-api-endpoint", "https://192.0.2.12:6443", "--installer-ca-digest", testSHA("2"),
		"--installer-token-digest", testSHA("7"), "--installer-tokenrequest-evidence-digest", testSHA("8"),
		"--prepared-at", "2026-08-17T08:01:00Z",
	)
}

func runtimeBindingLaunchExecuteArguments(template, runtimeManifest string) []string {
	arguments := runtimeBindingLaunchPrepareArguments(template, runtimeManifest)
	arguments[5] = "execute"
	return append(arguments,
		"--execute", "--expected-candidate-digest", testSHA("9"),
		"--installer-token-file", "/private/tmp/installer-token", "--installer-ca-file", "/private/tmp/installer-ca",
	)
}
