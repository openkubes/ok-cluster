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

func TestEnablementLaunchPrepareBuildsOneNonMutatingCandidate(t *testing.T) {
	previous := prepareEnablementStageLaunch
	defer func() { prepareEnablementStageLaunch = previous }()
	var captured runner.EnablementStageLaunchMaterialConfig
	prepareEnablementStageLaunch = func(config runner.EnablementStageLaunchMaterialConfig) (enablementLaunchPreparation, error) {
		captured = config
		return enablementLaunchPreparation{
			Format: "ok147-enablement-stage-launch-preparation/v1", State: "PREPARED",
			Material: runner.EnablementStageLaunchMaterialReceipt{
				Format: runner.EnablementStageLaunchMaterialFormat, State: "VERIFIED", StageID: "enablement",
				Authority: "ok-mgmt", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			Candidate: runner.EnablementStageLaunchCandidateReceipt{
				Format: runner.EnablementStageLaunchCandidateFormat, State: "PREPARED", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "enablement.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-enablement-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(enablementLaunchPrepareArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Package.Bundle.PlanExpected.ManagementAuthority != "ok-mgmt" {
		t.Fatalf("management authority differs: %q", captured.Package.Bundle.PlanExpected.ManagementAuthority)
	}
	if captured.Package.RunID != "ok147-enablement-20260816-01" || captured.Package.HelmChartProxyName != "disposable-ok147-cilium" {
		t.Fatalf("enablement object identity differs: %q %q", captured.Package.RunID, captured.Package.HelmChartProxyName)
	}
	if string(captured.Package.JobTemplate) != "bounded-enablement-template" || string(captured.RuntimeManifest) != "bounded-runtime" {
		t.Fatalf("enablement private templates differ: %q %q", captured.Package.JobTemplate, captured.RuntimeManifest)
	}
	if captured.Ledger.AuthorityIdentity != "ok-mgmt" || captured.ManagementWriter.AuthorityIdentity != "ok-mgmt" || captured.Ledger.TokenFile == captured.ManagementWriter.TokenFile {
		t.Fatalf("enablement credential boundary differs: %#v %#v", captured.Ledger, captured.ManagementWriter)
	}
	var preparation enablementLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.State != "PREPARED" || preparation.MutationAllowed || preparation.Material.MutationAllowed || preparation.Candidate.MutationAllowed {
		t.Fatalf("unsafe enablement launch preparation: %#v", preparation)
	}

	invalid := removeArgumentWithValue(enablementLaunchPrepareArguments(template, runtimeManifest), "--management-writer-job-token-file")
	stdout.Reset()
	if err := run(invalid, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("incomplete private material reached preparation")
	}
}

func TestEnablementLaunchExecuteUsesExactBoundary(t *testing.T) {
	previous := executeEnablementStageLaunch
	defer func() { executeEnablementStageLaunch = previous }()
	var calls int
	var candidate string
	executeEnablementStageLaunch = func(ctx context.Context, config runner.EnablementStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.EnablementStageLaunchReceipt, error) {
		calls++
		candidate = expectedCandidateDigest
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout {
			t.Fatal("enablement launch context is not bounded")
		}
		if config.Package.RunID != "ok147-enablement-20260816-01" || authority.Endpoint != "https://192.0.2.12:6443" || authority.TokenFile != "/private/tmp/installer-token" {
			t.Fatalf("execute boundary differs: %#v %#v", config, authority)
		}
		return runner.EnablementStageLaunchReceipt{
			Format: runner.EnablementStageLaunchReceiptFormat, StageID: "enablement", Authority: "ok-mgmt",
			State: "LAUNCHED", MutationState: "ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "enablement.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-enablement-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(enablementLaunchExecuteArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 || candidate != testSHA("9") {
		t.Fatalf("exact enablement candidate not used: calls=%d digest=%q", calls, candidate)
	}
	var receipt runner.EnablementStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("unexpected enablement launch receipt: %#v %v", receipt, err)
	}

	valid := enablementLaunchExecuteArguments(template, runtimeManifest)
	for name, arguments := range map[string][]string{
		"missing execute":         removeArgument(valid, "--execute"),
		"missing candidate":       removeArgumentWithValue(valid, "--expected-candidate-digest"),
		"malformed candidate":     replaceArgument(valid, "--expected-candidate-digest", "sha256:ABC"),
		"missing installer token": removeArgumentWithValue(valid, "--installer-token-file"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			stdout.Reset()
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 || calls != before {
				t.Fatal("unsafe enablement launch input reached executor")
			}
		})
	}
}

func enablementLaunchPrepareArguments(template, runtimeManifest string) []string {
	packaged := enablementStagePackageArguments(template, "/private/tmp/not-used-package")
	packaged = removeArgumentWithValue(packaged, "--output")
	arguments := append([]string{"cluster", "stage", "run", "enablement", "launch", "prepare"}, packaged[5:]...)
	arguments = append(arguments, "--credential-materialized-at", "2026-08-16T12:00:00Z")
	for _, credential := range []struct{ prefix, tokenFile, tokenDigest, caFile, caDigest, evidence, subject string }{
		{"ledger-job", "/private/tmp/ledger-enablement-token", testSHA("1"), "/private/tmp/ledger-enablement-ca", testSHA("2"), testSHA("3"), "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"},
		{"management-writer-job", "/private/tmp/management-writer-token", testSHA("4"), "/private/tmp/management-writer-ca", testSHA("2"), testSHA("5"), "system:serviceaccount:openkubes-execution-system:ok147-enablement-writer"},
	} {
		arguments = append(arguments,
			"--"+credential.prefix+"-authority", "ok-mgmt",
			"--"+credential.prefix+"-token-file", credential.tokenFile, "--"+credential.prefix+"-token-digest", credential.tokenDigest,
			"--"+credential.prefix+"-ca-file", credential.caFile, "--"+credential.prefix+"-ca-digest", credential.caDigest,
			"--"+credential.prefix+"-tokenrequest-evidence-digest", credential.evidence,
			"--"+credential.prefix+"-issuer", "https://kubernetes.default.svc.cluster.local", "--"+credential.prefix+"-subject", credential.subject,
			"--"+credential.prefix+"-audiences", "https://kubernetes.default.svc",
			"--"+credential.prefix+"-issued-at", "2026-08-16T11:59:00Z", "--"+credential.prefix+"-expires-at", "2026-08-16T12:30:00Z",
		)
	}
	return append(arguments,
		"--runtime-manifest", runtimeManifest, "--runtime-manifest-digest", digest.SHA256([]byte("bounded-runtime")),
		"--installer-api-endpoint", "https://192.0.2.12:6443", "--installer-ca-digest", testSHA("2"),
		"--installer-token-digest", testSHA("7"), "--installer-tokenrequest-evidence-digest", testSHA("8"),
		"--prepared-at", "2026-08-16T12:01:00Z",
	)
}

func enablementLaunchExecuteArguments(template, runtimeManifest string) []string {
	arguments := enablementLaunchPrepareArguments(template, runtimeManifest)
	arguments[5] = "execute"
	return append(arguments,
		"--execute", "--expected-candidate-digest", testSHA("9"),
		"--installer-token-file", "/private/tmp/installer-token", "--installer-ca-file", "/private/tmp/installer-ca",
	)
}
