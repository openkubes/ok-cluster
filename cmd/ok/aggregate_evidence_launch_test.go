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

func TestAggregateEvidenceLaunchPrepareBuildsOneNonMutatingCandidate(t *testing.T) {
	previous := prepareAggregateEvidenceStageLaunch
	defer func() { prepareAggregateEvidenceStageLaunch = previous }()
	var captured runner.AggregateEvidenceStageLaunchMaterialConfig
	prepareAggregateEvidenceStageLaunch = func(config runner.AggregateEvidenceStageLaunchMaterialConfig) (aggregateEvidenceLaunchPreparation, error) {
		captured = config
		return aggregateEvidenceLaunchPreparation{
			Format: "ok147-aggregate-evidence-stage-launch-preparation/v1", State: "PREPARED",
			Material: runner.AggregateEvidenceStageLaunchMaterialReceipt{
				Format: runner.AggregateEvidenceStageLaunchMaterialFormat, State: "VERIFIED", StageID: "aggregate-evidence",
				Authority: "ok-mgmt", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			Candidate: runner.AggregateEvidenceStageLaunchCandidateReceipt{
				Format: runner.AggregateEvidenceStageLaunchCandidateFormat, State: "PREPARED",
				CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			MutationAllowed: false,
		}, nil
	}
	paths := aggregateEvidenceLaunchTestFiles(t)
	var stdout, stderr bytes.Buffer
	if err := run(aggregateEvidenceLaunchPrepareArguments(paths), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Package.Input.Bundle.PlanExpected.ManagementAuthority != "ok-mgmt" || len(captured.Package.Input.Bundle.Receipts) != 11 || captured.Package.RunID != "ok147-aggregate-evidence-20260817-01" {
		t.Fatalf("aggregate evidence package identity differs: %#v", captured.Package)
	}
	if captured.Package.RuntimeBindingMaterialPath != paths.runtimeBinding || captured.Package.PlatformCapabilityPath != paths.capability || string(captured.Package.JobTemplate) != "bounded-aggregate-template" || string(captured.RuntimeManifest) != "bounded-runtime" {
		t.Fatalf("aggregate evidence private inputs differ: %#v", captured.Package)
	}
	credentials := []runner.SubmissionStageCredentialSource{captured.Ledger, captured.ManagementObserver, captured.WorkloadObserver, captured.ArgoObserver}
	seen := map[string]bool{}
	for _, credential := range credentials {
		if credential.TokenFile == "" || seen[credential.TokenFile] {
			t.Fatalf("aggregate evidence credentials are not distinct: %#v", credentials)
		}
		seen[credential.TokenFile] = true
	}
	var preparation aggregateEvidenceLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.State != "PREPARED" || preparation.MutationAllowed || preparation.Material.MutationAllowed || preparation.Candidate.MutationAllowed {
		t.Fatalf("unsafe aggregate evidence preparation: %#v", preparation)
	}

	invalid := removeArgumentWithValue(aggregateEvidenceLaunchPrepareArguments(paths), "--argo-observer-job-token-file")
	stdout.Reset()
	if err := run(invalid, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("incomplete aggregate evidence material reached preparation")
	}
}

func TestAggregateEvidenceLaunchExecuteUsesExactBoundary(t *testing.T) {
	previous := executeAggregateEvidenceStageLaunch
	defer func() { executeAggregateEvidenceStageLaunch = previous }()
	var calls int
	var candidate string
	executeAggregateEvidenceStageLaunch = func(ctx context.Context, config runner.AggregateEvidenceStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.AggregateEvidenceStageLaunchReceipt, error) {
		calls++
		candidate = expectedCandidateDigest
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout {
			t.Fatal("aggregate evidence launch context is not bounded")
		}
		if config.Package.RunID != "ok147-aggregate-evidence-20260817-01" || authority.Endpoint != "https://192.0.2.12:6443" || authority.TokenFile != "/private/tmp/aggregate-installer-token" {
			t.Fatalf("aggregate evidence execute boundary differs: %#v %#v", config, authority)
		}
		return runner.AggregateEvidenceStageLaunchReceipt{
			Format: runner.AggregateEvidenceStageLaunchReceiptFormat, StageID: "aggregate-evidence", Authority: "ok-mgmt",
			State: "LAUNCHED", MutationState: "ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, nil
	}
	paths := aggregateEvidenceLaunchTestFiles(t)
	var stdout, stderr bytes.Buffer
	if err := run(aggregateEvidenceLaunchExecuteArguments(paths), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 || candidate != testSHA("9") {
		t.Fatalf("exact aggregate evidence candidate not used: calls=%d digest=%q", calls, candidate)
	}
	var receipt runner.AggregateEvidenceStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("unexpected aggregate evidence launch receipt: %#v %v", receipt, err)
	}

	valid := aggregateEvidenceLaunchExecuteArguments(paths)
	for name, arguments := range map[string][]string{
		"missing execute":         removeArgument(valid, "--execute"),
		"missing candidate":       removeArgumentWithValue(valid, "--expected-candidate-digest"),
		"malformed candidate":     replaceArgument(valid, "--expected-candidate-digest", "sha256:ABC"),
		"missing installer token": removeArgumentWithValue(valid, "--installer-token-file"),
		"missing runtime binding": removeArgumentWithValue(valid, "--runtime-binding-material"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			stdout.Reset()
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 || calls != before {
				t.Fatal("unsafe aggregate evidence input reached executor")
			}
		})
	}
}

type aggregateEvidenceLaunchPaths struct {
	template, runtimeManifest, runtimeBinding, runtimeReceipt, capability string
}

func aggregateEvidenceLaunchTestFiles(t *testing.T) aggregateEvidenceLaunchPaths {
	t.Helper()
	root := t.TempDir()
	paths := aggregateEvidenceLaunchPaths{
		template: filepath.Join(root, "aggregate.yaml.tpl"), runtimeManifest: filepath.Join(root, "runtime.yaml"),
		runtimeBinding: filepath.Join(root, "runtime-binding.json"), runtimeReceipt: filepath.Join(root, "runtime-binding-receipt.json"),
		capability: filepath.Join(root, "platform-capability.json"),
	}
	for path, content := range map[string]string{
		paths.template: "bounded-aggregate-template", paths.runtimeManifest: "bounded-runtime",
		paths.runtimeBinding: "private-runtime-binding", paths.runtimeReceipt: "private-runtime-receipt",
		paths.capability: "private-platform-capability",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func aggregateEvidenceLaunchPrepareArguments(paths aggregateEvidenceLaunchPaths) []string {
	resume := stageResumeArguments()
	arguments := append([]string{"cluster", "stage", "run", "aggregate-evidence", "launch", "prepare"}, resume[3:]...)
	for index := 1; index <= 11; index++ {
		arguments = append(arguments, "--receipt", "/tmp/stage-"+string(rune('a'+index-1))+".json@"+testSHA(string(rune('0'+index%10))))
	}
	arguments = append(arguments,
		"--aggregate-profile", "/tmp/aggregate-profile.json", "--aggregate-profile-digest", testSHA("1"),
		"--network-profile", "/tmp/network-profile.json", "--network-profile-digest", testSHA("2"),
		"--platform-profile", "/tmp/platform-profile.json", "--platform-profile-digest", testSHA("3"),
		"--input-configmap", "ok147-aggregate-evidence-input",
		"--job-template", paths.template, "--job-template-digest", digest.SHA256([]byte("bounded-aggregate-template")),
		"--run-id", "ok147-aggregate-evidence-20260817-01", "--image", "ghcr.io/openkubes/ok-cluster@"+testSHA("a"),
		"--ledger-api-url", "https://192.0.2.12:6443", "--ledger-api-cidr", "192.0.2.12/32", "--ledger-credential-secret", "ok147-ledger-aggregate",
		"--management-api-url", "https://192.0.2.12:6443", "--management-api-cidr", "192.0.2.12/32", "--management-credential-secret", "ok147-management-aggregate",
		"--workload-api-url", "https://192.0.2.20:6443", "--workload-api-cidr", "192.0.2.20/32", "--workload-credential-secret", "ok147-workload-aggregate",
		"--argo-api-url", "https://192.0.2.30:6443", "--argo-api-cidr", "192.0.2.30/32", "--argo-credential-secret", "ok147-argo-aggregate",
		"--runtime-binding-secret", "ok147-runtime-binding-run-01", "--runtime-binding-material", paths.runtimeBinding, "--runtime-binding-receipt", paths.runtimeReceipt,
		"--platform-capability-secret", "ok147-platform-capability-01", "--platform-capability", paths.capability, "--platform-capability-digest", testSHA("4"),
		"--credential-materialized-at", "2026-08-17T08:00:00Z",
	)
	for index, credential := range []struct{ prefix, authority, subject string }{
		{"ledger-job", "ok-mgmt", "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"},
		{"management-observer-job", "ok-mgmt", "system:serviceaccount:openkubes-execution-system:ok147-management-observer"},
		{"workload-observer-job", testSHA("b"), "system:serviceaccount:openkubes-execution-system:ok147-workload-observer"},
		{"argo-observer-job", "ok-shared", "system:serviceaccount:openkubes-execution-system:ok147-argo-observer"},
	} {
		marker := string(rune('5' + index))
		arguments = append(arguments,
			"--"+credential.prefix+"-authority", credential.authority,
			"--"+credential.prefix+"-token-file", "/private/tmp/"+credential.prefix+"-token", "--"+credential.prefix+"-token-digest", testSHA(marker),
			"--"+credential.prefix+"-ca-file", "/private/tmp/"+credential.prefix+"-ca", "--"+credential.prefix+"-ca-digest", testSHA("c"),
			"--"+credential.prefix+"-tokenrequest-evidence-digest", testSHA(marker),
			"--"+credential.prefix+"-issuer", "https://kubernetes.default.svc.cluster.local", "--"+credential.prefix+"-subject", credential.subject,
			"--"+credential.prefix+"-audiences", "https://kubernetes.default.svc",
			"--"+credential.prefix+"-issued-at", "2026-08-17T07:59:00Z", "--"+credential.prefix+"-expires-at", "2026-08-17T08:30:00Z",
		)
	}
	return append(arguments,
		"--runtime-manifest", paths.runtimeManifest, "--runtime-manifest-digest", digest.SHA256([]byte("bounded-runtime")),
		"--installer-api-endpoint", "https://192.0.2.12:6443", "--installer-ca-digest", testSHA("c"),
		"--installer-token-digest", testSHA("d"), "--installer-tokenrequest-evidence-digest", testSHA("e"),
		"--prepared-at", "2026-08-17T08:01:00Z",
	)
}

func aggregateEvidenceLaunchExecuteArguments(paths aggregateEvidenceLaunchPaths) []string {
	arguments := aggregateEvidenceLaunchPrepareArguments(paths)
	arguments[5] = "execute"
	return append(arguments,
		"--execute", "--expected-candidate-digest", testSHA("9"),
		"--installer-token-file", "/private/tmp/aggregate-installer-token", "--installer-ca-file", "/private/tmp/aggregate-installer-ca",
	)
}
