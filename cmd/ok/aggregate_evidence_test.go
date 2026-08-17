package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func aggregateEvidenceStageArguments(t *testing.T) []string {
	t.Helper()
	platformArguments := platformApplicationsStageRunArguments(t)
	platformPath := testFlagValue(t, platformArguments, "--platform-profile")
	platformDigest := testFlagValue(t, platformArguments, "--platform-profile-digest")
	networkProfile := observation.NetworkProfile{
		Format: observation.NetworkProfileFormat, IntentRevision: testSHA("a"), EnablementRevision: testSHA("b"),
		ExpectedNodeCount: 2, ExpectedHCPSpecDigest: testSHA("4"), ExpectedHRPSpecDigest: testSHA("5"),
		ExpectedImages: observation.NetworkImages{
			CiliumAgent: "example.invalid/cilium@" + testSHA("1"), CiliumEnvoy: "example.invalid/envoy@" + testSHA("2"), CiliumOperator: "example.invalid/operator@" + testSHA("3"),
		},
		MinimumProbeFreshnessSeconds: 60, MaximumProbeIntervalSeconds: 60, CacheExposureSeconds: 30,
	}
	networkDigest, err := observation.NetworkProfileDigest(networkProfile)
	if err != nil {
		t.Fatal(err)
	}
	aggregateProfile := runner.AggregateEvidenceProfile{
		Format: runner.AggregateEvidenceProfileFormat, IntentRevision: testSHA("a"), EnablementRevision: testSHA("b"),
		PlatformRevision: testSHA("c"), ExecutionFixture: testSHA("d"),
		Required: []string{"InfrastructureReady", "ControlPlaneAvailable", "NetworkReady", "PlatformReady"},
	}
	aggregateDigest, err := runner.AggregateEvidenceProfileDigest(aggregateProfile)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	networkPath := writeAggregateEvidenceCLIJSON(t, root, "network-profile.json", networkProfile)
	aggregatePath := writeAggregateEvidenceCLIJSON(t, root, "aggregate-profile.json", aggregateProfile)
	resume := stageResumeArguments()
	arguments := append([]string{"cluster", "stage", "evaluate", "aggregate"}, resume[3:]...)
	receiptNames := []string{
		"provider", "lifecycle", "lifecycle-observation", "enablement", "network-observation", "runtime-binding",
		"target-access", "target-credential", "target-registration", "platform-applications", "platform-observation",
	}
	receiptDigests := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "e"}
	for index, name := range receiptNames {
		arguments = append(arguments, "--receipt", "/tmp/"+name+".json@"+testSHA(receiptDigests[index]))
	}
	return append(arguments,
		"--aggregate-profile", aggregatePath, "--aggregate-profile-digest", aggregateDigest,
		"--network-profile", networkPath, "--network-profile-digest", networkDigest,
		"--platform-profile", platformPath, "--platform-profile-digest", platformDigest,
		"--runtime-binding", "/private/tmp/runtime-binding.json", "--runtime-binding-receipt", "/private/tmp/runtime-binding-receipt.json",
		"--platform-capability", "/private/tmp/platform-capability.json", "--platform-capability-digest", testSHA("6"),
		"--execute",
		"--ledger-api-endpoint", "https://192.0.2.12:6443", "--ledger-token-file", "/private/tmp/ledger-token", "--ledger-ca-file", "/private/tmp/ledger-ca",
		"--management-api-endpoint", "https://192.0.2.12:6443", "--management-token-file", "/private/tmp/management-token", "--management-ca-file", "/private/tmp/management-ca",
		"--workload-api-endpoint", "https://192.0.2.20:6443", "--workload-token-file", "/private/tmp/workload-token", "--workload-ca-file", "/private/tmp/workload-ca",
		"--argo-api-endpoint", "https://192.0.2.13:6443", "--argo-token-file", "/private/tmp/argo-token", "--argo-ca-file", "/private/tmp/argo-ca",
	)
}

func TestAggregateEvidenceStageBindsExactProfilesAuthoritiesAndPrivateEvidence(t *testing.T) {
	previous := executeAggregateEvidenceStage
	defer func() { executeAggregateEvidenceStage = previous }()
	var calls int
	executeAggregateEvidenceStage = func(ctx context.Context, bundle runner.AggregateEvidenceStageBundleConfig, runtime runner.AggregateEvidenceStageFileRuntimeConfig) (execution.EvaluationStageRunReceipt, error) {
		calls++
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > stageRunTimeout || time.Until(deadline) < stageRunTimeout-time.Minute {
			t.Fatalf("aggregate evidence context is not bounded: %s %t", deadline, bounded)
		}
		if len(bundle.Receipts) != 11 || bundle.ExpectedProfileDigest == "" || len(bundle.Profile.Required) != 4 {
			t.Fatalf("aggregate evidence bundle differs: %#v", bundle)
		}
		if runtime.Bundle.PlanExpected.IntentRevision != testSHA("a") || runtime.NetworkProfile.EnablementRevision != testSHA("b") || runtime.PlatformProfile.PlatformRevision != testSHA("c") {
			t.Fatalf("aggregate profile binding differs: %#v", runtime)
		}
		if runtime.Ledger.Namespace != ledgerNamespace || runtime.Management.AuthorityIdentity != "ok-mgmt" || runtime.Argo.AuthorityIdentity != "ok-shared" || runtime.ExpectedWorkloadEndpoint != "https://192.0.2.20:6443" {
			t.Fatalf("aggregate authority binding differs: %#v", runtime)
		}
		if runtime.RuntimeMaterialPath != "/private/tmp/runtime-binding.json" || runtime.RuntimeReceiptPath != "/private/tmp/runtime-binding-receipt.json" || runtime.CapabilityPath != "/private/tmp/platform-capability.json" || runtime.ExpectedCapabilityDigest != testSHA("6") || runtime.Clock == nil {
			t.Fatalf("aggregate private input binding differs: %#v", runtime)
		}
		return execution.EvaluationStageRunReceipt{Format: execution.EvaluationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", StageID: "aggregate-evidence", StageReceiptDigest: testSHA("9")}, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run(aggregateEvidenceStageArguments(t), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("aggregate evidence runner calls = %d", calls)
	}
	var receipt execution.EvaluationStageRunReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.StageID != "aggregate-evidence" {
		t.Fatalf("unexpected aggregate evidence receipt: %#v %v", receipt, err)
	}
}

func TestAggregateEvidenceStageFailsClosedBeforeExecution(t *testing.T) {
	previous := executeAggregateEvidenceStage
	defer func() { executeAggregateEvidenceStage = previous }()
	calls := 0
	executeAggregateEvidenceStage = func(context.Context, runner.AggregateEvidenceStageBundleConfig, runner.AggregateEvidenceStageFileRuntimeConfig) (execution.EvaluationStageRunReceipt, error) {
		calls++
		return execution.EvaluationStageRunReceipt{}, nil
	}
	valid := aggregateEvidenceStageArguments(t)
	for name, arguments := range map[string][]string{
		"missing execute":           removeArgument(valid, "--execute"),
		"missing aggregate profile": removeArgumentWithValue(valid, "--aggregate-profile"),
		"missing runtime binding":   removeArgumentWithValue(valid, "--runtime-binding"),
		"missing capability digest": removeArgumentWithValue(valid, "--platform-capability-digest"),
		"invalid network digest":    replaceArgument(valid, "--network-profile-digest", "not-a-digest"),
		"missing workload endpoint": removeArgumentWithValue(valid, "--workload-api-endpoint"),
		"missing Argo credential":   removeArgumentWithValue(valid, "--argo-token-file"),
		"positional":                append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe aggregate evidence run was accepted: %v %s", err, stdout.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("aggregate evidence runner reached %d times for invalid input", calls)
	}
}

func writeAggregateEvidenceCLIJSON(t *testing.T, root, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
