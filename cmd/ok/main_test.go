package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "internal", "contract", "testdata", name)
}

func TestVersionIncludesExecutableRevision(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "0.0.0-dev unknown\n" {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestCreateDryRunProducesNonMutatingPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"cluster", "create",
		"--contract", fixturePath(t, "ok141-contract-v5.yaml"),
		"--schema", fixturePath(t, "ok141-contract-v3.schema.json"),
		"--dry-run",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	var plan createPlan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Format != "ok147-create-plan/v1" || plan.Operation != "CreateCluster" || plan.MutationAllowed {
		t.Fatalf("unsafe plan: %#v", plan)
	}
	if plan.AuthorizationState != "NOT_EVALUATED" {
		t.Fatalf("authorization = %s", plan.AuthorizationState)
	}
}

func TestCreateWithoutDryRunFailsClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"cluster", "create",
		"--contract", fixturePath(t, "ok141-contract-v5.yaml"),
		"--schema", fixturePath(t, "ok141-contract-v3.schema.json"),
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestCreateRejectsIncompleteProjectionAndAuthorizationInputs(t *testing.T) {
	base := []string{
		"cluster", "create",
		"--contract", fixturePath(t, "ok141-contract-v5.yaml"),
		"--schema", fixturePath(t, "ok141-contract-v3.schema.json"),
		"--dry-run",
	}
	for name, extra := range map[string][]string{
		"projection root without manifest":     {"--projection-root", "/tmp/projection"},
		"authorization without projection":     {"--authorization", "/tmp/grant.json", "--authorization-key", "/tmp/key", "--evaluation-time", "2026-08-16T10:00:00Z"},
		"ledger inspect without authorization": {"--ledger-inspect", "--ledger-api-endpoint", "https://10.43.0.1:443", "--ledger-token-file", "/tmp/token", "--ledger-ca-file", "/tmp/ca"},
		"ledger inputs without inspect":        {"--ledger-api-endpoint", "https://10.43.0.1:443"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			arguments := append(append([]string{}, base...), extra...)
			if err := run(arguments, &stdout, &stderr); err == nil {
				t.Fatal("unsafe incomplete input was accepted")
			}
		})
	}
}

func TestArbitraryCommandsAreAbsent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, arguments := range [][]string{
		{"shell", "echo", "unsafe"},
		{"cluster", "apply", "--file", "anything.yaml"},
		{"cluster", "create", "unexpected-positional-command"},
	} {
		if err := run(arguments, &stdout, &stderr); err == nil {
			t.Fatalf("arguments unexpectedly accepted: %v", arguments)
		}
	}
}

func TestStageInspectBindsInputsAndEmitsNonMutatingDecision(t *testing.T) {
	previous := inspectSubmissionStage
	defer func() { inspectSubmissionStage = previous }()
	var captured runner.SubmissionStageBundleConfig
	inspectSubmissionStage = func(config runner.SubmissionStageBundleConfig) (stageInspection, error) {
		captured = config
		return stageInspection{
			Format: "ok147-stage-inspection/v1",
			Decision: stagecursor.Decision{
				Format: stagecursor.DecisionFormat, State: "NEXT", PlanDigest: testSHA("9"), StageID: "cluster-lifecycle",
				StageOrder: 2, StageDigest: testSHA("8"), Kind: "Submission", Authority: "management",
				Operation: "CreateCluster", RequiresAuthorization: true, Predecessors: []stagecursor.Predecessor{},
			},
			AuthorizationState: "VERIFIED", MutationAllowed: false,
		}, nil
	}
	arguments := stageInspectArguments()
	arguments = append(arguments, "--receipt", "/tmp/provider.json@"+testSHA("7"))
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.PlanPath != "/tmp/plan.json" || captured.PlanExpected.ContractIdentity.Name != "disposable-ok147" || len(captured.Receipts) != 1 {
		t.Fatalf("unexpected bundle config: %#v", captured)
	}
	if captured.Receipts[0].Path != "/tmp/provider.json" || captured.Receipts[0].Digest != testSHA("7") || !captured.EvaluationTime.Equal(time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected receipt/time binding: %#v %s", captured.Receipts, captured.EvaluationTime)
	}
	var result stageInspection
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Format != "ok147-stage-inspection/v1" || result.Decision.StageID != "cluster-lifecycle" || result.AuthorizationState != "VERIFIED" || result.MutationAllowed {
		t.Fatalf("unsafe inspection output: %#v", result)
	}
}

func TestStageInspectRequiresCompleteInputsAndStrictReceipts(t *testing.T) {
	for name, arguments := range map[string][]string{
		"missing bindings": {"cluster", "stage", "inspect", "--plan", "/tmp/plan.json"},
		"positional":       append(stageInspectArguments(), "unexpected"),
		"bad receipt":      append(stageInspectArguments(), "--receipt", "/tmp/provider.json"),
		"bad time":         replaceArgument(stageInspectArguments(), "--evaluation-time", "now"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil {
				t.Fatal("incomplete or ambiguous stage inspection was accepted")
			}
			if stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %s", stdout.String())
			}
		})
	}
}

func TestStageRunRequiresExplicitExecutionAndBindsOneRuntime(t *testing.T) {
	previous := executeSubmissionStage
	defer func() { executeSubmissionStage = previous }()
	var capturedBundle runner.SubmissionStageBundleConfig
	var capturedRuntime runner.SubmissionStageRuntimeConfig
	var capturedContext context.Context
	executeSubmissionStage = func(ctx context.Context, bundle runner.SubmissionStageBundleConfig, runtime runner.SubmissionStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
		capturedContext = ctx
		capturedBundle, capturedRuntime = bundle, runtime
		return execution.StagedOperationReceipt{
			Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: testSHA("9"),
			StageID: "provider-prerequisites", StageReceiptDigest: testSHA("8"),
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run(stageRunArguments(), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if capturedBundle.PlanPath != "/tmp/plan.json" || capturedRuntime.Ledger.Namespace != ledgerNamespace || capturedRuntime.Ledger.TokenFile != "/tmp/ledger-token" || capturedRuntime.Authority.TokenFile != "/tmp/authority-token" {
		t.Fatalf("unexpected bound runtime: %#v %#v", capturedBundle, capturedRuntime)
	}
	if capturedRuntime.Clock == nil || capturedRuntime.Clock().IsZero() {
		t.Fatal("claim-time clock was not bound")
	}
	deadline, bounded := capturedContext.Deadline()
	if !bounded || time.Until(deadline) > stageRunTimeout || time.Until(deadline) < stageRunTimeout-time.Minute {
		t.Fatalf("stage run context is not bounded to the fixed timeout: %s %t", deadline, bounded)
	}
	var receipt execution.StagedOperationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "provider-prerequisites" {
		t.Fatalf("unexpected run receipt: %#v", receipt)
	}
}

func TestStageRunFailsClosedBeforeExecution(t *testing.T) {
	withoutExecute := stageRunArguments()
	withoutExecute = removeArgument(withoutExecute, "--execute")
	withoutAuthorityToken := stageRunArguments()
	withoutAuthorityToken = removeArgumentWithValue(withoutAuthorityToken, "--authority-token-file")
	for name, arguments := range map[string][]string{
		"missing execute":         withoutExecute,
		"missing runtime binding": withoutAuthorityToken,
		"positional":              append(stageRunArguments(), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil {
				t.Fatal("unsafe stage run was accepted")
			}
			if stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %s", stdout.String())
			}
		})
	}
}

func TestSubmissionStageAuthorityIsDerivedFromVerifiedTopology(t *testing.T) {
	expected := stageplan.Expected{InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt"}
	for symbolic, want := range map[string]string{"infrastructure": "ok-infra", "management": "ok-mgmt"} {
		got, err := submissionStageAuthority(stagecursor.Decision{Authority: symbolic}, expected)
		if err != nil || got != want {
			t.Fatalf("authority %s resolved to %q: %v", symbolic, got, err)
		}
	}
	if _, err := submissionStageAuthority(stagecursor.Decision{Authority: "gitops"}, expected); err == nil {
		t.Fatal("unsupported authority was accepted")
	}
}

func stageInspectArguments() []string {
	return []string{
		"cluster", "stage", "inspect",
		"--plan", "/tmp/plan.json", "--contract-namespace", "disposable-ok147", "--contract-name", "disposable-ok147",
		"--intent-revision", testSHA("a"), "--enablement-revision", testSHA("b"), "--platform-revision", testSHA("c"),
		"--execution-fixture", testSHA("d"), "--infrastructure-authority", "ok-infra", "--management-authority", "ok-mgmt", "--gitops-authority", "ok-shared",
		"--grant", "/tmp/grant.json", "--grant-key", "/tmp/grant.pub", "--projection-manifest", "/tmp/projection.json",
		"--evaluation-time", "2026-08-16T14:00:00Z",
	}
}

func stageRunArguments() []string {
	arguments := stageInspectArguments()
	arguments[2] = "run"
	return append(arguments,
		"--execute",
		"--ledger-api-endpoint", "https://192.0.2.12:6443", "--ledger-token-file", "/tmp/ledger-token", "--ledger-ca-file", "/tmp/ledger-ca",
		"--authority-api-endpoint", "https://192.0.2.11:6443", "--authority-token-file", "/tmp/authority-token", "--authority-ca-file", "/tmp/authority-ca",
	)
}

func replaceArgument(arguments []string, name, value string) []string {
	result := append([]string(nil), arguments...)
	for index := range result {
		if result[index] == name && index+1 < len(result) {
			result[index+1] = value
			return result
		}
	}
	return result
}

func removeArgument(arguments []string, name string) []string {
	result := append([]string(nil), arguments...)
	for index := range result {
		if result[index] == name {
			return append(result[:index], result[index+1:]...)
		}
	}
	return result
}

func removeArgumentWithValue(arguments []string, name string) []string {
	result := append([]string(nil), arguments...)
	for index := range result {
		if result[index] == name && index+1 < len(result) {
			return append(result[:index], result[index+2:]...)
		}
	}
	return result
}

func testSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
