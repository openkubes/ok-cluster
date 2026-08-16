package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
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

func testSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
