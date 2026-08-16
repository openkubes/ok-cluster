package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
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
	arguments = replaceArgument(arguments, "--expected-stage", "cluster-lifecycle")
	arguments = append(arguments, "--receipt", "/tmp/provider.json@"+testSHA("7"))
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.ExpectedStageID != "cluster-lifecycle" || captured.PlanPath != "/tmp/plan.json" || captured.PlanExpected.ContractIdentity.Name != "disposable-ok147" || len(captured.Receipts) != 1 {
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

func TestStageInspectLoadsDigestBoundReceiptPrefix(t *testing.T) {
	previous := inspectSubmissionStage
	defer func() { inspectSubmissionStage = previous }()
	var captured runner.SubmissionStageBundleConfig
	inspectSubmissionStage = func(config runner.SubmissionStageBundleConfig) (stageInspection, error) {
		captured = config
		return stageInspection{Format: "ok147-stage-inspection/v1", Decision: stagecursor.Decision{Format: stagecursor.DecisionFormat, State: "NEXT"}, AuthorizationState: "VERIFIED"}, nil
	}
	root := t.TempDir()
	raw := []byte(`{"format":"` + runner.StageReceiptPrefixFormat + `","receipts":[{"file":"provider.json","digest":"` + testSHA("7") + `"}]}`)
	prefixPath := filepath.Join(root, "prefix.json")
	if err := os.WriteFile(prefixPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := append(stageInspectArguments(), "--receipt-prefix", prefixPath, "--receipt-prefix-digest", digest.SHA256(raw))
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if len(captured.Receipts) != 1 || captured.Receipts[0].Path != filepath.Join(root, "provider.json") || captured.Receipts[0].Digest != testSHA("7") {
		t.Fatalf("receipt-prefix manifest was not bound: %#v", captured.Receipts)
	}

	arguments = append(arguments, "--receipt", "/tmp/other.json@"+testSHA("8"))
	stdout.Reset()
	if err := run(arguments, &stdout, &stderr); err == nil {
		t.Fatal("receipt-prefix manifest and direct receipt were combined")
	}
}

func TestStageResumeSelectsReadOnlyStageWithoutGrantOrCredentials(t *testing.T) {
	previous := inspectStageResume
	defer func() { inspectStageResume = previous }()
	var captured runner.StageResumeConfig
	inspectStageResume = func(config runner.StageResumeConfig) (stageResumeInspection, error) {
		captured = config
		return stageResumeInspection{
			Format: "ok147-stage-resume-inspection/v1",
			Decision: stagecursor.Decision{
				Format: stagecursor.DecisionFormat, State: "NEXT", PlanDigest: testSHA("9"), CompletedStages: 2,
				StageID: "lifecycle-observation", StageOrder: 3, StageDigest: testSHA("8"), Kind: "Observation",
				Authority: "management", RequiresAuthorization: false, Predecessors: []stagecursor.Predecessor{},
			},
			MutationAllowed: false,
		}, nil
	}
	arguments := stageResumeArguments()
	arguments = append(arguments,
		"--receipt", "/tmp/provider.json@"+testSHA("6"),
		"--receipt", "/tmp/lifecycle.json@"+testSHA("7"),
	)
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.PlanPath != "/tmp/plan.json" || captured.PlanExpected.ContractIdentity.Name != "disposable-ok147" || len(captured.Receipts) != 2 {
		t.Fatalf("resume config differs: %#v", captured)
	}
	var result stageResumeInspection
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Format != "ok147-stage-resume-inspection/v1" || result.Decision.StageID != "lifecycle-observation" || result.Decision.RequiresAuthorization || result.MutationAllowed {
		t.Fatalf("unsafe resume inspection: %#v", result)
	}
}

func TestStageResumeRequiresCompleteUnambiguousInputs(t *testing.T) {
	for name, arguments := range map[string][]string{
		"missing bindings": {"cluster", "stage", "resume", "--plan", "/tmp/plan.json"},
		"positional":       append(stageResumeArguments(), "unexpected"),
		"bad receipt":      append(stageResumeArguments(), "--receipt", "/tmp/provider.json"),
		"half prefix":      append(stageResumeArguments(), "--receipt-prefix", "/tmp/prefix.json"),
		"mixed prefix": append(append(stageResumeArguments(),
			"--receipt-prefix", "/tmp/prefix.json", "--receipt-prefix-digest", testSHA("1")),
			"--receipt", "/tmp/provider.json@"+testSHA("2")),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("ambiguous resume input was accepted: err=%v stdout=%s", err, stdout.String())
			}
		})
	}
}

func TestStageObserveLifecycleRequiresExplicitExecutionAndBindsRuntime(t *testing.T) {
	previous := executeLifecycleObservationStage
	defer func() { executeLifecycleObservationStage = previous }()
	var capturedBundle runner.StageResumeConfig
	var capturedRuntime runner.LifecycleObservationStageRuntimeConfig
	var capturedContext context.Context
	executeLifecycleObservationStage = func(ctx context.Context, bundle runner.StageResumeConfig, runtime runner.LifecycleObservationStageRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
		capturedContext, capturedBundle, capturedRuntime = ctx, bundle, runtime
		return execution.ObservationStageRunReceipt{
			Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_SUCCEEDED",
			PlanDigest: testSHA("9"), StageID: "lifecycle-observation", StageReceiptDigest: testSHA("8"),
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run(stageObserveLifecycleArguments(), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if capturedBundle.PlanPath != "/tmp/plan.json" || len(capturedBundle.Receipts) != 2 {
		t.Fatalf("unexpected observation bundle: %#v", capturedBundle)
	}
	if capturedRuntime.Ledger.Namespace != ledgerNamespace || capturedRuntime.Ledger.TokenFile != "/tmp/ledger-token" || capturedRuntime.Management.TokenFile != "/tmp/management-observer-token" || capturedRuntime.Management.AuthorityIdentity != "" {
		t.Fatalf("unexpected observation runtime: %#v", capturedRuntime)
	}
	if capturedRuntime.PollInterval != 15*time.Second || capturedRuntime.PollTimeout != 5*time.Minute || capturedRuntime.Clock == nil || capturedRuntime.Wait == nil {
		t.Fatalf("bounded observation timing differs: %#v", capturedRuntime)
	}
	deadline, bounded := capturedContext.Deadline()
	remaining := time.Until(deadline)
	if !bounded || remaining > 6*time.Minute || remaining < 5*time.Minute {
		t.Fatalf("lifecycle observation context is not bounded: %s %t", deadline, bounded)
	}
	var receipt execution.ObservationStageRunReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "lifecycle-observation" {
		t.Fatalf("unexpected observation receipt: %#v", receipt)
	}
}

func TestStageObserveLifecycleFailsClosedBeforeExecution(t *testing.T) {
	previous := executeLifecycleObservationStage
	defer func() { executeLifecycleObservationStage = previous }()
	calls := 0
	executeLifecycleObservationStage = func(context.Context, runner.StageResumeConfig, runner.LifecycleObservationStageRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
		calls++
		return execution.ObservationStageRunReceipt{}, nil
	}
	valid := stageObserveLifecycleArguments()
	for name, arguments := range map[string][]string{
		"missing execute":          removeArgument(valid, "--execute"),
		"missing ledger token":     removeArgumentWithValue(valid, "--ledger-token-file"),
		"missing management token": removeArgumentWithValue(valid, "--management-token-file"),
		"missing poll timeout":     removeArgumentWithValue(valid, "--poll-timeout"),
		"too frequent":             replaceArgument(valid, "--poll-interval", "500ms"),
		"interval exceeds timeout": replaceArgument(valid, "--poll-interval", "6m"),
		"too long":                 replaceArgument(valid, "--poll-timeout", "7h"),
		"positional":               append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe lifecycle observation input was accepted: err=%v stdout=%s", err, stdout.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("observation execution was reached %d times for invalid input", calls)
	}
}

func TestStageObserveLifecycleEmitsPersistedTerminalReceipt(t *testing.T) {
	previous := executeLifecycleObservationStage
	defer func() { executeLifecycleObservationStage = previous }()
	executeLifecycleObservationStage = func(context.Context, runner.StageResumeConfig, runner.LifecycleObservationStageRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
		return execution.ObservationStageRunReceipt{
			Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_STOPPED",
			PlanDigest: testSHA("9"), StageID: "lifecycle-observation", StageReceiptDigest: testSHA("8"),
		}, errors.New("bounded observation stopped")
	}
	var stdout, stderr bytes.Buffer
	if err := run(stageObserveLifecycleArguments(), &stdout, &stderr); err == nil {
		t.Fatal("terminal lifecycle observation returned success")
	}
	var receipt execution.ObservationStageRunReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("persisted terminal observation receipt was lost: %#v", receipt)
	}
}

func TestStageObserveLifecyclePackageWritesVerifiedOfflineArtifact(t *testing.T) {
	previous := materializeLifecycleObservationStagePackage
	defer func() { materializeLifecycleObservationStagePackage = previous }()
	var captured runner.LifecycleObservationStagePackageConfig
	materializeLifecycleObservationStagePackage = func(config runner.LifecycleObservationStagePackageConfig) ([]byte, runner.LifecycleObservationStagePackageReceipt, error) {
		captured = config
		return []byte("verified-observation-package\n"), runner.LifecycleObservationStagePackageReceipt{
			Format: runner.LifecycleObservationStagePackageFormat, State: "VERIFIED", StageID: "lifecycle-observation",
			PackageDigest: testSHA("1"), InputConfigMapDigest: testSHA("2"), ReceiptPrefixDigest: testSHA("3"),
			JobTemplateDigest: testSHA("4"), JobEnvelopeDigest: testSHA("5"), ObjectKinds: []string{"ConfigMap", "NetworkPolicy", "Job"},
			AuthorizationState: "NOT_REQUIRED", MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template := filepath.Join(root, "observation-job.yaml.tpl")
	if err := os.WriteFile(template, []byte("bounded-observation-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "observation-package.yaml")
	arguments := stageObserveLifecyclePackageArguments(template, output)
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Bundle.PlanPath != "/tmp/plan.json" || len(captured.Bundle.Receipts) != 2 || captured.RunID != "ok147-lifecycle-observation-01" || captured.PollTimeout != 5*time.Minute {
		t.Fatalf("unexpected observation package config: %#v", captured)
	}
	if string(captured.JobTemplate) != "bounded-observation-template" || captured.JobTemplateDigest != digest.SHA256([]byte("bounded-observation-template")) || captured.LedgerCredentialSecret == captured.ManagementCredentialSecret {
		t.Fatalf("template or credentials were not bound: %#v", captured)
	}
	written, err := os.ReadFile(output)
	if err != nil || string(written) != "verified-observation-package\n" {
		t.Fatalf("unexpected observation package: %q %v", written, err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("observation package mode is not 0600: %v %v", info, err)
	}
	var receipt runner.LifecycleObservationStagePackageReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.AuthorizationState != "NOT_REQUIRED" || receipt.MutationAllowed {
		t.Fatalf("unsafe observation package receipt: %#v", receipt)
	}
	stdout.Reset()
	if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("existing observation package was overwritten")
	}
}

func TestStageObserveLifecyclePackageRejectsIncompleteInputs(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "observation-job.yaml.tpl")
	if err := os.WriteFile(template, []byte("bounded-observation-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "observation-package.yaml")
	valid := stageObserveLifecyclePackageArguments(template, output)
	for name, arguments := range map[string][]string{
		"execute":                   append(append([]string{}, valid...), "--execute"),
		"missing template digest":   removeArgumentWithValue(valid, "--job-template-digest"),
		"missing management secret": removeArgumentWithValue(valid, "--management-credential-secret"),
		"missing poll timeout":      removeArgumentWithValue(valid, "--poll-timeout"),
		"positional":                append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe observation package input was accepted: %v %s", err, stdout.String())
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

func TestEnablementStageRunBindsExactHCPAndManagementRuntime(t *testing.T) {
	previous := executeEnablementStage
	defer func() { executeEnablementStage = previous }()
	var calls int
	executeEnablementStage = func(ctx context.Context, bundle runner.EnablementStageBundleConfig, runtime runner.SubmissionStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
		calls++
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > stageRunTimeout || time.Until(deadline) < stageRunTimeout-time.Minute {
			t.Fatalf("enablement context is not bounded: %s %t", deadline, bounded)
		}
		if bundle.PlanPath != "/tmp/plan.json" || len(bundle.Receipts) != 3 || bundle.ArtifactPath != "/tmp/enablement.yaml" || bundle.ExpectedObject.Kind != "HelmChartProxy" || bundle.ExpectedObject.Name != "disposable-ok147-cilium" || bundle.ExpectedObject.Namespace != "disposable-ok147" {
			t.Fatalf("enablement bundle differs: %#v", bundle)
		}
		if runtime.Ledger.Namespace != ledgerNamespace || runtime.Authority.AuthorityIdentity != "ok-mgmt" || runtime.Authority.TokenFile != "/tmp/management-token" || runtime.Clock == nil {
			t.Fatalf("enablement runtime differs: %#v", runtime)
		}
		return execution.StagedOperationReceipt{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", StageID: "enablement", StageReceiptDigest: testSHA("8")}, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run(enablementStageRunArguments(), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("enablement runner calls = %d", calls)
	}
	var receipt execution.StagedOperationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.StageID != "enablement" {
		t.Fatalf("unexpected enablement receipt: %#v %v", receipt, err)
	}
}

func TestEnablementStageRunFailsClosedBeforeExecution(t *testing.T) {
	previous := executeEnablementStage
	defer func() { executeEnablementStage = previous }()
	calls := 0
	executeEnablementStage = func(context.Context, runner.EnablementStageBundleConfig, runner.SubmissionStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
		calls++
		return execution.StagedOperationReceipt{}, nil
	}
	valid := enablementStageRunArguments()
	for name, arguments := range map[string][]string{
		"missing execute":    removeArgument(valid, "--execute"),
		"missing artifact":   removeArgumentWithValue(valid, "--enablement-artifact"),
		"missing credential": removeArgumentWithValue(valid, "--management-token-file"),
		"invalid time":       replaceArgument(valid, "--evaluation-time", "not-time"),
		"positional":         append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe enablement run was accepted: %v %s", err, stdout.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("enablement runner reached %d times for invalid input", calls)
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

func TestStagePackageWritesOneVerifiedOfflineArtifact(t *testing.T) {
	previous := materializeSubmissionStagePackage
	defer func() { materializeSubmissionStagePackage = previous }()
	var captured runner.SubmissionStagePackageConfig
	materializeSubmissionStagePackage = func(config runner.SubmissionStagePackageConfig) ([]byte, runner.SubmissionStagePackageReceipt, error) {
		captured = config
		return []byte("verified-package\n"), runner.SubmissionStagePackageReceipt{
			Format: runner.SubmissionStagePackageFormat, State: "VERIFIED", StageID: "provider-prerequisites",
			PackageDigest: testSHA("1"), InputConfigMapDigest: testSHA("2"), ReceiptPrefixDigest: testSHA("3"),
			JobTemplateDigest: testSHA("4"), JobEnvelopeDigest: testSHA("5"), ObjectKinds: []string{"ConfigMap", "Job", "NetworkPolicy"},
			AuthorizationState: "VERIFIED", MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "package.yaml")
	arguments := stagePackageArguments(template, output)
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Bundle.ExpectedStageID != "provider-prerequisites" || captured.RunID != "ok147-provider-20260816-01" || captured.InputConfigMap != "ok147-provider-input" {
		t.Fatalf("unexpected package config: %#v", captured)
	}
	if string(captured.JobTemplate) != "bounded-template" || captured.JobTemplateDigest != digest.SHA256([]byte("bounded-template")) || captured.LedgerCredentialSecret == captured.AuthorityCredentialSecret {
		t.Fatalf("template or credential identities were not bound: %#v", captured)
	}
	written, err := os.ReadFile(output)
	if err != nil || string(written) != "verified-package\n" {
		t.Fatalf("unexpected package file: %q %v", written, err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("package mode is not 0600: %v %v", info, err)
	}
	var receipt runner.SubmissionStagePackageReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "VERIFIED" || receipt.MutationAllowed {
		t.Fatalf("unsafe package receipt: %#v", receipt)
	}

	stdout.Reset()
	if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("existing output was overwritten or emitted a false receipt")
	}
}

func TestStagePackageRejectsIncompleteAndSymlinkTemplate(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "package.yaml")
	missingImage := removeArgumentWithValue(stagePackageArguments(template, output), "--image")
	var stdout, stderr bytes.Buffer
	if err := run(missingImage, &stdout, &stderr); err == nil {
		t.Fatal("incomplete package input was accepted")
	}
	symlink := filepath.Join(root, "job-link.yaml.tpl")
	if err := os.Symlink(template, symlink); err != nil {
		t.Fatal(err)
	}
	if err := run(stagePackageArguments(symlink, output), &stdout, &stderr); err == nil {
		t.Fatal("symlink Job template was accepted")
	}
}

func TestStageLaunchPrepareBuildsOneNonMutatingCandidate(t *testing.T) {
	previous := prepareSubmissionStageLaunch
	defer func() { prepareSubmissionStageLaunch = previous }()
	var captured runner.SubmissionStageLaunchMaterialConfig
	prepareSubmissionStageLaunch = func(config runner.SubmissionStageLaunchMaterialConfig) (stageLaunchPreparation, error) {
		captured = config
		return stageLaunchPreparation{
			Format: "ok147-submission-stage-launch-preparation/v1", State: "PREPARED",
			Material: runner.SubmissionStageLaunchMaterialReceipt{
				Format: runner.SubmissionStageLaunchMaterialFormat, State: "VERIFIED", StageID: "provider-prerequisites",
				Authority: "ok-mgmt", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			Candidate: runner.SubmissionStageLaunchCandidateReceipt{
				Format: runner.SubmissionStageLaunchCandidateFormat, State: "PREPARED", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	runtimeManifest := filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := stageLaunchPrepareArguments(template, runtimeManifest)
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Package.Bundle.ExpectedStageID != "provider-prerequisites" || captured.Package.RunID != "ok147-provider-20260816-01" || captured.Package.InputConfigMap != "ok147-provider-input" || string(captured.Package.JobTemplate) != "bounded-template" || string(captured.RuntimeManifest) != "bounded-runtime" {
		t.Fatalf("launch package/runtime input differs: %#v", captured)
	}
	if captured.Ledger.AuthorityIdentity != "ok-mgmt" || captured.SelectedAuthority.AuthorityIdentity != "ok-infra" || captured.Ledger.TokenFile != "/private/tmp/ledger-job-token" || captured.SelectedAuthority.TokenFile != "/private/tmp/authority-job-token" || len(captured.Ledger.ExpectedAudiences) != 1 || captured.Ledger.ExpectedAudiences[0] != "https://kubernetes.default.svc" {
		t.Fatalf("launch credential input differs: %#v %#v", captured.Ledger, captured.SelectedAuthority)
	}
	if captured.Candidate.AuthorityEndpoint != "https://192.0.2.12:6443" || captured.Candidate.InstallerTokenDigest != testSHA("7") || captured.Candidate.PreparedAt.Format(time.RFC3339) != "2026-08-16T12:01:00Z" {
		t.Fatalf("launch candidate input differs: %#v", captured.Candidate)
	}
	var preparation stageLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.Format != "ok147-submission-stage-launch-preparation/v1" || preparation.State != "PREPARED" || preparation.MutationAllowed || preparation.Material.MutationAllowed || preparation.Candidate.MutationAllowed {
		t.Fatalf("unsafe launch preparation: %#v", preparation)
	}
}

func TestStageLaunchPrepareRejectsExecuteIncompleteAndSymlinkInputs(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	runtimeManifest := filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := stageLaunchPrepareArguments(template, runtimeManifest)
	for name, arguments := range map[string][]string{
		"execute flag":             append(append([]string(nil), valid...), "--execute"),
		"missing installer digest": removeArgumentWithValue(valid, "--installer-token-digest"),
		"spaced audience":          replaceArgument(valid, "--ledger-job-audiences", "https://kubernetes.default.svc, other"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatal("unsafe launch preparation input was accepted")
			}
		})
	}
	runtimeLink := filepath.Join(root, "runtime-link.yaml")
	if err := os.Symlink(runtimeManifest, runtimeLink); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(stageLaunchPrepareArguments(template, runtimeLink), &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("symlink runtime manifest was accepted")
	}
}

func TestStageLaunchExecuteUsesExactSingleUseBoundary(t *testing.T) {
	previous := executeSubmissionStageLaunch
	defer func() { executeSubmissionStageLaunch = previous }()
	var calls int
	var capturedAuthority runner.KubernetesAuthorityConfig
	var capturedCandidate string
	executeSubmissionStageLaunch = func(ctx context.Context, config runner.SubmissionStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.SubmissionStageLaunchReceipt, error) {
		calls++
		capturedAuthority, capturedCandidate = authority, expectedCandidateDigest
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout {
			t.Fatal("stage launch context is not bounded")
		}
		if config.Package.RunID != "ok147-provider-20260816-01" || config.Candidate.AuthorityEndpoint != "https://192.0.2.12:6443" {
			t.Fatalf("stage launch material differs: %#v", config)
		}
		return runner.SubmissionStageLaunchReceipt{
			Format: runner.SubmissionStageLaunchReceiptFormat, StageID: "provider-prerequisites", Authority: "ok-mgmt",
			State: "LAUNCHED", MutationState: "ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, nil
	}
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	runtimeManifest := filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := stageLaunchExecuteArguments(template, runtimeManifest)
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 || capturedCandidate != testSHA("9") {
		t.Fatalf("exact launch candidate was not used: calls=%d digest=%q", calls, capturedCandidate)
	}
	if capturedAuthority.Endpoint != "https://192.0.2.12:6443" || capturedAuthority.TokenFile != "/private/tmp/installer-token" || capturedAuthority.CAFile != "/private/tmp/installer-ca" || capturedAuthority.CABundleDigest != testSHA("2") {
		t.Fatalf("installer authority differs: %#v", capturedAuthority)
	}
	var receipt runner.SubmissionStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Format != runner.SubmissionStageLaunchReceiptFormat || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" {
		t.Fatalf("launch receipt differs: %#v", receipt)
	}
}

func TestStageLaunchExecuteFailsClosedBeforeLauncher(t *testing.T) {
	previous := executeSubmissionStageLaunch
	defer func() { executeSubmissionStageLaunch = previous }()
	var calls int
	executeSubmissionStageLaunch = func(context.Context, runner.SubmissionStageLaunchMaterialConfig, runner.KubernetesAuthorityConfig, string) (runner.SubmissionStageLaunchReceipt, error) {
		calls++
		return runner.SubmissionStageLaunchReceipt{}, nil
	}
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	runtimeManifest := filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := stageLaunchExecuteArguments(template, runtimeManifest)
	for name, arguments := range map[string][]string{
		"missing execute":           removeArgument(valid, "--execute"),
		"missing candidate":         removeArgumentWithValue(valid, "--expected-candidate-digest"),
		"malformed candidate":       replaceArgument(valid, "--expected-candidate-digest", "sha256:ABC"),
		"missing installer token":   removeArgumentWithValue(valid, "--installer-token-file"),
		"missing installer CA file": removeArgumentWithValue(valid, "--installer-ca-file"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatal("unsafe stage launch input was accepted")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("launcher was reached %d times for invalid input", calls)
	}
}

func TestStageLaunchExecuteEmitsStoppedReceipt(t *testing.T) {
	previous := executeSubmissionStageLaunch
	defer func() { executeSubmissionStageLaunch = previous }()
	executeSubmissionStageLaunch = func(context.Context, runner.SubmissionStageLaunchMaterialConfig, runner.KubernetesAuthorityConfig, string) (runner.SubmissionStageLaunchReceipt, error) {
		return runner.SubmissionStageLaunchReceipt{
			Format: runner.SubmissionStageLaunchReceiptFormat, StageID: "provider-prerequisites", Authority: "ok-mgmt",
			State: "STOPPED_ZERO_WRITE", MutationState: "NOT_ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, errors.New("bounded launch stopped")
	}
	root := t.TempDir()
	template := filepath.Join(root, "job.yaml.tpl")
	runtimeManifest := filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(stageLaunchExecuteArguments(template, runtimeManifest), &stdout, &stderr); err == nil {
		t.Fatal("stopped launch returned success")
	}
	var receipt runner.SubmissionStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("stopped launch receipt was lost: %#v", receipt)
	}
}

func TestLifecycleObservationLaunchPrepareBuildsOneNonMutatingCandidate(t *testing.T) {
	previous := prepareLifecycleObservationStageLaunch
	defer func() { prepareLifecycleObservationStageLaunch = previous }()
	var captured runner.LifecycleObservationStageLaunchMaterialConfig
	prepareLifecycleObservationStageLaunch = func(config runner.LifecycleObservationStageLaunchMaterialConfig) (lifecycleObservationLaunchPreparation, error) {
		captured = config
		return lifecycleObservationLaunchPreparation{
			Format: "ok147-lifecycle-observation-stage-launch-preparation/v1", State: "PREPARED",
			Material: runner.LifecycleObservationStageLaunchMaterialReceipt{
				Format: runner.LifecycleObservationStageLaunchMaterialFormat, State: "VERIFIED", StageID: "lifecycle-observation",
				Authority: "ok-mgmt", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			Candidate: runner.LifecycleObservationStageLaunchCandidateReceipt{
				Format: runner.LifecycleObservationStageLaunchCandidateFormat, State: "PREPARED", CandidateDigest: testSHA("1"), MutationAllowed: false,
			},
			MutationAllowed: false,
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "observation.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-observation-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(lifecycleObservationLaunchPrepareArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if captured.Package.Bundle.PlanExpected.ManagementAuthority != "ok-mgmt" || captured.Package.RunID != "ok147-lifecycle-observation-01" || captured.Package.PollInterval != 15*time.Second || captured.Package.PollTimeout != 5*time.Minute || string(captured.Package.JobTemplate) != "bounded-observation-template" || string(captured.RuntimeManifest) != "bounded-runtime" {
		t.Fatalf("lifecycle observation launch material differs: %#v", captured)
	}
	if captured.Ledger.AuthorityIdentity != "ok-mgmt" || captured.ManagementObserver.AuthorityIdentity != "ok-mgmt" || captured.Ledger.TokenFile == captured.ManagementObserver.TokenFile {
		t.Fatalf("observation credential boundary differs: %#v %#v", captured.Ledger, captured.ManagementObserver)
	}
	var preparation lifecycleObservationLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.State != "PREPARED" || preparation.MutationAllowed || preparation.Material.MutationAllowed || preparation.Candidate.MutationAllowed {
		t.Fatalf("unsafe lifecycle observation preparation: %#v", preparation)
	}
}

func TestLifecycleObservationLaunchExecuteUsesExactBoundary(t *testing.T) {
	previous := executeLifecycleObservationStageLaunch
	defer func() { executeLifecycleObservationStageLaunch = previous }()
	var calls int
	var candidate string
	executeLifecycleObservationStageLaunch = func(ctx context.Context, config runner.LifecycleObservationStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.LifecycleObservationStageLaunchReceipt, error) {
		calls++
		candidate = expectedCandidateDigest
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout {
			t.Fatal("lifecycle observation launch context is not bounded")
		}
		if config.Package.RunID != "ok147-lifecycle-observation-01" || authority.Endpoint != "https://192.0.2.12:6443" || authority.TokenFile != "/private/tmp/installer-token" {
			t.Fatalf("execute boundary differs: %#v %#v", config, authority)
		}
		return runner.LifecycleObservationStageLaunchReceipt{
			Format: runner.LifecycleObservationStageLaunchReceiptFormat, StageID: "lifecycle-observation", Authority: "ok-mgmt",
			State: "LAUNCHED", MutationState: "ATTEMPTED", Results: []runner.SubmissionStageLaunchResult{},
		}, nil
	}
	root := t.TempDir()
	template, runtimeManifest := filepath.Join(root, "observation.yaml.tpl"), filepath.Join(root, "runtime.yaml")
	if err := os.WriteFile(template, []byte("bounded-observation-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeManifest, []byte("bounded-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(lifecycleObservationLaunchExecuteArguments(template, runtimeManifest), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 || candidate != testSHA("9") {
		t.Fatalf("exact observation candidate not used: calls=%d digest=%q", calls, candidate)
	}
	var receipt runner.LifecycleObservationStageLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("unexpected observation launch receipt: %#v %v", receipt, err)
	}

	valid := lifecycleObservationLaunchExecuteArguments(template, runtimeManifest)
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
				t.Fatal("unsafe observation launch input reached executor")
			}
		})
	}
}

func stageInspectArguments() []string {
	return []string{
		"cluster", "stage", "inspect",
		"--expected-stage", "provider-prerequisites",
		"--plan", "/tmp/plan.json", "--contract-namespace", "disposable-ok147", "--contract-name", "disposable-ok147",
		"--intent-revision", testSHA("a"), "--enablement-revision", testSHA("b"), "--platform-revision", testSHA("c"),
		"--execution-fixture", testSHA("d"), "--infrastructure-authority", "ok-infra", "--management-authority", "ok-mgmt", "--gitops-authority", "ok-shared",
		"--grant", "/tmp/grant.json", "--grant-key", "/tmp/grant.pub", "--projection-manifest", "/tmp/projection.json",
		"--evaluation-time", "2026-08-16T14:00:00Z",
	}
}

func stageResumeArguments() []string {
	return []string{
		"cluster", "stage", "resume",
		"--plan", "/tmp/plan.json", "--contract-namespace", "disposable-ok147", "--contract-name", "disposable-ok147",
		"--intent-revision", testSHA("a"), "--enablement-revision", testSHA("b"), "--platform-revision", testSHA("c"),
		"--execution-fixture", testSHA("d"), "--infrastructure-authority", "ok-infra", "--management-authority", "ok-mgmt", "--gitops-authority", "ok-shared",
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

func enablementStageRunArguments() []string {
	resume := stageResumeArguments()
	arguments := append([]string{"cluster", "stage", "run", "enablement"}, resume[3:]...)
	return append(arguments,
		"--receipt", "/tmp/provider.json@"+testSHA("1"),
		"--receipt", "/tmp/lifecycle.json@"+testSHA("2"),
		"--receipt", "/tmp/lifecycle-observation.json@"+testSHA("3"),
		"--grant", "/tmp/enablement-grant.json", "--grant-key", "/tmp/enablement-grant.pub",
		"--evaluation-time", "2026-08-16T21:00:00Z",
		"--enablement-artifact", "/tmp/enablement.yaml", "--helmchartproxy-name", "disposable-ok147-cilium",
		"--execute",
		"--ledger-api-endpoint", "https://192.0.2.12:6443", "--ledger-token-file", "/tmp/ledger-token", "--ledger-ca-file", "/tmp/ledger-ca",
		"--management-api-endpoint", "https://192.0.2.12:6443", "--management-token-file", "/tmp/management-token", "--management-ca-file", "/tmp/management-ca",
	)
}

func stageObserveLifecycleArguments() []string {
	arguments := stageResumeArguments()
	arguments = append([]string{"cluster", "stage", "observe", "lifecycle"}, arguments[3:]...)
	return append(arguments,
		"--receipt", "/tmp/provider.json@"+testSHA("6"),
		"--receipt", "/tmp/lifecycle.json@"+testSHA("7"),
		"--execute",
		"--ledger-api-endpoint", "https://192.0.2.12:6443", "--ledger-token-file", "/tmp/ledger-token", "--ledger-ca-file", "/tmp/ledger-ca",
		"--management-api-endpoint", "https://192.0.2.12:6443", "--management-token-file", "/tmp/management-observer-token", "--management-ca-file", "/tmp/management-ca",
		"--poll-interval", "15s", "--poll-timeout", "5m",
	)
}

func stageObserveLifecyclePackageArguments(template, output string) []string {
	arguments := stageObserveLifecycleArguments()
	arguments = removeArgument(arguments, "--execute")
	for _, name := range []string{"--ledger-api-endpoint", "--ledger-token-file", "--ledger-ca-file", "--management-api-endpoint", "--management-token-file", "--management-ca-file", "--poll-interval", "--poll-timeout"} {
		arguments = removeArgumentWithValue(arguments, name)
	}
	arguments = append(arguments[:4], append([]string{"package"}, arguments[4:]...)...)
	return append(arguments,
		"--job-template", template, "--job-template-digest", digest.SHA256([]byte("bounded-observation-template")),
		"--output", output, "--run-id", "ok147-lifecycle-observation-01",
		"--image", "ghcr.io/openkubes/ok-cluster@"+testSHA("a"), "--input-configmap", "ok147-lifecycle-observation-input",
		"--ledger-api-url", "https://192.0.2.12:6443", "--ledger-api-cidr", "192.0.2.12/32", "--ledger-credential-secret", "ok147-ledger-observation",
		"--management-api-url", "https://192.0.2.12:6443", "--management-api-cidr", "192.0.2.12/32", "--management-credential-secret", "ok147-management-observer",
		"--poll-interval", "15s", "--poll-timeout", "5m",
	)
}

func stagePackageArguments(template, output string) []string {
	arguments := stageInspectArguments()
	arguments[2] = "package"
	return append(arguments,
		"--job-template", template, "--job-template-digest", digest.SHA256([]byte("bounded-template")), "--output", output,
		"--run-id", "ok147-provider-20260816-01",
		"--image", "ghcr.io/openkubes/ok-cluster@"+testSHA("a"),
		"--input-configmap", "ok147-provider-input",
		"--ledger-api-url", "https://192.0.2.12:6443", "--ledger-api-cidr", "192.0.2.12/32", "--ledger-credential-secret", "ok147-ledger-credential",
		"--authority-api-url", "https://192.0.2.11:6443", "--authority-api-cidr", "192.0.2.11/32", "--authority-credential-secret", "ok147-authority-credential",
	)
}

func stageLaunchPrepareArguments(template, runtimeManifest string) []string {
	bundle := stageInspectArguments()
	arguments := append([]string{"cluster", "stage", "launch", "prepare"}, bundle[3:]...)
	arguments = append(arguments,
		"--job-template", template, "--job-template-digest", digest.SHA256([]byte("bounded-template")),
		"--run-id", "ok147-provider-20260816-01", "--image", "ghcr.io/openkubes/ok-cluster@"+testSHA("a"),
		"--input-configmap", "ok147-provider-input",
		"--ledger-api-url", "https://192.0.2.12:6443", "--ledger-api-cidr", "192.0.2.12/32", "--ledger-credential-secret", "ok147-ledger-credential",
		"--authority-api-url", "https://192.0.2.11:6443", "--authority-api-cidr", "192.0.2.11/32", "--authority-credential-secret", "ok147-authority-credential",
		"--credential-materialized-at", "2026-08-16T12:00:00Z",
	)
	for _, credential := range []struct{ prefix, authority, tokenFile, tokenDigest, caFile, caDigest, evidence, subject string }{
		{"ledger-job", "ok-mgmt", "/private/tmp/ledger-job-token", testSHA("1"), "/private/tmp/ledger-job-ca", testSHA("2"), testSHA("3"), "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"},
		{"authority-job", "ok-infra", "/private/tmp/authority-job-token", testSHA("4"), "/private/tmp/authority-job-ca", testSHA("5"), testSHA("6"), "system:serviceaccount:openkubes-execution-system:ok147-provider-writer"},
	} {
		arguments = append(arguments,
			"--"+credential.prefix+"-authority", credential.authority,
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

func stageLaunchExecuteArguments(template, runtimeManifest string) []string {
	arguments := stageLaunchPrepareArguments(template, runtimeManifest)
	arguments[3] = "execute"
	return append(arguments,
		"--execute", "--expected-candidate-digest", testSHA("9"),
		"--installer-token-file", "/private/tmp/installer-token", "--installer-ca-file", "/private/tmp/installer-ca",
	)
}

func lifecycleObservationLaunchPrepareArguments(template, runtimeManifest string) []string {
	packaged := stageObserveLifecyclePackageArguments(template, "/private/tmp/not-used-package")
	packaged = removeArgumentWithValue(packaged, "--output")
	arguments := append([]string{"cluster", "stage", "observe", "lifecycle", "launch", "prepare"}, packaged[5:]...)
	arguments = append(arguments, "--credential-materialized-at", "2026-08-16T12:00:00Z")
	for _, credential := range []struct{ prefix, tokenFile, tokenDigest, caFile, caDigest, evidence, subject string }{
		{"ledger-job", "/private/tmp/ledger-observation-token", testSHA("1"), "/private/tmp/ledger-observation-ca", testSHA("2"), testSHA("3"), "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"},
		{"management-observer-job", "/private/tmp/management-observer-token", testSHA("4"), "/private/tmp/management-observer-ca", testSHA("2"), testSHA("5"), "system:serviceaccount:openkubes-execution-system:ok147-lifecycle-observer"},
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

func lifecycleObservationLaunchExecuteArguments(template, runtimeManifest string) []string {
	arguments := lifecycleObservationLaunchPrepareArguments(template, runtimeManifest)
	arguments[5] = "execute"
	return append(arguments,
		"--execute", "--expected-candidate-digest", testSHA("9"),
		"--installer-token-file", "/private/tmp/installer-token", "--installer-ca-file", "/private/tmp/installer-ca",
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
