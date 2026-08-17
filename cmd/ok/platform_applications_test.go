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

func platformApplicationsStageRunArguments(t *testing.T) []string {
	t.Helper()
	profile := observation.PlatformProfile{
		Format:               observation.PlatformProfileFormat,
		IntentRevision:       testSHA("a"),
		PlatformRevision:     testSHA("c"),
		ExecutionFixture:     testSHA("d"),
		TargetIdentityScheme: "capi-cluster-uid/v1",
		ArgoNamespace:        "argocd",
		RegistrationName:     "disposable-ok147",
		RequiredApplications: []observation.PlatformApplicationExpectation{
			{Name: "disposable-ok147-observability-core", SpecDigest: testSHA("1")},
			{Name: "disposable-ok147-observability-logs", SpecDigest: testSHA("2")},
			{Name: "disposable-ok147-observability-metrics", SpecDigest: testSHA("3")},
		},
		CapabilityContractDigest:    testSHA("4"),
		CapabilityExecutableDigest:  testSHA("5"),
		MaximumCapabilityAgeSeconds: 900,
	}
	profileDigest, err := observation.PlatformProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	rawProfile, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(t.TempDir(), "platform-profile.json")
	if err := os.WriteFile(profilePath, rawProfile, 0o600); err != nil {
		t.Fatal(err)
	}
	resume := stageResumeArguments()
	arguments := append([]string{"cluster", "stage", "run", "platform-applications"}, resume[3:]...)
	return append(arguments,
		"--receipt", "/tmp/provider.json@"+testSHA("1"),
		"--receipt", "/tmp/lifecycle.json@"+testSHA("2"),
		"--receipt", "/tmp/lifecycle-observation.json@"+testSHA("3"),
		"--receipt", "/tmp/enablement.json@"+testSHA("4"),
		"--receipt", "/tmp/network-observation.json@"+testSHA("5"),
		"--receipt", "/tmp/runtime-binding.json@"+testSHA("6"),
		"--receipt", "/tmp/target-access.json@"+testSHA("7"),
		"--receipt", "/tmp/target-credential.json@"+testSHA("8"),
		"--receipt", "/tmp/target-registration.json@"+testSHA("9"),
		"--grant", "/tmp/platform-applications-grant.json", "--grant-key", "/tmp/platform-applications-grant.pub",
		"--evaluation-time", "2026-08-17T16:00:00Z",
		"--platform-applications-artifact", "/tmp/platform-applications.yaml", "--platform-applications-digest", testSHA("6"),
		"--platform-profile", profilePath, "--platform-profile-digest", profileDigest,
		"--target-identity-digest", testSHA("7"),
		"--argo-namespace", "argocd", "--project-name", "ok147-disposable", "--registration-name", "disposable-ok147",
		"--source-repository", "https://github.com/openkubes/ok-observability.git",
		"--execute",
		"--ledger-api-endpoint", "https://192.0.2.12:6443", "--ledger-token-file", "/private/tmp/ledger-token", "--ledger-ca-file", "/private/tmp/ledger-ca",
		"--gitops-api-endpoint", "https://192.0.2.13:6443", "--gitops-token-file", "/private/tmp/gitops-token", "--gitops-ca-file", "/private/tmp/gitops-ca", "--gitops-ca-digest", testSHA("8"),
	)
}

func TestPlatformApplicationsStageRunBindsExactProfileAndGitOpsRuntime(t *testing.T) {
	previous := executePlatformApplicationsStage
	defer func() { executePlatformApplicationsStage = previous }()
	var calls int
	executePlatformApplicationsStage = func(ctx context.Context, bundle runner.PlatformApplicationsStageBundleConfig, runtime runner.PlatformApplicationsStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
		calls++
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > stageRunTimeout || time.Until(deadline) < stageRunTimeout-time.Minute {
			t.Fatalf("platform-applications context is not bounded: %s %t", deadline, bounded)
		}
		if bundle.PlanPath != "/tmp/plan.json" || len(bundle.Receipts) != 9 || bundle.ArtifactPath != "/tmp/platform-applications.yaml" || bundle.Expected.ArtifactDigest != testSHA("6") {
			t.Fatalf("platform-applications bundle differs: %#v", bundle)
		}
		if bundle.Expected.IntentRevision != testSHA("a") || bundle.Expected.PlatformRevision != testSHA("c") || bundle.Expected.ExecutionFixture != testSHA("d") || bundle.Expected.TargetIdentityDigest != testSHA("7") {
			t.Fatalf("platform-applications revision binding differs: %#v", bundle.Expected)
		}
		if bundle.Expected.ArgoAuthority != "ok-shared" || bundle.Expected.ArgoNamespace != "argocd" || bundle.Expected.ProjectName != "ok147-disposable" || bundle.Expected.RegistrationName != "disposable-ok147" || len(bundle.Expected.Profile.RequiredApplications) != 3 {
			t.Fatalf("platform-applications authority or profile differs: %#v", bundle.Expected)
		}
		if runtime.Ledger.Namespace != ledgerNamespace || runtime.GitOps.AuthorityIdentity != "ok-shared" || runtime.GitOps.Endpoint != "https://192.0.2.13:6443" || runtime.GitOps.TokenFile != "/private/tmp/gitops-token" || runtime.GitOps.CABundleDigest != testSHA("8") || runtime.Clock == nil {
			t.Fatalf("platform-applications runtime differs: %#v", runtime)
		}
		return execution.StagedOperationReceipt{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", StageID: "platform-applications", StageReceiptDigest: testSHA("9")}, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run(platformApplicationsStageRunArguments(t), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("platform-applications runner calls = %d", calls)
	}
	var receipt execution.StagedOperationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.StageID != "platform-applications" {
		t.Fatalf("unexpected platform-applications receipt: %#v %v", receipt, err)
	}
}

func TestPlatformApplicationsStageRunFailsClosedBeforeExecution(t *testing.T) {
	previous := executePlatformApplicationsStage
	defer func() { executePlatformApplicationsStage = previous }()
	calls := 0
	executePlatformApplicationsStage = func(context.Context, runner.PlatformApplicationsStageBundleConfig, runner.PlatformApplicationsStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
		calls++
		return execution.StagedOperationReceipt{}, nil
	}
	valid := platformApplicationsStageRunArguments(t)
	for name, arguments := range map[string][]string{
		"missing execute":         removeArgument(valid, "--execute"),
		"missing artifact":        removeArgumentWithValue(valid, "--platform-applications-artifact"),
		"missing profile":         removeArgumentWithValue(valid, "--platform-profile"),
		"invalid profile digest":  replaceArgument(valid, "--platform-profile-digest", "not-a-digest"),
		"missing gitops identity": removeArgumentWithValue(valid, "--gitops-ca-digest"),
		"invalid time":            replaceArgument(valid, "--evaluation-time", "not-time"),
		"positional":              append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe platform-applications run was accepted: %v %s", err, stdout.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("platform-applications runner reached %d times for invalid input", calls)
	}
}
