package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func platformObservationStageArguments(t *testing.T) []string {
	t.Helper()
	platformArguments := platformApplicationsStageRunArguments(t)
	profilePath := testFlagValue(t, platformArguments, "--platform-profile")
	profileDigest := testFlagValue(t, platformArguments, "--platform-profile-digest")
	resume := stageResumeArguments()
	arguments := append([]string{"cluster", "stage", "observe", "platform"}, resume[3:]...)
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
		"--receipt", "/tmp/platform-applications.json@"+testSHA("0"),
		"--platform-profile", profilePath, "--platform-profile-digest", profileDigest,
		"--runtime-binding-material", "/private/tmp/runtime-binding.json", "--runtime-binding-receipt", "/private/tmp/runtime-binding-receipt.json",
		"--platform-capability", "/private/tmp/platform-capability.json", "--platform-capability-digest", testSHA("6"),
		"--execute",
		"--ledger-api-endpoint", "https://192.0.2.12:6443", "--ledger-token-file", "/private/tmp/ledger-token", "--ledger-ca-file", "/private/tmp/ledger-ca",
		"--argo-api-endpoint", "https://192.0.2.13:6443", "--argo-token-file", "/private/tmp/argo-token", "--argo-ca-file", "/private/tmp/argo-ca", "--argo-ca-digest", testSHA("8"),
		"--poll-interval", "15s", "--poll-timeout", "5m",
	)
}

func TestPlatformObservationStageBindsPrivateRuntimeCapabilityAndArgo(t *testing.T) {
	previous := executePlatformObservationStage
	defer func() { executePlatformObservationStage = previous }()
	var calls int
	executePlatformObservationStage = func(ctx context.Context, bundle runner.PlatformObservationStageBundleConfig, runtime runner.PlatformObservationStageFileRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
		calls++
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > 6*time.Minute || time.Until(deadline) < 4*time.Minute {
			t.Fatalf("platform observation context is not bounded: %s %t", deadline, bounded)
		}
		if len(bundle.Receipts) != 10 || bundle.ExpectedProfileDigest == "" || len(bundle.Profile.RequiredApplications) != 3 {
			t.Fatalf("platform observation bundle differs: %#v", bundle)
		}
		if runtime.RuntimeMaterialPath != "/private/tmp/runtime-binding.json" || runtime.RuntimeReceiptPath != "/private/tmp/runtime-binding-receipt.json" || runtime.CapabilityPath != "/private/tmp/platform-capability.json" || runtime.ExpectedCapabilityDigest != testSHA("6") {
			t.Fatalf("platform observation private inputs differ: %#v", runtime)
		}
		if runtime.Ledger.Namespace != ledgerNamespace || runtime.Argo.AuthorityIdentity != "ok-shared" || runtime.Argo.CABundleDigest != testSHA("8") || runtime.PollInterval != 15*time.Second || runtime.PollTimeout != 5*time.Minute || runtime.Clock == nil || runtime.Wait == nil {
			t.Fatalf("platform observation authority differs: %#v", runtime)
		}
		return execution.ObservationStageRunReceipt{Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_TRUE", StageID: "platform-observation", StageReceiptDigest: testSHA("9")}, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run(platformObservationStageArguments(t), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("platform observation calls = %d", calls)
	}
	var receipt execution.ObservationStageRunReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.StageID != "platform-observation" {
		t.Fatalf("unexpected platform observation receipt: %#v %v", receipt, err)
	}
}

func TestPlatformObservationStageFailsClosedBeforeExecution(t *testing.T) {
	previous := executePlatformObservationStage
	defer func() { executePlatformObservationStage = previous }()
	calls := 0
	executePlatformObservationStage = func(context.Context, runner.PlatformObservationStageBundleConfig, runner.PlatformObservationStageFileRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
		calls++
		return execution.ObservationStageRunReceipt{}, nil
	}
	valid := platformObservationStageArguments(t)
	for name, arguments := range map[string][]string{
		"missing execute":          removeArgument(valid, "--execute"),
		"missing runtime material": removeArgumentWithValue(valid, "--runtime-binding-material"),
		"missing capability":       removeArgumentWithValue(valid, "--platform-capability"),
		"invalid capability":       replaceArgument(valid, "--platform-capability-digest", "not-a-digest"),
		"missing Argo credential":  removeArgumentWithValue(valid, "--argo-token-file"),
		"unbounded polling":        replaceArgument(valid, "--poll-timeout", "7h"),
		"positional":               append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatalf("unsafe platform observation was accepted: %v %s", err, stdout.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("platform observation runner reached %d times for invalid input", calls)
	}
}

func testFlagValue(t *testing.T, arguments []string, name string) string {
	t.Helper()
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	t.Fatalf("missing test flag %s", name)
	return ""
}
