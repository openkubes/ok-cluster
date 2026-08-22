package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestFullRunPackageMaterializesPrivateInstallationUnit(t *testing.T) {
	previous := materializeFullRunExecutionActivationPackage
	defer func() { materializeFullRunExecutionActivationPackage = previous }()
	directory := t.TempDir()
	templatePath := filepath.Join(directory, "full-run-job.yaml.tpl")
	if err := os.WriteFile(templatePath, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "full-run-package.yaml")
	calls := 0
	materializeFullRunExecutionActivationPackage = func(config runner.FullRunExecutionActivationPackageConfig) ([]byte, runner.FullRunExecutionActivationPackageReceipt, error) {
		calls++
		if config.ManifestPath != "/private/full-run.json" || config.IndependentEvidencePublicKey != "/private/evidence.pub" ||
			config.ActivationSecret != "ok147-full-run-activation-01" || config.EvidenceAuthority.ActivationSecret != "ok147-evidence-authority-01" ||
			config.EvidenceAuthority.PrivateKeyPath != "/private/evidence.key" || config.EvidenceAuthority.CollectorEndpoint != "https://192.0.2.40:8443" ||
			config.EvidenceAuthority.RuntimeAuthorityRoot != "/var/run/openkubes/evidence-authority" || config.EvidenceAuthority.RuntimeHandoffRoot != "/var/run/openkubes/handoff" ||
			config.EvidenceAuthority.IdentityPollInterval != time.Second || config.EvidenceAuthority.IdentityWaitTimeout != 30*time.Minute ||
			config.EvidenceAuthority.EvidenceValidFor != 10*time.Minute || config.EvidenceAuthority.CollectionTimeout != 2*time.Minute ||
			string(config.JobTemplate) != "bounded-template" || config.JobTemplateDigest != testSHA("1") ||
			config.Job.RunID != "ok147-full-run-01" || config.Job.ImageDigest != "ghcr.io/openkubes/ok-cluster@"+testSHA("2") ||
			config.Job.InfrastructureAPICIDR != "192.0.2.13/32" || config.Job.ManagementAPICIDR != "192.0.2.12/32" ||
			config.Job.WorkloadAPIURL != "https://192.0.2.30:6443" || config.Job.WorkloadAPICIDR != "192.0.2.30/32" ||
			config.Job.ArgoAPICIDR != "192.0.2.11/32" || config.Job.AuthorizationAPICIDR != "192.0.2.10/32" ||
			config.Job.CollectorAPICIDR != "192.0.2.40/32" {
			t.Fatalf("full-run package config differs: %#v", config)
		}
		return []byte("private-package"), runner.FullRunExecutionActivationPackageReceipt{
			Format: runner.FullRunExecutionActivationPackageFormat, State: "VERIFIED", PackageDigest: testSHA("3"),
			ActivationSecret: config.ActivationSecret, EvidenceAuthoritySecret: config.EvidenceAuthority.ActivationSecret,
			ObjectKinds: []string{"Secret", "Secret", "NetworkPolicy", "Job"}, PrivateFileCount: 30,
		}, nil
	}
	arguments := fullRunPackageCLIArguments(templatePath, outputPath)
	var stdout bytes.Buffer
	if err := run(arguments, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	info, statErr := os.Stat(outputPath)
	if err != nil || statErr != nil || string(raw) != "private-package" || info.Mode().Perm() != 0o600 || calls != 1 {
		t.Fatalf("private package differs: raw=%q mode=%v calls=%d err=%v stat=%v", raw, info.Mode().Perm(), calls, err, statErr)
	}
	var receipt runner.FullRunExecutionActivationPackageReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "VERIFIED" || receipt.MutationAllowed {
		t.Fatalf("unexpected public receipt: %#v err=%v", receipt, err)
	}
	for _, forbidden := range []string{"/private/", outputPath, "collector-endpoint", "token", "kubeconfig", "private-key"} {
		if strings.Contains(strings.ToLower(stdout.String()), strings.ToLower(forbidden)) {
			t.Fatalf("public receipt disclosed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestFullRunPackageFailsClosedBeforeMaterialization(t *testing.T) {
	previous := materializeFullRunExecutionActivationPackage
	defer func() { materializeFullRunExecutionActivationPackage = previous }()
	directory := t.TempDir()
	templatePath := filepath.Join(directory, "full-run-job.yaml.tpl")
	if err := os.WriteFile(templatePath, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := fullRunPackageCLIArguments(templatePath, filepath.Join(directory, "package.yaml"))
	calls := 0
	materializeFullRunExecutionActivationPackage = func(runner.FullRunExecutionActivationPackageConfig) ([]byte, runner.FullRunExecutionActivationPackageReceipt, error) {
		calls++
		return []byte("private-package"), runner.FullRunExecutionActivationPackageReceipt{State: "VERIFIED"}, nil
	}
	for name, arguments := range map[string][]string{
		"missing output":       removeArgument(valid, filepath.Join(directory, "package.yaml")),
		"missing manifest":     removeArgument(valid, "/private/full-run.json"),
		"bad template digest":  replaceArgument(valid, "--job-template-digest", "sha256:bad"),
		"bad collector digest": replaceArgument(valid, "--collector-ca-digest", "sha256:bad"),
		"missing timing":       removeArgument(valid, "1s"),
		"unbounded timing":     replaceArgument(valid, "--identity-wait-timeout", "4h"),
		"positional":           append(append([]string(nil), valid...), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe full-run package input was accepted")
			}
			if calls != before {
				t.Fatalf("invalid input reached package materializer: calls=%d before=%d", calls, before)
			}
		})
	}
}

func fullRunPackageCLIArguments(templatePath, outputPath string) []string {
	return []string{
		"cluster", "stage", "run", "full", "package",
		"--manifest", "/private/full-run.json", "--independent-evidence-public-key", "/private/evidence.pub",
		"--activation-secret", "ok147-full-run-activation-01", "--evidence-authority-secret", "ok147-evidence-authority-01",
		"--evidence-private-key", "/private/evidence.key", "--collector-endpoint", "https://192.0.2.40:8443",
		"--collector-token-file", "/private/collector.token", "--collector-ca-file", "/private/collector-ca.crt",
		"--collector-ca-digest", testSHA("4"), "--identity-poll-interval", "1s", "--identity-wait-timeout", "30m",
		"--evidence-valid-for", "10m", "--collection-timeout", "2m", "--job-template", templatePath,
		"--job-template-digest", testSHA("1"), "--run-id", "ok147-full-run-01",
		"--image", "ghcr.io/openkubes/ok-cluster@" + testSHA("2"), "--infrastructure-api-cidr", "192.0.2.13/32",
		"--management-api-cidr", "192.0.2.12/32", "--workload-api-url", "https://192.0.2.30:6443",
		"--workload-api-cidr", "192.0.2.30/32", "--argo-api-cidr", "192.0.2.11/32",
		"--authorization-api-cidr", "192.0.2.10/32", "--collector-api-cidr", "192.0.2.40/32",
		"--output", outputPath,
	}
}

func TestFullRunLaunchPrepareEmitsCredentialFreePlan(t *testing.T) {
	previous := prepareFullRunExecutionActivationLaunch
	defer func() { prepareFullRunExecutionActivationLaunch = previous }()
	directory := t.TempDir()
	templatePath := filepath.Join(directory, "full-run-job.yaml.tpl")
	if err := os.WriteFile(templatePath, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	prepareFullRunExecutionActivationLaunch = func(config runner.FullRunExecutionActivationPackageConfig) (fullRunActivationLaunchPreparation, error) {
		calls++
		if config.Job.RunID != "ok147-full-run-01" || config.ActivationSecret != "ok147-full-run-activation-01" {
			t.Fatalf("full-run launch preparation differs: %#v", config)
		}
		return fullRunActivationLaunchPreparation{
			Format: "ok147-full-run-activation-launch-preparation/v1", State: "PREPARED",
			Package: runner.FullRunExecutionActivationPackageReceipt{
				Format: runner.FullRunExecutionActivationPackageFormat, State: "VERIFIED", PackageDigest: testSHA("3"),
				ManagementAuthority: "ok-mgmt", ObjectKinds: []string{"Secret", "Secret", "NetworkPolicy", "Job"},
			},
			Plan: runner.FullRunExecutionActivationInstallationPlan{
				Format: runner.FullRunExecutionActivationInstallationPlanFormat, State: "VERIFIED", RunID: config.Job.RunID,
				PackageDigest: testSHA("3"), Authority: "ok-mgmt", Creates: []runner.SubmissionStageCreatePlan{},
			},
		}, nil
	}
	var stdout bytes.Buffer
	if err := run(fullRunLaunchCLIArguments("prepare", templatePath), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt fullRunActivationLaunchPreparation
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "PREPARED" || receipt.MutationAllowed || calls != 1 {
		t.Fatalf("unexpected launch preparation: %#v calls=%d err=%v", receipt, calls, err)
	}
	for _, forbidden := range []string{"/private/", "token", "kubeconfig", "certificate", "endpoint"} {
		if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
			t.Fatalf("launch preparation disclosed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestFullRunLaunchExecuteRequiresExplicitBoundIdentity(t *testing.T) {
	previous := executeFullRunExecutionActivationLaunch
	defer func() { executeFullRunExecutionActivationLaunch = previous }()
	directory := t.TempDir()
	templatePath := filepath.Join(directory, "full-run-job.yaml.tpl")
	if err := os.WriteFile(templatePath, []byte("bounded-template"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	executeFullRunExecutionActivationLaunch = func(ctx context.Context, config runner.FullRunExecutionActivationPackageConfig, authority runner.KubernetesAuthorityConfig, expected string) (runner.FullRunExecutionActivationLaunchReceipt, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > stageLaunchTimeout || config.Job.RunID != "ok147-full-run-01" ||
			authority.Endpoint != "https://192.0.2.12:6443" || authority.TokenFile != "/private/installer.token" ||
			authority.CAFile != "/private/installer-ca.crt" || authority.CABundleDigest != testSHA("5") || expected != testSHA("3") {
			t.Fatalf("full-run launch execution differs: config=%#v authority=%#v expected=%q", config, authority, expected)
		}
		return runner.FullRunExecutionActivationLaunchReceipt{
			Format: runner.FullRunExecutionActivationLaunchReceiptFormat, State: "ACTIVATED", MutationState: "ATTEMPTED",
			RunID: config.Job.RunID, PackageDigest: expected, Authority: "ok-mgmt", Results: []runner.SubmissionStageInstalledObject{},
		}, nil
	}
	valid := append(fullRunLaunchCLIArguments("execute", templatePath),
		"--expected-package-digest", testSHA("3"), "--installer-api-endpoint", "https://192.0.2.12:6443",
		"--installer-ca-digest", testSHA("5"), "--installer-token-file", "/private/installer.token",
		"--installer-ca-file", "/private/installer-ca.crt", "--execute")
	var stdout bytes.Buffer
	if err := run(valid, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt runner.FullRunExecutionActivationLaunchReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "ACTIVATED" || calls != 1 {
		t.Fatalf("unexpected launch receipt: %#v calls=%d err=%v", receipt, calls, err)
	}
	for name, arguments := range map[string][]string{
		"missing execute":    removeArgument(valid, "--execute"),
		"bad package digest": replaceArgument(valid, "--expected-package-digest", "sha256:bad"),
		"bad CA digest":      replaceArgument(valid, "--installer-ca-digest", "sha256:bad"),
		"positional":         append(append([]string(nil), valid...), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe full-run launch was accepted")
			}
			if calls != before {
				t.Fatalf("invalid launch input reached executor: calls=%d before=%d", calls, before)
			}
		})
	}
}

func fullRunLaunchCLIArguments(action, templatePath string) []string {
	packageArguments := fullRunPackageCLIArguments(templatePath, "/unused/private-package.yaml")
	arguments := []string{"cluster", "stage", "run", "full", "launch", action}
	return append(arguments, packageArguments[5:len(packageArguments)-2]...)
}

func TestFullRunPrepareVerifiesWithoutOpeningExecution(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	calls := 0
	prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
		calls++
		if path != "/private/full-run.json" {
			t.Fatalf("full-run manifest path differs: %q", path)
		}
		return fullRunCLITestManifestReceipt("VERIFIED"), nil
	}
	var stdout bytes.Buffer
	if err := run([]string{"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt runner.FullRunExecutionActivationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || calls != 1 || receipt.Format != runner.FullRunExecutionActivationReceiptFormat || receipt.State != "PREPARED" || receipt.Manifest.ManifestDigest != testSHA("1") || receipt.Execution != nil {
		t.Fatalf("unexpected full-run preparation: receipt=%#v calls=%d err=%v", receipt, calls, err)
	}
	for _, forbidden := range []string{"/private/", "token", "endpoint", "kubeconfig", "certificate", "targetidentity"} {
		if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
			t.Fatalf("full-run preparation disclosed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestFullRunMaterializeRequiresExplicitBoundIdentity(t *testing.T) {
	previous := materializeFullRunExecutionBundle
	defer func() { materializeFullRunExecutionBundle = previous }()
	calls := 0
	materializeFullRunExecutionBundle = func(config runner.FullRunExecutionBundleMaterializationConfig) (runner.FullRunExecutionBundleMaterializationReceipt, error) {
		calls++
		if config.SourceDirectory != "/var/run/openkubes/source" || config.DestinationDirectory != "/var/run/openkubes/workspace" ||
			config.HandoffDirectory != "/var/run/openkubes/handoff-volume/private" || config.ExpectedBundleDigest != testSHA("1") {
			t.Fatalf("full-run materialization config differs: %#v", config)
		}
		return runner.FullRunExecutionBundleMaterializationReceipt{
			Format: runner.FullRunExecutionBundleMaterializationReceiptFormat, State: "MATERIALIZED_VERIFIED",
			BundleDigest: testSHA("1"), ManifestDigest: testSHA("2"), EvidenceKeyID: testSHA("3"), FileCount: 26, TotalBytes: 1024,
		}, nil
	}
	valid := []string{
		"cluster", "stage", "run", "full", "materialize",
		"--source", "/var/run/openkubes/source", "--destination", "/var/run/openkubes/workspace",
		"--handoff", "/var/run/openkubes/handoff-volume/private", "--expected-bundle-digest", testSHA("1"), "--materialize",
	}
	var stdout bytes.Buffer
	if err := run(valid, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt runner.FullRunExecutionBundleMaterializationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || calls != 1 || receipt.State != "MATERIALIZED_VERIFIED" || receipt.KubernetesMutationAllowed {
		t.Fatalf("unexpected full-run materialization: receipt=%#v calls=%d err=%v", receipt, calls, err)
	}
	for name, arguments := range map[string][]string{
		"missing activation": removeArgument(valid, "--materialize"),
		"missing source":     removeArgument(valid, "/var/run/openkubes/source"),
		"missing handoff":    removeArgument(valid, "/var/run/openkubes/handoff-volume/private"),
		"bad digest":         replaceArgument(valid, "--expected-bundle-digest", "sha256:bad"),
		"positional":         append(append([]string(nil), valid...), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe full-run materialization was accepted")
			}
			if calls != before {
				t.Fatalf("invalid CLI input reached materializer: calls=%d before=%d", calls, before)
			}
		})
	}
}

func TestFullRunExecuteRequiresPreparedIdentityAndRunsOnce(t *testing.T) {
	previous := openKubernetesObservabilityFullRunActivation
	previousPrepare := prepareFullRunExecutionManifest
	defer func() {
		openKubernetesObservabilityFullRunActivation = previous
		prepareFullRunExecutionManifest = previousPrepare
	}()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return fullRunCLITestManifestReceipt("VERIFIED"), nil
	}
	runs := 0
	openKubernetesObservabilityFullRunActivation = func(path, publicKeyPath string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
		if path != "/private/full-run.json" || publicKeyPath != "/private/evidence.pub" {
			t.Fatalf("concrete activation input differs: path=%q key=%q", path, publicKeyPath)
		}
		return fullRunActivationRunnerFunc(func(ctx context.Context) (runner.FullRunExecutionActivationReceipt, error) {
				runs++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > fullRunExecutionTimeout {
					t.Fatalf("full-run execution was not bounded: %v %v", deadline, ok)
				}
				return runner.FullRunExecutionActivationReceipt{
					Format: runner.FullRunExecutionActivationReceiptFormat, State: "SUCCEEDED",
					Manifest: fullRunCLITestManifestReceipt("VERIFIED"),
				}, nil
			}), runner.FullRunExecutionActivationReceipt{
				Format: runner.FullRunExecutionActivationReceiptFormat, State: "PREPARED",
				Manifest: fullRunCLITestManifestReceipt("VERIFIED"),
			}, nil
	}
	arguments := []string{
		"cluster", "stage", "run", "full", "execute", "--manifest", "/private/full-run.json",
		"--expected-manifest-digest", testSHA("1"), "--independent-evidence-public-key", "/private/evidence.pub", "--execute",
	}
	var stdout bytes.Buffer
	if err := run(arguments, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt runner.FullRunExecutionActivationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "SUCCEEDED" || runs != 1 {
		t.Fatalf("unexpected full-run execution receipt: %#v runs=%d err=%v", receipt, runs, err)
	}
	for _, forbidden := range []string{"/private/", "token", "endpoint", "kubeconfig", "certificate", "targetidentity"} {
		if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
			t.Fatalf("full-run execution disclosed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestFullRunExecuteFailsClosedBeforeRun(t *testing.T) {
	previous := openKubernetesObservabilityFullRunActivation
	previousPrepare := prepareFullRunExecutionManifest
	defer func() {
		openKubernetesObservabilityFullRunActivation = previous
		prepareFullRunExecutionManifest = previousPrepare
	}()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return fullRunCLITestManifestReceipt("VERIFIED"), nil
	}
	opens, runs := 0, 0
	openKubernetesObservabilityFullRunActivation = func(string, string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
		opens++
		return fullRunActivationRunnerFunc(func(context.Context) (runner.FullRunExecutionActivationReceipt, error) {
				runs++
				return runner.FullRunExecutionActivationReceipt{}, nil
			}), runner.FullRunExecutionActivationReceipt{
				Format: runner.FullRunExecutionActivationReceiptFormat, State: "PREPARED",
				Manifest: fullRunCLITestManifestReceipt("VERIFIED"),
			}, nil
	}
	valid := []string{
		"cluster", "stage", "run", "full", "execute", "--manifest", "/private/full-run.json",
		"--expected-manifest-digest", testSHA("1"), "--independent-evidence-public-key", "/private/evidence.pub", "--execute",
	}
	for name, arguments := range map[string][]string{
		"missing execute":    removeArgument(valid, "--execute"),
		"missing manifest":   removeArgument(valid, "/private/full-run.json"),
		"bad digest":         replaceArgument(valid, "--expected-manifest-digest", "sha256:bad"),
		"wrong digest":       replaceArgument(valid, "--expected-manifest-digest", testSHA("2")),
		"missing public key": removeArgument(valid, "/private/evidence.pub"),
		"positional":         append(append([]string(nil), valid...), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			before := opens
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe full-run execution was accepted")
			}
			if opens != before || runs != 0 {
				t.Fatalf("invalid CLI input reached activation: opens=%d before=%d runs=%d", opens, before, runs)
			}
		})
	}

	openKubernetesObservabilityFullRunActivation = func(string, string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
		opens++
		foreign := fullRunCLITestManifestReceipt("VERIFIED")
		foreign.ManifestDigest = testSHA("2")
		return fullRunActivationRunnerFunc(func(context.Context) (runner.FullRunExecutionActivationReceipt, error) {
			runs++
			return runner.FullRunExecutionActivationReceipt{}, nil
		}), runner.FullRunExecutionActivationReceipt{Format: runner.FullRunExecutionActivationReceiptFormat, State: "PREPARED", Manifest: foreign}, nil
	}
	if err := run(valid, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || runs != 0 {
		t.Fatalf("foreign prepared identity reached execution: opens=%d runs=%d err=%v", opens, runs, err)
	}

	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return runner.FullRunExecutionManifestReceipt{}, errors.New("specific manifest rejection")
	}
	opensBefore := opens
	err := run(valid, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "specific manifest rejection") || opens != opensBefore || runs != 0 {
		t.Fatalf("manifest rejection was not preserved before activation: opens=%d runs=%d err=%v", opens, runs, err)
	}
}

type fullRunActivationRunnerFunc func(context.Context) (runner.FullRunExecutionActivationReceipt, error)

func (run fullRunActivationRunnerFunc) Run(ctx context.Context) (runner.FullRunExecutionActivationReceipt, error) {
	return run(ctx)
}

func TestFullRunPrepareFailsClosed(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	calls := 0
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		calls++
		return runner.FullRunExecutionManifestReceipt{}, errors.New("private manifest rejected")
	}
	for name, arguments := range map[string][]string{
		"missing manifest": {"cluster", "stage", "run", "full", "prepare"},
		"positional":       {"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json", "extra"},
		"load rejection":   {"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json"},
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("unsafe full-run preparation was accepted")
			}
			if name != "load rejection" && calls != before {
				t.Fatalf("invalid CLI input reached manifest loader: calls=%d before=%d", calls, before)
			}
		})
	}

	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return fullRunCLITestManifestReceipt("STOPPED"), nil
	}
	if err := run([]string{"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unverified full-run receipt was accepted")
	}
	if err := run([]string{"cluster", "stage", "run", "full", "execute", "--manifest", "/private/full-run.json", "--execute"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unimplemented full-run execute surface was accepted")
	}
}

func fullRunCLITestManifestReceipt(state string) runner.FullRunExecutionManifestReceipt {
	return runner.FullRunExecutionManifestReceipt{
		Format: runner.FullRunExecutionManifestReceiptFormat, State: state,
		ManifestDigest: testSHA("1"), PlanDigest: testSHA("2"),
		ProjectionManifestDigest: testSHA("3"), ProjectionAuthorityDigest: testSHA("4"),
		NetworkProfileDigest: testSHA("5"), PlatformProfileDigest: testSHA("6"), AggregateProfileDigest: testSHA("7"),
		RuntimeIdentityMode: "lifecycle-derived-private/v1", AuthorizationMode: "predecessor-bound-tls/v1",
		CapabilityMode: "runtime-bound-in-memory/v1", MutationAllowed: false,
	}
}
