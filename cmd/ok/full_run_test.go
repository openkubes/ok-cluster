package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

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
			config.HandoffDirectory != "/var/run/openkubes/handoff" || config.ExpectedBundleDigest != testSHA("1") {
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
		"--handoff", "/var/run/openkubes/handoff", "--expected-bundle-digest", testSHA("1"), "--materialize",
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
		"missing handoff":    removeArgument(valid, "/var/run/openkubes/handoff"),
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
