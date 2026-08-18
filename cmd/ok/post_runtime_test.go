package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

type fakePostRuntimeExecutor struct {
	calls         int
	deadlineBound bool
	receipt       runner.PostRuntimeExecutionReceipt
	err           error
}

func (executor *fakePostRuntimeExecutor) Run(ctx context.Context) (runner.PostRuntimeExecutionReceipt, error) {
	executor.calls++
	_, executor.deadlineBound = ctx.Deadline()
	return executor.receipt, executor.err
}

func TestPostRuntimePrepareVerifiesWithoutExecution(t *testing.T) {
	fake := &fakePostRuntimeExecutor{}
	restore := stubPostRuntimeExecutor(t, fake, testPostRuntimeManifestReceipt(testSHA("1")))
	defer restore()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"cluster", "stage", "run", "post-runtime", "prepare", "--manifest", "/private/tmp/post-runtime.json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if fake.calls != 0 {
		t.Fatal("post-runtime prepare executed the suffix")
	}
	var receipt postRuntimeCLIReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.Format != postRuntimeCLIReceiptFormat || receipt.State != "PREPARED" ||
		receipt.Manifest.ManifestDigest != testSHA("1") || receipt.Execution != nil {
		t.Fatalf("unexpected prepare receipt: %#v %v", receipt, err)
	}
}

func TestPostRuntimeMaterializeRequiresExplicitBoundIdentity(t *testing.T) {
	previous := materializePostRuntimeBundle
	defer func() { materializePostRuntimeBundle = previous }()
	calls := 0
	materializePostRuntimeBundle = func(config runner.PostRuntimeExecutionBundleMaterializationConfig) (runner.PostRuntimeExecutionBundleReceipt, error) {
		calls++
		if config.SourceDirectory != "/var/run/openkubes/source" || config.DestinationDirectory != "/var/run/openkubes/workspace" || config.ExpectedBundleDigest != testSHA("1") {
			t.Fatalf("unexpected materialization config: %#v", config)
		}
		return runner.PostRuntimeExecutionBundleReceipt{
			Format: runner.PostRuntimeExecutionBundleReceiptFormat, State: "MATERIALIZED_VERIFIED", BundleDigest: testSHA("1"), FileCount: 34,
		}, nil
	}
	arguments := []string{
		"cluster", "stage", "run", "post-runtime", "materialize", "--source", "/var/run/openkubes/source",
		"--destination", "/var/run/openkubes/workspace", "--expected-bundle-digest", testSHA("1"), "--materialize",
	}
	var stdout bytes.Buffer
	if err := run(arguments, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(stdout.String(), `"state": "MATERIALIZED_VERIFIED"`) {
		t.Fatalf("materialization did not execute exactly once: calls=%d output=%s", calls, stdout.String())
	}
	for name, remove := range map[string]string{"no explicit flag": "--materialize", "no digest": testSHA("1"), "positional": ""} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]string(nil), arguments...)
			if remove == "" {
				candidate = append(candidate, "extra")
			} else {
				for index, value := range candidate {
					if value == remove {
						candidate = append(candidate[:index], candidate[index+1:]...)
						break
					}
				}
			}
			before := calls
			if err := run(candidate, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || calls != before {
				t.Fatalf("unsafe materialization reached runner: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestPostRuntimeExecuteRequiresPreparedIdentityAndRunsOnce(t *testing.T) {
	fake := &fakePostRuntimeExecutor{receipt: runner.PostRuntimeExecutionReceipt{
		Format: runner.PostRuntimeExecutionReceiptFormat, State: "SUCCEEDED", PlanDigest: testSHA("2"),
	}}
	restore := stubPostRuntimeExecutor(t, fake, testPostRuntimeManifestReceipt(testSHA("1")))
	defer restore()
	var stdout, stderr bytes.Buffer
	err := runContext(context.Background(), []string{
		"cluster", "stage", "run", "post-runtime", "execute",
		"--manifest", "/private/tmp/post-runtime.json", "--expected-manifest-digest", testSHA("1"), "--execute",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 || !fake.deadlineBound {
		t.Fatalf("post-runtime execution was not exact and bounded: calls=%d deadline=%v", fake.calls, fake.deadlineBound)
	}
	var receipt postRuntimeCLIReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "SUCCEEDED" || receipt.Execution == nil || receipt.Execution.PlanDigest != testSHA("2") {
		t.Fatalf("unexpected execution receipt: %#v %v", receipt, err)
	}
}

func TestPostRuntimeExecuteFailsClosedBeforeRun(t *testing.T) {
	for name, arguments := range map[string][]string{
		"no execute":   {"cluster", "stage", "run", "post-runtime", "execute", "--manifest", "/private/tmp/post-runtime.json", "--expected-manifest-digest", testSHA("1")},
		"bad digest":   {"cluster", "stage", "run", "post-runtime", "execute", "--manifest", "/private/tmp/post-runtime.json", "--expected-manifest-digest", "sha256:no", "--execute"},
		"wrong digest": {"cluster", "stage", "run", "post-runtime", "execute", "--manifest", "/private/tmp/post-runtime.json", "--expected-manifest-digest", testSHA("2"), "--execute"},
		"positional":   {"cluster", "stage", "run", "post-runtime", "execute", "--manifest", "/private/tmp/post-runtime.json", "--expected-manifest-digest", testSHA("1"), "--execute", "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakePostRuntimeExecutor{}
			restore := stubPostRuntimeExecutor(t, fake, testPostRuntimeManifestReceipt(testSHA("1")))
			defer restore()
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || fake.calls != 0 {
				t.Fatalf("unsafe execution reached runner: calls=%d err=%v", fake.calls, err)
			}
		})
	}
}

func TestPostRuntimeExecuteEmitsStoppedReceiptOnRunFailure(t *testing.T) {
	fake := &fakePostRuntimeExecutor{
		receipt: runner.PostRuntimeExecutionReceipt{Format: runner.PostRuntimeExecutionReceiptFormat, State: "STOPPED", StoppedAt: "target-registration"},
		err:     errors.New("private authority failure"),
	}
	restore := stubPostRuntimeExecutor(t, fake, testPostRuntimeManifestReceipt(testSHA("1")))
	defer restore()
	var stdout bytes.Buffer
	err := run([]string{
		"cluster", "stage", "run", "post-runtime", "execute", "--manifest", "/private/tmp/post-runtime.json",
		"--expected-manifest-digest", testSHA("1"), "--execute",
	}, &stdout, &bytes.Buffer{})
	if err == nil || strings.Contains(stdout.String(), "private authority failure") {
		t.Fatalf("failed execution was not redaction-safe: output=%q err=%v", stdout.String(), err)
	}
	var receipt postRuntimeCLIReceipt
	if decodeErr := json.Unmarshal(stdout.Bytes(), &receipt); decodeErr != nil || receipt.State != "STOPPED" || receipt.Execution == nil || receipt.Execution.StoppedAt != "target-registration" {
		t.Fatalf("stopped execution receipt was not emitted: %#v %v", receipt, decodeErr)
	}
}

func stubPostRuntimeExecutor(t *testing.T, executor postRuntimeExecutor, receipt runner.PostRuntimeExecutionManifestReceipt) func() {
	t.Helper()
	previous := openPostRuntimeExecutor
	openPostRuntimeExecutor = func(path string) (postRuntimeExecutor, runner.PostRuntimeExecutionManifestReceipt, error) {
		if path != "/private/tmp/post-runtime.json" {
			return nil, runner.PostRuntimeExecutionManifestReceipt{}, errors.New("unexpected private path")
		}
		return executor, receipt, nil
	}
	return func() { openPostRuntimeExecutor = previous }
}

func testPostRuntimeManifestReceipt(manifestDigest string) runner.PostRuntimeExecutionManifestReceipt {
	return runner.PostRuntimeExecutionManifestReceipt{
		Format: runner.PostRuntimeExecutionManifestReceiptFormat, State: "VERIFIED", ManifestDigest: manifestDigest,
		PlanDigest: testSHA("3"), InitialReceiptCount: 7, TargetIdentityDigest: testSHA("4"),
		NetworkProfileDigest: testSHA("5"), PlatformProfileDigest: testSHA("6"), AggregateProfileDigest: testSHA("7"),
		AuthorizationMode: "predecessor-bound-tls/v1", MutationAllowed: false,
	}
}
