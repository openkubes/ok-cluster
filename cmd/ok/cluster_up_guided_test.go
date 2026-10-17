package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func guidedUpFixture(t *testing.T) (string, string, string) {
	t.Helper()
	_, configArgs := configFixture(t)
	if err := run(configArgs, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	path := intentFixture(t, nil)
	dir, _ := os.UserConfigDir()
	root := filepath.Join(dir, "ok", "runs", "my-cluster")
	contract := filepath.Join(t.TempDir(), "reviewed contract.yaml")
	refs := filepath.Join(t.TempDir(), "private refs.json")
	for name, raw := range map[string][]byte{contract: []byte("reviewed fixture"), refs: []byte(`{"independentEvidencePublicKeyPath":"/explicit/evidence.pub"}`)} {
		if err := os.WriteFile(name, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousPrepare, previousVerify, previousEvidence, previousMarker := prepareGuidedClusterIntent, verifyPreparedManifestFixture, verifyGuidedEvidenceKey, validateClusterCreateTerminalMarker
	t.Cleanup(func() {
		prepareGuidedClusterIntent, verifyPreparedManifestFixture, verifyGuidedEvidenceKey, validateClusterCreateTerminalMarker = previousPrepare, previousVerify, previousEvidence, previousMarker
	})
	prepareGuidedClusterIntent = func(_ context.Context, args []string, stdout, _ io.Writer) error {
		if !strings.Contains(strings.Join(args, "|"), contract) || !strings.Contains(strings.Join(args, "|"), refs) {
			t.Fatal("missing explicit reviewed inputs")
		}
		_, source, _ := preparedIntentFixture(t)
		output := filepath.Join(root, "preparation")
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"execution-fixture.json", "binding-receipt.json", "full-run-manifest.json"} {
			raw, _ := os.ReadFile(filepath.Join(source, name))
			if err := os.WriteFile(filepath.Join(output, name), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		raw, _ := os.ReadFile(refs)
		return json.NewEncoder(stdout).Encode(map[string]any{"format": "ok-cli-cluster-runner-handoff/v1", "state": "PREPARED_NOT_AUTHORIZED", "runnerReady": true, "manifestDigest": testSHA("1"), "runtimeInputsDigest": digest.SHA256(raw), "independentEvidenceKeyId": testSHA("2")})
	}
	verifyPreparedManifestFixture = func(string, []byte) (runner.FullRunExecutionManifestReceipt, error) {
		return bareClusterCreateManifestReceipt(), nil
	}
	verifyGuidedEvidenceKey = func(path, key string) error {
		if path != "/explicit/evidence.pub" || key != testSHA("2") {
			t.Fatal("evidence pin changed")
		}
		return nil
	}
	validateClusterCreateTerminalMarker = func(path string) error {
		if path != filepath.Join(root, "executor-terminal") {
			t.Fatal("terminal path changed")
		}
		return nil
	}
	return path, root, contract + "\n" + refs + "\n"
}

func TestGuidedUpConfirmationAndSingleStart(t *testing.T) {
	for _, answer := range []string{"ok\n", "no\n", "\n", "yes\n", "ok"} {
		t.Run(strings.ReplaceAll(answer, "\n", "newline"), func(t *testing.T) {
			path, root, input := guidedUpFixture(t)
			previous := executeClusterCreateLive
			defer func() { executeClusterCreateLive = previous }()
			calls := 0
			stop := errors.New("simulated incomplete STOP")
			executeClusterCreateLive = func(_ context.Context, config clusterCreateLiveConfig, _, _ io.Writer) error {
				calls++
				if _, err := os.Stat(filepath.Join(root, "execution-started.json")); err != nil {
					t.Fatal("missing durable start fence")
				}
				if config.ExpectedManifestDigest != testSHA("1") || config.IndependentEvidencePublicKey != "/explicit/evidence.pub" || config.ManifestPath != filepath.Join(root, "preparation", "full-run-manifest.json") || config.TerminalMarker != filepath.Join(root, "executor-terminal") {
					t.Fatalf("wrong live binding: %+v", config)
				}
				return stop
			}
			var out, prompts bytes.Buffer
			err := runGuidedClusterUpWithRuntime(context.Background(), path, &out, &prompts, guidedUpRuntime{strings.NewReader(input + answer), true})
			if answer == "ok\n" {
				if !errors.Is(err, stop) || calls != 1 {
					t.Fatalf("err=%v calls=%d", err, calls)
				}
				err = runGuidedClusterUpWithRuntime(context.Background(), path, &out, &prompts, guidedUpRuntime{panicConfigReader{}, true})
				if err == nil || calls != 1 {
					t.Fatal("replayed a claimed/failed run")
				}
			} else if err == nil || calls != 0 {
				t.Fatalf("cancelled run executed: %v calls=%d", err, calls)
			}
			if !strings.Contains(prompts.String(), testSHA("1")) || !strings.Contains(prompts.String(), "1 control plane, 1 worker") {
				t.Fatal("confirmation missing exact plan summary")
			}
			if out.Len() != 0 {
				t.Fatal("guided preparation leaked JSON or a success claim")
			}
		})
	}
}

func TestGuidedUpReusesUnstartedPreparationButRejectsDrift(t *testing.T) {
	path, root, input := guidedUpFixture(t)
	var output bytes.Buffer
	invoke := func(input io.Reader) error {
		return runGuidedClusterUpWithRuntime(context.Background(), path, &output, &output, guidedUpRuntime{input, true})
	}
	if err := invoke(strings.NewReader(input + "no\n")); err == nil {
		t.Fatal("expected cancellation")
	}
	prepareGuidedClusterIntent = func(context.Context, []string, io.Writer, io.Writer) error {
		t.Fatal("rerendered existing preparation")
		return nil
	}
	if err := invoke(strings.NewReader("no\n")); err == nil {
		t.Fatal("expected cancellation")
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.ReplaceAll(raw, []byte("192.0.2.10"), []byte("192.0.2.11")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := invoke(panicConfigReader{}); err == nil {
		t.Fatal("accepted changed YAML")
	}
	if _, err := os.Stat(filepath.Join(root, "execution-started.json")); !os.IsNotExist(err) {
		t.Fatal("started cancelled run")
	}
}

func TestGuidedUpRejectsBeforePreparationAndRetainsPartial(t *testing.T) {
	path, root, input := guidedUpFixture(t)
	var output bytes.Buffer
	if err := runGuidedClusterUpWithRuntime(context.Background(), path, &output, &output, guidedUpRuntime{panicConfigReader{}, false}); err == nil {
		t.Fatal("piped invocation accepted")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("non-terminal created state")
	}
	prepareGuidedClusterIntent = func(context.Context, []string, io.Writer, io.Writer) error {
		return errors.New("synthetic preparation failure")
	}
	if err := runGuidedClusterUpWithRuntime(context.Background(), path, &output, &output, guidedUpRuntime{strings.NewReader(input), true}); err == nil {
		t.Fatal("preparation failure swallowed")
	}
	if err := runGuidedClusterUpWithRuntime(context.Background(), path, &output, &output, guidedUpRuntime{panicConfigReader{}, true}); err == nil {
		t.Fatal("automatically retried partial preparation")
	}
}

func TestGuidedUpBoundedInputAndCancellation(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", 5000) + "\n", "\n", "bad\x1bpath\n"} {
		if _, err := guidedUpPath(context.Background(), bufio.NewReaderSize(strings.NewReader(input), 4096), io.Discard, "path"); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	if _, err := guidedUpLine(ctx, bufio.NewReader(reader)); err == nil {
		t.Fatal("ignored interruption")
	}
}

type guidedHookReader struct {
	source io.Reader
	hook   func()
}

func (r *guidedHookReader) Read(p []byte) (int, error) {
	if r.hook != nil {
		hook := r.hook
		r.hook = nil
		hook()
	}
	return r.source.Read(p)
}

func TestGuidedUpRechecksAfterConfirmation(t *testing.T) {
	path, root, input := guidedUpFixture(t)
	var output bytes.Buffer
	invoke := func(reader io.Reader) error {
		return runGuidedClusterUpWithRuntime(context.Background(), path, &output, &output, guidedUpRuntime{reader, true})
	}
	if err := invoke(strings.NewReader(input + "no\n")); err == nil {
		t.Fatal("expected cancellation")
	}
	previous := executeClusterCreateLive
	defer func() { executeClusterCreateLive = previous }()
	executeClusterCreateLive = func(context.Context, clusterCreateLiveConfig, io.Writer, io.Writer) error {
		t.Fatal("changed inputs reached executor")
		return nil
	}
	refs := strings.Split(strings.TrimSpace(input), "\n")[1]
	reader := &guidedHookReader{source: strings.NewReader("ok\n"), hook: func() {
		file, err := os.OpenFile(refs, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := file.WriteString("\n"); err != nil {
			t.Fatal(err)
		}
	}}
	if err := invoke(reader); err == nil {
		t.Fatal("changed references accepted after confirmation")
	}
	if _, err := os.Stat(filepath.Join(root, "execution-started.json")); !os.IsNotExist(err) {
		t.Fatal("claimed changed inputs")
	}
}

func TestGuidedUpConcurrentConfirmationsStartOnlyOnce(t *testing.T) {
	path, _, input := guidedUpFixture(t)
	if err := runGuidedClusterUpWithRuntime(context.Background(), path, io.Discard, io.Discard, guidedUpRuntime{strings.NewReader(input + "no\n"), true}); err == nil {
		t.Fatal("expected cancellation")
	}
	previous := executeClusterCreateLive
	defer func() { executeClusterCreateLive = previous }()
	var calls, ready atomic.Int32
	release := make(chan struct{})
	executeClusterCreateLive = func(context.Context, clusterCreateLiveConfig, io.Writer, io.Writer) error { calls.Add(1); return nil }
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			reader := &guidedHookReader{source: strings.NewReader("ok\n"), hook: func() {
				if ready.Add(1) == 2 {
					close(release)
				}
				<-release
			}}
			results <- runGuidedClusterUpWithRuntime(context.Background(), path, io.Discard, io.Discard, guidedUpRuntime{reader, true})
		}()
	}
	first, second := <-results, <-results
	if calls.Load() != 1 || (first == nil) == (second == nil) {
		t.Fatalf("starts=%d first=%v second=%v", calls.Load(), first, second)
	}
}

func TestGuidedUpDoesNotMisrepresentYAMLChangedDuringPreparation(t *testing.T) {
	path, root, input := guidedUpFixture(t)
	prepare := prepareGuidedClusterIntent
	prepareGuidedClusterIntent = func(ctx context.Context, args []string, out, errOut io.Writer) error {
		if err := prepare(ctx, args, out, errOut); err != nil {
			return err
		}
		raw, _ := os.ReadFile(path)
		if err := os.WriteFile(path, bytes.ReplaceAll(raw, []byte("192.0.2.10"), []byte("192.0.2.11")), 0o600); err != nil {
			t.Fatal(err)
		}
		intent, err := readClusterIntent(path)
		if err != nil {
			t.Fatal(err)
		}
		normalized, _ := json.Marshal(intent)
		bindingPath := filepath.Join(root, "preparation", "binding-receipt.json")
		bindingRaw, _ := os.ReadFile(bindingPath)
		var binding clusterIntentBindingReceipt
		if err := json.Unmarshal(bindingRaw, &binding); err != nil {
			t.Fatal(err)
		}
		binding.NormalizedIntentDigest = digest.SHA256(normalized)
		bindingRaw, _ = json.Marshal(binding)
		if err := os.WriteFile(bindingPath, bindingRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		fixturePath := filepath.Join(root, "preparation", "execution-fixture.json")
		fixtureRaw, _ := os.ReadFile(fixturePath)
		var fixture clusterIntentExecutionFixture
		if err := json.Unmarshal(fixtureRaw, &fixture); err != nil {
			t.Fatal(err)
		}
		fixture.BindingReceiptDigest = digest.SHA256(bindingRaw)
		fixtureRaw, _ = json.Marshal(fixture)
		if err := os.WriteFile(fixturePath, fixtureRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	var output bytes.Buffer
	err := runGuidedClusterUpWithRuntime(context.Background(), path, &output, &output, guidedUpRuntime{strings.NewReader(input + "ok\n"), true})
	if err == nil || !strings.Contains(err.Error(), "YAML changed during") || strings.Contains(output.String(), "Type ok to create") {
		t.Fatalf("misrepresented a changed plan: %v %s", err, &output)
	}
}

func TestGuidedUpPreservesExistingUnownedDirectory(t *testing.T) {
	path, root, _ := guidedUpFixture(t)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "existing-untracked-file")
	if err := os.WriteFile(marker, []byte("preserve exactly"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runGuidedClusterUpWithRuntime(context.Background(), path, io.Discard, io.Discard, guidedUpRuntime{panicConfigReader{}, true}); err == nil {
		t.Fatal("adopted unowned directory")
	}
	entries, _ := os.ReadDir(root)
	raw, _ := os.ReadFile(marker)
	if len(entries) != 1 || string(raw) != "preserve exactly" {
		t.Fatal("changed unowned files")
	}
}
