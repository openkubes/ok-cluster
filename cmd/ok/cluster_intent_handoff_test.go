package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestClusterIntentNextCommandsKeepExistingRunnerBoundary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spaces ' ; $(not-a-command)")
	manifest, key := filepath.Join(root, "full-run-manifest.json"), filepath.Join(root, "evidence key.pub")
	digest := testSHA("1")
	commands := preparedClusterIntentCommands(manifest, digest, key)
	raw, err := json.Marshal(commands)
	if err != nil {
		t.Fatal(err)
	}
	var decoded clusterIntentNextCommands
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(commands, decoded) {
		t.Fatal("argv did not survive JSON exactly")
	}
	previousPrepare, previousExecute, previousMarker := prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker = previousPrepare, previousExecute, previousMarker
	}()
	prepareCalls, liveCalls := 0, 0
	prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
		prepareCalls++
		if path != manifest {
			t.Fatalf("manifest argument changed: %q", path)
		}
		return bareClusterCreateManifestReceipt(), nil
	}
	validateClusterCreateTerminalMarker = func(path string) error {
		if path != filepath.Join(root, "executor-terminal") {
			t.Fatalf("terminal argument changed: %q", path)
		}
		return nil
	}
	stop := errors.New("simulated terminal STOP; no retry")
	executeClusterCreateLive = func(_ context.Context, config clusterCreateLiveConfig, _, _ io.Writer) error {
		liveCalls++
		if config.ManifestPath != manifest || config.ExpectedManifestDigest != digest || config.IndependentEvidencePublicKey != key || config.TerminalMarker != filepath.Join(root, "executor-terminal") {
			t.Fatalf("changed live binding: %+v", config)
		}
		return stop
	}
	if err := run(decoded.DryRun[1:], &bytes.Buffer{}, &bytes.Buffer{}); err != nil || prepareCalls != 1 || liveCalls != 0 {
		t.Fatalf("dry run: %v prepare=%d live=%d", err, prepareCalls, liveCalls)
	}
	// Simulated execution only: check command routing and preserve non-zero STOP.
	if err := run(decoded.LiveAfterApproval[1:], &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, stop) || liveCalls != 1 {
		t.Fatalf("live hint routing: %v live=%d", err, liveCalls)
	}
	args := append([]string{}, decoded.LiveAfterApproval[1:]...)
	for i, arg := range args {
		if arg == "--execute" {
			args = append(args[:i], args[i+1:]...)
			break
		}
	}
	if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || liveCalls != 1 {
		t.Fatal("live hint bypassed execute gate")
	}
	args = append([]string{}, decoded.LiveAfterApproval[1:]...)
	for i, arg := range args {
		if arg == "--expected-manifest-digest" {
			args[i+1] = testSHA("2")
		}
	}
	if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || liveCalls != 1 {
		t.Fatal("live hint bypassed digest binding")
	}
}
