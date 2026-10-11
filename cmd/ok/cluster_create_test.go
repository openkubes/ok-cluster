package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func bareClusterCreateManifestReceipt() runner.FullRunExecutionManifestReceipt {
	return runner.FullRunExecutionManifestReceipt{
		Format: runner.FullRunExecutionManifestReceiptFormatV2, State: "VERIFIED",
		ManifestDigest: testSHA("1"), PlanDigest: testSHA("2"),
		CompletionMode: stageplan.CompletionModeBareClusterMVP,
	}
}

func TestHierarchicalHelp(t *testing.T) {
	for name, test := range map[string]struct {
		arguments []string
		contains  []string
	}{
		"root":                 {[]string{"--help"}, []string{"ok <command>", "cluster"}},
		"cluster":              {[]string{"cluster", "--help"}, []string{"ok cluster <command>", "create"}},
		"cluster create":       {[]string{"cluster", "create", "--help"}, []string{"--file", "--dry-run", "--prepare", "--live --execute", "may create cluster resources"}},
		"create trailing help": {[]string{"cluster", "create", "--file", "/private/run.json", "--help"}, []string{"--file", "--dry-run", "--live --execute"}},
		"cluster stage":        {[]string{"cluster", "stage", "--help"}, []string{"Expert stage-level", "observe", "launch"}},
		"cluster stage run":    {[]string{"cluster", "stage", "run", "--help"}, []string{"Manual Bare-MVP order", "provider-prerequisites", "separate approval"}},
		"stage run full":       {[]string{"cluster", "stage", "run", "full", "--help"}, []string{"in-process executor", "four-object installation plan", "different live boundaries"}},
		"stage observe":        {[]string{"cluster", "stage", "observe", "--help"}, []string{"lifecycle", "network", "do not repair"}},
		"stage bind":           {[]string{"cluster", "stage", "bind", "--help"}, []string{"runtime identity", "Bare-MVP Stage 6", "--execute"}},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(test.arguments, &stdout, &stderr); err != nil {
				t.Fatalf("help failed: %v", err)
			}
			for _, expected := range test.contains {
				if !strings.Contains(stdout.String(), expected) {
					t.Fatalf("help missing %q:\n%s", expected, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("unexpected stderr: %s", stderr.String())
			}
		})
	}
}

func TestLeafFlagHelpIsSuccessfulAndUsesStdout(t *testing.T) {
	for name, arguments := range map[string][]string{
		"full prepare":      {"cluster", "stage", "run", "full", "prepare", "--help"},
		"observe lifecycle": {"cluster", "stage", "observe", "lifecycle", "--help"},
		"bind runtime":      {"cluster", "stage", "bind", "runtime", "--help"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err != nil {
				t.Fatalf("leaf help failed: %v", err)
			}
			if !strings.Contains(stdout.String(), "Usage of ok cluster stage") {
				t.Fatalf("leaf help missing usage:\n%s", stdout.String())
			}
			if strings.Contains(stdout.String(), "ERROR:") || stderr.Len() != 0 {
				t.Fatalf("leaf help reported an error: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestClusterCreateFileRejectsAmbiguousFileFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"cluster", "create", "--file", "/private/a.json", "-f", "/private/b.json", "--dry-run"},
		{"cluster", "create", "--file=/private/a.json", "--file=/private/b.json", "--prepare"},
	} {
		var stdout bytes.Buffer
		err := run(arguments, &stdout, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "exactly one --file") || stdout.Len() != 0 {
			t.Fatalf("ambiguous file input accepted: arguments=%v err=%v stdout=%s", arguments, err, stdout.String())
		}
	}
}

func TestClusterCreateFileDryRunAndPrepareAreNonMutating(t *testing.T) {
	previousPrepare := prepareFullRunExecutionManifest
	previousExecute := executeClusterCreateLive
	previousMarkerValidation := validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest = previousPrepare
		executeClusterCreateLive = previousExecute
		validateClusterCreateTerminalMarker = previousMarkerValidation
	}()
	liveCalls, markerCalls := 0, 0
	executeClusterCreateLive = func(context.Context, clusterCreateLiveConfig, io.Writer, io.Writer) error {
		liveCalls++
		return errors.New("offline mode reached live executor")
	}
	validateClusterCreateTerminalMarker = func(string) error {
		markerCalls++
		return errors.New("offline mode reached live marker preflight")
	}
	prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
		if path != "/private/bare-run.json" {
			t.Fatalf("manifest path = %q", path)
		}
		return bareClusterCreateManifestReceipt(), nil
	}
	for _, mode := range []struct {
		flag, state, next string
	}{
		{"--dry-run", "VALIDATED", "review the validated identities, then run --prepare with the same file"},
		{"--prepare", "PREPARED", "obtain separate live approval; pass manifestDigest as --expected-manifest-digest"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run([]string{"cluster", "create", "--file", "/private/bare-run.json", mode.flag}, &stdout, &stderr); err != nil {
			t.Fatalf("%s: %v", mode.flag, err)
		}
		var receipt clusterCreateWorkflowReceipt
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.Format != clusterCreateWorkflowFormat || receipt.State != mode.state || receipt.MutationAllowed ||
			receipt.APIContacted || receipt.AuthorizationConsumed || receipt.NextAction != mode.next ||
			receipt.CompletionMode != stageplan.CompletionModeBareClusterMVP || receipt.ManifestDigest != testSHA("1") {
			t.Fatalf("unsafe or incomplete receipt: %#v", receipt)
		}
		for _, forbidden := range []string{"/private/", "bare-run.json", "credential", "kubeconfig", "token"} {
			if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
				t.Fatalf("offline receipt disclosed %q: %s", forbidden, stdout.String())
			}
		}
	}
	if liveCalls != 0 || markerCalls != 0 {
		t.Fatalf("offline modes reached live boundaries: executor=%d marker=%d", liveCalls, markerCalls)
	}
}

func TestClusterCreateFileRejectsNonBareManifest(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		receipt := bareClusterCreateManifestReceipt()
		receipt.CompletionMode = ""
		return receipt, nil
	}
	var stdout bytes.Buffer
	err := run([]string{"cluster", "create", "-f", "/private/full-run.json", "--prepare"}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), stageplan.CompletionModeBareClusterMVP) || stdout.Len() != 0 {
		t.Fatalf("non-bare manifest accepted: err=%v stdout=%s", err, stdout.String())
	}
}

func TestClusterCreateLiveRequiresPreparedIdentityAndExplicitDoubleGate(t *testing.T) {
	previousPrepare := prepareFullRunExecutionManifest
	previousExecute := executeClusterCreateLive
	previousMarkerValidation := validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest = previousPrepare
		executeClusterCreateLive = previousExecute
		validateClusterCreateTerminalMarker = previousMarkerValidation
	}()
	validateClusterCreateTerminalMarker = func(path string) error {
		if path != "/private/executor-terminal" {
			t.Fatalf("terminal marker path = %q", path)
		}
		return nil
	}
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return bareClusterCreateManifestReceipt(), nil
	}
	calls := 0
	executeClusterCreateLive = func(ctx context.Context, config clusterCreateLiveConfig, stdout, stderr io.Writer) error {
		calls++
		if config.ManifestPath != "/private/bare-run.json" || config.ExpectedManifestDigest != testSHA("1") ||
			config.IndependentEvidencePublicKey != "/private/evidence.pub" || config.TerminalMarker != "/private/executor-terminal" {
			t.Fatalf("live config differs: %#v", config)
		}
		_, _ = stdout.Write([]byte("{\"state\":\"SUCCEEDED\"}\n"))
		return nil
	}
	valid := []string{
		"cluster", "create", "--file", "/private/bare-run.json", "--live", "--execute",
		"--expected-manifest-digest", testSHA("1"),
		"--independent-evidence-public-key", "/private/evidence.pub",
		"--terminal-marker", "/private/executor-terminal",
	}
	for name, arguments := range map[string][]string{
		"missing live":            removeArgument(valid, "--live"),
		"missing execute":         removeArgument(valid, "--execute"),
		"wrong prepared identity": replaceArgument(valid, "--expected-manifest-digest", testSHA("3")),
		"mixed modes":             append(append([]string(nil), valid...), "--prepare"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe live invocation was accepted")
			}
			if calls != before {
				t.Fatalf("unsafe invocation reached live executor: calls=%d before=%d", calls, before)
			}
		})
	}
	var stdout bytes.Buffer
	if err := run(valid, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(stdout.String(), "SUCCEEDED") {
		t.Fatalf("live execution not forwarded exactly once: calls=%d stdout=%s", calls, stdout.String())
	}
}
