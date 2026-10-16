package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func intentFixture(t *testing.T, transform func(string) string) string {
	t.Helper()
	var template bytes.Buffer
	if err := writeClusterIntentTemplate(&template); err != nil {
		t.Fatal(err)
	}
	raw := template.String()
	if transform != nil {
		raw = transform(raw)
	}
	path := filepath.Join(t.TempDir(), "cluster.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClusterIntentDryRunIsDistinctAndNeverRunnerReady(t *testing.T) {
	path := intentFixture(t, nil)
	previousPrepare, previousExecute, previousMarker := prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker = previousPrepare, previousExecute, previousMarker
	}()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		t.Fatal("intent reached technical preparation")
		return runner.FullRunExecutionManifestReceipt{}, nil
	}
	executeClusterCreateLive = func(context.Context, clusterCreateLiveConfig, io.Writer, io.Writer) error {
		t.Fatal("intent reached live runner")
		return nil
	}
	validateClusterCreateTerminalMarker = func(string) error { t.Fatal("intent reached terminal-marker preflight"); return nil }
	for _, prefix := range [][]string{{"up"}, {"cluster", "create"}} {
		var stdout bytes.Buffer
		if err := run(append(append([]string{}, prefix...), "--file", path, "--dry-run"), &stdout, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		var receipt map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt["state"] != "INTENT_VALIDATED_NO_GO" || receipt["runnerReady"] != false || receipt["mutationAllowed"] != false || receipt["apiContacted"] != false || receipt["authorizationConsumed"] != false || receipt["collisionChecked"] != false {
			t.Fatalf("unsafe receipt %v", receipt)
		}
		for _, suffix := range [][]string{{"--prepare"}, {"--live", "--execute", "--expected-manifest-digest", testSHA("1"), "--independent-evidence-public-key", "/not-read.pub", "--terminal-marker", "/not-read/executor-terminal"}} {
			stdout.Reset()
			err := run(append(append(append([]string{}, prefix...), "--file", path), suffix...), &stdout, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "NO-GO") || stdout.Len() != 0 {
				t.Fatalf("intent prepared/executed: %v %s", err, &stdout)
			}
		}
	}
}

func TestClusterIntentStrictSchemaAndNetwork(t *testing.T) {
	for name, rewrite := range map[string]func(string) string{
		"unknown":              func(s string) string { return s + "unknown: ignored\n" },
		"duplicate":            func(s string) string { return s + "kind: Cluster\n" },
		"multiple":             func(s string) string { return s + "---\nkind: Cluster\n" },
		"anchor":               func(s string) string { return strings.Replace(s, "name: my-cluster", "name: &name my-cluster", 1) },
		"numeric name":         func(s string) string { return strings.Replace(s, "my-cluster", "123", 1) },
		"reserved":             func(s string) string { return strings.Replace(s, "my-cluster", "kube-system", 1) },
		"traversal":            func(s string) string { return strings.Replace(s, "my-cluster", "../escape", 1) },
		"profile":              func(s string) string { return strings.Replace(s, "talos-kubevirt-mvp", "flatcar", 1) },
		"auto":                 func(s string) string { return strings.Replace(s, "192.0.2.10", "auto", 1) },
		"loopback":             func(s string) string { return strings.Replace(s, "192.0.2.10", "127.0.0.1", 1) },
		"overlap":              func(s string) string { return strings.Replace(s, "10.96.0.0/20", "10.42.0.0/20", 1) },
		"host bits":            func(s string) string { return strings.Replace(s, "10.42.0.0/16", "10.42.0.1/16", 1) },
		"endpoint inside pods": func(s string) string { return strings.Replace(s, "192.0.2.10", "10.42.0.1", 1) },
		"sizing not supported": func(s string) string { return strings.Replace(s, "  network:", "  workers: 4\n  network:", 1) },
		"oversized":            func(s string) string { return strings.Repeat(" ", 65537) + s },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readClusterIntent(intentFixture(t, rewrite)); err == nil {
				t.Fatal("unsafe intent accepted")
			}
		})
	}
}

func TestClusterIntentPreservesJSONWorkflowDespiteYAMLSuffix(t *testing.T) {
	path := intentFixture(t, func(string) string { return `{ "format": "technical-json-fixture" }` })
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	calls := 0
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		calls++
		return bareClusterCreateManifestReceipt(), nil
	}
	if err := run([]string{"up", "--file", path, "--prepare"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil || calls != 1 {
		t.Fatalf("JSON path compatibility: %v calls=%d", err, calls)
	}
}

func TestClusterIntentRenderRejectsInputsBeforeChild(t *testing.T) {
	isolatedConfigHome(t)
	path := intentFixture(t, nil)
	for _, args := range [][]string{{}, {"--file", path}, {"--file", path, "--output", t.TempDir()}, {"--file", path, "--output", filepath.Join(t.TempDir(), "new"), "--live"}} {
		if err := runClusterIntentRender(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe render accepted %v", args)
		}
	}
	if _, err := readClusterIntent(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := readClusterIntent(missing); err == nil || !isClusterYAMLFile(missing) {
		t.Fatal("missing YAML was not rejected")
	}
}

func TestClusterIntentOfflineHelpAndTemplate(t *testing.T) {
	for _, args := range [][]string{{"up", "render", "--help"}, {"up", "bind", "--help"}, {"up", "cluster-template", "--help"}, {"cluster", "create", "render", "--help"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "NO_GO") || stderr.Len() != 0 {
			t.Fatalf("help %v: %v", args, err)
		}
	}
	var stdout bytes.Buffer
	if err := run([]string{"up", "cluster-template"}, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), "cli.openkubes.io/v1alpha1") {
		t.Fatalf("template %v", err)
	}
}

func TestClusterIntentBindingRequiresExplicitContractAndBoundedFiles(t *testing.T) {
	path := intentFixture(t, nil)
	output := filepath.Join(t.TempDir(), "new-binding")
	err := runClusterIntentBind(context.Background(), []string{"--file", path, "--output", output}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "explicit --contract") {
		t.Fatalf("implicit Contract accepted: %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("missing Contract created output")
	}
	if _, err := readIntentBindingFile(t.TempDir()); err == nil {
		t.Fatal("directory accepted as Contract")
	}
	oversized := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), 1024*1024+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIntentBindingFile(oversized); err == nil {
		t.Fatal("oversized binding input accepted")
	}
}

func TestClusterIntentPreparationInputsAreModeSpecific(t *testing.T) {
	yamlPath := intentFixture(t, nil)
	jsonPath := intentFixture(t, func(string) string { return `{ "format": "technical-json-fixture" }` })
	for _, path := range []string{yamlPath, jsonPath} {
		for _, mode := range []string{"--dry-run", "--prepare", "--live"} {
			if path == yamlPath && mode == "--prepare" {
				continue
			}
			for _, name := range []string{"contract", "output", "lifecycle-root", "ok-linux-path", "config", "runtime-inputs"} {
				var stdout bytes.Buffer
				err := run([]string{"up", "--file", path, mode, "--" + name, "/must-not-read"}, &stdout, &bytes.Buffer{})
				if err == nil || !strings.Contains(err.Error(), "only accepted with YAML --prepare") || stdout.Len() != 0 {
					t.Fatalf("preparation input escaped mode gate: %s %s %s: %v", path, mode, name, err)
				}
			}
		}
	}
	output := filepath.Join(t.TempDir(), "new-prepare")
	err := run([]string{"up", "--file", yamlPath, "--prepare", "--output", output}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "NO-GO") {
		t.Fatalf("missing Contract accepted: %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("incomplete inputs reserved output")
	}
	var help bytes.Buffer
	writeClusterCreateHelp(&help)
	if strings.Contains(help.String(), "ok up bind") || !strings.Contains(help.String(), "exits\nnon-zero") {
		t.Fatal("help presents an extra binding step or successful partial preparation")
	}
}
