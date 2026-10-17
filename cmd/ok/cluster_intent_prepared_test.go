package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func preparedIntentFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	path := intentFixture(t, nil)
	intent, err := readClusterIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(intent)
	root := privateConfigTestDir(t)
	binding := clusterIntentBindingReceipt{Format: "ok-cli-cluster-static-binding/v1", State: "CONTRACT_PROJECTION_BOUND_NO_GO",
		Identity: contract.Identity{Name: intent.Metadata.Name, Namespace: intent.Metadata.Name}, IntentRevision: testSHA("2"), NormalizedIntentDigest: digest.SHA256(raw)}
	bindingRaw, _ := json.Marshal(binding)
	fixture := clusterIntentExecutionFixture{Format: "ok-cli-local-execution-fixture/v2", AuthorizationState: "NO-GO",
		ContractIdentity: binding.Identity, IntentRevision: binding.IntentRevision, BindingReceiptDigest: digest.SHA256(bindingRaw)}
	fixtureRaw, _ := json.Marshal(fixture)
	for name, data := range map[string][]byte{"binding-receipt.json": bindingRaw, "execution-fixture.json": fixtureRaw, "full-run-manifest.json": []byte(`{}`)} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path, root, fixtureRaw
}

func TestClusterIntentPreparedRoutesThroughExistingGates(t *testing.T) {
	path, root, fixture := preparedIntentFixture(t)
	previousVerify, previousPrepare, previousExecute, previousMarker := verifyPreparedManifestFixture, prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker
	defer func() {
		verifyPreparedManifestFixture, prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker = previousVerify, previousPrepare, previousExecute, previousMarker
	}()
	manifest := filepath.Join(root, "full-run-manifest.json")
	verifyPreparedManifestFixture = func(p string, raw []byte) (runner.FullRunExecutionManifestReceipt, error) {
		if p != manifest || !bytes.Equal(raw, fixture) {
			t.Fatal("changed manifest/fixture")
		}
		return bareClusterCreateManifestReceipt(), nil
	}
	prepareFullRunExecutionManifest = func(p string) (runner.FullRunExecutionManifestReceipt, error) {
		if p != manifest {
			t.Fatal("YAML sent to JSON runner")
		}
		return bareClusterCreateManifestReceipt(), nil
	}
	marker := filepath.Join(root, "executor-terminal")
	validateClusterCreateTerminalMarker = func(p string) error {
		if p != marker {
			t.Fatal("changed terminal")
		}
		return nil
	}
	calls := 0
	stop := errors.New("simulated STOP")
	executeClusterCreateLive = func(_ context.Context, config clusterCreateLiveConfig, _, _ io.Writer) error {
		calls++
		if config.ManifestPath != manifest || config.ExpectedManifestDigest != testSHA("1") || config.IndependentEvidencePublicKey != "/explicit/key.pub" || config.TerminalMarker != marker {
			t.Fatalf("changed live inputs: %+v", config)
		}
		return stop
	}
	for _, prefix := range [][]string{{"up"}, {"cluster", "create"}} {
		base := append(append([]string{}, prefix...), "--file", path, "--prepared-dir", root)
		var stdout bytes.Buffer
		if err := run(append(base, "--dry-run"), &stdout, &bytes.Buffer{}); err != nil || calls != 0 {
			t.Fatalf("dry-run: %v live=%d", err, calls)
		}
		if !strings.Contains(stdout.String(), `"apiContacted": false`) {
			t.Fatal("unsafe dry-run receipt")
		}
	}
	live := []string{"up", "--file", path, "--prepared-dir", root, "--live", "--execute", "--expected-manifest-digest", testSHA("1"), "--independent-evidence-public-key", "/explicit/key.pub", "--terminal-marker", marker}
	if err := run(live, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("live: %v calls=%d", err, calls)
	}
	live[8] = testSHA("3")
	if err := run(live, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || calls != 1 {
		t.Fatal("digest mismatch executed")
	}
}

func TestClusterIntentPreparedRejectsDriftAndUnsafeInputs(t *testing.T) {
	for _, change := range []string{"yaml", "binding", "fixture", "unanchored-fixture", "manifest-mode", "directory-mode", "symlink", "missing"} {
		t.Run(change, func(t *testing.T) {
			path, root, fixture := preparedIntentFixture(t)
			previous := verifyPreparedManifestFixture
			defer func() { verifyPreparedManifestFixture = previous }()
			verifyPreparedManifestFixture = func(_ string, raw []byte) (runner.FullRunExecutionManifestReceipt, error) {
				if !bytes.Equal(raw, fixture) {
					return runner.FullRunExecutionManifestReceipt{}, errors.New("fixture not anchored by manifest")
				}
				return bareClusterCreateManifestReceipt(), nil
			}
			switch change {
			case "yaml":
				raw, _ := os.ReadFile(path)
				os.WriteFile(path, bytes.ReplaceAll(raw, []byte("192.0.2.10"), []byte("192.0.2.11")), 0o600)
			case "binding":
				os.WriteFile(filepath.Join(root, "binding-receipt.json"), []byte(`{}`), 0o600)
			case "fixture":
				os.WriteFile(filepath.Join(root, "execution-fixture.json"), []byte(`{"format":"ok-cli-local-execution-fixture/v1"}`), 0o600)
			case "unanchored-fixture":
				var data map[string]any
				json.Unmarshal(fixture, &data)
				data["runner"] = localCLIFixtureRunner{Version: "foreign"}
				raw, _ := json.Marshal(data)
				os.WriteFile(filepath.Join(root, "execution-fixture.json"), raw, 0o600)
			case "manifest-mode":
				os.Chmod(filepath.Join(root, "full-run-manifest.json"), 0o644)
			case "directory-mode":
				os.Chmod(root, 0o755)
			case "symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(root, link); err != nil {
					t.Skip(err)
				}
				root = link
			case "missing":
				os.Remove(filepath.Join(root, "binding-receipt.json"))
			}
			if _, err := resolvePreparedClusterIntent(path, root, testSHA("1")); err == nil {
				t.Fatal("unsafe preparation accepted")
			}
		})
	}
}

func TestClusterIntentPreparedModeAndLiveDoubleGate(t *testing.T) {
	path := intentFixture(t, nil)
	jsonPath := intentFixture(t, func(string) string { return `{}` })
	previous := verifyPreparedManifestFixture
	defer func() { verifyPreparedManifestFixture = previous }()
	verifyPreparedManifestFixture = func(string, []byte) (runner.FullRunExecutionManifestReceipt, error) {
		t.Fatal("reached private verifier before mode/live gate")
		return runner.FullRunExecutionManifestReceipt{}, nil
	}
	for _, args := range [][]string{
		{"--file", path, "--prepare", "--prepared-dir", "/must-not-read"},
		{"--file", path, "--dry-run", "--prepared-dir="},
		{"--file", jsonPath, "--dry-run", "--prepared-dir", "/must-not-read"},
		{"--file", path, "--live", "--prepared-dir", "/must-not-read"},
		{"--file", path, "--live", "--execute", "--prepared-dir", "/must-not-read"},
		{"--file", path, "--dry-run", "--prepared-dir", "/must-not-read", "--output", "/must-not-create"},
	} {
		if err := run(append([]string{"up"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe arguments accepted: %v", args)
		}
	}
}

func TestClusterIntentPreparedRejectsNonFreshOrUnverifiedManifest(t *testing.T) {
	path, root, _ := preparedIntentFixture(t)
	previous := verifyPreparedManifestFixture
	defer func() { verifyPreparedManifestFixture = previous }()
	for _, change := range []func(*runner.FullRunExecutionManifestReceipt){
		func(r *runner.FullRunExecutionManifestReceipt) { r.ExecutionAttemptDigest = testSHA("3") },
		func(r *runner.FullRunExecutionManifestReceipt) { r.State = "NO-GO" },
		func(r *runner.FullRunExecutionManifestReceipt) { r.MutationAllowed = true },
		func(r *runner.FullRunExecutionManifestReceipt) { r.Format = "foreign" },
		func(r *runner.FullRunExecutionManifestReceipt) { r.CompletionMode = "post-runtime" },
		func(r *runner.FullRunExecutionManifestReceipt) { r.ManifestDigest = "invalid" },
	} {
		receipt := bareClusterCreateManifestReceipt()
		change(&receipt)
		verifyPreparedManifestFixture = func(string, []byte) (runner.FullRunExecutionManifestReceipt, error) { return receipt, nil }
		if _, err := resolvePreparedClusterIntent(path, root, ""); err == nil {
			t.Fatal("unverified or recovery manifest accepted")
		}
	}
}
