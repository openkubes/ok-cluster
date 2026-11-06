package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const localKubeconfigFixture = `apiVersion: v1
kind: Config
current-context: kind-ok-local
clusters:
- name: kind-ok-local
  cluster:
    server: https://127.0.0.1:12345
    certificate-authority-data: Y2E=
contexts:
- name: kind-ok-local
  context:
    cluster: kind-ok-local
    user: kind-ok-local
users:
- name: kind-ok-local
  user:
    client-certificate-data: Y2VydA==
    client-key-data: a2V5
`

func localStateFixture(t *testing.T) (string, localClusterState) {
	t.Helper()
	privateParent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(privateParent, "ok-local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	clusterDir := filepath.Join(root, "clusters", localClusterDefaultName)
	if err := os.MkdirAll(clusterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(clusterDir, "kubeconfig")
	kindName := localKindClusterName(localClusterDefaultName, "0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(kubeconfig, []byte(strings.ReplaceAll(localKubeconfigFixture, "kind-ok-local", "kind-"+kindName)), 0o600); err != nil {
		t.Fatal(err)
	}
	state := localClusterState{
		Format: localClusterStateFormat, Phase: "READY", Name: localClusterDefaultName,
		OwnerID: "0123456789abcdef0123456789abcdef", KindName: kindName,
		Provider:      localProviderIdentity{Kind: "docker", Context: "desktop-linux", Endpoint: "unix:///tmp/docker.sock", DaemonID: "daemon-123"},
		Kubeconfig:    kubeconfig,
		KubeSystemUID: "kube-system-uid",
		Nodes:         []localNodeIdentity{{Name: kindName + "-control-plane", UID: "node-uid"}},
		Containers:    []localContainerIdentity{{ID: "container-123", Name: kindName + "-control-plane", Role: "control-plane"}},
	}
	return root, state
}

func localOwnershipRunner(state localClusterState, ownerID string, present bool, deleted *bool) localCommandRunner {
	return func(_ context.Context, command string, arguments ...string) ([]byte, error) {
		if command == "docker" {
			joined := strings.Join(arguments, " ")
			switch {
			case joined == "context show":
				return []byte(state.Provider.Context + "\n"), nil
			case strings.Contains(joined, "context inspect"):
				return []byte(state.Provider.Endpoint + "\n"), nil
			case strings.Contains(joined, "info --format"):
				return []byte(state.Provider.DaemonID + "\n"), nil
			case strings.Contains(joined, " ps ") || strings.HasPrefix(joined, "ps "):
				if deleted != nil && *deleted {
					return []byte(""), nil
				}
				if present {
					return []byte(state.Containers[0].ID + "|" + state.Containers[0].Name + "|" + state.Containers[0].Role + "\n"), nil
				}
				return []byte(""), nil
			}
		}
		switch command {
		case "kind":
			if len(arguments) > 0 && arguments[0] == "get" {
				if len(arguments) > 1 && arguments[1] == "kubeconfig" {
					return []byte(strings.ReplaceAll(localKubeconfigFixture, "kind-ok-local", "kind-"+state.KindName)), nil
				}
				if deleted != nil && *deleted {
					return []byte(""), nil
				}
				if present {
					return []byte(state.KindName + "\n"), nil
				}
				return []byte(""), nil
			}
			if len(arguments) > 0 && arguments[0] == "delete" {
				if strings.Join(arguments, " ") != "delete cluster --name "+state.KindName+" --kubeconfig "+state.Kubeconfig {
					return nil, errors.New("unexpected deletion target")
				}
				if deleted != nil {
					*deleted = true
				}
				return nil, nil
			}
		case "kubectl":
			joined := strings.Join(arguments, " ")
			if strings.Contains(joined, "get nodes -o json") {
				payload, _ := json.Marshal(localNodeList{Items: []struct {
					Metadata struct {
						Name   string            `json:"name"`
						UID    string            `json:"uid"`
						Labels map[string]string `json:"labels"`
					} `json:"metadata"`
				}{{Metadata: struct {
					Name   string            `json:"name"`
					UID    string            `json:"uid"`
					Labels map[string]string `json:"labels"`
				}{Name: state.Nodes[0].Name, UID: state.Nodes[0].UID, Labels: map[string]string{localOwnerLabel: ownerID}}}}})
				return payload, nil
			}
			if strings.Contains(joined, "get namespace kube-system -o json") {
				payload, _ := json.Marshal(localNamespace{Metadata: struct {
					UID string `json:"uid"`
				}{UID: state.KubeSystemUID}})
				return payload, nil
			}
		}
		return nil, errors.New("unexpected command: " + command + " " + strings.Join(arguments, " "))
	}
}

func TestLocalUpFailsClosedWhenConsoleIntegrationIsUnavailable(t *testing.T) {
	called := false
	root := t.TempDir()
	err := runLocalWithRuntime(context.Background(), []string{"up"}, io.Discard, io.Discard,
		localRuntime{stateRoot: filepath.Join(root, "state"), run: func(context.Context, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}})
	if err == nil || !strings.Contains(err.Error(), "no cluster was contacted") || called {
		t.Fatalf("up must fail closed without invoking cluster tools; err=%v called=%v", err, called)
	}
	err = runLocalWithRuntime(context.Background(), []string{"up", "--name", "not_valid"}, io.Discard, io.Discard,
		localRuntime{stateRoot: filepath.Join(root, "state"), run: func(context.Context, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}})
	if err == nil || called {
		t.Fatalf("invalid name must fail locally; err=%v called=%v", err, called)
	}
}

func TestLocalUpPersistsIntentBeforeSingleVerifierCallAndStopsIncomplete(t *testing.T) {
	root, fixture := localStateFixture(t)
	if err := os.RemoveAll(filepath.Join(root, "clusters", fixture.Name)); err != nil {
		t.Fatal(err)
	}
	console := filepath.Join(t.TempDir(), "ok-console")
	for _, path := range []string{"deploy/kubernetes", "deploy/kubernetes/overlays/local-kind"} {
		if err := os.MkdirAll(filepath.Join(console, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"deploy/kubernetes/verify-local-kind.sh", "deploy/kubernetes/overlays/local-kind/kustomization.yaml"} {
		if err := os.WriteFile(filepath.Join(console, path), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provider := fixture.Provider
	verified := false
	runtime := localRuntime{stateRoot: root, consoleRoot: console,
		run: func(_ context.Context, command string, args ...string) ([]byte, error) {
			if command == "bash" && strings.Join(args, " ") == "--version" {
				return []byte("GNU bash, version 5.3.20(1)-release\n"), nil
			}
			if command == "kind" && strings.Join(args, " ") == "version" {
				return []byte("kind v0.33.0 go1.27.0 darwin/arm64\n"), nil
			}
			if command == "git" && strings.Contains(strings.Join(args, " "), "rev-parse HEAD") {
				return []byte("revision\n"), nil
			}
			if command == "git" && strings.Contains(strings.Join(args, " "), "status --porcelain") {
				return []byte(""), nil
			}
			if command == "docker" && strings.Join(args, " ") == "context show" {
				return []byte(provider.Context), nil
			}
			if command == "docker" && strings.Contains(strings.Join(args, " "), "context inspect") {
				return []byte(provider.Endpoint), nil
			}
			if command == "docker" && strings.Contains(strings.Join(args, " "), "info --format") {
				return []byte(provider.DaemonID), nil
			}
			return nil, errors.New("unexpected external call")
		},
		runVerifier: func(_ context.Context, script string, env map[string]string) error {
			verified = true
			if _, err := os.Stat(localStateFilePath(root, fixture.Name)); err != nil {
				t.Fatalf("durable intent missing before verifier: %v", err)
			}
			state, err := readLocalClusterState(root, fixture.Name)
			if err != nil {
				t.Fatal(err)
			}
			if state.Phase != "CREATING" || env["KUBECONFIG"] != state.Kubeconfig || env["OK_CONSOLE_KEEP_CLUSTER"] != "true" || env["OK_CONSOLE_KIND_CONFIG"] == "" {
				t.Fatalf("unsafe verifier contract: state=%+v env=%v", state, env)
			}
			return errors.New("simulated partial deployment")
		},
	}
	err := runLocalWithRuntime(context.Background(), []string{"up"}, io.Discard, io.Discard, runtime)
	if err == nil || !strings.Contains(err.Error(), "no retry performed") || strings.Contains(err.Error(), "simulated partial") || !verified {
		t.Fatalf("expected one failed verifier and terminal stop, got err=%v called=%v", err, verified)
	}
	state, err := readLocalClusterState(root, fixture.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != "INCOMPLETE" {
		t.Fatalf("partial run not durably terminal: %s", state.Phase)
	}
	called := false
	statusErr := runLocalWithRuntime(context.Background(), []string{"status", "--json"}, io.Discard, io.Discard, localRuntime{stateRoot: root, run: func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }})
	if statusErr != nil || called {
		t.Fatalf("incomplete status must be local-only: err=%v contacted=%v", statusErr, called)
	}
	called = false
	downErr := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard, localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }})
	if downErr == nil || called {
		t.Fatalf("incomplete state must block deletion without contacting cluster: err=%v contacted=%v", downErr, called)
	}
}

func TestLocalPortPreflightDetectsLoopbackConflict(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := ensureLocalPortAvailable(port); err == nil {
		t.Fatal("occupied loopback port must fail before cluster create")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalPortAvailable(port); err != nil {
		t.Fatalf("released port should pass local preflight: %v", err)
	}
}

func TestLocalUpRejectsDirtyConsoleBeforeDurableIntentOrDocker(t *testing.T) {
	root, fixture := localStateFixture(t)
	if err := os.RemoveAll(filepath.Join(root, "clusters", fixture.Name)); err != nil {
		t.Fatal(err)
	}
	console := filepath.Join(t.TempDir(), "ok-console")
	for _, path := range []string{"deploy/kubernetes", "deploy/kubernetes/overlays/local-kind"} {
		if err := os.MkdirAll(filepath.Join(console, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"deploy/kubernetes/verify-local-kind.sh", "deploy/kubernetes/overlays/local-kind/kustomization.yaml"} {
		if err := os.WriteFile(filepath.Join(console, path), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dockerCalled := false
	runtime := localRuntime{stateRoot: root, consoleRoot: console, runVerifier: func(context.Context, string, map[string]string) error {
		t.Fatal("dirty tree must not reach verifier")
		return nil
	}, run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command == "git" && strings.Contains(strings.Join(args, " "), "rev-parse HEAD") {
			return []byte("revision\n"), nil
		}
		if command == "git" && strings.Contains(strings.Join(args, " "), "status --porcelain") {
			return []byte("?? user-data.txt\n"), nil
		}
		if command == "docker" {
			dockerCalled = true
		}
		return nil, errors.New("unexpected command")
	}}
	err := runLocalWithRuntime(context.Background(), []string{"up"}, io.Discard, io.Discard, runtime)
	if err == nil || !strings.Contains(err.Error(), "including untracked files") || dockerCalled {
		t.Fatalf("dirty source tree must stop before provider contact: err=%v docker=%v", err, dockerCalled)
	}
	if _, err := os.Lstat(localStateFilePath(root, fixture.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dirty preflight must precede durable run intent; state err=%v", err)
	}
}

func TestLocalStatusWithoutReceiptDoesNotContactCluster(t *testing.T) {
	called := false
	var output strings.Builder
	err := runLocalWithRuntime(context.Background(), []string{"status", "--json"}, &output, io.Discard,
		localRuntime{stateRoot: t.TempDir(), run: func(context.Context, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}})
	if err != nil || called {
		t.Fatalf("status without receipt should be local-only; err=%v called=%v", err, called)
	}
	if !strings.Contains(output.String(), `"state":"NOT_INSTALLED"`) || !strings.Contains(output.String(), `"clusterContacted":false`) {
		t.Fatalf("unexpected status: %s", output.String())
	}
}

func TestLocalStatusVerifiesLiveOwnerUsingOnlyIsolatedContext(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	base := localOwnershipRunner(state, state.OwnerID, true, nil)
	var calls [][]string
	runner := func(ctx context.Context, command string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string{command}, arguments...))
		return base(ctx, command, arguments...)
	}
	var output strings.Builder
	if err := runLocalWithRuntime(context.Background(), []string{"status", "--json"}, &output, io.Discard,
		localRuntime{stateRoot: root, run: runner}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"state":"OWNED_CLUSTER_PRESENT"`) || !strings.Contains(output.String(), `"consoleChecked":false`) {
		t.Fatalf("unexpected verified status: %s", output.String())
	}
	for _, call := range calls {
		if call[0] == "kubectl" && (!containsExactLine(strings.Join(call, "\n"), state.Kubeconfig) || !containsExactLine(strings.Join(call, "\n"), "--context")) {
			t.Fatalf("kubectl must be routed through the private kubeconfig/context: %v", call)
		}
		if call[0] == "kubectl" && strings.Contains(strings.Join(call, " "), "current-context") {
			t.Fatalf("global/current context must not be consulted: %v", call)
		}
	}
}

func TestLocalOwnerIDAndKindConfig(t *testing.T) {
	first, err := newLocalOwnerID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newLocalOwnerID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !localOwnerIDPattern.MatchString(first) {
		t.Fatalf("owner IDs must be unique 128-bit lowercase hex values: %q %q", first, second)
	}
	for _, logicalName := range []string{
		"ok-local-e2e-arash-20261105",
		"ok-local-e2e-arash-20261105-b",
		"ok-local-e2e-attempt3",
		"ok-local-e2e-attempt4",
	} {
		generated := localKindClusterName(logicalName, first)
		hostname := generated + localKindControlPlaneSuffix
		if len(generated) > localKindMaxNameLength || !validLocalKindClusterName(generated) ||
			len(hostname) > 63 || !strings.HasSuffix(generated, "-"+first) {
			t.Fatalf("logical name %q must produce a <=49-character Kind name and <=63-character control-plane hostname with the complete owner ID: %q hostname length=%d", logicalName, generated, len(hostname))
		}
	}
	maximumName := strings.Repeat("a", localKindMaxNameLength-len(first)-1) + "-" + first
	if len(maximumName) != 49 || len(maximumName+localKindControlPlaneSuffix) != 63 || !validLocalKindClusterName(maximumName) {
		t.Fatalf("49-character Kind name with a 63-character control-plane hostname must be accepted: %q length=%d hostname=%d", maximumName, len(maximumName), len(maximumName+localKindControlPlaneSuffix))
	}
	fiftyCharacterName := strings.Repeat("a", localKindMaxNameLength-len(first)) + "-" + first
	if len(fiftyCharacterName) != 50 || validLocalKindClusterName(fiftyCharacterName) {
		t.Fatalf("50-character Kind DNS label with a 64-character control-plane hostname must be rejected: %q length=%d", fiftyCharacterName, len(fiftyCharacterName))
	}
	if got := localKindClusterName("ok-local-e2e-arash-20261105", first); got == localKindClusterName("ok-local-e2e-arash-20261105-b", second) {
		t.Fatal("truncated readable prefixes must not collapse distinct owner identities")
	}
	config, err := renderKindOwnershipConfig(localClusterDefaultName, first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(string(config), '\t') {
		t.Fatalf("generated Kind YAML must not contain tabs: %q", config)
	}
	var parsed struct {
		Kind       string `yaml:"kind"`
		APIVersion string `yaml:"apiVersion"`
		Name       string `yaml:"name"`
		Nodes      []struct {
			Role                 string   `yaml:"role"`
			KubeadmConfigPatches []string `yaml:"kubeadmConfigPatches"`
		} `yaml:"nodes"`
	}
	if err := yaml.Unmarshal(config, &parsed); err != nil {
		t.Fatalf("generated Kind YAML must parse: %v\n%s", err, config)
	}
	if parsed.Kind != "Cluster" || parsed.APIVersion != "kind.x-k8s.io/v1alpha4" || parsed.Name != localKindClusterName(localClusterDefaultName, first) || len(parsed.Nodes) != 1 || parsed.Nodes[0].Role != "control-plane" || len(parsed.Nodes[0].KubeadmConfigPatches) != 1 {
		t.Fatalf("unexpected parsed Kind cluster structure: %+v", parsed)
	}
	var patch struct {
		Kind             string `yaml:"kind"`
		NodeRegistration struct {
			KubeletExtraArgs map[string]string `yaml:"kubeletExtraArgs"`
		} `yaml:"nodeRegistration"`
	}
	if err := yaml.Unmarshal([]byte(parsed.Nodes[0].KubeadmConfigPatches[0]), &patch); err != nil {
		t.Fatalf("owner-label kubeadm patch must parse: %v", err)
	}
	if patch.Kind != "InitConfiguration" || patch.NodeRegistration.KubeletExtraArgs["node-labels"] != localOwnerLabel+"="+first {
		t.Fatalf("owner label is not placed on the control-plane node registration: %+v", patch)
	}
	if localKindClusterName(localClusterDefaultName, first) == localKindClusterName(localClusterDefaultName, second) {
		t.Fatal("actual Kind cluster name must include the unique owner ID")
	}
	if _, err := renderKindOwnershipConfig("bad_name", first); err == nil {
		t.Fatal("invalid cluster name accepted")
	}
	if _, err := renderKindOwnershipConfig(strings.Repeat("a", 31), first); err == nil {
		t.Fatal("invalid logical cluster name accepted")
	}
}

func TestLocalKindNameShortensOnlyReadablePrefixAndPersistsLogicalName(t *testing.T) {
	ownerID := "edd83ae5428019db1593dd56e6105916"
	for _, logicalName := range []string{
		"ok-local-e2e-arash-20261105",
		"ok-local-e2e-arash-20261105-b",
		"ok-local-e2e-attempt3",
		"ok-local-e2e-attempt4",
	} {
		t.Run(logicalName, func(t *testing.T) {
			privateParent := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(privateParent, 0o700); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(privateParent, "ok-local")
			clusterDir := filepath.Join(root, "clusters", logicalName)
			if err := os.MkdirAll(clusterDir, 0o700); err != nil {
				t.Fatal(err)
			}
			kindName := localKindClusterName(logicalName, ownerID)
			provider := localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: "unix:///tmp/docker.sock", DaemonID: "daemon"}
			state := localClusterState{
				Format: localClusterStateFormat, Phase: "CREATING", Name: logicalName, OwnerID: ownerID,
				KindName: kindName, Provider: provider,
				Kubeconfig: filepath.Join(clusterDir, "kubeconfig"),
			}
			if err := writeLocalClusterIntent(root, logicalName, state); err != nil {
				t.Fatal(err)
			}
			persisted, err := readLocalClusterState(root, logicalName)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.Name != logicalName || persisted.KindName != kindName || !strings.HasSuffix(persisted.KindName, "-"+ownerID) {
				t.Fatalf("durable state must retain the complete logical name and owner binding: %+v", persisted)
			}
			legacy := state
			legacy.KindName = logicalName + "-" + ownerID
			if len(legacy.KindName) <= localKindMaxNameLength {
				t.Fatalf("fixture must cover the prior over-50-character name: %q", legacy.KindName)
			}
			if err := validateLocalClusterState(root, logicalName, legacy); err != nil {
				t.Fatalf("existing full-name receipt should remain inspectable: %v", err)
			}
			previousContract := state
			previousContract.KindName = localKindClusterNameWithLimit(logicalName, ownerID, localKindPreviousMaxNameLength)
			if len(previousContract.KindName) != 50 {
				t.Fatalf("legacy fixture must cover the previous 50-character Kind contract: %q", previousContract.KindName)
			}
			if err := validateLocalClusterState(root, logicalName, previousContract); err != nil {
				t.Fatalf("existing 50-character receipt should remain inspectable: kind=%q err=%v", previousContract.KindName, err)
			}
			diagnosticReceipt := localBootstrapDiagnosticReceipt{
				Format: localBootstrapDiagnosticFormat, Name: logicalName, OwnerID: ownerID,
				KindName: previousContract.KindName, Provider: provider,
				ConfigSHA256: strings.Repeat("a", 64), State: "PREPARED", ResourceState: "UNKNOWN",
			}
			if err := validateLocalBootstrapDiagnosticReceipt(diagnosticReceipt); err != nil {
				t.Fatalf("existing 50-character diagnostic receipt should remain inspectable: %v", err)
			}
		})
	}
}

func TestCompareKindKubeconfigBindsEndpointAndCredentials(t *testing.T) {
	if err := compareKindKubeconfig([]byte(localKubeconfigFixture), []byte(localKubeconfigFixture), "kind-ok-local"); err != nil {
		t.Fatalf("matching isolated kind kubeconfig rejected: %v", err)
	}
	for name, private := range map[string]string{
		"wrong server":      strings.Replace(localKubeconfigFixture, "127.0.0.1:12345", "192.0.2.1:6443", 1),
		"wrong CA":          strings.Replace(localKubeconfigFixture, "Y2E=", "b3RoZXI=", 1),
		"wrong client cert": strings.Replace(localKubeconfigFixture, "Y2VydA==", "b3RoZXI=", 1),
		"insecure TLS":      strings.Replace(localKubeconfigFixture, "server: https://127.0.0.1:12345", "server: https://127.0.0.1:12345\n    insecure-skip-tls-verify: true", 1),
		"proxy URL":         strings.Replace(localKubeconfigFixture, "server: https://127.0.0.1:12345", "server: https://127.0.0.1:12345\n    proxy-url: http://127.0.0.1:8888", 1),
		"exec credential":   strings.Replace(localKubeconfigFixture, "client-certificate-data: Y2VydA==\n    client-key-data: a2V5", "exec:\n      command: unexpected\n    client-certificate-data: Y2VydA==\n    client-key-data: a2V5", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := compareKindKubeconfig([]byte(localKubeconfigFixture), []byte(private), "kind-ok-local"); err == nil {
				t.Fatal("mismatched kubeconfig accepted")
			}
		})
	}
}

func TestLocalStateIsPrivateCreateOnlyAndStrict(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	path := localStateFilePath(root, state.Name)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state must be 0600: info=%v err=%v", info, err)
	}
	if err := writeLocalClusterState(root, state.Name, state); err == nil {
		t.Fatal("state overwrite accepted")
	}
	loaded, err := readLocalClusterState(root, state.Name)
	if err != nil || loaded.OwnerID != state.OwnerID {
		t.Fatalf("read state: loaded=%+v err=%v", loaded, err)
	}
	state.OwnerID = "not-an-owner-id"
	if err := validateLocalClusterState(root, state.Name, state); err == nil {
		t.Fatal("invalid owner identifier accepted")
	}
}

func TestLocalStateRejectsSymlinkedKubeconfig(t *testing.T) {
	root, state := localStateFixture(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state.Kubeconfig); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, state.Kubeconfig); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalClusterState(root, state.Name, state); err == nil {
		t.Fatal("symlinked kubeconfig accepted")
	}
}

func TestLocalDownDoesNotDeleteWithoutReceipt(t *testing.T) {
	called := false
	err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard,
		localRuntime{stateRoot: t.TempDir(), input: strings.NewReader("ok\n"), interactive: true, run: func(context.Context, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}})
	if err == nil || !strings.Contains(err.Error(), "no local ownership receipt") || called {
		t.Fatalf("down without receipt must not contact kind; err=%v called=%v", err, called)
	}
}

func TestLocalDownRefusesMismatchedLiveOwner(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	deleted := false
	runtime := localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: localOwnershipRunner(state, "ffffffffffffffffffffffffffffffff", true, &deleted)}
	err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard, runtime)
	if err == nil || deleted {
		t.Fatalf("mismatched live owner must not be deleted; err=%v deleted=%v", err, deleted)
	}
}

func TestLocalDownRequiresConfirmationAndRechecksOwnership(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	deleted := false
	runner := localOwnershipRunner(state, state.OwnerID, true, &deleted)
	pinnedCalls := 0
	runtime := localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: runner,
		runPinned: func(ctx context.Context, provider localProviderIdentity, command string, arguments ...string) ([]byte, error) {
			pinnedCalls++
			if provider != state.Provider {
				t.Fatalf("command not pinned to receipt provider: %+v", provider)
			}
			return runner(ctx, command, arguments...)
		},
	}
	var output strings.Builder
	if err := runLocalWithRuntime(context.Background(), []string{"down"}, &output, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("verified and confirmed local cluster was not deleted")
	}
	if pinnedCalls == 0 {
		t.Fatal("Kind and Docker identity operations must use the recorded provider context")
	}
	if _, err := os.Lstat(localStateFilePath(root, state.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state receipt was not removed after confirmed deletion: %v", err)
	}
	if !strings.Contains(output.String(), "Deleted verified local cluster") {
		t.Fatalf("missing deletion confirmation: %s", output.String())
	}
}

func TestLocalDownDoesNotDeleteIfIdentityChangesDuringConfirmation(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	deleted := false
	nodeCalls := 0
	base := localOwnershipRunner(state, state.OwnerID, true, &deleted)
	runner := func(ctx context.Context, command string, arguments ...string) ([]byte, error) {
		if command == "kubectl" && strings.Contains(strings.Join(arguments, " "), "get nodes -o json") {
			nodeCalls++
			if nodeCalls > 1 {
				return localOwnershipRunner(state, "ffffffffffffffffffffffffffffffff", true, &deleted)(ctx, command, arguments...)
			}
		}
		return base(ctx, command, arguments...)
	}
	err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard,
		localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: runner})
	if err == nil || deleted {
		t.Fatalf("changed identity after confirmation must fail closed: err=%v deleted=%v", err, deleted)
	}
}

func TestLocalDownRejectsReplacementContainerAfterConfirmation(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	deleted := false
	psCalls := 0
	base := localOwnershipRunner(state, state.OwnerID, true, &deleted)
	runner := func(ctx context.Context, command string, arguments ...string) ([]byte, error) {
		if command == "docker" && (strings.Contains(strings.Join(arguments, " "), " ps ") || strings.HasPrefix(strings.Join(arguments, " "), "ps ")) {
			psCalls++
			if psCalls > 1 {
				return []byte("replacement-container|" + state.Containers[0].Name + "|control-plane\n"), nil
			}
		}
		return base(ctx, command, arguments...)
	}
	err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard,
		localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: runner})
	if err == nil || deleted {
		t.Fatalf("replacement container must be rejected before deletion: err=%v deleted=%v", err, deleted)
	}
}

func TestLocalOwnershipRejectsChangedDockerProviderIdentity(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	base := localOwnershipRunner(state, state.OwnerID, true, nil)
	for name, response := range map[string]string{"context": "other-context\n", "endpoint": "unix:///tmp/other.sock\n", "daemon": "other-daemon\n"} {
		t.Run(name, func(t *testing.T) {
			runner := func(ctx context.Context, command string, arguments ...string) ([]byte, error) {
				joined := strings.Join(arguments, " ")
				if command == "docker" && ((name == "context" && strings.Contains(joined, "context show")) || (name == "endpoint" && strings.Contains(joined, "context inspect")) || (name == "daemon" && strings.Contains(joined, "info --format"))) {
					return []byte(response), nil
				}
				return base(ctx, command, arguments...)
			}
			var output strings.Builder
			err := runLocalWithRuntime(context.Background(), []string{"status"}, &output, io.Discard, localRuntime{stateRoot: root, run: runner})
			if err == nil || !strings.Contains(err.Error(), "provider identity differs") {
				t.Fatalf("changed Docker %s must fail closed: %v", name, err)
			}
		})
	}
}

func TestLocalDownWithoutTerminalDoesNotContactCluster(t *testing.T) {
	root, state := localStateFixture(t)
	if err := writeLocalClusterState(root, state.Name, state); err != nil {
		t.Fatal(err)
	}
	called := false
	err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard,
		localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), run: func(context.Context, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}})
	if err == nil || called {
		t.Fatalf("non-interactive down must stop before cluster contact: err=%v called=%v", err, called)
	}
}

func TestLocalForwardIdentityIncludesOwnerAndArgumentDigest(t *testing.T) {
	root, state := localStateFixture(t)
	digest := sha256.Sum256([]byte("ok local internal port forward"))
	state.Forward = &localForwardIdentity{PID: 123, OwnerID: state.OwnerID, StartedAt: "2026-11-05T00:00:00Z", Executable: "/usr/local/bin/ok", ArgumentsSHA256: "sha256:" + hex.EncodeToString(digest[:])}
	if err := validateLocalClusterState(root, state.Name, state); err != nil {
		t.Fatalf("complete process identity rejected: %v", err)
	}
	state.Forward.OwnerID = "ffffffffffffffffffffffffffffffff"
	if err := validateLocalClusterState(root, state.Name, state); err == nil {
		t.Fatal("forward bound to a different owner was accepted")
	}
}

func TestLocalForwardCannotBeAuthorizedByPIDAlone(t *testing.T) {
	command := "/opt/homebrew/bin/kubectl --kubeconfig /private/ok/kubeconfig --context kind-ok-local-0123456789abcdef0123456789abcdef -n openkubes-console port-forward --address 127.0.0.1 service/ok-console 18787:8787"
	hash := sha256.Sum256([]byte(command))
	identity := localForwardIdentity{PID: 123, OwnerID: "0123456789abcdef0123456789abcdef", StartedAt: "Wed Nov  5 10:00:00 2026", Executable: "/opt/homebrew/bin/kubectl", ArgumentsSHA256: "sha256:" + hex.EncodeToString(hash[:])}
	if err := validateLocalForwardObservation(identity, identity.StartedAt, command); err != nil {
		t.Fatalf("exact recorded process identity rejected: %v", err)
	}
	for _, observed := range []struct{ started, command string }{{"different start", command}, {identity.StartedAt, command + " --other"}, {identity.StartedAt, "/tmp/other-kubectl " + strings.TrimPrefix(command, identity.Executable+" ")}} {
		if err := validateLocalForwardObservation(identity, observed.started, observed.command); err == nil {
			t.Fatalf("mismatched process authorized for signal: %+v", observed)
		}
	}
}

func TestLocalForwardInspectorClassifiesUnrelatedLivePIDAsReused(t *testing.T) {
	identity := localForwardIdentity{PID: os.Getpid(), OwnerID: "0123456789abcdef0123456789abcdef", StartedAt: "not-the-current-start-time", Executable: "/no/such/kubectl", ArgumentsSHA256: "sha256:" + strings.Repeat("0", 64)}
	state, err := inspectLocalForwardProcess(identity)
	if err != nil {
		t.Fatal(err)
	}
	if state != localForwardPIDReused {
		t.Fatalf("current unrelated process classified as %s", state)
	}
}

func TestLocalDownClearsStaleForwardReceiptsWithoutSignalingReusedPID(t *testing.T) {
	for _, processState := range []localForwardProcessState{localForwardAbsent, localForwardPIDReused} {
		t.Run(string(processState), func(t *testing.T) {
			root, state := localStateFixture(t)
			state.Forward = &localForwardIdentity{PID: 43210, OwnerID: state.OwnerID, StartedAt: "previous boot", Executable: "/usr/bin/kubectl", ArgumentsSHA256: "sha256:" + strings.Repeat("a", 64)}
			if err := writeLocalClusterState(root, state.Name, state); err != nil {
				t.Fatal(err)
			}
			deleted := false
			base := localOwnershipRunner(state, state.OwnerID, true, &deleted)
			signals := 0
			runtime := localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: base,
				inspectForward: func(localForwardIdentity) (localForwardProcessState, error) { return processState, nil },
				stopForward:    func(localForwardIdentity) error { signals++; return nil },
			}
			err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard, runtime)
			if err != nil || !deleted {
				t.Fatalf("stale receipt blocked owned cleanup: err=%v deleted=%v", err, deleted)
			}
			if signals != 0 {
				t.Fatalf("stale/reused PID was signaled %d times", signals)
			}
		})
	}
}

func TestLocalDownOnlyStopsMatchingForwardAndFailsOnUnknownIdentity(t *testing.T) {
	for _, test := range []struct {
		name       string
		observed   localForwardProcessState
		inspectErr bool
		wantSignal bool
	}{
		{name: "matching", observed: localForwardMatches, wantSignal: true},
		{name: "uninspectable", inspectErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, state := localStateFixture(t)
			state.Forward = &localForwardIdentity{PID: 1234, OwnerID: state.OwnerID, StartedAt: "start", Executable: "/usr/bin/kubectl", ArgumentsSHA256: "sha256:" + strings.Repeat("b", 64)}
			if err := writeLocalClusterState(root, state.Name, state); err != nil {
				t.Fatal(err)
			}
			deleted := false
			base := localOwnershipRunner(state, state.OwnerID, true, &deleted)
			signals := 0
			runtime := localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: base,
				inspectForward: func(localForwardIdentity) (localForwardProcessState, error) {
					if test.inspectErr {
						return "", errors.New("ps unavailable")
					}
					return test.observed, nil
				},
				stopForward: func(localForwardIdentity) error { signals++; return nil },
			}
			err := runLocalWithRuntime(context.Background(), []string{"down"}, io.Discard, io.Discard, runtime)
			if test.inspectErr {
				if err == nil || deleted || signals != 0 {
					t.Fatalf("unknown identity must stop without signal/delete: err=%v deleted=%v signals=%d", err, deleted, signals)
				}
				return
			}
			if err != nil || !deleted || signals != 1 {
				t.Fatalf("matching identity cleanup failed: err=%v deleted=%v signals=%d", err, deleted, signals)
			}
		})
	}
}

func TestLocalVerifierDiagnosticsAreActionableAndDoNotLeakInput(t *testing.T) {
	exitErr := exec.Command("sh", "-c", "exit 17").Run()
	cases := []struct {
		stage string
		code  string
	}{
		{"preflight", "KIND_NAME_TOO_LONG"},
		{"kind_inventory", "KIND_LIST_FAILED"},
		{"kind_create", "KIND_CONFIG_OR_CREATE_FAILED"},
		{"image_deploy", "IMAGE_OR_DEPLOY_FAILED"},
		{"temp_file", "TEMP_FILE_PREPARATION_FAILED"},
		{"unknown", "UNKNOWN"},
	}
	for _, test := range cases {
		t.Run(test.code, func(t *testing.T) {
			output := []byte("Authorization: Bearer planted-secret-token\nclient-certificate-data: private-kubeconfig-material\nOK_LOCAL_DIAGNOSTIC stage=" + test.stage + " code=" + test.code + "\n")
			diagnostic := localVerifierDiagnostic(output, exitErr)
			if !strings.Contains(diagnostic, "stage="+test.stage) || !strings.Contains(diagnostic, "code="+test.code) || !strings.Contains(diagnostic, "exit 17") {
				t.Fatalf("structured safe category missing: %s", diagnostic)
			}
			for _, secret := range []string{"planted-secret-token", "private-kubeconfig-material", "Authorization", "certificate-data"} {
				if strings.Contains(diagnostic, secret) {
					t.Fatalf("sensitive verifier output leaked %q: %s", secret, diagnostic)
				}
			}
		})
	}
	for _, invalid := range [][]byte{
		[]byte("OK_LOCAL_DIAGNOSTIC stage=kind_inventory code=IMAGE_OR_DEPLOY_FAILED\n"),
		[]byte("OK_LOCAL_DIAGNOSTIC stage=kind_inventory code=KIND_LIST_FAILED\nraw-secret-after-marker\n"),
		[]byte("Authorization: Bearer raw-secret\n"),
	} {
		got := localVerifierDiagnostic(invalid, exitErr)
		if !strings.Contains(got, "stage=unknown code=UNKNOWN") || strings.Contains(got, "raw-secret") {
			t.Fatalf("untrusted or non-terminal diagnostic marker must map to safe UNKNOWN: %s", got)
		}
	}
	if got := safeLocalVerifierFailure(errors.New("Authorization: Bearer arbitrary-secret")); strings.Contains(got, "arbitrary-secret") || !strings.Contains(got, "UNKNOWN") {
		t.Fatalf("untrusted callback error did not map to safe UNKNOWN: %s", got)
	}
}

func TestLocalVerifierPropagatesOnlyAllowlistedDiagnostics(t *testing.T) {
	root := filepath.Join(t.TempDir(), "console", "deploy", "kubernetes")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "verify-local-kind.sh")
	contents := "#!/usr/bin/env bash\necho 'Authorization: Bearer verifier-private-token' >&2\necho 'OK_LOCAL_DIAGNOSTIC stage=kind_inventory code=KIND_LIST_FAILED' >&2\nexit 17\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	err := runLocalConsoleVerifier(context.Background(), script, map[string]string{})
	if err == nil {
		t.Fatal("mock verifier failure unexpectedly succeeded")
	}
	diagnostic := safeLocalVerifierFailure(err)
	if !strings.Contains(diagnostic, "stage=kind_inventory code=KIND_LIST_FAILED") || !strings.Contains(diagnostic, "exit 17") {
		t.Fatalf("allowlisted failure was not propagated: %s", diagnostic)
	}
	if strings.Contains(diagnostic, "verifier-private-token") || strings.Contains(diagnostic, "Authorization") {
		t.Fatalf("raw verifier stderr leaked into the CLI diagnostic: %s", diagnostic)
	}
}

const localDiagnosticOwnerID = "0123456789abcdef0123456789abcdef"

func newDiagnosticStateRoot(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "ok-local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "clusters"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func diagnosticTestRuntime(t *testing.T, name string, failureOutput string, failureErr error, retainedContainers []localContainerIdentity, clusterPresent bool) (localRuntime, *int, *bool) {
	t.Helper()
	root := newDiagnosticStateRoot(t)
	provider := localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: "unix:///tmp/colima/docker.sock", DaemonID: "daemon-diagnostic"}
	kindName := localKindClusterName(name, localDiagnosticOwnerID)
	createCalls := 0
	verifierCalled := false
	kindListCalls := 0
	dockerListCalls := 0
	kubeconfig := strings.ReplaceAll(localKubeconfigFixture, "kind-ok-local", "kind-"+kindName)
	runtime := localRuntime{
		stateRoot: root,
		run: func(_ context.Context, command string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch command {
			case "kind":
				if len(args) > 0 && (args[0] == "delete" || args[0] == "export") {
					t.Fatalf("diagnostic workflow attempted Kind cleanup/export: %v", args)
				}
				if joined == "version" {
					return []byte("kind v0.33.0 go1.27.0 darwin/arm64"), nil
				}
			case "docker":
				if strings.HasPrefix(joined, "build ") || strings.HasPrefix(joined, "rm ") || strings.HasPrefix(joined, "stop ") || strings.HasPrefix(joined, "run ") {
					t.Fatalf("diagnostic workflow attempted Docker mutation: %s", joined)
				}
				switch {
				case joined == "context show":
					return []byte(provider.Context), nil
				case strings.HasPrefix(joined, "context inspect "):
					return []byte(provider.Endpoint), nil
				case strings.Contains(joined, "info --format"):
					return []byte(provider.DaemonID), nil
				}
			case "kubectl":
				if strings.Contains(joined, "get nodes -o json") {
					return []byte(fmt.Sprintf(`{"items":[{"metadata":{"name":%q,"uid":"node-uid","labels":{"%s":%q}}}]}`, kindName+"-control-plane", localOwnerLabel, localDiagnosticOwnerID)), nil
				}
				if strings.Contains(joined, "get namespace kube-system -o json") {
					return []byte(`{"metadata":{"uid":"kube-system-uid"}}`), nil
				}
			}
			return nil, fmt.Errorf("unexpected non-pinned diagnostic test command %s %s", command, joined)
		},
		runPinned: func(_ context.Context, actualProvider localProviderIdentity, command string, args ...string) ([]byte, error) {
			if actualProvider != provider {
				t.Fatalf("provider not pinned: got=%+v want=%+v", actualProvider, provider)
			}
			joined := strings.Join(args, " ")
			switch command {
			case "kind":
				if len(args) > 0 && (args[0] == "delete" || args[0] == "export") {
					t.Fatalf("diagnostic workflow attempted Kind cleanup/export: %v", args)
				}
				if joined == "get clusters" {
					kindListCalls++
					if clusterPresent && kindListCalls > 1 {
						return []byte(kindName + "\n"), nil
					}
					return []byte(""), nil
				}
				if joined == "get kubeconfig --name "+kindName {
					return []byte(kubeconfig), nil
				}
			case "docker":
				if len(args) > 0 && (args[0] == "rm" || args[0] == "stop" || args[0] == "build" || args[0] == "run") {
					t.Fatalf("diagnostic workflow attempted Docker mutation: %v", args)
				}
				if len(args) > 0 && args[0] == "ps" {
					dockerListCalls++
					if dockerListCalls == 1 {
						return []byte(""), nil
					}
					var rows []string
					for _, container := range retainedContainers {
						rows = append(rows, container.ID+"|"+container.Name+"|"+container.Role)
					}
					return []byte(strings.Join(rows, "\n")), nil
				}
			}
			return nil, fmt.Errorf("unexpected pinned diagnostic test command %s %s", command, joined)
		},
		runKindCreate: func(_ context.Context, actualProvider localProviderIdentity, kubeconfigPath string, args ...string) ([]byte, bool, error) {
			createCalls++
			if actualProvider != provider || kubeconfigPath != filepath.Join(root, "clusters", name, "kubeconfig") {
				t.Fatalf("wrong pinned create identity: provider=%+v kubeconfig=%q", actualProvider, kubeconfigPath)
			}
			expected := localKindDiagnosticCreateArguments(filepath.Join(root, "clusters", name, "kind.yaml"), kindName, kubeconfigPath)
			if !reflect.DeepEqual(args, expected) {
				t.Fatalf("Kind args differ\n got: %#v\nwant: %#v", args, expected)
			}
			if failureErr != nil {
				return []byte(failureOutput), false, failureErr
			}
			if err := os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0o600); err != nil {
				return nil, false, err
			}
			return nil, false, nil
		},
		runVerifier: func(context.Context, string, map[string]string) error {
			verifierCalled = true
			return errors.New("Console verifier must never run from bootstrap diagnostics")
		},
		newOwnerID: func() (string, error) { return localDiagnosticOwnerID, nil },
	}
	return runtime, &createCalls, &verifierCalled
}

func TestLocalKindDiagnosticClassifierIsAllowlistedAndSecretSafe(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"config", "ERROR: failed to create cluster: failed to load config: secret-value", "KIND_CONFIG_REJECTED"},
		{"docker", "ERROR: failed to create cluster: failed to create container: authorization bearer secret-value", "DOCKER_PROVISION_FAILED"},
		{"kubeadm", "ERROR: failed to create cluster: failed to init node with kubeadm: exit status 1 secret-value", "NODE_BOOTSTRAP_FAILED"},
		{"readiness", "ERROR: failed to create cluster: timed out waiting for control plane secret-value", "KIND_READINESS_TIMEOUT"},
		{"unknown", "unexpected error secret-value", "UNKNOWN"},
		{"unanchored", "private-config-field=failed to create container", "UNKNOWN"},
		{"ambiguous", "ERROR: failed to create cluster: failed to create container\nERROR: failed to create cluster: failed to init node with kubeadm:", "UNKNOWN"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyLocalKindCreateFailure([]byte(test.text), false); got != test.want {
				t.Fatalf("classification=%s want=%s", got, test.want)
			}
		})
	}
	if got := classifyLocalKindCreateFailure([]byte("ERROR: failed to create cluster: failed to init node with kubeadm:"), true); got != "UNKNOWN" {
		t.Fatalf("truncated output must be UNKNOWN, got %s", got)
	}
}

func TestLocalKindDiagnosticArgumentsAreExactAndRetained(t *testing.T) {
	config := "/private/state path/kind.yaml"
	kubeconfig := "/private/state path/kubeconfig"
	got := localKindDiagnosticCreateArguments(config, "ok-local-diag-0123456789abcdef0123456789abcdef", kubeconfig)
	want := []string{"create", "cluster", "--retain", "--config", config, "--name", "ok-local-diag-0123456789abcdef0123456789abcdef", "--kubeconfig", kubeconfig, "--wait", "90s"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args differ\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRunLocalKindCreatePinsColimaAndPrivateKubeconfigWithMockExecutable(t *testing.T) {
	binDir := t.TempDir()
	envPath := filepath.Join(t.TempDir(), "env.txt")
	argsPath := filepath.Join(t.TempDir(), "args.txt")
	globalKubeconfigPath := filepath.Join(t.TempDir(), "global-kubeconfig")
	globalKubeconfig := []byte("preserve-global-kubeconfig-marker")
	if err := os.WriteFile(globalKubeconfigPath, globalKubeconfig, 0o600); err != nil {
		t.Fatal(err)
	}
	globalDigest := sha256.Sum256(globalKubeconfig)
	script := `#!/bin/sh
printf '%s\n' "$DOCKER_HOST" "$KIND_EXPERIMENTAL_PROVIDER" "$KUBECONFIG" > "$DIAGNOSTIC_ENV_CAPTURE"
printf '%s\n' "$@" > "$DIAGNOSTIC_ARGS_CAPTURE"
printf '%s\n' 'Authorization: Bearer intentionally-secret'
exit 1
`
	if err := os.WriteFile(filepath.Join(binDir, "kind"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("KUBECONFIG", globalKubeconfigPath)
	t.Setenv("DOCKER_CONTEXT", "unrelated-context")
	t.Setenv("DIAGNOSTIC_ENV_CAPTURE", envPath)
	t.Setenv("DIAGNOSTIC_ARGS_CAPTURE", argsPath)
	provider := localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: "unix:///private/colima.sock", DaemonID: "daemon-id"}
	kubeconfig := "/private/state with spaces/kubeconfig"
	args := localKindDiagnosticCreateArguments("/private/state with spaces/kind.yaml", "ok-local-diag-0123456789abcdef0123456789abcdef", kubeconfig)
	output, truncated, err := runLocalKindCreatePinned(context.Background(), provider, kubeconfig, args...)
	if err == nil || truncated || !strings.Contains(string(output), "intentionally-secret") {
		t.Fatalf("mock executable result err=%v truncated=%v", err, truncated)
	}
	envBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(envBytes), provider.Endpoint+"\ndocker\n"+kubeconfig+"\n"; got != want {
		t.Fatalf("unsafe child environment: got=%q want=%q", got, want)
	}
	argBytes, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(strings.TrimSuffix(string(argBytes), "\n"), "\n"); !reflect.DeepEqual(got, args) {
		t.Fatalf("shell argument boundaries changed: got=%#v want=%#v", got, args)
	}
	afterGlobal, err := os.ReadFile(globalKubeconfigPath)
	if err != nil || sha256.Sum256(afterGlobal) != globalDigest {
		t.Fatalf("global kubeconfig changed: err=%v", err)
	}
}

func TestLocalDiagnoseBootstrapPersistsRetainedFailureAndNeverLeaksRawOutput(t *testing.T) {
	name := "ok-local-e2e-diagnostic"
	container := localContainerIdentity{ID: strings.Repeat("a", 64), Name: localKindClusterName(name, localDiagnosticOwnerID) + "-control-plane", Role: "control-plane"}
	runtime, calls, verifierCalled := diagnosticTestRuntime(t, name, "ERROR: failed to create cluster: failed to init node with kubeadm: Authorization: Bearer planted-secret", errors.New("raw secret in wrapped error"), []localContainerIdentity{container}, true)
	var stdout, stderr strings.Builder
	err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, &stdout, &stderr, runtime)
	if err == nil || !strings.Contains(err.Error(), "NODE_BOOTSTRAP_FAILED") || strings.Contains(err.Error(), "planted-secret") || strings.Contains(err.Error(), "raw secret") {
		t.Fatalf("unsafe or missing failure result: %v", err)
	}
	if *calls != 1 || *verifierCalled || stdout.Len() != 0 || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("unexpected retry, Console call or output: calls=%d verifier=%v stdout=%q stderr=%q", *calls, *verifierCalled, stdout.String(), stderr.String())
	}
	state, err := readLocalClusterState(runtime.stateRoot, name)
	if err != nil || state.Format != localBootstrapStateFormat || state.Phase != "INCOMPLETE" || len(state.Containers) != 1 || state.Containers[0] != container || !strings.HasSuffix(state.KindName, localDiagnosticOwnerID) || len(state.KindName) > localKindMaxNameLength {
		t.Fatalf("bad durable failure identity: state=%+v err=%v", state, err)
	}
	receipt, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, name)
	if err != nil || receipt.State != "FAILED" || receipt.FailureCode != "NODE_BOOTSTRAP_FAILED" || receipt.ResourceState != "VERIFIED_RETAINED" || len(receipt.Containers) != 1 {
		t.Fatalf("bad diagnostic receipt: receipt=%+v err=%v", receipt, err)
	}
	if receipt.Provider.Endpoint != "unix:///tmp/colima/docker.sock" || receipt.Provider.DaemonID != "daemon-diagnostic" || receipt.OwnerID != localDiagnosticOwnerID || receipt.KindName != state.KindName {
		t.Fatalf("diagnostic receipt lost provider/owner binding: %+v", receipt)
	}
	rawReceipt, err := os.ReadFile(localBootstrapDiagnosticPath(runtime.stateRoot, name))
	if err != nil || strings.Contains(string(rawReceipt), "planted-secret") || strings.Contains(string(rawReceipt), "raw secret") || strings.Contains(string(rawReceipt), "Authorization") {
		t.Fatalf("raw failure material was persisted: err=%v", err)
	}
	before := *calls
	downErr := runLocalWithRuntime(context.Background(), []string{"down", "--name", name}, io.Discard, io.Discard, runtime)
	if downErr == nil || !strings.Contains(downErr.Error(), "separately authorized") || *calls != before {
		t.Fatalf("diagnostic down must block before cluster contact: err=%v calls=%d/%d", downErr, *calls, before)
	}
	retryErr := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, io.Discard, io.Discard, runtime)
	if retryErr == nil || !strings.Contains(retryErr.Error(), "will not retry") || *calls != 1 {
		t.Fatalf("existing diagnostic attempt must be terminal: err=%v createCalls=%d", retryErr, *calls)
	}
	var status strings.Builder
	if err := runLocalWithRuntime(context.Background(), []string{"status", "--name", name, "--json"}, &status, io.Discard, runtime); err != nil || !strings.Contains(status.String(), `"state":"DIAGNOSTIC_FAILED"`) || !strings.Contains(status.String(), `"clusterContacted":false`) {
		t.Fatalf("diagnostic status must be local and explicit: output=%s err=%v", status.String(), err)
	}
}

func TestLocalDiagnoseBootstrapFailureCategoriesArePersistedWithoutRawOutput(t *testing.T) {
	for _, test := range []struct{ name, output, want string }{
		{"config", "ERROR: failed to create cluster: failed to parse config: bearer secret-value", "KIND_CONFIG_REJECTED"},
		{"docker", "ERROR: failed to create cluster: failed to create container: credential secret-value", "DOCKER_PROVISION_FAILED"},
		{"readiness", "ERROR: failed to create cluster: timed out waiting for control plane: private detail", "KIND_READINESS_TIMEOUT"},
		{"unknown", "unclassified secret-value", "UNKNOWN"},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := "ok-local-diagnostic-" + test.name
			runtime, calls, verifierCalled := diagnosticTestRuntime(t, name, test.output, errors.New("wrapped bearer secret-value"), nil, false)
			err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, io.Discard, io.Discard, runtime)
			if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "secret-value") || *calls != 1 || *verifierCalled {
				t.Fatalf("failure was not safely recorded exactly once: err=%v calls=%d verifier=%v", err, *calls, *verifierCalled)
			}
			receipt, readErr := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, name)
			if readErr != nil || receipt.FailureCode != test.want || receipt.ResourceState != "ABSENT" {
				t.Fatalf("wrong safe terminal receipt: %+v err=%v", receipt, readErr)
			}
			raw, readErr := os.ReadFile(localBootstrapDiagnosticPath(runtime.stateRoot, name))
			if readErr != nil || strings.Contains(string(raw), "secret-value") || strings.Contains(string(raw), "private detail") || strings.Contains(string(raw), "wrapped bearer") {
				t.Fatalf("raw failure material was persisted: err=%v", readErr)
			}
		})
	}
}

func TestLocalDiagnoseBootstrapSuccessRetainsVerifiedClusterAndDoesNotDeployConsole(t *testing.T) {
	name := "ok-local-diagnostic-success"
	container := localContainerIdentity{ID: strings.Repeat("1", 64), Name: localKindClusterName(name, localDiagnosticOwnerID) + "-control-plane", Role: "control-plane"}
	runtime, calls, verifierCalled := diagnosticTestRuntime(t, name, "", nil, []localContainerIdentity{container}, true)
	var output strings.Builder
	if err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, &output, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 || *verifierCalled || !strings.Contains(output.String(), "retained") || strings.Contains(output.String(), "127.0.0.1") {
		t.Fatalf("unexpected success path: calls=%d verifier=%v output=%q", *calls, *verifierCalled, output.String())
	}
	state, err := readLocalClusterState(runtime.stateRoot, name)
	if err != nil || state.Format != localBootstrapStateFormat || state.Phase != "CLUSTER_READY" || len(state.Containers) != 1 || len(state.Nodes) != 1 || state.KubeSystemUID == "" {
		t.Fatalf("success without complete identity must not be claimed: state=%+v err=%v", state, err)
	}
	receipt, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, name)
	if err != nil || receipt.State != "SUCCEEDED_RETAINED" || receipt.ResourceState != "VERIFIED_RETAINED" || !receipt.KubeconfigSeen {
		t.Fatalf("successful cluster not durably bound: receipt=%+v err=%v", receipt, err)
	}
	before := *calls
	downErr := runLocalWithRuntime(context.Background(), []string{"down", "--name", name}, io.Discard, io.Discard, runtime)
	if downErr == nil || *calls != before {
		t.Fatalf("normal down must never delete a diagnostic cluster: err=%v calls=%d/%d", downErr, *calls, before)
	}
	var status strings.Builder
	if err := runLocalWithRuntime(context.Background(), []string{"status", "--name", name, "--json"}, &status, io.Discard, runtime); err != nil || !strings.Contains(status.String(), `"state":"OWNED_CLUSTER_PRESENT"`) {
		t.Fatalf("verified diagnostic cluster should be inspectable: output=%s err=%v", status.String(), err)
	}
	if err := os.Remove(localBootstrapDiagnosticPath(runtime.stateRoot, name)); err != nil {
		t.Fatal(err)
	}
	before = *calls
	downErr = runLocalWithRuntime(context.Background(), []string{"down", "--name", name}, io.Discard, io.Discard, runtime)
	if downErr == nil || !strings.Contains(downErr.Error(), "without its required receipt") || *calls != before {
		t.Fatalf("missing diagnostic receipt must still block deletion: err=%v calls=%d/%d", downErr, *calls, before)
	}
}

func TestLocalDiagnoseBootstrapPreservesOtherIncompleteReceipts(t *testing.T) {
	name := "ok-local-diagnostic-fresh"
	runtime, calls, _ := diagnosticTestRuntime(t, name, "failure", errors.New("failure"), nil, false)
	root := runtime.stateRoot
	previous := []string{"ok-local-e2e-arash-20261105", "ok-local-e2e-arash-20261105-b", "ok-local-e2e-attempt3"}
	before := map[string][2]string{}
	for _, oldName := range previous {
		dir := filepath.Join(root, "clusters", oldName)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for index, filename := range []string{"state.json", "kind.yaml"} {
			contents := []byte("preserved-existing-evidence:" + oldName + ":" + filename)
			path := filepath.Join(dir, filename)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(contents)
			pair := before[oldName]
			pair[index] = hex.EncodeToString(digest[:])
			before[oldName] = pair
		}
	}
	if err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, io.Discard, io.Discard, runtime); err == nil || *calls != 1 {
		t.Fatalf("expected one isolated diagnostic invocation, err=%v calls=%d", err, *calls)
	}
	for _, oldName := range previous {
		for index, filename := range []string{"state.json", "kind.yaml"} {
			contents, err := os.ReadFile(filepath.Join(root, "clusters", oldName, filename))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(contents)
			if got := hex.EncodeToString(digest[:]); got != before[oldName][index] {
				t.Fatalf("existing evidence changed: %s/%s", oldName, filename)
			}
		}
	}
}

func TestLocalDiagnoseBootstrapFailureResourceIdentityIsFailClosed(t *testing.T) {
	name := "ok-local-diagnostic-identity"
	goodName := localKindClusterName(name, localDiagnosticOwnerID) + "-control-plane"
	cases := []struct {
		name string
		rows []localContainerIdentity
		list bool
		want string
	}{
		{"no resources", nil, false, "ABSENT"},
		{"cluster without node", nil, true, "AMBIGUOUS"},
		{"exact node", []localContainerIdentity{{ID: strings.Repeat("b", 64), Name: goodName, Role: "control-plane"}}, true, "VERIFIED_RETAINED"},
		{"unexpected name", []localContainerIdentity{{ID: strings.Repeat("c", 64), Name: "unexpected-control-plane", Role: "control-plane"}}, true, "AMBIGUOUS"},
		{"multiple nodes", []localContainerIdentity{{ID: strings.Repeat("d", 64), Name: goodName, Role: "control-plane"}, {ID: strings.Repeat("e", 64), Name: localKindClusterName(name, localDiagnosticOwnerID) + "-worker", Role: "worker"}}, true, "AMBIGUOUS"},
		{"container without kind listing", []localContainerIdentity{{ID: strings.Repeat("f", 64), Name: goodName, Role: "control-plane"}}, false, "AMBIGUOUS"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runtime, calls, _ := diagnosticTestRuntime(t, name, "unexpected failure", errors.New("failed"), test.rows, test.list)
			if err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, io.Discard, io.Discard, runtime); err == nil {
				t.Fatal("mock failure should produce terminal error")
			}
			receipt, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, name)
			if err != nil || receipt.ResourceState != test.want || *calls != 1 {
				t.Fatalf("identity did not fail closed: receipt=%+v err=%v calls=%d", receipt, err, *calls)
			}
		})
	}
}

func TestLocalDiagnoseBootstrapRejectsCollisionAndProviderDriftBeforeCreate(t *testing.T) {
	name := "ok-local-diagnostic-collision"
	root := newDiagnosticStateRoot(t)
	provider := localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: "unix:///tmp/colima/docker.sock", DaemonID: "daemon-diagnostic"}
	kindName := localKindClusterName(name, localDiagnosticOwnerID)
	for _, test := range []struct {
		name   string
		run    localCommandRunner
		pinned func(context.Context, localProviderIdentity, string, ...string) ([]byte, error)
		want   string
	}{
		{name: "kind name collision", run: func(_ context.Context, command string, args ...string) ([]byte, error) {
			if command == "kind" && strings.Join(args, " ") == "version" {
				return []byte("kind v0.33.0"), nil
			}
			if command == "docker" {
				joined := strings.Join(args, " ")
				if joined == "context show" {
					return []byte(provider.Context), nil
				}
				if strings.HasPrefix(joined, "context inspect ") {
					return []byte(provider.Endpoint), nil
				}
				if strings.Contains(joined, "info --format") {
					return []byte(provider.DaemonID), nil
				}
			}
			return nil, errors.New("unexpected")
		}, pinned: func(_ context.Context, _ localProviderIdentity, command string, args ...string) ([]byte, error) {
			if command == "kind" && strings.Join(args, " ") == "get clusters" {
				return []byte(kindName + "\n"), nil
			}
			return nil, errors.New("collision must stop before container lookup")
		}, want: "already exists"},
		{name: "provider changes before intent", run: func(_ context.Context, command string, args ...string) ([]byte, error) {
			if command == "kind" && strings.Join(args, " ") == "version" {
				return []byte("kind v0.33.0"), nil
			}
			if command == "docker" {
				joined := strings.Join(args, " ")
				if joined == "context show" {
					return []byte(provider.Context), nil
				}
				if strings.HasPrefix(joined, "context inspect ") {
					return []byte(provider.Endpoint), nil
				}
				if strings.Contains(joined, "info --format") {
					return []byte(provider.DaemonID), nil
				}
			}
			return nil, errors.New("unexpected")
		}, pinned: func(context.Context, localProviderIdentity, string, ...string) ([]byte, error) {
			return nil, errors.New("pinned call must not occur")
		}, want: "identity changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			callCount := 0
			runtime := localRuntime{stateRoot: root, run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
				if test.name == "provider changes before intent" && command == "docker" && strings.Contains(strings.Join(args, " "), "info --format") {
					callCount++
					if callCount > 1 {
						return []byte("different-daemon"), nil
					}
				}
				return test.run(ctx, command, args...)
			}, runPinned: test.pinned, newOwnerID: func() (string, error) { return localDiagnosticOwnerID, nil }, runKindCreate: func(context.Context, localProviderIdentity, string, ...string) ([]byte, bool, error) {
				t.Fatal("Kind create must not be reached")
				return nil, false, nil
			}}
			err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, io.Discard, io.Discard, runtime)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected preflight result: %v", err)
			}
			if _, statErr := os.Lstat(localStateFilePath(root, name)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("preflight failure wrote state: %v", statErr)
			}
		})
	}
}

func TestLocalDiagnosticReceiptCannotOverwriteOutcomeOrLeakTamperedConfig(t *testing.T) {
	name := "ok-local-diagnostic-receipt"
	runtime, _, _ := diagnosticTestRuntime(t, name, "failed", errors.New("failed"), nil, false)
	if err := runLocalWithRuntime(context.Background(), []string{"diagnose", "bootstrap", "--name", name}, io.Discard, io.Discard, runtime); err == nil {
		t.Fatal("expected diagnostic failure")
	}
	receipt, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, name)
	if err != nil {
		t.Fatal(err)
	}
	receipt.State = "SUCCEEDED_RETAINED"
	if err := writeLocalBootstrapDiagnosticReceipt(runtime.stateRoot, receipt, true); err == nil {
		t.Fatal("terminal receipt must not be overwritten")
	}
	configPath := filepath.Join(runtime.stateRoot, "clusters", name, "kind.yaml")
	if err := os.WriteFile(configPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, name); err == nil {
		t.Fatal("changed config digest must invalidate diagnostic receipt")
	}
}

func TestLocalKindMinimumVersion(t *testing.T) {
	for _, test := range []struct {
		output    string
		supported bool
	}{
		{"kind v0.33.0 go1.27.0 darwin/arm64", true},
		{"kind v0.34.1 go1.27.0 darwin/arm64", true},
		{"kind v0.32.9 go1.27.0 darwin/arm64", false},
		{"kind unknown", false},
	} {
		if got := localKindVersionSupported(test.output, localKindMinimumVersion); got != test.supported {
			t.Fatalf("version %q supported=%v, want %v", test.output, got, test.supported)
		}
	}
}
