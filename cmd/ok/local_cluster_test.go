package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	for _, logicalName := range []string{"ok-local-e2e-arash-20261105", "ok-local-e2e-arash-20261105-b"} {
		generated := localKindClusterName(logicalName, first)
		if len(generated) > localKindMaxNameLength || !validLocalKindClusterName(generated) || !strings.HasSuffix(generated, "-"+first) {
			t.Fatalf("logical name %q must produce a <=50-character Kind name with the complete owner ID: %q length=%d", logicalName, generated, len(generated))
		}
	}
	maximumName := strings.Repeat("a", localKindMaxNameLength-len(first)-1) + "-" + first
	if len(maximumName) != 50 || !validLocalKindClusterName(maximumName) {
		t.Fatalf("50-character Kind DNS label must be accepted: %q length=%d", maximumName, len(maximumName))
	}
	if validLocalKindClusterName(maximumName + "a") {
		t.Fatal("51-character Kind DNS label must be rejected")
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
	for _, logicalName := range []string{"ok-local-e2e-arash-20261105", "ok-local-e2e-arash-20261105-b"} {
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
			state := localClusterState{
				Format: localClusterStateFormat, Phase: "CREATING", Name: logicalName, OwnerID: ownerID,
				KindName: kindName, Provider: localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: "unix:///tmp/docker.sock", DaemonID: "daemon"},
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
