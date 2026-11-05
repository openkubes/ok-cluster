package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := os.WriteFile(kubeconfig, []byte(localKubeconfigFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	state := localClusterState{
		Format: localClusterStateFormat, Name: localClusterDefaultName,
		OwnerID: "0123456789abcdef0123456789abcdef", Kubeconfig: kubeconfig,
		KubeSystemUID: "kube-system-uid",
		Nodes:         []localNodeIdentity{{Name: "ok-local-control-plane", UID: "node-uid"}},
	}
	return root, state
}

func localOwnershipRunner(state localClusterState, ownerID string, present bool, deleted *bool) localCommandRunner {
	return func(_ context.Context, command string, arguments ...string) ([]byte, error) {
		switch command {
		case "kind":
			if len(arguments) > 0 && arguments[0] == "get" {
				if len(arguments) > 1 && arguments[1] == "kubeconfig" {
					return []byte(localKubeconfigFixture), nil
				}
				if deleted != nil && *deleted {
					return []byte(""), nil
				}
				if present {
					return []byte(state.Name + "\n"), nil
				}
				return []byte(""), nil
			}
			if len(arguments) > 0 && arguments[0] == "delete" {
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

func TestLocalUpIsNotEnabledBeforeConsoleIntegration(t *testing.T) {
	called := false
	root := t.TempDir()
	err := runLocalWithRuntime(context.Background(), []string{"up"}, io.Discard, io.Discard,
		localRuntime{stateRoot: filepath.Join(root, "state"), run: func(context.Context, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}})
	if err == nil || !strings.Contains(err.Error(), "no cluster was contacted or changed") || called {
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
	config, err := renderKindOwnershipConfig(localClusterDefaultName, first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "kind: Cluster") || !strings.Contains(string(config), localOwnerLabel+"="+first) {
		t.Fatalf("kind config must bind generated owner ID to a node label: %s", config)
	}
	if _, err := renderKindOwnershipConfig("bad_name", first); err == nil {
		t.Fatal("invalid cluster name accepted")
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
	runtime := localRuntime{stateRoot: root, input: strings.NewReader("ok\n"), interactive: true, run: localOwnershipRunner(state, state.OwnerID, true, &deleted)}
	var output strings.Builder
	if err := runLocalWithRuntime(context.Background(), []string{"down"}, &output, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("verified and confirmed local cluster was not deleted")
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
