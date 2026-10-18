package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

func managedDestroyFixture(t *testing.T) (string, string, []string) {
	t.Helper()
	root, args := destroyFixture(t)
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(base, "ok", "runs", "demo-cluster")
	directory := filepath.Join(managed, "preparation", "demo-cluster")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	var targets clusterIntentTargets
	for filename, target := range map[string]*kubeconfigtarget.Target{"management.yaml": &targets.Management, "provider.yaml": &targets.Infrastructure} {
		path := filepath.Join(root, filename)
		raw := "apiVersion: v1\nkind: Config\ncurrent-context: selected\ncontexts:\n- name: selected\n  context: {cluster: plane, user: operator}\nclusters:\n- name: plane\n  cluster:\n    server: https://" + filename + ".example\n    certificate-authority-data: " + ca + "\nusers:\n- name: operator\n  user: {token: expired-create-token, exec: {command: MUST_NOT_RUN}}\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		*target, err = kubeconfigtarget.ReadCurrent(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := clusterIntentBindingReceipt{Format: "ok-cli-cluster-static-binding/v1", State: "CONTRACT_PROJECTION_BOUND_NO_GO", Identity: contract.Identity{Name: "demo-cluster", Namespace: "demo-cluster"}, IntentRevision: testSHA("1"), NormalizedIntentDigest: testSHA("2"), Targets: &targets}
	raw, _ := json.Marshal(binding)
	fixture, _ := json.Marshal(clusterIntentExecutionFixture{Format: "ok-cli-local-execution-fixture/v2", AuthorizationState: "NO-GO", ContractIdentity: binding.Identity, IntentRevision: binding.IntentRevision, BindingReceiptDigest: digest.SHA256(raw)})
	for name, data := range map[string][]byte{"binding-receipt.json": raw, "execution-fixture.json": fixture} {
		if err := os.WriteFile(filepath.Join(managed, "preparation", name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Intentionally no runtime inputs, handoff or full manifest. Terminal create
	// state is immutable and must not prevent a separately confirmed teardown.
	if err := os.WriteFile(filepath.Join(managed, "executor-terminal"), []byte("STOP"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, managed, args
}

func TestManagedDestroyDiscoversRenderWithoutRuntimeOrCreateReplay(t *testing.T) {
	for _, answer := range []string{"ok\n", "no\n"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			_, managed, args := managedDestroyFixture(t)
			calls := 0
			var out bytes.Buffer
			err := runDestroyClusterWithRuntime(context.Background(), args, &out, io.Discard, destroyClusterRuntime{input: strings.NewReader(answer), interactive: true, execute: func(_ context.Context, _ string, argv []string, _, _ io.Writer) error {
				calls++
				if argv[5] != filepath.Join(managed, "preparation", "demo-cluster") {
					t.Fatalf("wrong directory: %v", argv)
				}
				return nil
			}})
			if err != nil || (calls == 1) != (answer == "ok\n") {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
			raw, _ := os.ReadFile(filepath.Join(managed, "executor-terminal"))
			if string(raw) != "STOP" {
				t.Fatal("terminal evidence changed")
			}
		})
	}
}

func TestManagedDestroyRejectsAmbiguousUnsafeOrChangedState(t *testing.T) {
	for _, scenario := range []string{"legacy-conflict", "missing-binding", "wrong-name", "fixture-drift", "public-root", "symlink-render", "target-change", "context-change", "unknown-field"} {
		t.Run(scenario, func(t *testing.T) {
			root, managed, args := managedDestroyFixture(t)
			binding := filepath.Join(managed, "preparation", "binding-receipt.json")
			var err error
			switch scenario {
			case "legacy-conflict":
				err = os.Mkdir(filepath.Join(root, "demo-cluster"), 0o700)
			case "missing-binding":
				err = os.Remove(binding)
			case "wrong-name", "unknown-field":
				raw, _ := os.ReadFile(binding)
				if scenario == "wrong-name" {
					raw = bytes.ReplaceAll(raw, []byte("demo-cluster"), []byte("other-cluster"))
				} else {
					raw = append([]byte(`{"unknown":true,`), raw[1:]...)
				}
				err = os.WriteFile(binding, raw, 0o600)
			case "fixture-drift":
				err = os.WriteFile(filepath.Join(managed, "preparation", "execution-fixture.json"), []byte(`{}`), 0o600)
			case "public-root":
				err = os.Chmod(managed, 0o755)
			case "symlink-render":
				dir := filepath.Join(managed, "preparation", "demo-cluster")
				if err = os.Rename(dir, dir+".retained"); err == nil {
					err = os.Symlink(dir+".retained", dir)
				}
			case "target-change", "context-change":
				path := filepath.Join(root, "management.yaml")
				raw, _ := os.ReadFile(path)
				if scenario == "target-change" {
					raw = bytes.ReplaceAll(raw, []byte("management.yaml.example"), []byte("another.example"))
				} else {
					raw = bytes.Replace(raw, []byte("current-context: selected"), []byte("current-context: missing"), 1)
				}
				err = os.WriteFile(path, raw, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = runDestroyClusterWithRuntime(context.Background(), args, &out, io.Discard, destroyClusterRuntime{input: strings.NewReader("ok\n"), interactive: true, execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
				t.Fatal("unsafe discovery invoked lifecycle")
				return nil
			}})
			if err == nil || out.Len() != 0 {
				t.Fatalf("err=%v prompt=%s", err, &out)
			}
		})
	}
}

type destroyMutationReader struct{ mutate func() }

func (r destroyMutationReader) Read(p []byte) (int, error) { r.mutate(); return copy(p, "ok\n"), nil }

func TestManagedDestroyRechecksAfterConfirmation(t *testing.T) {
	_, managed, args := managedDestroyFixture(t)
	err := runDestroyClusterWithRuntime(context.Background(), args, io.Discard, io.Discard, destroyClusterRuntime{input: destroyMutationReader{func() { os.Remove(filepath.Join(managed, "preparation", "binding-receipt.json")) }}, interactive: true, execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
		t.Fatal("changed selection invoked lifecycle")
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "changed during confirmation") {
		t.Fatal(err)
	}
}

func TestDestroyExplicitDirectoryRetainsOverride(t *testing.T) {
	root, managed, args := managedDestroyFixture(t)
	if err := os.Remove(filepath.Join(managed, "preparation", "binding-receipt.json")); err != nil {
		t.Fatal(err)
	}
	args = append(args, "--cluster-dir", filepath.Join(root, "demo-cluster"))
	err := runDestroyClusterWithRuntime(context.Background(), args, io.Discard, io.Discard, destroyClusterRuntime{input: strings.NewReader("no\n"), interactive: true})
	if err != nil {
		t.Fatal(err)
	}
}
