package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestEvidenceObservabilityServeOpensBoundedRuntime(t *testing.T) {
	workload := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("opening collector contacted workload Kubernetes")
	}))
	defer workload.Close()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: workload.Certificate().Raw})
	paths := map[string]string{}
	for name, value := range map[string][]byte{
		"webhook-token":  []byte("ok147-webhook-token-0123456789abcdef"),
		"query-token":    []byte("ok147-query-token-0123456789abcdefgh"),
		"workload-token": []byte("ok147-workload-token-0123456789abcdef"),
		"workload-ca":    ca,
		"tls-cert":       []byte("collector-certificate-placeholder"),
		"tls-key":        []byte("collector-key-placeholder"),
	} {
		mode := os.FileMode(0o600)
		if name == "workload-ca" || name == "tls-cert" {
			mode = 0o644
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, value, mode); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	original := serveBoundedObservabilityCollector
	defer func() { serveBoundedObservabilityCollector = original }()
	called := false
	serveBoundedObservabilityCollector = func(_ context.Context, address string, handler http.Handler, certRaw, keyRaw []byte) error {
		called = address == "127.0.0.1:9443" && handler != nil && string(certRaw) == "collector-certificate-placeholder" && string(keyRaw) == "collector-key-placeholder"
		return nil
	}
	stdout := &bytes.Buffer{}
	err := run([]string{
		"evidence", "observability", "serve",
		"--webhook-token-file", paths["webhook-token"], "--query-token-file", paths["query-token"], "--state-directory", state,
		"--workload-endpoint", workload.URL, "--workload-token-file", paths["workload-token"], "--workload-ca-file", paths["workload-ca"],
		"--workload-ca-digest", digest.SHA256(ca), "--target-cluster-uid", "cluster-uid-disposable-ok147",
		"--maximum-record-age", "10m", "--listen", "127.0.0.1:9443", "--tls-cert", paths["tls-cert"], "--tls-key", paths["tls-key"],
	}, stdout, &bytes.Buffer{})
	if err != nil || !called {
		t.Fatalf("collector serve failed: %v called=%v", err, called)
	}
	var receipt runner.ObservabilityIndependentEvidenceCollectorServerReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "VERIFIED" || !receipt.SeparateAuthorities || receipt.MutationAllowed {
		t.Fatalf("collector receipt differs: %#v err=%v", receipt, err)
	}
}

func TestEvidenceObservabilityServeRejectsIncompleteActivation(t *testing.T) {
	if err := run([]string{"evidence", "observability", "serve"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete collector activation was accepted")
	}
}

type fakeObservabilityCollectorActivation struct {
	served bool
}

func (activation *fakeObservabilityCollectorActivation) Receipt() (runner.ObservabilityIndependentEvidenceCollectorServerReceipt, error) {
	return runner.ObservabilityIndependentEvidenceCollectorServerReceipt{
		Format: runner.ObservabilityIndependentEvidenceCollectorServerReceiptFormat,
		State:  "VERIFIED", SeparateAuthorities: true, MutationAllowed: false,
	}, nil
}

func (activation *fakeObservabilityCollectorActivation) Serve(ctx context.Context, serve runner.ObservabilityCollectorServeFunc) error {
	activation.served = true
	return serve(ctx, "127.0.0.1:8443", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), []byte("cert"), []byte("key"))
}

func TestEvidenceObservabilityServeUsesPackagedActivation(t *testing.T) {
	originalOpen := openObservabilityCollectorActivation
	originalServe := serveBoundedObservabilityCollector
	defer func() {
		openObservabilityCollectorActivation = originalOpen
		serveBoundedObservabilityCollector = originalServe
	}()
	fake := &fakeObservabilityCollectorActivation{}
	openObservabilityCollectorActivation = func(path string) (observabilityCollectorActivationRunner, error) {
		if path != "/var/run/openkubes/collector/activation.json" {
			t.Fatalf("unexpected activation path: %q", path)
		}
		return fake, nil
	}
	serveBoundedObservabilityCollector = func(_ context.Context, address string, handler http.Handler, certRaw, keyRaw []byte) error {
		if address != "127.0.0.1:8443" || handler == nil || string(certRaw) != "cert" || string(keyRaw) != "key" {
			t.Fatal("packaged activation lost serving identity")
		}
		return nil
	}
	stdout := &bytes.Buffer{}
	if err := run([]string{"evidence", "observability", "serve", "--activation", "/var/run/openkubes/collector/activation.json"}, stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !fake.served || !bytes.Contains(stdout.Bytes(), []byte(`"state": "VERIFIED"`)) {
		t.Fatal("packaged collector activation was not served")
	}
	if err := run([]string{
		"evidence", "observability", "serve", "--activation", "/var/run/openkubes/collector/activation.json",
		"--listen", "127.0.0.1:8443",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("packaged activation accepted an individual serving flag")
	}
}
