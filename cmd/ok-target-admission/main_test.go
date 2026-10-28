package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/targetadmission"
)

func TestReadInputRequiresBoundedRegularFilesAndPrivatePermissions(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "private")
	if err := os.WriteFile(privatePath, []byte("private-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := readInput(privatePath, 64, true)
	if err != nil || string(contents) != "private-value" {
		t.Fatalf("private file rejected: %v", err)
	}

	publicPath := filepath.Join(root, "public")
	if err := os.WriteFile(publicPath, []byte("public-value"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readInput(publicPath, 64, true); err == nil {
		t.Fatal("group/world-readable private material accepted")
	}
	if _, err := readInput(publicPath, 64, false); err != nil {
		t.Fatalf("public trust file rejected: %v", err)
	}
	if _, err := readInput(publicPath, 2, false); err == nil {
		t.Fatal("oversized input accepted")
	}

	directory := filepath.Join(root, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readInput(directory, 64, false); err == nil {
		t.Fatal("directory accepted as an input file")
	}

	linkPath := filepath.Join(root, "private-link")
	if err := os.Symlink(publicPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readInput(linkPath, 64, true); err == nil {
		t.Fatal("symlink to broadly readable private material accepted")
	}
}

func TestTargetAdmissionServerRequiresExplicitInputs(t *testing.T) {
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("help should exit successfully: %v", err)
	}
	if err := run(nil); err == nil {
		t.Fatal("server defaults authorized without explicit input paths")
	}
	if err := run([]string{"unexpected-argument"}); err == nil {
		t.Fatal("positional server input accepted")
	}
}

func TestRenderInstallModeDoesNotRequireOrAcceptServerInputs(t *testing.T) {
	image := "ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("a", 64)
	if err := run([]string{"--render-install-set", "--image-ref", image}); err != nil {
		t.Fatalf("offline install rendering failed: %v", err)
	}
	if err := run([]string{"--render-install-set", "--image-ref", image, "unexpected"}); err == nil {
		t.Fatal("positional argument accepted in render mode")
	}
	if err := run([]string{"--render-install-set", "--image-ref", image, "--target-api-endpoint", "https://example.invalid"}); err == nil {
		t.Fatal("render mode accepted server/API inputs instead of remaining offline")
	}
	if err := run([]string{"--render-install-set", "--image-ref", image, "--activation-plan-file=ignored.json"}); err == nil {
		t.Fatal("render mode silently accepted a preflight-only activation-plan input")
	}
}

func TestOfflineActivationModeRejectsLiveInputsAndMissingBindings(t *testing.T) {
	if err := run([]string{"--render-activation-plan"}); err == nil {
		t.Fatal("incomplete activation-plan inputs accepted")
	}
	if err := run([]string{
		"--render-activation-plan", "--bundle-file=bundle", "--policy-public-key-file=pin",
		"--webhook-ca-file=ca", "--image-ref=ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("a", 64),
		"--target-api-endpoint=https://example.invalid",
	}); err == nil {
		t.Fatal("offline activation-plan mode accepted target API input")
	}
}

func TestTargetPreflightRequiresReadOnlyInputsAndRejectsServerMode(t *testing.T) {
	if err := run([]string{"--preflight-target"}); err == nil {
		t.Fatal("target preflight accepted missing explicit inputs")
	}
	args := []string{
		"--preflight-target", "--activation-plan-file=plan.json", "--bundle-file=bundle.json",
		"--policy-public-key-file=public.key", "--webhook-ca-file=webhook-ca.pem",
		"--target-api-endpoint=https://127.0.0.1:6443", "--target-api-ca-file=api-ca.pem",
		"--target-read-token-file=token",
	}
	if err := run(append(append([]string(nil), args...), "--listen=127.0.0.1:8443")); err == nil {
		t.Fatal("target preflight accepted a server listen option")
	}
	if err := run(append(append([]string(nil), args...), "--tls-private-key-file=server.key")); err == nil {
		t.Fatal("target preflight accepted server identity inputs")
	}
}

func TestTargetPreflightCLIUsesExactlyTwoReadOnlyGETsAndEmitsNoGoEvidence(t *testing.T) {
	apiCAPEM, apiCertificate := targetPreflightTestCertificate(t)
	certificate, err := tls.X509KeyPair(apiCAPEM, apiCertificate)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-read-only-token" {
			t.Errorf("preflight made a non-GET or uncredentialed request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"preflight-test-namespace-uid"}}`)
		case "/version":
			_, _ = io.WriteString(w, `{"gitVersion":"v1.35.0","major":"1","minor":"35"}`)
		default:
			t.Errorf("preflight requested unexpected target path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := targetadmission.TargetBinding{CAPIClusterUID: "preflight-test-cluster-uid", KubeSystemNamespaceUID: "preflight-test-namespace-uid"}
	config := targetPreflightTestPolicy(t, target.CAPIClusterUID)
	bundle, err := targetadmission.SignBundle(config, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	image := "ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("d", 64)
	plan, err := targetadmission.BuildOfflineActivationPlan(bundle, publicKey, apiCAPEM, image)
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	paths := map[string]string{
		"plan": filepath.Join(root, "plan.json"), "bundle": filepath.Join(root, "bundle.json"),
		"publicKey": filepath.Join(root, "policy-public.key"), "webhookCA": filepath.Join(root, "webhook-ca.pem"),
		"apiCA": filepath.Join(root, "api-ca.pem"), "token": filepath.Join(root, "token"),
	}
	for name, data := range map[string][]byte{
		"plan": planBytes, "bundle": bundle, "publicKey": publicKey, "webhookCA": apiCAPEM,
		"apiCA": apiCAPEM, "token": []byte("test-read-only-token"),
	} {
		mode := os.FileMode(0o644)
		if name == "bundle" || name == "token" {
			mode = 0o600
		}
		if err := os.WriteFile(paths[name], data, mode); err != nil {
			t.Fatal(err)
		}
	}

	previousStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	callErr := run([]string{
		"--preflight-target", "--activation-plan-file=" + paths["plan"], "--bundle-file=" + paths["bundle"],
		"--policy-public-key-file=" + paths["publicKey"], "--webhook-ca-file=" + paths["webhookCA"],
		"--target-api-endpoint=" + server.URL, "--target-api-ca-file=" + paths["apiCA"],
		"--target-read-token-file=" + paths["token"],
	})
	_ = writer.Close()
	os.Stdout = previousStdout
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if callErr != nil || readErr != nil {
		t.Fatalf("read-only CLI preflight failed: run=%v read=%v", callErr, readErr)
	}
	if requests != 2 {
		t.Fatalf("preflight made %d target requests, want exactly 2", requests)
	}
	var evidence targetadmission.TargetActivationEvidence
	if err := json.Unmarshal(output, &evidence); err != nil {
		t.Fatalf("preflight did not emit JSON evidence: %q: %v", output, err)
	}
	if evidence.State != "READ_ONLY_PREFLIGHT_PASSED_NOT_AUTHORIZED" || !evidence.APIAccessed || evidence.MutationAllowed || evidence.WebhookActive || !evidence.RecheckRequiredAtWrite {
		t.Fatalf("preflight evidence overstates authority or success: %#v", evidence)
	}
}

func targetPreflightTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "preflight-test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{targetadmission.InstallServiceDNS},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certificatePEM, keyPEM
}

func targetPreflightTestPolicy(t *testing.T, clusterUID string) targetadmission.Config {
	t.Helper()
	kinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole"}
	apiVersions := []string{"v1", "v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1"}
	config := targetadmission.Config{
		WriterUsername: "system:serviceaccount:ok-system:target-writer", ArtifactDigest: digest.SHA256([]byte("artifact")),
		IntentRevision: digest.SHA256([]byte("intent")), PlatformRevision: digest.SHA256([]byte("platform")),
		ExecutionFixture: digest.SHA256([]byte("fixture")), TargetIdentityDigest: digest.SHA256([]byte(clusterUID)),
		APIServerSourceCIDRs: []string{"127.0.0.1/32"}, Objects: make([]targetadmission.Object, len(kinds)),
	}
	for index, kind := range kinds {
		identity := projection.ResourceIdentity{APIVersion: apiVersions[index], Kind: kind, Name: "target-" + string(rune('a'+index))}
		if kind == "ServiceAccount" || kind == "Role" || kind == "RoleBinding" {
			identity.Namespace = "ok-observability"
		}
		metadata := map[string]any{"name": identity.Name}
		if identity.Namespace != "" {
			metadata["namespace"] = identity.Namespace
		}
		raw, err := json.Marshal(map[string]any{"apiVersion": identity.APIVersion, "kind": identity.Kind, "metadata": metadata})
		if err != nil {
			t.Fatal(err)
		}
		config.Objects[index] = targetadmission.Object{Identity: identity, Digest: digest.SHA256(raw), Raw: raw}
	}
	return config
}

func TestOfflinePlanVerificationRejectsLiveInputsAndMissingSources(t *testing.T) {
	if err := run([]string{"--verify-activation-plan-file=plan.json"}); err == nil {
		t.Fatal("plan verification accepted missing signed-source inputs")
	}
	if err := run([]string{
		"--verify-activation-plan-file=plan.json", "--bundle-file=bundle", "--policy-public-key-file=pin",
		"--webhook-ca-file=ca", "--target-api-endpoint=https://example.invalid",
	}); err == nil {
		t.Fatal("offline plan verification accepted target API input")
	}
}
