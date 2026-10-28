package targetadmission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestVerifyLiveTargetBindingUsesPinnedTLSAndExactNamespaceUID(t *testing.T) {
	caPEM, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	contentType := "application/json"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer read-only-token" {
			t.Errorf("unexpected target read: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", contentType)
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"target-kube-system-uid","resourceVersion":"12345","labels":{"kubernetes.io/metadata.name":"kube-system"},"creationTimestamp":"2026-10-22T12:00:00Z"}}`))
		case "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.35.5+rke2r1","major":"1","minor":"35","platform":"linux/amd64"}`))
		default:
			t.Errorf("unexpected target API path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	expected := TargetBinding{CAPIClusterUID: "capi-target-uid", KubeSystemNamespaceUID: "target-kube-system-uid"}
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, []byte("read-only-token"), expected); err != nil {
		t.Fatal(err)
	}
	contentType = "application/json-malformed"
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, []byte("read-only-token"), expected); err == nil {
		t.Fatal("non-JSON media type with a JSON prefix was accepted")
	}
	contentType = "application/json; charset=utf-8"
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, []byte("read-only-token"), expected); err != nil {
		t.Fatalf("valid JSON media type with charset was rejected: %v", err)
	}
	expected.KubeSystemNamespaceUID = "replacement-uid"
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, []byte("read-only-token"), expected); err == nil {
		t.Fatal("replacement target UID was accepted")
	}
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, []byte("wrong CA"), []byte("read-only-token"), expected); err == nil {
		t.Fatal("untrusted target API certificate was accepted")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := policyConfig()
	config.TargetIdentityDigest = digest.SHA256([]byte(expected.CAPIClusterUID))
	expected.KubeSystemNamespaceUID = "target-kube-system-uid"
	bundle, err := SignBundle(config, expected, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	webhookCA, servingCert, servingKey := testCertificates(t, InstallServiceDNS)
	opened, policyDigest, err := NewBoundTLSServer(context.Background(), bundle, publicKey, server.URL, caPEM, []byte("read-only-token"), servingCert, servingKey, webhookCA, InstallServiceDNS)
	if err != nil || opened == nil || policyDigest == "" {
		t.Fatalf("bound target server did not open: %s %v", policyDigest, err)
	}
	wrongTarget := expected
	wrongTarget.KubeSystemNamespaceUID = "replacement-uid"
	wrongBundle, err := SignBundle(config, wrongTarget, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if opened, _, err := NewBoundTLSServer(context.Background(), wrongBundle, publicKey, server.URL, caPEM, []byte("read-only-token"), servingCert, servingKey, webhookCA, InstallServiceDNS); err == nil || opened != nil {
		t.Fatal("server opened for a replacement workload cluster")
	}
}

func TestVerifyTargetActivationReadOnlyChecksBindingAndVersionExactlyOnce(t *testing.T) {
	apiCA, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := TargetBinding{CAPIClusterUID: "preflight-capi-uid", KubeSystemNamespaceUID: "preflight-namespace-uid"}
	config := policyConfig()
	config.TargetIdentityDigest = digest.SHA256([]byte(target.CAPIClusterUID))
	bundle, err := SignBundle(config, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	webhookCA, _, _ := testCertificates(t, "webhook-ca")
	image := "ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("d", 64)
	plan, err := BuildOfflineActivationPlan(bundle, publicKey, webhookCA, image)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer readonly" {
			t.Errorf("read-only token was not sent")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"preflight-namespace-uid","resourceVersion":"12345","labels":{"kubernetes.io/metadata.name":"kube-system"},"creationTimestamp":"2026-10-22T12:00:00Z"}}`))
		case "/version":
			_, _ = w.Write([]byte(`{"major":"1","minor":"35","gitVersion":"v1.35.5+rke2r1","gitCommit":"abc","platform":"linux/amd64"}`))
		default:
			t.Errorf("unexpected target API path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	now := time.Date(2026, time.October, 22, 12, 0, 0, 0, time.UTC)
	evidence, err := VerifyTargetActivationReadOnly(context.Background(), plan, bundle, publicKey, webhookCA, server.URL, apiCA, []byte("readonly"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "GET /api/v1/namespaces/kube-system" || paths[1] != "GET /version" {
		t.Fatalf("expected exactly the two read-only target checks, got %#v", paths)
	}
	if evidence.State != "READ_ONLY_PREFLIGHT_PASSED_NOT_AUTHORIZED" || evidence.PlanDigest != plan.PlanDigest || evidence.KubernetesGitVersion != "v1.35.5+rke2r1" ||
		!evidence.NamespaceIdentityVerified || !evidence.KubernetesVersionVerified || !evidence.APIAccessed || evidence.MutationAllowed || evidence.WebhookActive || !evidence.RecheckRequiredAtWrite || evidence.ObservedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected target preflight result: %#v", evidence)
	}
}

func TestVerifyTargetActivationReadOnlyFailsBeforeVersionOnIdentityMismatch(t *testing.T) {
	apiCA, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := TargetBinding{CAPIClusterUID: "capi-uid", KubeSystemNamespaceUID: "expected-namespace"}
	config := policyConfig()
	config.TargetIdentityDigest = digest.SHA256([]byte(target.CAPIClusterUID))
	bundle, err := SignBundle(config, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	webhookCA, _, _ := testCertificates(t, "webhook-ca")
	plan, err := BuildOfflineActivationPlan(bundle, publicKey, webhookCA, "ghcr.io/openkubes/ok-target-admission@sha256:"+strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"different-namespace"}}`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	if _, err := VerifyTargetActivationReadOnly(context.Background(), plan, bundle, publicKey, webhookCA, server.URL, apiCA, []byte("readonly"), time.Now()); err == nil {
		t.Fatal("replacement cluster was accepted by preflight")
	}
	if requests != 1 {
		t.Fatalf("preflight continued after identity mismatch: requests=%d", requests)
	}
}

func TestVerifyLiveTargetKubernetesVersionRejectsUnsupportedVersions(t *testing.T) {
	caPEM, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	gitVersion := "v1.29.9"
	contentType := "application/json"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/version" {
			t.Errorf("unexpected version request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = fmt.Fprintf(w, `{"gitVersion":%q,"major":"1","minor":"29"}`, gitVersion)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	if version, err := VerifyLiveTargetKubernetesVersion(context.Background(), server.URL, caPEM, []byte("readonly")); err == nil || version != "" {
		t.Fatalf("unsupported target version accepted: %q %v", version, err)
	}
	contentType = "application/jsonp"
	if version, err := VerifyLiveTargetKubernetesVersion(context.Background(), server.URL, caPEM, []byte("readonly")); err == nil || version != "" {
		t.Fatalf("non-JSON media type with a JSON prefix accepted: %q %v", version, err)
	}
	contentType = "application/json"
	gitVersion = "v1.30.0"
	if version, err := VerifyLiveTargetKubernetesVersion(context.Background(), server.URL, caPEM, []byte("readonly")); err != nil || version != gitVersion {
		t.Fatalf("minimum supported target version rejected: %q %v", version, err)
	}
}

func TestLiveTargetReadChecksDoNotFollowRedirects(t *testing.T) {
	caPEM, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Location", "/redirect-target")
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	expected := TargetBinding{CAPIClusterUID: "target-capi-uid", KubeSystemNamespaceUID: "target-namespace-uid"}
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, []byte("read-only"), expected); err == nil {
		t.Fatal("target identity redirect was accepted")
	}
	if requests != 1 {
		t.Fatalf("identity check followed redirect: got %d requests, want exactly 1", requests)
	}

	requests = 0
	if version, err := VerifyLiveTargetKubernetesVersion(context.Background(), server.URL, caPEM, []byte("read-only")); err == nil || version != "" {
		t.Fatalf("target version redirect was accepted: version=%q err=%v", version, err)
	}
	if requests != 1 {
		t.Fatalf("version check followed redirect: got %d requests, want exactly 1", requests)
	}
}

func TestLiveTargetReadChecksRejectOversizedJSONResponses(t *testing.T) {
	caPEM, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	namespace := []byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"expected-namespace"}}`)
	version := []byte(`{"gitVersion":"v1.35.5"}`)
	if len(namespace) > MaxTargetIdentityResponseBytes || len(version) > MaxTargetIdentityResponseBytes {
		t.Fatal("test fixtures unexpectedly exceed target response limit")
	}
	namespace = append(namespace, bytes.Repeat([]byte{' '}, MaxTargetIdentityResponseBytes+1-len(namespace))...)
	version = append(version, bytes.Repeat([]byte{' '}, MaxTargetIdentityResponseBytes+1-len(version))...)
	requests := map[string]int{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			_, _ = w.Write(namespace)
		case "/version":
			_, _ = w.Write(version)
		default:
			t.Errorf("unexpected target API path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	expected := TargetBinding{CAPIClusterUID: "target-capi-uid", KubeSystemNamespaceUID: "expected-namespace"}
	if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, []byte("read-only"), expected); err == nil {
		t.Fatal("oversized namespace response was accepted")
	}
	if requests["/api/v1/namespaces/kube-system"] != 1 {
		t.Fatalf("identity check made unexpected requests: %#v", requests)
	}
	if gitVersion, err := VerifyLiveTargetKubernetesVersion(context.Background(), server.URL, caPEM, []byte("read-only")); err == nil || gitVersion != "" {
		t.Fatalf("oversized version response was accepted: version=%q err=%v", gitVersion, err)
	}
	if requests["/version"] != 1 {
		t.Fatalf("version check made unexpected requests: %#v", requests)
	}
}

func TestLiveTargetReadInputsAreRejectedBeforeNetworkContact(t *testing.T) {
	caPEM, certPEM, keyPEM := testCertificates(t, "127.0.0.1")
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	expected := TargetBinding{CAPIClusterUID: "target-capi-uid", KubeSystemNamespaceUID: "target-namespace-uid"}

	invalidEndpoints := []string{
		"http" + strings.TrimPrefix(server.URL, "https"),
		server.URL + "/unexpected",
		server.URL + "?query=unexpected",
		server.URL + "#fragment",
		strings.Replace(server.URL, "https://", "https://user@", 1),
		strings.Repeat("x", 513),
	}
	for _, endpoint := range invalidEndpoints {
		if err := VerifyLiveTargetBinding(context.Background(), endpoint, caPEM, []byte("readonly"), expected); err == nil {
			t.Errorf("identity check accepted invalid endpoint %q", endpoint)
		}
		if version, err := VerifyLiveTargetKubernetesVersion(context.Background(), endpoint, caPEM, []byte("readonly")); err == nil || version != "" {
			t.Errorf("version check accepted invalid endpoint %q: version=%q err=%v", endpoint, version, err)
		}
	}
	invalidTokens := [][]byte{nil, {}, []byte("line\nbreak"), []byte("carriage\rreturn")}
	for _, token := range invalidTokens {
		if err := VerifyLiveTargetBinding(context.Background(), server.URL, caPEM, token, expected); err == nil {
			t.Errorf("identity check accepted invalid token %q", token)
		}
		if version, err := VerifyLiveTargetKubernetesVersion(context.Background(), server.URL, caPEM, token); err == nil || version != "" {
			t.Errorf("version check accepted invalid token %q: version=%q err=%v", token, version, err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("invalid endpoint or token caused %d target API requests", got)
	}
}
