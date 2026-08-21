package runner

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestHTTPObservabilityIndependentEvidenceCollectorUsesExactRequest(t *testing.T) {
	material := newSignedObservabilityEvidenceMaterial(t)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != observabilityIndependentEvidenceCollectionPath || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "Bearer independent-evidence-token" || request.Header.Get("Content-Type") != "application/json" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var document ObservabilityIndependentEvidenceCollectionRequest
		if err := json.Unmarshal(raw, &document); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		canonical, requestDigest, err := canonicalObservabilityIndependentEvidenceCollectionRequest(document)
		if err != nil || string(canonical) != string(raw) {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(ObservabilityIndependentEvidenceCollectionResponse{
			Format: ObservabilityIndependentEvidenceCollectionResponseFormat, RequestDigest: requestDigest,
			ReceiverDeliveryObserved: true, ReceiverIdentityDigest: digest.SHA256([]byte("receiver")),
			ClusterLocalServicesReady: true, ExternalClusterDependencies: 0, AutonomyProfileDigest: digest.SHA256([]byte("autonomy")),
		})
	}))
	defer server.Close()
	collector := openHTTPIndependentEvidenceCollector(t, server)
	if requests != 0 {
		t.Fatal("collector open contacted evidence authority")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation, err := collector.Collect(ctx, material.identity, material.alertName)
	if err != nil || !observation.ReceiverDeliveryObserved || !observation.ClusterLocalServicesReady || observation.ExternalClusterDependencies != 0 || requests != 1 {
		t.Fatalf("exact evidence collection differs: %#v requests=%d err=%v", observation, requests, err)
	}
}

func TestHTTPObservabilityIndependentEvidenceCollectorFailsClosed(t *testing.T) {
	material := newSignedObservabilityEvidenceMaterial(t)

	t.Run("unbounded context", func(t *testing.T) {
		requests := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
		defer server.Close()
		collector := openHTTPIndependentEvidenceCollector(t, server)
		if _, err := collector.Collect(context.Background(), material.identity, material.alertName); err == nil || requests != 0 {
			t.Fatal("unbounded collection reached evidence authority")
		}
	})

	t.Run("foreign response", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(ObservabilityIndependentEvidenceCollectionResponse{
				Format: ObservabilityIndependentEvidenceCollectionResponseFormat, RequestDigest: digest.SHA256([]byte("foreign")),
				ReceiverIdentityDigest: digest.SHA256([]byte("receiver")), AutonomyProfileDigest: digest.SHA256([]byte("autonomy")),
			})
		}))
		defer server.Close()
		collector := openHTTPIndependentEvidenceCollector(t, server)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := collector.Collect(ctx, material.identity, material.alertName); err == nil {
			t.Fatal("foreign request correlation was accepted")
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			fmt.Fprint(response, strings.Repeat("x", maximumObservabilityIndependentEvidenceCollectionBytes+1))
		}))
		defer server.Close()
		collector := openHTTPIndependentEvidenceCollector(t, server)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := collector.Collect(ctx, material.identity, material.alertName); err == nil {
			t.Fatal("oversized evidence response was accepted")
		}
	})

	t.Run("redirect", func(t *testing.T) {
		requests := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			requests++
			http.Redirect(response, request, "/foreign", http.StatusFound)
		}))
		defer server.Close()
		collector := openHTTPIndependentEvidenceCollector(t, server)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := collector.Collect(ctx, material.identity, material.alertName); err == nil || requests != 1 {
			t.Fatal("evidence authority redirect was followed")
		}
	})
}

func openHTTPIndependentEvidenceCollector(t *testing.T, server *httptest.Server) *HTTPObservabilityIndependentEvidenceCollector {
	t.Helper()
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(tokenPath, []byte("independent-evidence-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	collector, err := OpenHTTPObservabilityIndependentEvidenceCollector(HTTPObservabilityIndependentEvidenceCollectorConfig{
		Endpoint: server.URL, TokenFile: tokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector
}
