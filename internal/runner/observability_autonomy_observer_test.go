package runner

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestKubernetesObservabilityAutonomyObserverUsesEightBoundedReads(t *testing.T) {
	var requests []string
	observer, request, closeServer := testAutonomyObserver(t, false, func(httpRequest *http.Request) {
		requests = append(requests, httpRequest.URL.RequestURI())
		if httpRequest.Method != http.MethodGet || httpRequest.Header.Get("Authorization") != "Bearer ok147-autonomy-token-0123456789abcdef" || httpRequest.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected authority or method")
		}
	})
	defer closeServer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := observer.Observe(ctx, request)
	if err != nil || !observation.ClusterLocalServicesReady || observation.ExternalClusterDependencies != 0 || !platformInputDigestPattern.MatchString(observation.AutonomyProfileDigest) {
		t.Fatalf("autonomy observation differs: %#v err=%v", observation, err)
	}
	expected := []string{}
	for _, name := range []string{"ok-observability-prometheus", "ok-observability-grafana", "opensearch-cluster-master", "ok-observability-alertmanager"} {
		expected = append(expected,
			"/api/v1/namespaces/ok-observability/services/"+name,
			"/apis/discovery.k8s.io/v1/namespaces/ok-observability/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D"+name,
		)
	}
	if !reflect.DeepEqual(requests, expected) {
		t.Fatalf("autonomy request surface changed:\nobserved=%#v\nexpected=%#v", requests, expected)
	}
}

func TestKubernetesObservabilityAutonomyObserverReportsForeignEndpoint(t *testing.T) {
	observer, request, closeServer := testAutonomyObserver(t, true, nil)
	defer closeServer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := observer.Observe(ctx, request)
	if err != nil || observation.ClusterLocalServicesReady || observation.ExternalClusterDependencies != 4 {
		t.Fatalf("foreign endpoint was not reported fail-closed: %#v err=%v", observation, err)
	}
}

func TestKubernetesObservabilityAutonomyObserverRejectsUnboundedOrForeignClaim(t *testing.T) {
	requests := 0
	observer, request, closeServer := testAutonomyObserver(t, false, func(*http.Request) { requests++ })
	defer closeServer()
	if _, err := observer.Observe(context.Background(), request); err == nil || requests != 0 {
		t.Fatal("unbounded autonomy observation reached Kubernetes")
	}
	foreign := request
	foreign.TargetClusterUID = "foreign-cluster"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := observer.Observe(ctx, foreign); err == nil || requests != 0 {
		t.Fatal("foreign autonomy claim reached Kubernetes")
	}
}

func testAutonomyObserver(t *testing.T, foreignEndpoints bool, observe func(*http.Request)) (*KubernetesObservabilityAutonomyObserver, ObservabilityIndependentEvidenceCollectionRequest, func()) {
	t.Helper()
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	ports := map[string]int{
		profile.prometheus.Name: profile.prometheus.Port, profile.grafana.Name: profile.grafana.Port,
		profile.opensearch.Name: profile.opensearch.Port, profile.alertmanager.Name: profile.alertmanager.Port,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if observe != nil {
			observe(request)
		}
		response.Header().Set("Content-Type", "application/json")
		if strings.Contains(request.URL.Path, "/services/") {
			name := filepath.Base(request.URL.Path)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": name, "namespace": "ok-observability"},
				"spec": map[string]any{"type": "ClusterIP", "clusterIP": "10.96.0.10", "ports": []any{map[string]any{"port": ports[name], "protocol": "TCP"}}},
			})
			return
		}
		selector := request.URL.Query().Get("labelSelector")
		name := strings.TrimPrefix(selector, "kubernetes.io/service-name=")
		targetNamespace := "ok-observability"
		if foreignEndpoints {
			targetNamespace = "foreign-cluster"
		}
		ready, port := true, 9090
		_ = json.NewEncoder(response).Encode(map[string]any{
			"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList",
			"items": []any{map[string]any{
				"addressType": "IPv4", "metadata": map[string]any{"namespace": "ok-observability", "labels": map[string]string{"kubernetes.io/service-name": name}},
				"ports": []any{map[string]any{"port": port, "protocol": "TCP"}},
				"endpoints": []any{map[string]any{
					"addresses": []string{"10.244.0.10"}, "conditions": map[string]any{"ready": ready, "terminating": false},
					"targetRef": map[string]any{"kind": "Pod", "namespace": targetNamespace, "name": name + "-0"},
				}},
			}},
		})
	}))
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	token := []byte("ok147-autonomy-token-0123456789abcdef")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(tokenPath, token, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	observer, err := OpenKubernetesObservabilityAutonomyObserver(KubernetesObservabilityAutonomyObserverConfig{
		Endpoint: server.URL, TokenFile: tokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
		TargetClusterUID: run.TargetClusterUID, Profile: profile,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	request := ObservabilityIndependentEvidenceCollectionRequest{
		Format: ObservabilityIndependentEvidenceCollectionRequestFormat, RunID: run.RunID, TargetClusterUID: run.TargetClusterUID,
		FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest(), AlertName: profile.alertName,
	}
	return observer, request, server.Close
}
