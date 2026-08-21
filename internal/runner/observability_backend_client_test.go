package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type observabilityBackendRecordedRequest struct {
	method        string
	requestURI    string
	authorization string
	contentType   string
}

func TestKubernetesObservabilityBackendClientUsesOnlyBoundExactRequests(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	var requests []observabilityBackendRecordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, observabilityBackendRecordedRequest{method: request.Method, requestURI: request.URL.RequestURI(), authorization: request.Header.Get("Authorization"), contentType: request.Header.Get("Content-Type")})
		if request.URL.Path == "/api/v1/namespaces/ok-observability/secrets/ok-observability-credentials" {
			writeObservabilityBackendJSON(writer, http.StatusOK, map[string]any{
				"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "ok-observability-credentials", "namespace": "ok-observability"},
				"data": map[string]any{
					"grafana-admin-user":        base64.StdEncoding.EncodeToString([]byte("admin")),
					"grafana-admin-password":    base64.StdEncoding.EncodeToString([]byte("grafana-password")),
					"opensearch-admin-password": base64.StdEncoding.EncodeToString([]byte("opensearch-password")),
				},
			})
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/api/v1/namespaces/ok-observability/services/http:"+fixture.MetricsWorkload+":9091/proxy/metrics/job/"+fixture.MetricsWorkload {
			writer.WriteHeader(http.StatusOK)
			return
		}
		writeObservabilityBackendJSON(writer, http.StatusOK, map[string]any{"status": "ok"})
	}))
	defer server.Close()
	client, err := newKubernetesObservabilityBackendClient(KubernetesObservabilityBackendClientConfig{
		Endpoint: server.URL, ClientCertificate: true, AuthorityIdentity: run.TargetClusterUID, Client: server.Client(), Profile: profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.credentials(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if !validObservabilityCredential(credentials.grafanaUser) || !validObservabilityCredential(credentials.grafanaPassword) || !validObservabilityCredential(credentials.opensearchPassword) {
		t.Fatal("exact credential Secret did not produce the three private values")
	}
	operations := []func() error{
		func() error { _, err := client.dashboard(context.Background(), run); return err },
		func() error { _, err := client.pushMetrics(context.Background(), run, fixture); return err },
		func() error { _, err := client.prometheusQuery(context.Background(), run, fixture); return err },
		func() error { _, err := client.grafanaDatasources(context.Background(), run, credentials); return err },
		func() error {
			_, err := client.grafanaQuery(context.Background(), run, fixture, "prometheus-uid", credentials)
			return err
		},
		func() error { _, err := client.searchLogs(context.Background(), run, fixture, credentials); return err },
		func() error { _, err := client.alerts(context.Background(), run); return err },
	}
	for index, operation := range operations {
		if err := operation(); err != nil {
			t.Fatalf("bounded backend operation %d failed: %v", index, err)
		}
	}
	expected := []observabilityBackendRecordedRequest{
		{method: "GET", requestURI: "/api/v1/namespaces/ok-observability/secrets/ok-observability-credentials"},
		{method: "GET", requestURI: "/api/v1/namespaces/ok-observability/configmaps/ok-observability-dashboard-platform-overview"},
		{method: "POST", requestURI: "/api/v1/namespaces/ok-observability/services/http:" + fixture.MetricsWorkload + ":9091/proxy/metrics/job/" + fixture.MetricsWorkload, contentType: "text/plain; version=0.0.4"},
		{method: "GET", requestURI: "/api/v1/namespaces/ok-observability/services/http:ok-observability-prometheus:9090/proxy/api/v1/query?query=" + fixture.MetricName},
		{method: "GET", requestURI: "/api/v1/namespaces/ok-observability/services/http:ok-observability-grafana:80/proxy/api/datasources", authorization: "Basic YWRtaW46Z3JhZmFuYS1wYXNzd29yZA=="},
		{method: "GET", requestURI: "/api/v1/namespaces/ok-observability/services/http:ok-observability-grafana:80/proxy/api/datasources/proxy/uid/prometheus-uid/api/v1/query?query=" + fixture.MetricName, authorization: "Basic YWRtaW46Z3JhZmFuYS1wYXNzd29yZA=="},
		{method: "POST", requestURI: "/api/v1/namespaces/ok-observability/services/https:opensearch-cluster-master:9200/proxy/ok-observability-logs%2A/_search", authorization: "Basic YWRtaW46b3BlbnNlYXJjaC1wYXNzd29yZA==", contentType: "application/json"},
		{method: "GET", requestURI: "/api/v1/namespaces/ok-observability/services/http:ok-observability-alertmanager:9093/proxy/api/v2/alerts"},
	}
	if !reflect.DeepEqual(requests, expected) {
		t.Fatalf("backend request surface changed:\nobserved=%#v\nexpected=%#v", requests, expected)
	}
}

func TestKubernetesObservabilityBackendClientRejectsUnsafeBindings(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	base := KubernetesObservabilityBackendClientConfig{Endpoint: "http://127.0.0.1:12345", ClientCertificate: true, AuthorityIdentity: run.TargetClusterUID, Client: &http.Client{}, Profile: profile}
	for name, mutate := range map[string]func(*KubernetesObservabilityBackendClientConfig){
		"no mTLS identity":  func(config *KubernetesObservabilityBackendClientConfig) { config.ClientCertificate = false },
		"foreign authority": func(config *KubernetesObservabilityBackendClientConfig) { config.AuthorityIdentity = "" },
		"unbound profile": func(config *KubernetesObservabilityBackendClientConfig) {
			config.Profile = ObservabilityCapabilityCheckProfile{}
		},
		"redirectable endpoint": func(config *KubernetesObservabilityBackendClientConfig) {
			config.Endpoint = "https://user@example.test/path"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := newKubernetesObservabilityBackendClient(config); err == nil {
				t.Fatal("unsafe observability backend binding was accepted")
			}
		})
	}
}

func TestKubernetesObservabilityBackendClientRejectsCredentialAndFixtureDrift(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeObservabilityBackendJSON(writer, http.StatusOK, map[string]any{
			"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "ok-observability-credentials", "namespace": "ok-observability"},
			"data": map[string]any{"grafana-admin-user": base64.StdEncoding.EncodeToString([]byte("admin"))},
		})
	}))
	defer server.Close()
	client, _ := newKubernetesObservabilityBackendClient(KubernetesObservabilityBackendClientConfig{Endpoint: server.URL, ClientCertificate: true, AuthorityIdentity: run.TargetClusterUID, Client: server.Client(), Profile: profile})
	if _, err := client.credentials(context.Background(), run); err == nil {
		t.Fatal("incomplete credential Secret was accepted")
	}
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	fixture.LogMarker += "_tampered"
	if _, err := client.searchLogs(context.Background(), run, fixture, observabilityBackendCredentials{opensearchPassword: "password"}); err == nil {
		t.Fatal("tampered synthetic fixture reached the service proxy")
	}
}

func writeObservabilityBackendJSON(writer http.ResponseWriter, status int, value any) {
	raw, _ := json.Marshal(value)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(raw)
}
