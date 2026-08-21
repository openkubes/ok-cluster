package runner

import (
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestStandardObservabilityCapabilityCheckProfileFreezesExactContractIdentities(t *testing.T) {
	profile, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	document := profile.document()
	if document.Format != ObservabilityCapabilityCheckProfileFormat || document.Namespace != "ok-observability" ||
		document.Prometheus != (observabilityServiceBinding{Name: "ok-observability-prometheus", Port: 9090, Scheme: "http"}) ||
		document.Grafana != (observabilityServiceBinding{Name: "ok-observability-grafana", Port: 80, Scheme: "http"}) ||
		document.OpenSearch != (observabilityServiceBinding{Name: "opensearch-cluster-master", Port: 9200, Scheme: "https"}) ||
		document.Alertmanager != (observabilityServiceBinding{Name: "ok-observability-alertmanager", Port: 9093, Scheme: "http"}) ||
		document.CredentialsSecret != "ok-observability-credentials" || document.GrafanaUserKey != "grafana-admin-user" ||
		document.GrafanaPasswordKey != "grafana-admin-password" || document.OpenSearchPasswordKey != "opensearch-admin-password" ||
		document.DashboardConfigMap != "ok-observability-dashboard-platform-overview" || document.DashboardUID != "ok-obs-platform-overview" ||
		document.PrometheusDatasource != "Prometheus" || document.AlertName != "OKObservabilitySyntheticAlert" ||
		document.LogIndexPattern != "ok-observability-logs*" || !document.RequireReceiverDelivery {
		t.Fatalf("standard capability identities changed: %#v", document)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Digest() != digest.SHA256(raw) || profile.Digest() == "" {
		t.Fatalf("profile digest does not bind the canonical document: %s", profile.Digest())
	}
	second, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || second.Digest() != profile.Digest() {
		t.Fatal("standard capability profile is not reproducible")
	}
}

func TestStandardObservabilityCapabilityCheckProfileRejectsRedirectedNamespace(t *testing.T) {
	for _, namespace := range []string{"", "default", "ok-observability-other"} {
		if _, err := StandardObservabilityCapabilityCheckProfile(namespace); err == nil {
			t.Fatalf("redirected capability namespace %q was accepted", namespace)
		}
	}
}
