package runner

import (
	"strings"
	"testing"
)

func TestObservabilityResponseParsersAcceptExactPositiveEvidence(t *testing.T) {
	metric := "ok_observability_contract_metric_test"
	if present, err := parsePrometheusMetricPresent([]byte(`{"status":"success","data":{"result":[{"metric":{"__name__":"`+metric+`"},"value":[1,"1"]}]}}`), metric); err != nil || !present {
		t.Fatalf("exact Prometheus evidence failed: present=%v err=%v", present, err)
	}
	uid, present, err := parseGrafanaPrometheusDatasource([]byte(`[{"name":"Prometheus","type":"prometheus","uid":"prometheus-uid"}]`), "Prometheus")
	if err != nil || !present || uid != "prometheus-uid" {
		t.Fatalf("exact Grafana datasource failed: uid=%q present=%v err=%v", uid, present, err)
	}
	dashboard := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"ok-observability-dashboard-platform-overview","namespace":"ok-observability","labels":{"grafana_dashboard":"1"}},"data":{"platform-overview.json":"{\"uid\":\"ok-obs-platform-overview\"}"}}`
	if present, err := parseDashboardProvisioned([]byte(dashboard), "ok-observability", "ok-observability-dashboard-platform-overview", "ok-obs-platform-overview"); err != nil || !present {
		t.Fatalf("exact dashboard evidence failed: present=%v err=%v", present, err)
	}
	for _, raw := range []string{`{"hits":{"total":{"value":1,"relation":"eq"}}}`, `{"hits":{"total":1}}`} {
		if present, err := parseOpenSearchMarkerPresent([]byte(raw)); err != nil || !present {
			t.Fatalf("exact OpenSearch evidence failed: present=%v err=%v", present, err)
		}
	}
	if firing, err := parseAlertmanagerFiring([]byte(`[{"labels":{"alertname":"OKObservabilitySyntheticAlert"},"status":{"state":"active"}}]`), "OKObservabilitySyntheticAlert"); err != nil || !firing {
		t.Fatalf("exact Alertmanager evidence failed: firing=%v err=%v", firing, err)
	}
}

func TestObservabilityResponseParsersReturnFalseForCorrelatedAbsence(t *testing.T) {
	metric := "ok_observability_contract_metric_test"
	if present, err := parsePrometheusMetricPresent([]byte(`{"status":"success","data":{"result":[]}}`), metric); err != nil || present {
		t.Fatalf("empty Prometheus result did not return false: present=%v err=%v", present, err)
	}
	if _, present, err := parseGrafanaPrometheusDatasource([]byte(`[{"name":"Other","type":"prometheus","uid":"other"}]`), "Prometheus"); err != nil || present {
		t.Fatalf("missing Grafana datasource did not return false: present=%v err=%v", present, err)
	}
	dashboard := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"ok-observability-dashboard-platform-overview","namespace":"ok-observability","labels":{"grafana_dashboard":"1"}},"data":{"platform-overview.json":"{\"uid\":\"other\"}"}}`
	if present, err := parseDashboardProvisioned([]byte(dashboard), "ok-observability", "ok-observability-dashboard-platform-overview", "ok-obs-platform-overview"); err != nil || present {
		t.Fatalf("wrong dashboard UID did not return false: present=%v err=%v", present, err)
	}
	if present, err := parseOpenSearchMarkerPresent([]byte(`{"hits":{"total":{"value":0}}}`)); err != nil || present {
		t.Fatalf("zero OpenSearch hits did not return false: present=%v err=%v", present, err)
	}
	if firing, err := parseAlertmanagerFiring([]byte(`[{"labels":{"alertname":"Other"},"status":{"state":"active"}}]`), "OKObservabilitySyntheticAlert"); err != nil || firing {
		t.Fatalf("missing alert did not return false: firing=%v err=%v", firing, err)
	}
}

func TestObservabilityResponseParsersFailClosedOnMalformedOrAmbiguousEvidence(t *testing.T) {
	if _, err := parsePrometheusMetricPresent([]byte(`{"status":"success","data":{"result":[]}} {}`), "metric"); err == nil {
		t.Fatal("trailing Prometheus response was accepted")
	}
	if _, _, err := parseGrafanaPrometheusDatasource([]byte(`[{"name":"Prometheus","type":"prometheus","uid":"one"},{"name":"Prometheus","type":"prometheus","uid":"two"}]`), "Prometheus"); err == nil {
		t.Fatal("ambiguous Grafana datasource was accepted")
	}
	if _, err := parseDashboardProvisioned([]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"foreign","namespace":"ok-observability","labels":{"grafana_dashboard":"1"}},"data":{}}`), "ok-observability", "ok-observability-dashboard-platform-overview", "ok-obs-platform-overview"); err == nil {
		t.Fatal("foreign dashboard ConfigMap was accepted")
	}
	if _, err := parseOpenSearchMarkerPresent([]byte(`{"hits":{"total":{"value":-1}}}`)); err == nil {
		t.Fatal("negative OpenSearch hit count was accepted")
	}
	if _, err := parseAlertmanagerFiring([]byte(strings.Repeat("x", maximumObservabilityBackendResponseBytes+1)), "alert"); err == nil {
		t.Fatal("oversized Alertmanager response was accepted")
	}
}
