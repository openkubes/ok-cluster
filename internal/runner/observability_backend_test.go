package runner

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

type scriptedObservabilityBackendAPI struct {
	metricQueries     int
	grafanaQueries    int
	logQueries        int
	alertQueries      int
	pushes            int
	alertAlwaysAbsent bool
}

func (api *scriptedObservabilityBackendAPI) credentials(context.Context, ObservabilityCapabilityRun) (observabilityBackendCredentials, error) {
	return observabilityBackendCredentials{grafanaUser: "admin", grafanaPassword: "grafana", opensearchPassword: "opensearch"}, nil
}

func (api *scriptedObservabilityBackendAPI) dashboard(context.Context, ObservabilityCapabilityRun) (observabilityBackendResponse, error) {
	return observabilityBackendResponse{status: http.StatusOK, raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"ok-observability-dashboard-platform-overview","namespace":"ok-observability","labels":{"grafana_dashboard":"1"}},"data":{"platform-overview.json":"{\"uid\":\"ok-obs-platform-overview\"}"}}`)}, nil
}

func (api *scriptedObservabilityBackendAPI) pushMetrics(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (observabilityBackendResponse, error) {
	api.pushes++
	return observabilityBackendResponse{status: http.StatusOK}, nil
}

func (api *scriptedObservabilityBackendAPI) prometheusQuery(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (observabilityBackendResponse, error) {
	api.metricQueries++
	return prometheusBackendResponse(fixture.MetricName, api.metricQueries > 1), nil
}

func (api *scriptedObservabilityBackendAPI) grafanaDatasources(context.Context, ObservabilityCapabilityRun, observabilityBackendCredentials) (observabilityBackendResponse, error) {
	return observabilityBackendResponse{status: http.StatusOK, raw: []byte(`[{"name":"Prometheus","type":"prometheus","uid":"prometheus-uid"}]`)}, nil
}

func (api *scriptedObservabilityBackendAPI) grafanaQuery(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, _ string, _ observabilityBackendCredentials) (observabilityBackendResponse, error) {
	api.grafanaQueries++
	return prometheusBackendResponse(fixture.MetricName, api.grafanaQueries > 1), nil
}

func (api *scriptedObservabilityBackendAPI) searchLogs(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, observabilityBackendCredentials) (observabilityBackendResponse, error) {
	api.logQueries++
	count := 0
	if api.logQueries > 1 {
		count = 1
	}
	return observabilityBackendResponse{status: http.StatusOK, raw: []byte(fmt.Sprintf(`{"hits":{"total":{"value":%d}}}`, count))}, nil
}

func (api *scriptedObservabilityBackendAPI) alerts(context.Context, ObservabilityCapabilityRun) (observabilityBackendResponse, error) {
	api.alertQueries++
	if api.alertAlwaysAbsent || api.alertQueries == 1 {
		return observabilityBackendResponse{status: http.StatusOK, raw: []byte(`[]`)}, nil
	}
	return observabilityBackendResponse{status: http.StatusOK, raw: []byte(`[{"labels":{"alertname":"OKObservabilitySyntheticAlert"},"status":{"state":"active"}}]`)}, nil
}

func prometheusBackendResponse(metric string, present bool) observabilityBackendResponse {
	result := "[]"
	if present {
		result = `[{"metric":{"__name__":"` + metric + `"},"value":[1,"1"]}]`
	}
	return observabilityBackendResponse{status: http.StatusOK, raw: []byte(`{"status":"success","data":{"result":` + result + `}}`)}
}

type recordingDeliveryEvidenceSource struct {
	identity  ObservabilityCapabilityObservationIdentity
	alert     string
	calls     int
	delivered bool
}

func (source *recordingDeliveryEvidenceSource) Delivery(_ context.Context, identity ObservabilityCapabilityObservationIdentity, alert string) (bool, error) {
	source.identity, source.alert = identity, alert
	source.calls++
	return source.delivered, nil
}

type recordingAutonomyEvidenceSource struct {
	identity     ObservabilityCapabilityObservationIdentity
	ready        bool
	dependencies int
}

func (source *recordingAutonomyEvidenceSource) Autonomy(_ context.Context, identity ObservabilityCapabilityObservationIdentity) (bool, int, error) {
	source.identity = identity
	return source.ready, source.dependencies, nil
}

func TestKubernetesObservabilityCapabilityBackendComposesExactObservations(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	api := &scriptedObservabilityBackendAPI{}
	delivery := &recordingDeliveryEvidenceSource{delivered: true}
	autonomy := &recordingAutonomyEvidenceSource{ready: true}
	backend, err := newKubernetesObservabilityCapabilityBackend(api, delivery, autonomy, profile, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	metrics, err := backend.ObserveMetrics(ctx, run, fixture, profile)
	if err != nil || !metrics.TargetDiscovered || !metrics.MetricPresent || api.pushes != 1 || api.metricQueries != 2 {
		t.Fatalf("metrics observation differs: %#v pushes=%d queries=%d err=%v", metrics, api.pushes, api.metricQueries, err)
	}
	dashboards, err := backend.ObserveDashboards(ctx, run, fixture, profile)
	if err != nil || !dashboards.GrafanaReachable || !dashboards.DashboardProvisioned || !dashboards.MetricPresent || api.grafanaQueries != 2 {
		t.Fatalf("dashboard observation differs: %#v queries=%d err=%v", dashboards, api.grafanaQueries, err)
	}
	logs, err := backend.ObserveLogs(ctx, run, fixture, profile)
	if err != nil || !logs.BackendReachable || !logs.MarkerPresent || api.logQueries != 2 {
		t.Fatalf("log observation differs: %#v queries=%d err=%v", logs, api.logQueries, err)
	}
	alert, err := backend.ObserveAlertDelivery(ctx, run, fixture, profile)
	if err != nil || !alert.Firing || !alert.Delivered || api.alertQueries != 2 || delivery.calls != 1 || delivery.alert != profile.alertName {
		t.Fatalf("alert observation differs: %#v queries=%d delivery=%d err=%v", alert, api.alertQueries, delivery.calls, err)
	}
	autonomyResult, err := backend.ObserveAutonomy(ctx, run, fixture, profile)
	if err != nil || !autonomyResult.ClusterLocalServicesReady || autonomyResult.ExternalClusterDependencies != 0 {
		t.Fatalf("autonomy observation differs: %#v err=%v", autonomyResult, err)
	}
	expectedIdentity := ObservabilityCapabilityObservationIdentity{RunID: run.RunID, TargetClusterUID: run.TargetClusterUID, FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest()}
	if delivery.identity != expectedIdentity || autonomy.identity != expectedIdentity {
		t.Fatal("independent evidence sources did not receive the exact observation identity")
	}
}

func TestKubernetesObservabilityCapabilityBackendDoesNotInventDeliveryOrAutonomy(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	api := &scriptedObservabilityBackendAPI{alertAlwaysAbsent: true}
	delivery := &recordingDeliveryEvidenceSource{delivered: true}
	autonomy := &recordingAutonomyEvidenceSource{ready: true, dependencies: 1}
	backend, _ := newKubernetesObservabilityCapabilityBackend(api, delivery, autonomy, profile, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	alert, err := backend.ObserveAlertDelivery(ctx, run, fixture, profile)
	if err != nil || alert.Firing || alert.Delivered || delivery.calls != 0 {
		t.Fatalf("non-firing alert invented delivery: %#v calls=%d err=%v", alert, delivery.calls, err)
	}
	autonomyCtx, autonomyCancel := context.WithTimeout(context.Background(), time.Second)
	defer autonomyCancel()
	autonomyResult, err := backend.ObserveAutonomy(autonomyCtx, run, fixture, profile)
	if err != nil || autonomyResult.ExternalClusterDependencies != 1 {
		t.Fatalf("external dependency was hidden: %#v err=%v", autonomyResult, err)
	}
}

func TestKubernetesObservabilityCapabilityBackendRequiresBoundedContext(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	api := &scriptedObservabilityBackendAPI{}
	backend, _ := newKubernetesObservabilityCapabilityBackend(api, &recordingDeliveryEvidenceSource{}, &recordingAutonomyEvidenceSource{}, profile, time.Millisecond)
	if _, err := backend.ObserveMetrics(context.Background(), run, fixture, profile); err == nil || api.pushes != 0 {
		t.Fatal("unbounded capability context reached the backend API")
	}
}
