package runner

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type observabilityBackendAPI interface {
	credentials(context.Context, ObservabilityCapabilityRun) (observabilityBackendCredentials, error)
	dashboard(context.Context, ObservabilityCapabilityRun) (observabilityBackendResponse, error)
	pushMetrics(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (observabilityBackendResponse, error)
	prometheusQuery(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (observabilityBackendResponse, error)
	grafanaDatasources(context.Context, ObservabilityCapabilityRun, observabilityBackendCredentials) (observabilityBackendResponse, error)
	grafanaQuery(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, string, observabilityBackendCredentials) (observabilityBackendResponse, error)
	searchLogs(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, observabilityBackendCredentials) (observabilityBackendResponse, error)
	alerts(context.Context, ObservabilityCapabilityRun) (observabilityBackendResponse, error)
}

// ObservabilityAlertDeliveryEvidenceSource proves receiver delivery separately
// from Alertmanager firing. It receives only the immutable observation
// identity and fixed alert name.
type ObservabilityAlertDeliveryEvidenceSource interface {
	Delivery(context.Context, ObservabilityCapabilityObservationIdentity, string) (bool, error)
}

// ObservabilityAutonomyEvidenceSource supplies the independent evidence needed
// to claim that the stack remains functional without another cluster.
type ObservabilityAutonomyEvidenceSource interface {
	Autonomy(context.Context, ObservabilityCapabilityObservationIdentity) (clusterLocalServicesReady bool, externalClusterDependencies int, err error)
}

// KubernetesObservabilityCapabilityBackend composes the closed Kubernetes API
// client, strict response parsers and the two claims that require independent
// evidence. It polls only a valid correlated absence and performs no repair.
type KubernetesObservabilityCapabilityBackend struct {
	api          observabilityBackendAPI
	delivery     ObservabilityAlertDeliveryEvidenceSource
	autonomy     ObservabilityAutonomyEvidenceSource
	profile      ObservabilityCapabilityCheckProfile
	pollInterval time.Duration
}

func newKubernetesObservabilityCapabilityBackend(api observabilityBackendAPI, delivery ObservabilityAlertDeliveryEvidenceSource, autonomy ObservabilityAutonomyEvidenceSource, profile ObservabilityCapabilityCheckProfile, pollInterval time.Duration) (*KubernetesObservabilityCapabilityBackend, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || api == nil || delivery == nil || autonomy == nil || profile.Digest() == "" || profile.Digest() != standard.Digest() || pollInterval < time.Millisecond || pollInterval > 30*time.Second {
		return nil, errors.New("Kubernetes observability capability backend binding is invalid")
	}
	return &KubernetesObservabilityCapabilityBackend{api: api, delivery: delivery, autonomy: autonomy, profile: profile, pollInterval: pollInterval}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) ObserveMetrics(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityMetricsObservation, error) {
	identity, err := backend.identity(ctx, run, fixture, profile)
	if err != nil {
		return ObservabilityMetricsObservation{}, err
	}
	response, err := backend.api.pushMetrics(ctx, run, fixture)
	if err != nil || response.status != http.StatusOK && response.status != http.StatusAccepted {
		return ObservabilityMetricsObservation{}, errors.New("push exact observability metrics")
	}
	present, err := backend.poll(ctx, func() (bool, error) {
		response, err := backend.api.prometheusQuery(ctx, run, fixture)
		if err != nil || response.status != http.StatusOK {
			return false, errors.New("query exact Prometheus metric")
		}
		return parsePrometheusMetricPresent(response.raw, fixture.MetricName)
	})
	if err != nil {
		return ObservabilityMetricsObservation{}, err
	}
	return ObservabilityMetricsObservation{Identity: identity, MetricName: fixture.MetricName, TargetDiscovered: present, MetricPresent: present}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) ObserveDashboards(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityDashboardObservation, error) {
	identity, err := backend.identity(ctx, run, fixture, profile)
	if err != nil {
		return ObservabilityDashboardObservation{}, err
	}
	dashboardResponse, err := backend.api.dashboard(ctx, run)
	if err != nil || dashboardResponse.status != http.StatusOK {
		return ObservabilityDashboardObservation{}, errors.New("read exact platform dashboard")
	}
	provisioned, err := parseDashboardProvisioned(dashboardResponse.raw, profile.namespace, profile.dashboardConfigMap, profile.dashboardUID)
	if err != nil {
		return ObservabilityDashboardObservation{}, err
	}
	credentials, err := backend.api.credentials(ctx, run)
	if err != nil {
		return ObservabilityDashboardObservation{}, err
	}
	datasourceResponse, err := backend.api.grafanaDatasources(ctx, run, credentials)
	if err != nil || datasourceResponse.status != http.StatusOK {
		return ObservabilityDashboardObservation{}, errors.New("read exact Grafana datasource")
	}
	datasourceUID, datasourcePresent, err := parseGrafanaPrometheusDatasource(datasourceResponse.raw, profile.prometheusDatasource)
	if err != nil {
		return ObservabilityDashboardObservation{}, err
	}
	metricPresent := false
	if datasourcePresent {
		metricPresent, err = backend.poll(ctx, func() (bool, error) {
			response, err := backend.api.grafanaQuery(ctx, run, fixture, datasourceUID, credentials)
			if err != nil || response.status != http.StatusOK {
				return false, errors.New("query exact Grafana datasource metric")
			}
			return parsePrometheusMetricPresent(response.raw, fixture.MetricName)
		})
		if err != nil {
			return ObservabilityDashboardObservation{}, err
		}
	}
	return ObservabilityDashboardObservation{
		Identity: identity, DashboardUID: profile.dashboardUID, DatasourceName: profile.prometheusDatasource,
		GrafanaReachable: true, DashboardProvisioned: provisioned, MetricPresent: metricPresent,
	}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) ObserveLogs(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityLogObservation, error) {
	identity, err := backend.identity(ctx, run, fixture, profile)
	if err != nil {
		return ObservabilityLogObservation{}, err
	}
	credentials, err := backend.api.credentials(ctx, run)
	if err != nil {
		return ObservabilityLogObservation{}, err
	}
	present, err := backend.poll(ctx, func() (bool, error) {
		response, err := backend.api.searchLogs(ctx, run, fixture, credentials)
		if err != nil || response.status != http.StatusOK {
			return false, errors.New("search exact OpenSearch log marker")
		}
		return parseOpenSearchMarkerPresent(response.raw)
	})
	if err != nil {
		return ObservabilityLogObservation{}, err
	}
	return ObservabilityLogObservation{Identity: identity, LogMarker: fixture.LogMarker, BackendReachable: true, MarkerPresent: present}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) ObserveAlertDelivery(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityAlertObservation, error) {
	identity, err := backend.identity(ctx, run, fixture, profile)
	if err != nil {
		return ObservabilityAlertObservation{}, err
	}
	firing, err := backend.poll(ctx, func() (bool, error) {
		response, err := backend.api.alerts(ctx, run)
		if err != nil || response.status != http.StatusOK {
			return false, errors.New("read exact Alertmanager alert")
		}
		return parseAlertmanagerFiring(response.raw, profile.alertName)
	})
	if err != nil {
		return ObservabilityAlertObservation{}, err
	}
	delivered := false
	if firing {
		delivered, err = backend.delivery.Delivery(ctx, identity, profile.alertName)
		if err != nil {
			return ObservabilityAlertObservation{}, errors.New("read independent alert-delivery evidence")
		}
	}
	return ObservabilityAlertObservation{Identity: identity, AlertName: profile.alertName, Firing: firing, Delivered: delivered}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) ObserveAutonomy(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityAutonomyObservation, error) {
	identity, err := backend.identity(ctx, run, fixture, profile)
	if err != nil {
		return ObservabilityAutonomyObservation{}, err
	}
	ready, dependencies, err := backend.autonomy.Autonomy(ctx, identity)
	if err != nil || dependencies < 0 {
		return ObservabilityAutonomyObservation{}, errors.New("read independent autonomy evidence")
	}
	return ObservabilityAutonomyObservation{Identity: identity, ClusterLocalServicesReady: ready, ExternalClusterDependencies: dependencies}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) identity(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityCapabilityObservationIdentity, error) {
	if backend == nil || backend.api == nil || backend.delivery == nil || backend.autonomy == nil {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability capability backend is required")
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil || profile.Digest() != backend.profile.Digest() || validateObservabilityCapabilityRun(run) != nil || fixture.RunID != run.RunID || fixture.Namespace != run.Namespace {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability capability backend input is invalid")
	}
	digestValue, err := ObservabilitySyntheticFixtureDigest(fixture)
	if err != nil || digestValue != fixture.FixtureDigest {
		return ObservabilityCapabilityObservationIdentity{}, errors.New("observability capability backend fixture identity is invalid")
	}
	return ObservabilityCapabilityObservationIdentity{RunID: run.RunID, TargetClusterUID: run.TargetClusterUID, FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest()}, nil
}

func (backend *KubernetesObservabilityCapabilityBackend) poll(ctx context.Context, observe func() (bool, error)) (bool, error) {
	for {
		present, err := observe()
		if err != nil || present {
			return present, err
		}
		timer := time.NewTimer(backend.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false, nil
		case <-timer.C:
		}
	}
}

var _ ObservabilityCapabilityBackend = (*KubernetesObservabilityCapabilityBackend)(nil)
