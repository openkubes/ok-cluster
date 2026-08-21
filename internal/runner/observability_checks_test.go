package runner

import (
	"context"
	"errors"
	"testing"
)

type recordingObservabilityCapabilityBackend struct {
	identity ObservabilityCapabilityObservationIdentity
	fixture  ObservabilitySyntheticFixture
	profile  ObservabilityCapabilityCheckProfile
	fail     string
}

func (backend *recordingObservabilityCapabilityBackend) capture(run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile, name string) error {
	backend.identity = ObservabilityCapabilityObservationIdentity{RunID: run.RunID, TargetClusterUID: run.TargetClusterUID, FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest()}
	backend.fixture, backend.profile = fixture, profile
	if backend.fail == name {
		return errors.New("backend failure")
	}
	return nil
}

func (backend *recordingObservabilityCapabilityBackend) ObserveMetrics(_ context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityMetricsObservation, error) {
	err := backend.capture(run, fixture, profile, "metrics")
	return ObservabilityMetricsObservation{Identity: backend.identity, MetricName: fixture.MetricName, TargetDiscovered: true, MetricPresent: true}, err
}

func (backend *recordingObservabilityCapabilityBackend) ObserveDashboards(_ context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityDashboardObservation, error) {
	err := backend.capture(run, fixture, profile, "dashboards")
	return ObservabilityDashboardObservation{Identity: backend.identity, DashboardUID: profile.dashboardUID, DatasourceName: profile.prometheusDatasource, GrafanaReachable: true, DashboardProvisioned: true, MetricPresent: true}, err
}

func (backend *recordingObservabilityCapabilityBackend) ObserveLogs(_ context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityLogObservation, error) {
	err := backend.capture(run, fixture, profile, "logs")
	return ObservabilityLogObservation{Identity: backend.identity, LogMarker: fixture.LogMarker, BackendReachable: true, MarkerPresent: true}, err
}

func (backend *recordingObservabilityCapabilityBackend) ObserveAlertDelivery(_ context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityAlertObservation, error) {
	err := backend.capture(run, fixture, profile, "alert")
	return ObservabilityAlertObservation{Identity: backend.identity, AlertName: profile.alertName, Firing: true, Delivered: true}, err
}

func (backend *recordingObservabilityCapabilityBackend) ObserveAutonomy(_ context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityAutonomyObservation, error) {
	err := backend.capture(run, fixture, profile, "autonomy")
	return ObservabilityAutonomyObservation{Identity: backend.identity, ClusterLocalServicesReady: true}, err
}

func TestStandardObservabilityCapabilityChecksAcceptExactFiveGuarantees(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, err := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	backend := &recordingObservabilityCapabilityBackend{}
	checks, err := NewStandardObservabilityCapabilityChecks(backend, profile)
	if err != nil {
		t.Fatal(err)
	}
	operations := []func(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error){checks.Metrics, checks.Dashboards, checks.Logs, checks.AlertDelivery, checks.Autonomy}
	for index, operation := range operations {
		passed, err := operation(context.Background(), run, fixture)
		if err != nil || !passed {
			t.Fatalf("exact capability guarantee %d failed: passed=%v err=%v", index, passed, err)
		}
		if backend.profile.Digest() != profile.Digest() || backend.fixture.FixtureDigest != fixture.FixtureDigest {
			t.Fatal("backend did not receive the exact profile and fixture")
		}
	}
}

func TestStandardObservabilityCapabilityChecksFailClosed(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")

	t.Run("alert firing without delivery is false", func(t *testing.T) {
		backend := &recordingObservabilityCapabilityBackend{}
		checks, _ := NewStandardObservabilityCapabilityChecks(backend, profile)
		backend.fail = ""
		observed, _ := backend.ObserveAlertDelivery(context.Background(), run, fixture, profile)
		observed.Delivered = false
		backendWithObservation := &fixedAlertBackend{recordingObservabilityCapabilityBackend: backend, observed: observed}
		checks, _ = NewStandardObservabilityCapabilityChecks(backendWithObservation, profile)
		passed, err := checks.AlertDelivery(context.Background(), run, fixture)
		if err != nil || passed {
			t.Fatalf("firing-only alert became delivery proof: passed=%v err=%v", passed, err)
		}
	})

	t.Run("foreign identity errors", func(t *testing.T) {
		backend := &recordingObservabilityCapabilityBackend{}
		checks, _ := NewStandardObservabilityCapabilityChecks(&foreignMetricsBackend{recordingObservabilityCapabilityBackend: backend}, profile)
		if _, err := checks.Metrics(context.Background(), run, fixture); err == nil {
			t.Fatal("foreign capability observation was accepted")
		}
	})

	t.Run("tampered fixture errors before backend", func(t *testing.T) {
		backend := &recordingObservabilityCapabilityBackend{}
		checks, _ := NewStandardObservabilityCapabilityChecks(backend, profile)
		fixture.MetricName += "_tampered"
		if _, err := checks.Metrics(context.Background(), run, fixture); err == nil || backend.identity.RunID != "" {
			t.Fatal("tampered fixture reached the capability backend")
		}
	})
}

type fixedAlertBackend struct {
	*recordingObservabilityCapabilityBackend
	observed ObservabilityAlertObservation
}

func (backend *fixedAlertBackend) ObserveAlertDelivery(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, ObservabilityCapabilityCheckProfile) (ObservabilityAlertObservation, error) {
	return backend.observed, nil
}

type foreignMetricsBackend struct {
	*recordingObservabilityCapabilityBackend
}

func (backend *foreignMetricsBackend) ObserveMetrics(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, profile ObservabilityCapabilityCheckProfile) (ObservabilityMetricsObservation, error) {
	observed, err := backend.recordingObservabilityCapabilityBackend.ObserveMetrics(ctx, run, fixture, profile)
	observed.Identity.TargetClusterUID = "foreign-cluster-uid"
	return observed, err
}
