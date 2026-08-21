package runner

import (
	"context"
	"errors"
)

// ObservabilityCapabilityObservationIdentity prevents a backend observation
// from being reused for another run, target, fixture or check profile.
type ObservabilityCapabilityObservationIdentity struct {
	RunID            string
	TargetClusterUID string
	FixtureDigest    string
	ProfileDigest    string
}

type ObservabilityMetricsObservation struct {
	Identity         ObservabilityCapabilityObservationIdentity
	MetricName       string
	TargetDiscovered bool
	MetricPresent    bool
}

type ObservabilityDashboardObservation struct {
	Identity             ObservabilityCapabilityObservationIdentity
	DashboardUID         string
	DatasourceName       string
	GrafanaReachable     bool
	DashboardProvisioned bool
	MetricPresent        bool
}

type ObservabilityLogObservation struct {
	Identity         ObservabilityCapabilityObservationIdentity
	LogMarker        string
	BackendReachable bool
	MarkerPresent    bool
}

type ObservabilityAlertObservation struct {
	Identity  ObservabilityCapabilityObservationIdentity
	AlertName string
	Firing    bool
	Delivered bool
}

type ObservabilityAutonomyObservation struct {
	Identity                    ObservabilityCapabilityObservationIdentity
	ClusterLocalServicesReady   bool
	ExternalClusterDependencies int
}

// ObservabilityCapabilityBackend is a typed observation source. It receives
// no caller-selected Service name, URL, query, command or credential. The
// Kubernetes implementation is responsible for using only the closed profile.
type ObservabilityCapabilityBackend interface {
	ObserveMetrics(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, ObservabilityCapabilityCheckProfile) (ObservabilityMetricsObservation, error)
	ObserveDashboards(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, ObservabilityCapabilityCheckProfile) (ObservabilityDashboardObservation, error)
	ObserveLogs(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, ObservabilityCapabilityCheckProfile) (ObservabilityLogObservation, error)
	ObserveAlertDelivery(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, ObservabilityCapabilityCheckProfile) (ObservabilityAlertObservation, error)
	ObserveAutonomy(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture, ObservabilityCapabilityCheckProfile) (ObservabilityAutonomyObservation, error)
}

// StandardObservabilityCapabilityChecks applies the five accepted contract
// assertions to identity-bound backend observations. It observes only; repair
// and reconciliation remain owned by the platform mechanisms.
type StandardObservabilityCapabilityChecks struct {
	backend ObservabilityCapabilityBackend
	profile ObservabilityCapabilityCheckProfile
}

func NewStandardObservabilityCapabilityChecks(backend ObservabilityCapabilityBackend, profile ObservabilityCapabilityCheckProfile) (*StandardObservabilityCapabilityChecks, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || backend == nil || profile.Digest() == "" || profile.Digest() != standard.Digest() {
		return nil, errors.New("standard observability capability checks binding is invalid")
	}
	return &StandardObservabilityCapabilityChecks{backend: backend, profile: profile}, nil
}

func (checks *StandardObservabilityCapabilityChecks) Metrics(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	if err := checks.validate(run, fixture); err != nil {
		return false, err
	}
	observed, err := checks.backend.ObserveMetrics(ctx, run, cloneSyntheticFixture(fixture), checks.profile)
	if err != nil || !checks.matches(observed.Identity, run, fixture) {
		return false, errors.New("metrics capability observation is invalid")
	}
	return observed.MetricName == fixture.MetricName && observed.TargetDiscovered && observed.MetricPresent, nil
}

func (checks *StandardObservabilityCapabilityChecks) Dashboards(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	if err := checks.validate(run, fixture); err != nil {
		return false, err
	}
	observed, err := checks.backend.ObserveDashboards(ctx, run, cloneSyntheticFixture(fixture), checks.profile)
	if err != nil || !checks.matches(observed.Identity, run, fixture) {
		return false, errors.New("dashboard capability observation is invalid")
	}
	return observed.DashboardUID == checks.profile.dashboardUID && observed.DatasourceName == checks.profile.prometheusDatasource &&
		observed.GrafanaReachable && observed.DashboardProvisioned && observed.MetricPresent, nil
}

func (checks *StandardObservabilityCapabilityChecks) Logs(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	if err := checks.validate(run, fixture); err != nil {
		return false, err
	}
	observed, err := checks.backend.ObserveLogs(ctx, run, cloneSyntheticFixture(fixture), checks.profile)
	if err != nil || !checks.matches(observed.Identity, run, fixture) {
		return false, errors.New("log capability observation is invalid")
	}
	return observed.LogMarker == fixture.LogMarker && observed.BackendReachable && observed.MarkerPresent, nil
}

func (checks *StandardObservabilityCapabilityChecks) AlertDelivery(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	if err := checks.validate(run, fixture); err != nil {
		return false, err
	}
	observed, err := checks.backend.ObserveAlertDelivery(ctx, run, cloneSyntheticFixture(fixture), checks.profile)
	if err != nil || !checks.matches(observed.Identity, run, fixture) {
		return false, errors.New("alert capability observation is invalid")
	}
	return observed.AlertName == checks.profile.alertName && observed.Firing && observed.Delivered, nil
}

func (checks *StandardObservabilityCapabilityChecks) Autonomy(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	if err := checks.validate(run, fixture); err != nil {
		return false, err
	}
	observed, err := checks.backend.ObserveAutonomy(ctx, run, cloneSyntheticFixture(fixture), checks.profile)
	if err != nil || !checks.matches(observed.Identity, run, fixture) || observed.ExternalClusterDependencies < 0 {
		return false, errors.New("autonomy capability observation is invalid")
	}
	return observed.ClusterLocalServicesReady && observed.ExternalClusterDependencies == 0, nil
}

func (checks *StandardObservabilityCapabilityChecks) validate(run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) error {
	if checks == nil || checks.backend == nil || checks.profile.Digest() == "" || validateObservabilityCapabilityRun(run) != nil ||
		fixture.RunID != run.RunID || fixture.Namespace != run.Namespace || fixture.Format != ObservabilitySyntheticFixtureFormat {
		return errors.New("observability capability check input is invalid")
	}
	digestValue, err := ObservabilitySyntheticFixtureDigest(fixture)
	if err != nil || digestValue != fixture.FixtureDigest {
		return errors.New("observability capability fixture identity is invalid")
	}
	return nil
}

func (checks *StandardObservabilityCapabilityChecks) matches(identity ObservabilityCapabilityObservationIdentity, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) bool {
	return identity.RunID == run.RunID && identity.TargetClusterUID == run.TargetClusterUID &&
		identity.FixtureDigest == fixture.FixtureDigest && identity.ProfileDigest == checks.profile.Digest()
}

var _ ObservabilityCapabilityChecks = (*StandardObservabilityCapabilityChecks)(nil)
