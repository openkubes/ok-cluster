package runner

import (
	"context"
	"errors"
	"sync"
)

// ObservabilityCapabilityChecks is the fixed, read-oriented half of the live
// capability adapter. Synthetic object lifecycle remains owned by the fixture
// client and cannot be influenced by a check implementation.
type ObservabilityCapabilityChecks interface {
	Metrics(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error)
	Dashboards(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error)
	Logs(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error)
	AlertDelivery(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error)
	Autonomy(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error)
}

// KubernetesObservabilityTransport combines one frozen synthetic fixture
// client with five fixed checks. It retains the private partial create receipt
// so cleanup cannot be redirected by its caller.
type KubernetesObservabilityTransport struct {
	mu        sync.Mutex
	run       ObservabilityCapabilityRun
	fixture   ObservabilitySyntheticFixture
	client    *KubernetesCapabilityFixtureClient
	checks    ObservabilityCapabilityChecks
	created   *CapabilityFixtureReceipt
	prepared  bool
	cleaned   bool
	nextCheck int
}

func newKubernetesObservabilityTransport(client *KubernetesCapabilityFixtureClient, run ObservabilityCapabilityRun, checks ObservabilityCapabilityChecks) (*KubernetesObservabilityTransport, error) {
	if client == nil || checks == nil || validateObservabilityCapabilityRun(run) != nil || client.fixture.RunID != run.RunID || client.fixture.Namespace != run.Namespace {
		return nil, errors.New("Kubernetes observability transport binding is invalid")
	}
	return &KubernetesObservabilityTransport{run: run, fixture: cloneSyntheticFixture(client.fixture), client: client, checks: checks}, nil
}

func (transport *KubernetesObservabilityTransport) PrepareSyntheticMetrics(ctx context.Context, run ObservabilityCapabilityRun) error {
	transport.mu.Lock()
	if transport.prepared || transport.cleaned || run != transport.run {
		transport.mu.Unlock()
		return errors.New("Kubernetes observability preparation state is invalid")
	}
	transport.prepared = true
	transport.mu.Unlock()
	receipt, err := transport.client.Create(ctx)
	transport.mu.Lock()
	transport.created = &receipt
	transport.mu.Unlock()
	if err != nil {
		return errors.New("create bounded observability synthetic fixture")
	}
	return nil
}

func (transport *KubernetesObservabilityTransport) VerifyMetrics(ctx context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.check(ctx, run, 0, transport.checks.Metrics)
}

func (transport *KubernetesObservabilityTransport) VerifyDashboards(ctx context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.check(ctx, run, 1, transport.checks.Dashboards)
}

func (transport *KubernetesObservabilityTransport) VerifyLogs(ctx context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.check(ctx, run, 2, transport.checks.Logs)
}

func (transport *KubernetesObservabilityTransport) VerifyAlertDelivery(ctx context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.check(ctx, run, 3, transport.checks.AlertDelivery)
}

func (transport *KubernetesObservabilityTransport) VerifyAutonomy(ctx context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.check(ctx, run, 4, transport.checks.Autonomy)
}

func (transport *KubernetesObservabilityTransport) check(ctx context.Context, run ObservabilityCapabilityRun, expectedIndex int, check func(context.Context, ObservabilityCapabilityRun, ObservabilitySyntheticFixture) (bool, error)) (bool, error) {
	transport.mu.Lock()
	valid := transport.prepared && !transport.cleaned && transport.created != nil && transport.created.State == "CREATED" && run == transport.run && transport.nextCheck == expectedIndex
	fixture := cloneSyntheticFixture(transport.fixture)
	if valid {
		transport.nextCheck++
	}
	transport.mu.Unlock()
	if !valid {
		return false, errors.New("Kubernetes observability check state is invalid")
	}
	passed, err := check(ctx, run, fixture)
	if err != nil {
		return false, errors.New("bounded Kubernetes observability check failed")
	}
	return passed, nil
}

func (transport *KubernetesObservabilityTransport) CleanupSyntheticResources(ctx context.Context, run ObservabilityCapabilityRun) error {
	transport.mu.Lock()
	if !transport.prepared || transport.cleaned || run != transport.run || transport.created == nil {
		transport.mu.Unlock()
		return errors.New("Kubernetes observability cleanup state is invalid")
	}
	transport.cleaned = true
	created := *transport.created
	transport.mu.Unlock()
	if created.MutationState == "NOT_ATTEMPTED" && len(created.Results) == 0 {
		return nil
	}
	if created.MutationState == "ATTEMPTED_UNKNOWN" || len(created.Results) == 0 {
		return errors.New("Kubernetes observability partial state cannot be safely cleaned")
	}
	if _, err := transport.client.Cleanup(ctx, created); err != nil {
		return errors.New("clean bounded observability synthetic fixture")
	}
	return nil
}

var _ ObservabilityCapabilityTransport = (*KubernetesObservabilityTransport)(nil)
