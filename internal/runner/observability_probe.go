package runner

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const ObservabilityCapabilityRunFormat = "ok147-observability-capability-run/v1"

var capabilityNamespacePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// ObservabilityCapabilityRun is the immutable identity supplied to every
// fixed observability-contract operation. It contains no credentials,
// endpoints, commands, manifests or arbitrary parameters.
type ObservabilityCapabilityRun struct {
	Format           string
	RunID            string
	Namespace        string
	TargetClusterUID string
	IntentRevision   string
	PlatformRevision string
	ExecutionFixture string
	ContractDigest   string
	ExecutableDigest string
}

// ObservabilityCapabilityTransport is deliberately a closed semantic surface
// for the five contract guarantees and their owned synthetic lifecycle. A
// concrete adapter cannot be used as a general Kubernetes or command client.
type ObservabilityCapabilityTransport interface {
	PrepareSyntheticMetrics(context.Context, ObservabilityCapabilityRun) error
	VerifyMetrics(context.Context, ObservabilityCapabilityRun) (bool, error)
	VerifyDashboards(context.Context, ObservabilityCapabilityRun) (bool, error)
	VerifyLogs(context.Context, ObservabilityCapabilityRun) (bool, error)
	VerifyAlertDelivery(context.Context, ObservabilityCapabilityRun) (bool, error)
	VerifyAutonomy(context.Context, ObservabilityCapabilityRun) (bool, error)
	CleanupSyntheticResources(context.Context, ObservabilityCapabilityRun) error
}

type ObservabilityCapabilityProbeConfig struct {
	Namespace                string
	ExpectedContractDigest   string
	ExpectedExecutableDigest string
	Timeout                  time.Duration
	CleanupTimeout           time.Duration
}

// ObservabilityCapabilityProbe executes the fixed contract sequence once per
// invocation. Retry authority remains outside this type.
type ObservabilityCapabilityProbe struct {
	transport ObservabilityCapabilityTransport
	config    ObservabilityCapabilityProbeConfig
}

func NewObservabilityCapabilityProbe(transport ObservabilityCapabilityTransport, config ObservabilityCapabilityProbeConfig) (*ObservabilityCapabilityProbe, error) {
	if transport == nil || !capabilityNamespacePattern.MatchString(config.Namespace) || len(config.Namespace) > 63 || !platformInputDigestPattern.MatchString(config.ExpectedContractDigest) || !platformInputDigestPattern.MatchString(config.ExpectedExecutableDigest) {
		return nil, errors.New("observability capability probe binding is invalid")
	}
	if config.Timeout < time.Minute || config.Timeout > 30*time.Minute || config.CleanupTimeout < 10*time.Second || config.CleanupTimeout > 2*time.Minute {
		return nil, errors.New("observability capability probe timeout is invalid")
	}
	return &ObservabilityCapabilityProbe{transport: transport, config: config}, nil
}

func (probe *ObservabilityCapabilityProbe) Probe(ctx context.Context, request PlatformCapabilityProbeRequest) (result PlatformCapabilityProbeResult, resultErr error) {
	if probe == nil || probe.transport == nil {
		return result, errors.New("observability capability probe is required")
	}
	if err := validatePlatformCapabilityProbeRequest(request); err != nil || request.ContractDigest != probe.config.ExpectedContractDigest || request.ExecutableDigest != probe.config.ExpectedExecutableDigest {
		return result, errors.New("observability capability request differs from the bound contract")
	}
	run, err := observabilityCapabilityRun(request, probe.config.Namespace)
	if err != nil {
		return result, errors.New("construct deterministic observability capability run")
	}
	bounded, cancel := context.WithTimeout(ctx, probe.config.Timeout)
	defer cancel()
	prepared := false
	defer func() {
		if !prepared {
			return
		}
		cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), probe.config.CleanupTimeout)
		defer cleanupCancel()
		if err := probe.transport.CleanupSyntheticResources(cleanup, run); err != nil {
			result = PlatformCapabilityProbeResult{}
			resultErr = errors.New("bounded observability capability cleanup failed")
		}
	}()

	// Prepare may have produced a partial prefix before returning an error, so
	// cleanup authority begins before the first transport call.
	prepared = true
	if err := probe.transport.PrepareSyntheticMetrics(bounded, run); err != nil {
		return result, errors.New("bounded observability capability preparation failed")
	}
	checks := []func(context.Context, ObservabilityCapabilityRun) (bool, error){
		probe.transport.VerifyMetrics,
		probe.transport.VerifyDashboards,
		probe.transport.VerifyLogs,
		probe.transport.VerifyAlertDelivery,
		probe.transport.VerifyAutonomy,
	}
	for _, check := range checks {
		passed, err := check(bounded, run)
		if err != nil {
			return result, errors.New("bounded observability capability check failed")
		}
		if !passed {
			return PlatformCapabilityProbeResult{Passed: false}, nil
		}
	}
	return PlatformCapabilityProbeResult{Passed: true}, nil
}

func validatePlatformCapabilityProbeRequest(request PlatformCapabilityProbeRequest) error {
	if request.Format != PlatformCapabilityProbeRequestFormat || !runtimeInputUIDPattern.MatchString(request.TargetClusterUID) {
		return errors.New("Platform capability probe request identity is invalid")
	}
	for _, value := range []string{request.IntentRevision, request.PlatformRevision, request.ExecutionFixture, request.ContractDigest, request.ExecutableDigest} {
		if !platformInputDigestPattern.MatchString(value) {
			return errors.New("Platform capability probe request revision is invalid")
		}
	}
	return nil
}

func observabilityCapabilityRun(request PlatformCapabilityProbeRequest, namespace string) (ObservabilityCapabilityRun, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return ObservabilityCapabilityRun{}, err
	}
	requestDigest := digest.SHA256(raw)
	return ObservabilityCapabilityRun{
		Format: ObservabilityCapabilityRunFormat, RunID: "ok147-" + requestDigest[len("sha256:"):len("sha256:")+24], Namespace: namespace,
		TargetClusterUID: request.TargetClusterUID, IntentRevision: request.IntentRevision,
		PlatformRevision: request.PlatformRevision, ExecutionFixture: request.ExecutionFixture,
		ContractDigest: request.ContractDigest, ExecutableDigest: request.ExecutableDigest,
	}, nil
}

var _ PlatformCapabilityProbe = (*ObservabilityCapabilityProbe)(nil)
