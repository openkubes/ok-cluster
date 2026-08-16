package runner

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

const PlatformCapabilityProbeRequestFormat = "ok147-platform-capability-probe-request/v1"

// PlatformCapabilityProbeRequest is the complete typed input a first-run
// capability implementation may receive. It intentionally has no command,
// argv, environment, path, endpoint, credential or arbitrary payload field.
type PlatformCapabilityProbeRequest struct {
	Format           string
	TargetClusterUID string
	IntentRevision   string
	PlatformRevision string
	ExecutionFixture string
	ContractDigest   string
	ExecutableDigest string
}

// PlatformCapabilityProbeResult exposes only the contract outcome. Raw probe
// output remains inside the concrete adapter and cannot enter runner evidence.
type PlatformCapabilityProbeResult struct {
	Passed bool
}

// PlatformCapabilityProbe implements one exact capability contract. It is not
// a general command runner.
type PlatformCapabilityProbe interface {
	Probe(context.Context, PlatformCapabilityProbeRequest) (PlatformCapabilityProbeResult, error)
}

// FirstRunPlatformCapabilityResolver creates a single-use capability source
// only after the runtime target UID and immutable Platform profile are bound.
type FirstRunPlatformCapabilityResolver struct {
	probe PlatformCapabilityProbe
	clock func() time.Time
}

func NewFirstRunPlatformCapabilityResolver(probe PlatformCapabilityProbe, clock func() time.Time) (*FirstRunPlatformCapabilityResolver, error) {
	if probe == nil || clock == nil {
		return nil, errors.New("first-run Platform capability probe and clock are required")
	}
	return &FirstRunPlatformCapabilityResolver{probe: probe, clock: clock}, nil
}

func (resolver *FirstRunPlatformCapabilityResolver) ResolvePlatformCapability(ctx context.Context, policy observation.Policy, profile observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
	if resolver == nil || resolver.probe == nil || resolver.clock == nil {
		return nil, errors.New("first-run Platform capability resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("first-run Platform capability resolution cancelled")
	}
	if _, err := observation.PolicyDigest(policy); err != nil {
		return nil, errors.New("runtime-bound observation policy is invalid")
	}
	if _, err := observation.PlatformProfileDigest(profile); err != nil || profile.IntentRevision != policy.IntentRevision || profile.PlatformRevision != policy.PlatformRevision {
		return nil, errors.New("Platform profile differs from runtime-bound observation policy")
	}
	request := PlatformCapabilityProbeRequest{
		Format: PlatformCapabilityProbeRequestFormat, TargetClusterUID: policy.TargetClusterUID,
		IntentRevision: policy.IntentRevision, PlatformRevision: policy.PlatformRevision,
		ExecutionFixture: profile.ExecutionFixture, ContractDigest: profile.CapabilityContractDigest,
		ExecutableDigest: profile.CapabilityExecutableDigest,
	}
	return &singleUsePlatformCapabilityProbe{probe: resolver.probe, clock: resolver.clock, request: request}, nil
}

type singleUsePlatformCapabilityProbe struct {
	mu       sync.Mutex
	consumed bool
	probe    PlatformCapabilityProbe
	clock    func() time.Time
	request  PlatformCapabilityProbeRequest
}

func (source *singleUsePlatformCapabilityProbe) Capability(ctx context.Context) (observation.PlatformCapabilityState, error) {
	if source == nil || source.probe == nil || source.clock == nil {
		return observation.PlatformCapabilityState{}, errors.New("first-run Platform capability source is required")
	}
	source.mu.Lock()
	if source.consumed {
		source.mu.Unlock()
		return observation.PlatformCapabilityState{}, errors.New("first-run Platform capability source was already consumed")
	}
	source.consumed = true
	source.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return observation.PlatformCapabilityState{}, errors.New("first-run Platform capability execution cancelled")
	}
	result, err := source.probe.Probe(ctx, source.request)
	if err != nil {
		return observation.PlatformCapabilityState{}, errors.New("bounded Platform capability probe failed")
	}
	state := observation.PlatformCapabilityState{
		Format: observation.PlatformCapabilityFormat, ObservedAt: source.clock().UTC().Format(time.RFC3339Nano),
		TargetClusterUID: source.request.TargetClusterUID, IntentRevision: source.request.IntentRevision,
		PlatformRevision: source.request.PlatformRevision, ExecutionFixture: source.request.ExecutionFixture,
		ContractDigest: source.request.ContractDigest, ExecutableDigest: source.request.ExecutableDigest,
		Passed: result.Passed,
	}
	digest, err := observation.PlatformCapabilityDigest(state)
	if err != nil {
		return observation.PlatformCapabilityState{}, errors.New("digest bounded Platform capability result")
	}
	state.EvidenceDigest = digest
	if err := observation.ValidatePlatformCapabilityState(state); err != nil {
		return observation.PlatformCapabilityState{}, errors.New("normalize bounded Platform capability result")
	}
	return state, nil
}

var _ PlatformCapabilityResolver = (*FirstRunPlatformCapabilityResolver)(nil)
var _ observation.PlatformCapabilitySource = (*singleUsePlatformCapabilityProbe)(nil)
