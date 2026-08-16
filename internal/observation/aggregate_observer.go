package observation

import (
	"context"
	"errors"
	"time"
)

// CAPIEvidenceSource owns only the two CAPI lifecycle statements.
type CAPIEvidenceSource interface {
	Collect(context.Context, Policy) ([]Evidence, error)
}

// NetworkEvidenceSource owns only the bounded NetworkReady statement.
type NetworkEvidenceSource interface {
	Observe(context.Context, Policy, NetworkProfile) (Evidence, error)
}

// PlatformEvidenceSource owns only the bounded PlatformReady statement. Its
// concrete GitOps adapter remains a separate mechanism checkpoint.
type PlatformEvidenceSource interface {
	Observe(context.Context, Policy) (Evidence, error)
}

// AggregateObserverConfig contains the complete set of authoritative source
// adapters. There is no permissive default or persistent status surface.
type AggregateObserverConfig struct {
	CAPI           CAPIEvidenceSource
	Network        NetworkEvidenceSource
	Platform       PlatformEvidenceSource
	NetworkProfile NetworkProfile
	Clock          func() time.Time
}

// AggregateObserver performs one bounded source pass and immediately applies
// the deterministic aggregate evaluator. It does not poll, retry, publish
// status, or repair any source resource.
type AggregateObserver struct {
	config AggregateObserverConfig
}

func NewAggregateObserver(config AggregateObserverConfig) (*AggregateObserver, error) {
	if config.CAPI == nil || config.Network == nil || config.Platform == nil || config.Clock == nil {
		return nil, errors.New("aggregate observer sources and clock are required")
	}
	return &AggregateObserver{config: config}, nil
}

func (observer *AggregateObserver) Observe(ctx context.Context, policy Policy) (VerifiedResult, error) {
	if err := validatePolicy(policy, true); err != nil {
		return VerifiedResult{}, err
	}
	required := make(map[string]struct{}, len(policy.Required))
	for _, condition := range policy.Required {
		required[condition] = struct{}{}
	}
	evidenceByType := make(map[string][]Evidence, len(policy.Required))

	if requiresAny(required, "InfrastructureReady", "ControlPlaneAvailable") {
		items, err := observer.config.CAPI.Collect(ctx, policy)
		if err != nil {
			return VerifiedResult{}, errors.New("collect bounded CAPI evidence")
		}
		if len(items) > 2 {
			return VerifiedResult{}, errors.New("CAPI source exceeded its evidence boundary")
		}
		for _, item := range items {
			if item.Type != "InfrastructureReady" && item.Type != "ControlPlaneAvailable" {
				return VerifiedResult{}, errors.New("CAPI source returned evidence outside its ownership domain")
			}
			if _, wanted := required[item.Type]; wanted {
				evidenceByType[item.Type] = append(evidenceByType[item.Type], item)
			}
		}
	}
	if _, wanted := required["NetworkReady"]; wanted {
		item, err := observer.config.Network.Observe(ctx, policy, observer.config.NetworkProfile)
		if err != nil {
			return VerifiedResult{}, errors.New("collect bounded NetworkReady evidence")
		}
		if item.Type != "NetworkReady" {
			return VerifiedResult{}, errors.New("Network source returned evidence outside its ownership domain")
		}
		evidenceByType[item.Type] = append(evidenceByType[item.Type], item)
	}
	if _, wanted := required["PlatformReady"]; wanted {
		item, err := observer.config.Platform.Observe(ctx, policy)
		if err != nil {
			return VerifiedResult{}, errors.New("collect bounded PlatformReady evidence")
		}
		if item.Type != "PlatformReady" {
			return VerifiedResult{}, errors.New("Platform source returned evidence outside its ownership domain")
		}
		evidenceByType[item.Type] = append(evidenceByType[item.Type], item)
	}

	evidence := make([]Evidence, 0, len(policy.Required))
	for _, condition := range policy.Required {
		evidence = append(evidence, evidenceByType[condition]...)
	}
	bundle := Bundle{
		Format: BundleFormat, IntentRevision: policy.IntentRevision,
		EvaluatedAt: observer.config.Clock().UTC().Format(time.RFC3339Nano), Evidence: evidence,
	}
	return Evaluate(policy, bundle)
}

func requiresAny(required map[string]struct{}, conditions ...string) bool {
	for _, condition := range conditions {
		if _, exists := required[condition]; exists {
			return true
		}
	}
	return false
}
