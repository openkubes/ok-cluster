package runner

import (
	"context"
	"errors"
	"sync"

	"github.com/openkubes/ok-cluster/internal/observation"
)

// FullRunWorkloadAuthorityBinder accepts the exact lifecycle-derived private
// authority once the Stage 1-7 prefix has completed. It is an in-process
// handoff only; the binding is never added to a public receipt.
type FullRunWorkloadAuthorityBinder interface {
	BindFullRunWorkloadAuthority(WorkloadAuthorityFileResolverConfig) error
}

// DeferredFullRunWorkloadAuthorityResolver bridges the lifecycle-owned
// authority materializer to the concrete Platform capability factory. It is
// inert until the completed prefix binds one already validated file resolver.
type DeferredFullRunWorkloadAuthorityResolver struct {
	mu       sync.Mutex
	resolver *WorkloadAuthorityFileResolver
}

func NewDeferredFullRunWorkloadAuthorityResolver() *DeferredFullRunWorkloadAuthorityResolver {
	return &DeferredFullRunWorkloadAuthorityResolver{}
}

func (resolver *DeferredFullRunWorkloadAuthorityResolver) BindFullRunWorkloadAuthority(config WorkloadAuthorityFileResolverConfig) error {
	if resolver == nil {
		return errors.New("deferred full-run workload authority resolver is required")
	}
	bound, err := OpenWorkloadAuthorityFileResolver(config)
	if err != nil {
		return errors.New("bind lifecycle-derived full-run workload authority")
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.resolver != nil {
		return errors.New("full-run workload authority is already bound")
	}
	resolver.resolver = bound
	return nil
}

func (resolver *DeferredFullRunWorkloadAuthorityResolver) ResolveWorkloadAuthority(ctx context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
	if resolver == nil {
		return KubernetesAuthorityConfig{}, errors.New("deferred full-run workload authority resolver is required")
	}
	resolver.mu.Lock()
	bound := resolver.resolver
	resolver.mu.Unlock()
	if bound == nil {
		return KubernetesAuthorityConfig{}, errors.New("full-run workload authority is not bound")
	}
	return bound.ResolveWorkloadAuthority(ctx, policy)
}

var _ FullRunWorkloadAuthorityBinder = (*DeferredFullRunWorkloadAuthorityResolver)(nil)
var _ WorkloadAuthorityResolver = (*DeferredFullRunWorkloadAuthorityResolver)(nil)
