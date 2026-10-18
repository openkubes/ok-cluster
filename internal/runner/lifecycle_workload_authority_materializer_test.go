package runner

import (
	"context"
	"errors"
	"testing"
)

func TestKubernetesLifecycleWorkloadAuthorityMaterializerRejectsBeforeAPIContact(t *testing.T) {
	materializer, err := OpenKubernetesLifecycleWorkloadAuthorityMaterializer(KubernetesLifecycleWorkloadAuthorityMaterializerConfig{})
	if !errors.Is(err, ErrClientCertificateDisabled) || materializer != nil {
		t.Fatalf("unsupported materializer constructed: %v", err)
	}
	files, err := (&KubernetesLifecycleWorkloadAuthorityMaterializer{}).ResolvePreRuntimeWorkloadAuthority(context.Background(), StageResumeConfig{})
	if !errors.Is(err, ErrClientCertificateDisabled) || files != (WorkloadAuthorityFileResolverConfig{}) {
		t.Fatalf("unsupported bootstrap resolved files: %v", err)
	}
}
