package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeferredFullRunWorkloadAuthorityBindsLifecycleResultOnce(t *testing.T) {
	root := t.TempDir()
	policy, binding, ca := runtimeWorkloadBindingFixture(t)
	bindingPath := filepath.Join(root, "binding.json")
	kubeconfigPath := filepath.Join(root, "workload.kubeconfig")
	caPath := filepath.Join(root, "ca.crt")
	writePlatformJSON(t, bindingPath, binding)
	if err := os.WriteFile(kubeconfigPath, []byte("lifecycle-derived-kubeconfig"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	config := WorkloadAuthorityFileResolverConfig{
		Path: bindingPath, ExpectedBindingDigest: bindingDigest, KubeconfigFile: kubeconfigPath, CAFile: caPath,
	}

	resolver := NewDeferredFullRunWorkloadAuthorityResolver()
	if _, err := resolver.ResolveWorkloadAuthority(context.Background(), policy); err == nil {
		t.Fatal("unbound full-run workload authority resolved")
	}
	if err := resolver.BindFullRunWorkloadAuthority(config); err != nil {
		t.Fatal(err)
	}
	authority, err := resolver.ResolveWorkloadAuthority(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Endpoint != binding.Endpoint || authority.AuthorityIdentity != binding.TargetClusterUID || authority.KubeconfigFile != kubeconfigPath || authority.TokenFile != "" || authority.CABundleDigest != binding.CABundleDigest {
		t.Fatalf("deferred full-run authority differs from lifecycle binding: %#v", authority)
	}
	if err := resolver.BindFullRunWorkloadAuthority(config); err == nil {
		t.Fatal("deferred full-run workload authority rebound")
	}
	foreign := policy
	foreign.TargetClusterUID = "foreign-cluster-uid"
	if _, err := resolver.ResolveWorkloadAuthority(context.Background(), foreign); err == nil || strings.Contains(err.Error(), binding.Endpoint) || strings.Contains(err.Error(), root) {
		t.Fatalf("foreign runtime target was accepted or private data disclosed: %v", err)
	}
}

func TestDeferredFullRunWorkloadAuthorityRejectsInvalidBindingWithoutReading(t *testing.T) {
	resolver := NewDeferredFullRunWorkloadAuthorityResolver()
	missing := filepath.Join(t.TempDir(), "not-created")
	config := WorkloadAuthorityFileResolverConfig{
		Path: missing, ExpectedBindingDigest: digestOf("a"), KubeconfigFile: missing + "-kubeconfig", CAFile: missing + "-ca",
	}
	if err := resolver.BindFullRunWorkloadAuthority(config); err != nil {
		t.Fatalf("binding performed an eager private file read: %v", err)
	}
	if err := NewDeferredFullRunWorkloadAuthorityResolver().BindFullRunWorkloadAuthority(WorkloadAuthorityFileResolverConfig{}); err == nil {
		t.Fatal("invalid lifecycle authority binding was accepted")
	}
}
