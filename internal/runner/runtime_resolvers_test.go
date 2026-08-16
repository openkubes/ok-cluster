package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestWorkloadAuthorityFileResolverBindsRuntimeIdentityAndCA(t *testing.T) {
	root := t.TempDir()
	policy, binding, ca := runtimeWorkloadBindingFixture(t)
	bindingPath := filepath.Join(root, "binding.json")
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	writePlatformJSON(t, bindingPath, binding)
	if err := os.WriteFile(tokenPath, []byte("short-lived-workload-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	bindingDigest, _ := WorkloadAuthorityBindingDigest(binding)
	resolver, err := OpenWorkloadAuthorityFileResolver(WorkloadAuthorityFileResolverConfig{
		Path: bindingPath, ExpectedBindingDigest: bindingDigest, TokenFile: tokenPath, CAFile: caPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := resolver.ResolveWorkloadAuthority(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Endpoint != binding.Endpoint || authority.AuthorityIdentity != policy.TargetClusterUID || authority.CABundleDigest != binding.CABundleDigest || authority.TokenFile != tokenPath || authority.CAFile != caPath {
		t.Fatalf("resolved workload authority differs from binding: %#v", authority)
	}
}

func TestWorkloadAuthorityFileResolverFailsClosedOnTampering(t *testing.T) {
	root := t.TempDir()
	policy, binding, ca := runtimeWorkloadBindingFixture(t)
	bindingPath := filepath.Join(root, "binding.json")
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	writePlatformJSON(t, bindingPath, binding)
	if err := os.WriteFile(tokenPath, []byte("short-lived-workload-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	bindingDigest, _ := WorkloadAuthorityBindingDigest(binding)
	open := func() *WorkloadAuthorityFileResolver {
		resolver, err := OpenWorkloadAuthorityFileResolver(WorkloadAuthorityFileResolverConfig{
			Path: bindingPath, ExpectedBindingDigest: bindingDigest, TokenFile: tokenPath, CAFile: caPath,
		})
		if err != nil {
			t.Fatal(err)
		}
		return resolver
	}

	t.Run("foreign runtime target", func(t *testing.T) {
		foreign := policy
		foreign.TargetClusterUID = "other-cluster-uid"
		if _, err := open().ResolveWorkloadAuthority(context.Background(), foreign); err == nil {
			t.Fatal("foreign target accepted")
		}
	})
	t.Run("changed CA", func(t *testing.T) {
		if err := os.WriteFile(caPath, testCA(t), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := open().ResolveWorkloadAuthority(context.Background(), policy)
		if err == nil || strings.Contains(err.Error(), root) || strings.Contains(err.Error(), binding.Endpoint) {
			t.Fatalf("changed CA accepted or disclosed runtime data: %v", err)
		}
		if err := os.WriteFile(caPath, ca, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("changed binding", func(t *testing.T) {
		changed := binding
		changed.Endpoint = "https://192.0.2.20:6443"
		writePlatformJSON(t, bindingPath, changed)
		_, err := open().ResolveWorkloadAuthority(context.Background(), policy)
		if err == nil || strings.Contains(err.Error(), changed.Endpoint) {
			t.Fatalf("changed binding accepted or disclosed endpoint: %v", err)
		}
		writePlatformJSON(t, bindingPath, binding)
	})
	t.Run("unknown field", func(t *testing.T) {
		raw, _ := json.Marshal(binding)
		raw = append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
		if err := os.WriteFile(bindingPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := open().ResolveWorkloadAuthority(context.Background(), policy); err == nil {
			t.Fatal("unknown workload binding field accepted")
		}
	})
	t.Run("symlink input", func(t *testing.T) {
		writePlatformJSON(t, bindingPath, binding)
		link := filepath.Join(root, "binding-link.json")
		if err := os.Symlink(bindingPath, link); err != nil {
			t.Fatal(err)
		}
		resolver, err := OpenWorkloadAuthorityFileResolver(WorkloadAuthorityFileResolverConfig{
			Path: link, ExpectedBindingDigest: bindingDigest, TokenFile: tokenPath, CAFile: caPath,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resolver.ResolveWorkloadAuthority(context.Background(), policy); err == nil || strings.Contains(err.Error(), root) {
			t.Fatalf("symlink binding accepted or disclosed path: %v", err)
		}
	})
}

func TestWorkloadAuthorityBindingCanonicalIdentity(t *testing.T) {
	_, binding, _ := runtimeWorkloadBindingFixture(t)
	first, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"targetClusterUid":"` + binding.TargetClusterUID + `","endpoint":"` + binding.Endpoint + `","format":"` + binding.Format + `","caBundleDigest":"` + binding.CABundleDigest + `","targetIdentityScheme":"capi-cluster-uid/v1","intentRevision":"` + binding.IntentRevision + `"}`)
	var reordered WorkloadAuthorityBinding
	if err := json.Unmarshal(raw, &reordered); err != nil {
		t.Fatal(err)
	}
	second, err := WorkloadAuthorityBindingDigest(reordered)
	if err != nil || first != second {
		t.Fatalf("equivalent workload binding changed identity: %s %s %v", first, second, err)
	}
	reordered.Endpoint = "https://192.0.2.20:6443"
	third, _ := WorkloadAuthorityBindingDigest(reordered)
	if third == first {
		t.Fatal("semantic endpoint change retained workload binding identity")
	}
}

func TestPlatformCapabilityFileResolverBindsResumeEvidenceAtRuntime(t *testing.T) {
	root := t.TempDir()
	profile := runnerPlatformProfile()
	state := runnerPlatformCapability(t)
	path := filepath.Join(root, "capability.json")
	writePlatformJSON(t, path, state)
	resolver, err := OpenPlatformCapabilityFileResolver(PlatformCapabilityFileResolverConfig{Path: path, ExpectedEvidenceDigest: state.EvidenceDigest})
	if err != nil {
		t.Fatal(err)
	}
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: state.IntentRevision, EnablementRevision: digestOf("e"), PlatformRevision: state.PlatformRevision,
		TargetClusterUID: state.TargetClusterUID, Required: []string{"PlatformReady"},
	}
	source, err := resolver.ResolvePlatformCapability(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := source.Capability(context.Background())
	if err != nil || observed != state {
		t.Fatalf("resume capability differs: %#v %v", observed, err)
	}

	foreign := policy
	foreign.TargetClusterUID = "other-cluster-uid"
	if _, err := resolver.ResolvePlatformCapability(context.Background(), foreign, profile); err == nil || strings.Contains(err.Error(), path) {
		t.Fatalf("foreign capability accepted or disclosed path: %v", err)
	}
	profile.CapabilityExecutableDigest = digestOf("9")
	if _, err := resolver.ResolvePlatformCapability(context.Background(), policy, profile); err == nil {
		t.Fatal("capability from a different executable was accepted")
	}
}

func TestRuntimeFileResolversDoNotReadDuringConstruction(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-created")
	if _, err := OpenWorkloadAuthorityFileResolver(WorkloadAuthorityFileResolverConfig{
		Path: missing, ExpectedBindingDigest: digestOf("a"), TokenFile: missing + "-token", CAFile: missing + "-ca",
	}); err != nil {
		t.Fatalf("workload resolver performed eager input validation: %v", err)
	}
	if _, err := OpenPlatformCapabilityFileResolver(PlatformCapabilityFileResolverConfig{Path: missing, ExpectedEvidenceDigest: digestOf("b")}); err != nil {
		t.Fatalf("Platform resolver performed eager input validation: %v", err)
	}
}

func runtimeWorkloadBindingFixture(t *testing.T) (observation.Policy, WorkloadAuthorityBinding, []byte) {
	t.Helper()
	ca := testCA(t)
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: digestOf("a"), EnablementRevision: digestOf("b"), PlatformRevision: digestOf("c"),
		TargetClusterUID: "cluster-uid-disposable-ok147", Required: []string{"NetworkReady"},
	}
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: policy.IntentRevision,
		TargetClusterUID: policy.TargetClusterUID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: "https://192.0.2.10:6443", CABundleDigest: digest.SHA256(ca),
	}
	return policy, binding, ca
}
