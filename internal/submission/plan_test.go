package submission

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
)

func TestLoadBindsExactProjectionObjectsAndRoutes(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != PlanFormat || plan.IntentRevision != binding.IntentRevision {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if len(plan.Infrastructure.Objects) != 1 || plan.Infrastructure.Objects[0].CollectionPath != "/api/v1/namespaces" {
		t.Fatalf("unexpected infrastructure objects: %#v", plan.Infrastructure.Objects)
	}
	if len(plan.Management.Objects) != 1 || plan.Management.Objects[0].ObjectPath != "/apis/cluster.x-k8s.io/v1beta2/namespaces/disposable-ok141/clusters/disposable-ok141" {
		t.Fatalf("unexpected management objects: %#v", plan.Management.Objects)
	}
}

func TestLoadReverifiesArtifactAtUseTime(t *testing.T) {
	root, binding := validProjection(t)
	path := filepath.Join(root, "ok-infra-prerequisites.yaml")
	if err := os.WriteFile(path, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, binding); err == nil || !strings.Contains(err.Error(), "changed after verification") {
		t.Fatalf("tampered projection accepted: %v", err)
	}
}

func TestLoadFailsClosedForIdentityAndYAMLGaps(t *testing.T) {
	for name, mutate := range map[string]func(string, *projection.Binding){
		"authority identity mismatch": func(_ string, binding *projection.Binding) {
			binding.ManagementPlane.Identity = "different"
		},
		"projection object differs from authority map": func(root string, binding *projection.Binding) {
			path := filepath.Join(root, "ok-mgmt-lifecycle.yaml")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = []byte(strings.Replace(string(raw), "apiVersion: cluster.x-k8s.io/v1beta2\nkind: Cluster", "apiVersion: apps/v1\nkind: Deployment", 1))
			writeBoundArtifact(t, root, "ok-mgmt-lifecycle.yaml", raw, binding)
		},
		"incomplete resource inventory": func(_ string, binding *projection.Binding) {
			binding.ManagementPlane.ResourceCount = 0
		},
		"alias in YAML": func(root string, binding *projection.Binding) {
			raw := []byte("apiVersion: v1\nkind: Namespace\nmetadata: &meta\n  name: disposable-ok141\n  annotations:\n    openkubes.io/contract-name: disposable-ok141\n    openkubes.io/contract-namespace: disposable-ok141\n    openkubes.io/intent-revision: " + binding.IntentRevision + "\n")
			writeBoundArtifact(t, root, "ok-infra-prerequisites.yaml", raw, binding)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, binding := validProjection(t)
			mutate(root, &binding)
			if _, err := Load(root, binding); err == nil {
				t.Fatal("unsafe projection accepted")
			}
		})
	}
}

func TestLoadReconstructsUnsignedInMemoryResourceInventory(t *testing.T) {
	root, binding := validProjection(t)
	binding.ManagementPlane.Resources[0].Name = "tampered-in-memory"
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Management.Objects[0].Identity.Name != "disposable-ok141" {
		t.Fatalf("unsigned in-memory identity became authoritative: %#v", plan.Management.Objects[0].Identity)
	}
}

func TestAllowedResourceRoutesAreExact(t *testing.T) {
	for key, expected := range map[projection.ResourceIdentity]string{
		{APIVersion: "v1", Kind: "Namespace", Name: "disposable-ok141"}:                                                                            "/api/v1/namespaces",
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "ok-images", Name: "cloner"}:                                         "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-images/roles",
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "ok-images", Name: "cloner"}:                                  "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-images/rolebindings",
		{APIVersion: "cluster.x-k8s.io/v1beta2", Kind: "Cluster", Namespace: "disposable-ok141", Name: "disposable-ok141"}:                         "/apis/cluster.x-k8s.io/v1beta2/namespaces/disposable-ok141/clusters",
		{APIVersion: "cluster.x-k8s.io/v1beta2", Kind: "MachineDeployment", Namespace: "disposable-ok141", Name: "workers"}:                        "/apis/cluster.x-k8s.io/v1beta2/namespaces/disposable-ok141/machinedeployments",
		{APIVersion: "infrastructure.cluster.x-k8s.io/v1alpha1", Kind: "KubevirtCluster", Namespace: "disposable-ok141", Name: "disposable-ok141"}: "/apis/infrastructure.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/kubevirtclusters",
		{APIVersion: "infrastructure.cluster.x-k8s.io/v1alpha1", Kind: "KubevirtMachineTemplate", Namespace: "disposable-ok141", Name: "template"}: "/apis/infrastructure.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/kubevirtmachinetemplates",
		{APIVersion: "controlplane.cluster.x-k8s.io/v1alpha3", Kind: "TalosControlPlane", Namespace: "disposable-ok141", Name: "cp"}:               "/apis/controlplane.cluster.x-k8s.io/v1alpha3/namespaces/disposable-ok141/taloscontrolplanes",
		{APIVersion: "bootstrap.cluster.x-k8s.io/v1alpha3", Kind: "TalosConfigTemplate", Namespace: "disposable-ok141", Name: "workers"}:           "/apis/bootstrap.cluster.x-k8s.io/v1alpha3/namespaces/disposable-ok141/talosconfigtemplates",
	} {
		collection, _, err := resourcePaths(key)
		if err != nil || collection != expected {
			t.Fatalf("route for %#v = %q %v, want %q", key, collection, err, expected)
		}
	}
	if _, _, err := resourcePaths(projection.ResourceIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "x", Name: "x"}); err == nil {
		t.Fatal("arbitrary resource route accepted")
	}
}

func validProjection(t *testing.T) (string, projection.Binding) {
	t.Helper()
	root := t.TempDir()
	revision := "sha256:" + strings.Repeat("1", 64)
	identity := contract.Identity{Name: "disposable-ok141", Namespace: "disposable-ok141"}
	infra := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: disposable-ok141\n  annotations:\n    openkubes.io/contract-name: disposable-ok141\n    openkubes.io/contract-namespace: disposable-ok141\n    openkubes.io/intent-revision: " + revision + "\n")
	mgmt := []byte("apiVersion: cluster.x-k8s.io/v1beta2\nkind: Cluster\nmetadata:\n  name: disposable-ok141\n  namespace: disposable-ok141\n  annotations:\n    openkubes.io/contract-name: disposable-ok141\n    openkubes.io/contract-namespace: disposable-ok141\n    openkubes.io/intent-revision: " + revision + "\nspec:\n  clusterNetwork:\n    services:\n      cidrBlocks: [10.100.0.0/20]\n")
	if err := os.WriteFile(filepath.Join(root, "ok-infra-prerequisites.yaml"), infra, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok-mgmt-lifecycle.yaml"), mgmt, 0o600); err != nil {
		t.Fatal(err)
	}
	authority, err := json.Marshal(map[string]any{
		"format":           "ok141-contract-to-capi-projection/v2",
		"contractIdentity": identity,
		"intentRevision":   revision,
		"infrastructurePlane": map[string]any{
			"identity": "ok-infra", "role": "provider-runtime-and-golden-image-prerequisites",
			"resources": []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "name": "disposable-ok141"}},
		},
		"managementPlane": map[string]any{
			"identity": "ok-mgmt", "role": "single-lifecycle-writer",
			"resources": []map[string]any{{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "name": "disposable-ok141", "namespace": "disposable-ok141"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "authority-map.json"), authority, 0o600); err != nil {
		t.Fatal(err)
	}
	binding := projection.Binding{
		Format: projection.BindingFormat, SourceFormat: "ok141-contract-to-capi-projection/v2", IntentRevision: revision, ContractIdentity: identity,
		AuthorityMapDigest: digest.SHA256(authority),
		InfrastructurePlane: projection.Plane{Identity: "ok-infra", Role: "provider-runtime-and-golden-image-prerequisites", ResourceCount: 1, Resources: []projection.ResourceIdentity{
			{APIVersion: "v1", Kind: "Namespace", Name: "disposable-ok141"},
		}},
		ManagementPlane: projection.Plane{Identity: "ok-mgmt", Role: "single-lifecycle-writer", ResourceCount: 1, Resources: []projection.ResourceIdentity{
			{APIVersion: "cluster.x-k8s.io/v1beta2", Kind: "Cluster", Name: "disposable-ok141", Namespace: "disposable-ok141"},
		}},
		Artifacts: []projection.Artifact{
			{Name: "authority-map.json", Digest: digest.SHA256(authority)},
			{Name: "ok-infra-prerequisites.yaml", Digest: digest.SHA256(infra)},
			{Name: "ok-mgmt-lifecycle.yaml", Digest: digest.SHA256(mgmt)},
		},
	}
	return root, binding
}

func writeBoundArtifact(t *testing.T, root, name string, raw []byte, binding *projection.Binding) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for index := range binding.Artifacts {
		if binding.Artifacts[index].Name == name {
			binding.Artifacts[index].Digest = digest.SHA256(raw)
			return
		}
	}
	t.Fatalf("artifact %s not found", name)
}
