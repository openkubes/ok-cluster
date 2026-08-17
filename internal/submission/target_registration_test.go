package submission

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestLoadTargetRegistrationBindsProjectAndCredentialFreeTemplate(t *testing.T) {
	raw, expected := targetRegistrationFixture(t)
	path := writeTargetRegistrationFixture(t, raw)
	plan, err := LoadTargetRegistration(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != TargetRegistrationPlanFormat || plan.IntentRevision != expected.IntentRevision || plan.PlatformRevision != expected.PlatformRevision || plan.ExecutionFixture != expected.ExecutionFixture || plan.TargetIdentityDigest != expected.TargetIdentityDigest || plan.ArtifactDigest != expected.ArtifactDigest || plan.Authority != "ok-shared" || plan.MutationAllowed {
		t.Fatalf("unexpected target-registration plan: %#v", plan)
	}
	if plan.Project.Identity.Kind != "AppProject" || plan.Project.CollectionPath != "/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects" || plan.Registration.Identity.Kind != "Secret" || plan.Registration.CollectionPath != "/api/v1/namespaces/argocd/secrets" {
		t.Fatalf("unexpected target-registration routes: %#v %#v", plan.Project, plan.Registration)
	}
	if bytes.Contains(plan.Registration.Raw, []byte("bearerToken")) || bytes.Contains(plan.Registration.Raw, []byte("caData")) || bytes.Contains(plan.Registration.Raw, []byte("private-token")) {
		t.Fatal("registration template contains credential material")
	}
}

func TestLoadTargetRegistrationFailsClosed(t *testing.T) {
	t.Run("changed artifact", func(t *testing.T) {
		raw, expected := targetRegistrationFixture(t)
		path := writeTargetRegistrationFixture(t, append(raw, '\n'))
		if _, err := LoadTargetRegistration(path, expected); err == nil {
			t.Fatal("changed target-registration artifact was accepted")
		}
	})

	tests := map[string]func([]map[string]any){
		"wildcard source": func(values []map[string]any) {
			values[0]["spec"].(map[string]any)["sourceRepos"] = []any{"*"}
		},
		"wildcard resource": func(values []map[string]any) {
			values[0]["spec"].(map[string]any)["clusterResourceWhitelist"] = []any{map[string]any{"group": "*", "kind": "*"}}
		},
		"default project allowed": func(values []map[string]any) {
			values[0]["spec"].(map[string]any)["permitOnlyProjectScopedClusters"] = false
		},
		"foreign destination": func(values []map[string]any) {
			values[0]["spec"].(map[string]any)["destinations"].([]any)[0].(map[string]any)["name"] = "foreign"
		},
		"embedded token": func(values []map[string]any) {
			values[1]["stringData"].(map[string]any)["config"] = `{"bearerToken":"private-token"}`
		},
		"runtime UID prefilled": func(values []map[string]any) {
			values[1]["metadata"].(map[string]any)["annotations"].(map[string]any)["openkubes.io/capi-cluster-uid"] = "raw-uid"
		},
		"extra object": func(values []map[string]any) {
			values = append(values, map[string]any{"apiVersion": "v1", "kind": "ConfigMap"})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			raw, expected := targetRegistrationFixture(t)
			values := decodeTargetRegistrationFixture(t, raw)
			if name == "extra object" {
				values = append(values, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "extra"}})
			} else {
				mutate(values)
			}
			changed := encodeTargetRegistrationFixture(t, values)
			expected.ArtifactDigest = digest.SHA256(changed)
			if _, err := LoadTargetRegistration(writeTargetRegistrationFixture(t, changed), expected); err == nil {
				t.Fatal("invalid target-registration artifact was accepted")
			}
		})
	}
}

func targetRegistrationFixture(t *testing.T) ([]byte, TargetRegistrationExpected) {
	t.Helper()
	expected := TargetRegistrationExpected{
		ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision:   targetRegistrationSHA("a"), PlatformRevision: targetRegistrationSHA("b"), ExecutionFixture: targetRegistrationSHA("c"),
		TargetIdentityDigest: targetRegistrationSHA("d"), ArgoAuthority: "ok-shared", ArgoNamespace: "argocd",
		ProjectName: "openkubes-disposable", RegistrationName: "disposable-ok147-cluster", TargetName: "disposable-ok147",
		SourceRepository: "https://github.com/openkubes/ok-observability.git", TargetNamespaces: []string{"ok-observability", "kube-system"},
	}
	baseAnnotations := map[string]any{
		"openkubes.io/intent-revision": expected.IntentRevision, "openkubes.io/platform-revision": expected.PlatformRevision,
		"openkubes.io/execution-fixture": expected.ExecutionFixture, "openkubes.io/target-identity-digest": expected.TargetIdentityDigest,
	}
	project := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "AppProject",
		"metadata": map[string]any{"name": expected.ProjectName, "namespace": expected.ArgoNamespace, "annotations": baseAnnotations},
		"spec": map[string]any{
			"description": "bounded OK-147 target", "permitOnlyProjectScopedClusters": true,
			"sourceRepos": []any{expected.SourceRepository}, "sourceNamespaces": []any{expected.ArgoNamespace},
			"destinations": []any{
				map[string]any{"name": expected.TargetName, "namespace": "ok-observability"},
				map[string]any{"name": expected.TargetName, "namespace": "kube-system"},
			},
			"clusterResourceWhitelist": []any{
				map[string]any{"group": "apiextensions.k8s.io", "kind": "CustomResourceDefinition"},
				map[string]any{"group": "rbac.authorization.k8s.io", "kind": "ClusterRole"},
			},
			"namespaceResourceWhitelist": []any{
				map[string]any{"group": "", "kind": "ConfigMap"},
				map[string]any{"group": "apps", "kind": "Deployment"},
			},
			"orphanedResources": map[string]any{"warn": true},
		},
	}
	secretAnnotations := map[string]any{}
	for key, value := range baseAnnotations {
		secretAnnotations[key] = value
	}
	secretAnnotations["openkubes.io/capi-cluster-uid"] = RegistrationCAPIUIDPlaceholder
	secretAnnotations["openkubes.io/workload-kube-system-uid"] = RegistrationWorkloadUIDPlaceholder
	secretAnnotations["openkubes.io/workload-api-ca-sha256"] = RegistrationCADigestPlaceholder
	secretAnnotations["openkubes.io/token-expiration"] = RegistrationExpirationPlaceholder
	secret := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]any{
			"name": expected.RegistrationName, "namespace": expected.ArgoNamespace,
			"labels": map[string]any{"argocd.argoproj.io/secret-type": "cluster"}, "annotations": secretAnnotations,
		},
		"stringData": map[string]any{
			"name": expected.TargetName, "server": RegistrationEndpointPlaceholder,
			"namespaces": "ok-observability,kube-system", "clusterResources": "true", "project": expected.ProjectName,
			"config": RegistrationConfigPlaceholder,
		},
	}
	raw := encodeTargetRegistrationFixture(t, []map[string]any{project, secret})
	expected.ArtifactDigest = digest.SHA256(raw)
	return raw, expected
}

func encodeTargetRegistrationFixture(t *testing.T, values []map[string]any) []byte {
	t.Helper()
	var result []byte
	for index, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if index > 0 {
			result = append(result, '\n', '-', '-', '-', '\n')
		}
		result = append(result, raw...)
	}
	return result
}

func decodeTargetRegistrationFixture(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	values, err := decodeTargetRegistrationDocuments(raw)
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func writeTargetRegistrationFixture(t *testing.T, raw []byte) string {
	t.Helper()
	path := t.TempDir() + "/target-registration.yaml"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func targetRegistrationSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
