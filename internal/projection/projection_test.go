package projection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestVerifyBindsArtifactsAndAuthority(t *testing.T) {
	root := t.TempDir()
	identity := contract.Identity{Namespace: "disposable-ok141", Name: "disposable-ok141"}
	revision := "sha256:" + strings.Repeat("1", 64)
	authority := authorityMap{
		Format:           "ok141-contract-to-capi-projection/v2",
		ContractIdentity: identity,
		IntentRevision:   revision,
		InfrastructurePlane: plane{Identity: "ok-infra", Role: "provider-runtime-and-golden-image-prerequisites", Resources: []resource{
			{APIVersion: "v1", Kind: "Namespace", Name: identity.Name},
		}},
		ManagementPlane: plane{Identity: "ok-mgmt", Role: "single-lifecycle-writer", Resources: []resource{
			{APIVersion: "v1", Kind: "Namespace", Name: identity.Name},
			{APIVersion: "cluster.x-k8s.io/v1beta2", Kind: "Cluster", Namespace: identity.Namespace, Name: identity.Name},
		}},
		ProviderAccess:            json.RawMessage(`{}`),
		ExcludedRendererArtifacts: json.RawMessage(`[]`),
	}
	authorityRaw, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "authority-map.json", authorityRaw)
	writeFile(t, root, "ok-infra-prerequisites.yaml", []byte("infra\n"))
	writeFile(t, root, "ok-mgmt-lifecycle.yaml", []byte("mgmt\n"))

	source := manifest{
		Format:             authority.Format,
		R:                  revision,
		AuthorizationState: "NO-GO",
		Artifacts: map[string]string{
			"authority-map.json":          digest.SHA256(authorityRaw),
			"ok-infra-prerequisites.yaml": digest.SHA256([]byte("infra\n")),
			"ok-mgmt-lifecycle.yaml":      digest.SHA256([]byte("mgmt\n")),
		},
		ObjectSets: map[string]objectSet{
			"okInfraPrerequisites": {Count: 1, Digest: "sha256:" + strings.Repeat("2", 64)},
			"okMgmtLifecycle":      {Count: 2, Digest: "sha256:" + strings.Repeat("3", 64)},
		},
		ProviderAccess: json.RawMessage(`{}`),
		Source:         json.RawMessage(`{}`),
	}
	manifestRaw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := writeFile(t, root, "projection-manifest.json", manifestRaw)

	binding, err := Verify(manifestPath, root, revision, identity)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Format != BindingFormat || binding.ManagementPlane.Role != "single-lifecycle-writer" || binding.InfrastructurePlane.Identity != "ok-infra" {
		t.Fatalf("unexpected binding: %#v", binding)
	}

	writeFile(t, root, "ok-mgmt-lifecycle.yaml", []byte("tampered\n"))
	if _, err := Verify(manifestPath, root, revision, identity); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestVerifyRejectsArtifactTraversal(t *testing.T) {
	root := t.TempDir()
	source := manifest{
		Format:             "ok141-contract-to-capi-projection/v2",
		R:                  "sha256:" + strings.Repeat("1", 64),
		AuthorizationState: "NO-GO",
		Artifacts:          map[string]string{"../authority-map.json": "sha256:" + strings.Repeat("2", 64)},
		ObjectSets:         map[string]objectSet{},
		ProviderAccess:     json.RawMessage(`{}`),
		Source:             json.RawMessage(`{}`),
	}
	raw, _ := json.Marshal(source)
	path := writeFile(t, root, "projection-manifest.json", raw)
	_, err := Verify(path, root, source.R, contract.Identity{Name: "x", Namespace: "x"})
	if err == nil || !strings.Contains(err.Error(), "plain file name") {
		t.Fatalf("expected path rejection, got %v", err)
	}
}

func writeFile(t *testing.T, root, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
