package submission

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

func TestProviderAccessPolicyMaterializesExactSecretAndRewritesNamespace(t *testing.T) {
	root := t.TempDir()
	policyPath, expected := writeProviderAccessPolicy(t, root)
	credentialPath := filepath.Join(root, "provider.kubeconfig")
	if err := os.WriteFile(credentialPath, providerKubeconfig("ok-infra"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadProviderAccessPolicy(policyPath, expected)
	if err != nil {
		t.Fatal(err)
	}
	object, err := policy.MaterializeSecret(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if object.Identity.APIVersion != "v1" || object.Identity.Kind != "Secret" ||
		object.Identity.Namespace != "disposable-ok147" || object.Identity.Name != "external-infra-kubeconfig-disposable-ok147" ||
		object.CollectionPath != "/api/v1/namespaces/disposable-ok147/secrets" ||
		object.ObjectPath != "/api/v1/namespaces/disposable-ok147/secrets/external-infra-kubeconfig-disposable-ok147" ||
		digest.SHA256(object.Raw) != object.Digest {
		t.Fatalf("provider Secret object is not exactly bound: %#v", object)
	}
	var secret struct {
		Immutable bool              `json:"immutable"`
		Type      string            `json:"type"`
		Metadata  map[string]any    `json:"metadata"`
		Data      map[string]string `json:"data"`
	}
	if err := json.Unmarshal(object.Raw, &secret); err != nil {
		t.Fatal(err)
	}
	if !secret.Immutable || secret.Type != "Opaque" || len(secret.Data) != 1 || secret.Data["kubeconfig"] == "" {
		t.Fatalf("provider Secret shape is invalid: %#v", secret)
	}
	rewritten, err := base64.StdEncoding.Strict().DecodeString(secret.Data["kubeconfig"])
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		CurrentContext string `yaml:"current-context"`
		Contexts       []struct {
			Name    string `yaml:"name"`
			Context struct {
				Namespace string `yaml:"namespace"`
			} `yaml:"context"`
		} `yaml:"contexts"`
	}
	if err := yaml.Unmarshal(rewritten, &config); err != nil {
		t.Fatal(err)
	}
	if config.CurrentContext != "provider" || len(config.Contexts) != 1 || config.Contexts[0].Context.Namespace != "disposable-ok147" {
		t.Fatalf("current context namespace was not rewritten exactly: %#v", config)
	}
	if bytes.Contains(object.Raw, []byte("ok-infra\n")) {
		t.Fatal("old provider namespace remained visible in the materialized Secret")
	}
}

func TestProviderAccessMaterializationIsDeterministic(t *testing.T) {
	root := t.TempDir()
	policyPath, expected := writeProviderAccessPolicy(t, root)
	credentialPath := filepath.Join(root, "provider.kubeconfig")
	if err := os.WriteFile(credentialPath, providerKubeconfig("another-namespace"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, _ := LoadProviderAccessPolicy(policyPath, expected)
	first, err := policy.MaterializeSecret(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := policy.MaterializeSecret(credentialPath)
	if err != nil || !bytes.Equal(first.Raw, second.Raw) || first.Digest != second.Digest {
		t.Fatalf("same provider credential did not produce one identity: first=%s second=%s err=%v", first.Digest, second.Digest, err)
	}
}

func TestProviderAccessMaterializationFailsClosedWithoutLeakingCredential(t *testing.T) {
	root := t.TempDir()
	policyPath, expected := writeProviderAccessPolicy(t, root)
	policy, _ := LoadProviderAccessPolicy(policyPath, expected)
	secretMarker := "DO-NOT-LEAK-PRIVATE-KEY-MARKER"
	cases := []struct {
		name string
		raw  []byte
		mode os.FileMode
	}{
		{name: "bad mode", raw: providerKubeconfig("ok-infra"), mode: 0o644},
		{name: "duplicate key", raw: []byte("apiVersion: v1\nkind: Config\nkind: " + secretMarker + "\n"), mode: 0o600},
		{name: "missing current context", raw: []byte("apiVersion: v1\nkind: Config\ncurrent-context: missing\ncontexts: []\nclusters: []\nusers: []\nmarker: " + secretMarker + "\n"), mode: 0o600},
		{name: "duplicate cluster identity", raw: []byte("apiVersion: v1\nkind: Config\ncurrent-context: provider\ncontexts:\n- name: provider\n  context: {cluster: duplicate, user: provider-user}\nclusters:\n- name: duplicate\n  cluster: {}\n- name: duplicate\n  cluster: {}\nusers:\n- name: provider-user\n  user: {token: " + secretMarker + "}\n"), mode: 0o600},
		{name: "trailing document", raw: append(providerKubeconfig("ok-infra"), []byte("---\nmarker: "+secretMarker+"\n")...), mode: 0o600},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-")+".yaml")
			if err := os.WriteFile(path, test.raw, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := policy.MaterializeSecret(path); err == nil || strings.Contains(err.Error(), secretMarker) || strings.Contains(err.Error(), "client-key-data") {
				t.Fatalf("unsafe provider credential did not fail closed and redacted: %v", err)
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(root, "target.yaml")
		link := filepath.Join(root, "link.yaml")
		if err := os.WriteFile(target, providerKubeconfig("ok-infra"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := policy.MaterializeSecret(link); err == nil {
			t.Fatal("provider credential symlink was accepted")
		}
	})
}

func TestProviderAccessPolicyRejectsUnboundOrMutableSecret(t *testing.T) {
	root := t.TempDir()
	policyPath, expected := writeProviderAccessPolicy(t, root)
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	secret := document["secret"].(map[string]any)
	secret["immutable"] = false
	changed, _ := json.Marshal(document)
	changedPath := filepath.Join(root, "mutable.json")
	if err := os.WriteFile(changedPath, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	expected.PolicyDigest = digest.SHA256(changed)
	if _, err := LoadProviderAccessPolicy(changedPath, expected); err == nil {
		t.Fatal("mutable provider Secret policy was accepted")
	}

	expected.PolicyDigest = digest.SHA256(raw)
	expected.ProviderAuthority = expected.ManagementAuthority
	if _, err := LoadProviderAccessPolicy(policyPath, expected); err == nil {
		t.Fatal("same-plane provider and management authority was accepted")
	}
}

func writeProviderAccessPolicy(t *testing.T, root string) (string, ProviderAccessExpected) {
	t.Helper()
	document := providerAccessPolicyDocument{
		Format:              ProviderAccessPolicyFormat,
		ContractIdentity:    contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision:      "sha256:" + strings.Repeat("a", 64),
		ExecutionFixture:    "sha256:" + strings.Repeat("b", 64),
		ManagementAuthority: "ok-mgmt",
		ProviderAuthority:   "ok-infra",
		Secret: providerAccessSecretPolicy{
			APIVersion: "v1", Kind: "Secret", Namespace: "disposable-ok147",
			Name: "external-infra-kubeconfig-disposable-ok147", Type: "Opaque", DataKey: "kubeconfig", Immutable: true,
		},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "provider-access-policy.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, ProviderAccessExpected{
		PolicyDigest: digest.SHA256(raw), ContractIdentity: document.ContractIdentity,
		IntentRevision: document.IntentRevision, ExecutionFixture: document.ExecutionFixture,
		ManagementAuthority: document.ManagementAuthority, ProviderAuthority: document.ProviderAuthority,
	}
}

func providerKubeconfig(namespace string) []byte {
	return []byte(`apiVersion: v1
kind: Config
current-context: provider
clusters:
  - name: provider-cluster
    cluster:
      server: https://provider.example.invalid:6443
      certificate-authority-data: Y2E=
users:
  - name: provider-user
    user:
      client-certificate-data: Y2VydA==
      client-key-data: cHJpdmF0ZS1rZXk=
contexts:
  - name: provider
    context:
      cluster: provider-cluster
      user: provider-user
      namespace: ` + namespace + "\n")
}
