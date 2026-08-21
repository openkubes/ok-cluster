package stageauthority

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildRuntimePackageBindsPrivateSecretAndRestartSafeRuntime(t *testing.T) {
	config := runtimePackageFixture(t)
	packaged, err := BuildRuntimePackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "VERIFIED" || receipt.PackageDigest != digest.SHA256(raw) || receipt.PolicyDigest != config.ExpectedPolicyDigest ||
		receipt.PrivateFileCount != 5 || len(receipt.ObjectKinds) != 6 || receipt.MutationAllowed {
		t.Fatalf("unexpected package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 {
		t.Fatal("private Secret and runtime objects were not separated")
	}
	var secret map[string]any
	if err := json.Unmarshal(parts[0], &secret); err != nil || secret["kind"] != "Secret" || secret["immutable"] != true {
		t.Fatalf("unexpected private Secret: %#v %v", secret, err)
	}
	runtime := string(parts[1])
	for _, required := range []string{
		"kind: PersistentVolumeClaim", "kind: StatefulSet", "replicas: 1", "automountServiceAccountToken: false",
		"readOnlyRootFilesystem: true", "egress: []", "authority\n            - stage\n            - materialize",
		"/var/lib/openkubes/stage-authority/claims", config.ImageDigest, config.ExpectedPolicyDigest,
	} {
		if !strings.Contains(runtime, required) {
			t.Fatalf("runtime envelope lacks %q", required)
		}
	}
	if strings.Contains(runtime, "${") {
		t.Fatal("runtime envelope retained a placeholder")
	}
}

func TestBuildRuntimePackageRejectsChangedTemplateAndMutableIdentity(t *testing.T) {
	config := runtimePackageFixture(t)
	config.Template = append(config.Template, '\n')
	if _, err := BuildRuntimePackage(config); err == nil {
		t.Fatal("changed template was accepted under old digest")
	}
	config = runtimePackageFixture(t)
	config.ImageDigest = "ghcr.io/openkubes/ok-cluster-runner:latest"
	if _, err := BuildRuntimePackage(config); err == nil {
		t.Fatal("mutable image was accepted")
	}
}

func runtimePackageFixture(t *testing.T) RuntimePackageConfig {
	t.Helper()
	material := testMaterial(t)
	root := t.TempDir()
	certRaw, tlsKeyRaw := selfSignedTLS(t)
	certPath := writeFile(t, root, "tls.crt", certRaw, 0o644)
	tlsKeyPath := writeFile(t, root, "tls.key", tlsKeyRaw, 0o600)
	template, err := os.ReadFile(filepath.Join("..", "..", "deploy", "bounded-stage-authority.yaml.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	return RuntimePackageConfig{
		PolicyPath: material.config.PolicyPath, ExpectedPolicyDigest: material.config.ExpectedPolicyDigest,
		PrivateKeyPath: material.config.PrivateKeyPath, TokenFile: material.config.TokenFile,
		TLSCertPath: certPath, TLSKeyPath: tlsKeyPath, Template: template, TemplateDigest: digest.SHA256(template),
		ImageDigest: "ghcr.io/openkubes/ok-cluster-runner@sha256:" + strings.Repeat("a", 64),
		Namespace:   "openkubes-execution-system", Name: "ok147-stage-authority", PrivateSecret: "ok147-stage-authority-private",
		StorageClass: "local-path", StorageRequest: "64Mi",
	}
}
