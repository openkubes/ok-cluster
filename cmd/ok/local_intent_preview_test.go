package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const previewFixture = `apiVersion: cli.openkubes.io/v1alpha1
kind: Cluster
metadata:
  name: preview-test
spec:
  profile: talos-kubevirt-mvp
  network:
    endpoint: 192.0.2.10
    podCIDR: 10.42.0.0/16
    serviceCIDR: 10.96.0.0/20
`

func TestLocalIntentPreviewDoesNotWriteOrClaimAuthority(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openkubes.yaml")
	if err := os.WriteFile(path, []byte(previewFixture), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(dir)
	if err != nil { t.Fatal(err) }
	var output, diagnostic bytes.Buffer
	if err := runLocalIntentPreview(nil, dir, &output, &diagnostic); err != nil { t.Fatal(err) }
	var receipt struct {
		Format string `json:"format"`
		State string `json:"state"`
		Name string `json:"name"`
		LocalIntentDigest string `json:"localIntentDigest"`
		AuthorityVerified bool `json:"authorityVerified"`
		APIContacted bool `json:"apiContacted"`
		AuthorizationConsumed bool `json:"authorizationConsumed"`
		MutationAllowed bool `json:"mutationAllowed"`
	}
	if err := json.Unmarshal(output.Bytes(), &receipt); err != nil { t.Fatal(err) }
	if receipt.Format != "ok-cli-local-intent-preview/v1" || receipt.State != "LOCAL_VALIDATION_ONLY" || receipt.Name != "preview-test" ||
		!strings.HasPrefix(receipt.LocalIntentDigest, "sha256:") ||
		receipt.AuthorityVerified || receipt.APIContacted || receipt.AuthorizationConsumed || receipt.MutationAllowed {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	after, err := os.ReadDir(dir)
	if err != nil { t.Fatal(err) }
	if len(before) != len(after) { t.Fatalf("local preview wrote files: before=%d after=%d", len(before), len(after)) }
	var alias bytes.Buffer
	if err := runLocalIntentPreview([]string{"-f", path}, dir, &alias, &diagnostic); err != nil { t.Fatal(err) }
	if output.String() != alias.String() { t.Fatalf("default and explicit file differ:\n%s\n%s", output.String(), alias.String()) }
}

func TestLocalIntentPreviewRejectsInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{nil, {"--file", ""}, {"--file", "missing.yaml"}, {"--file", "a", "-f", "b"}, {"unexpected"}} {
		if err := runLocalIntentPreview(args, dir, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Errorf("expected error for %v", args)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "openkubes.yaml"), []byte("invalid: true\n"), 0600); err != nil { t.Fatal(err) }
	if err := runLocalIntentPreview(nil, dir, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("malformed authoring must fail")
	}
}

func TestLocalIntentPreviewRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "original.yaml")
	if err := os.WriteFile(file, []byte(previewFixture), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(file, filepath.Join(dir, "openkubes.yaml")); err != nil { t.Skipf("symlink unsupported: %v", err) }
	if err := runLocalIntentPreview(nil, dir, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("symlink authoring path must be rejected")
	}
}
