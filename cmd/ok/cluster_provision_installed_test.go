package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveProvisionMakeRootColocatedBinary(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, ".tools", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveProvisionMakeRoot(filepath.Join(bin, "ok"), "")
	if err != nil || got != root {
		t.Fatalf("colocated root: got %q, err %v", got, err)
	}
}

func TestResolveProvisionMakeRootInstalledBinaryRequiresExplicitSource(t *testing.T) {
	_, err := resolveProvisionMakeRoot("/usr/local/bin/ok", "")
	if err == nil || !strings.Contains(err.Error(), "OK_CLUSTER_HOME") {
		t.Fatalf("expected explicit checkout guidance: %v", err)
	}
}

func TestResolveProvisionMakeRootInstalledBinaryExplicitCheckout(t *testing.T) {
	root := t.TempDir()
	got, err := resolveProvisionMakeRoot("/usr/local/bin/ok", root)
	if err != nil || got != root {
		t.Fatalf("installed root: got %q, err %v", got, err)
	}
}

func TestResolveProvisionMakeRootRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	for _, configured := range []string{
		"relative/ok-cluster", root + "/../" + filepath.Base(root),
		filepath.Join(root, "not-found"),
	} {
		if _, err := resolveProvisionMakeRoot("/usr/local/bin/ok", configured); err == nil {
			t.Errorf("accepted unsafe configured path %q", configured)
		}
	}
}

func TestResolveProvisionMakeRootNoSymlinkCache(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "checkout")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	// The path is resolved, and all other source/commit checks happen later.
	got, err := resolveProvisionMakeRoot("/usr/local/bin/ok", link)
	if err != nil || got != directory {
		t.Fatalf("expected canonical directory: %q, %v", got, err)
	}
}
