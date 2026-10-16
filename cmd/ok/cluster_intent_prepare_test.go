package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestClusterIntentLocalExecutableDigestIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary")
	raw := []byte("local CLI bytes, not a published image")
	if err := os.WriteFile(path, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := localCLIExecutableDigest(path)
	if err != nil || got != digest.SHA256(raw) {
		t.Fatalf("incorrect executable identity: %s %v", got, err)
	}
	if err := os.WriteFile(path, []byte("different CLI bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	changed, err := localCLIExecutableDigest(path)
	if err != nil || changed == got {
		t.Fatal("executable content change did not change fixture input")
	}
	for _, invalid := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := localCLIExecutableDigest(invalid); err == nil {
			t.Fatal("invalid executable accepted")
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(256*1024*1024 + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err := localCLIExecutableDigest(path); err == nil {
		t.Fatal("oversized executable accepted")
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := localCLIExecutableDigest(path); err == nil {
		t.Fatal("empty executable accepted")
	}
}
