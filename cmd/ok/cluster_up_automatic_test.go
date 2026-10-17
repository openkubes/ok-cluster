package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutomaticUpTerminalAndStartedFencePrecedeTargetReads(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := intentFixture(t, func(raw string) string {
		return strings.Replace(raw, "  profile:", "  management: {kubeconfig: /must-not-read-mgmt}\n  infrastructure: {kubeconfig: /must-not-read-provider}\n  profile:", 1)
	})
	if err := runAutomaticClusterUp(context.Background(), path, io.Discard, io.Discard, guidedUpRuntime{panicConfigReader{}, false}, false); err == nil || !strings.Contains(err.Error(), "requires a terminal") {
		t.Fatal("non-terminal reached preparation")
	}
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "ok", "runs", "my-cluster")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeStaticBindingFile(filepath.Join(root, "execution-started.json"), []byte("retained")); err != nil {
		t.Fatal(err)
	}
	for _, prepareOnly := range []bool{true, false} {
		err := runAutomaticClusterUp(context.Background(), path, io.Discard, io.Discard, guidedUpRuntime{panicConfigReader{}, true}, prepareOnly)
		if err == nil || !strings.Contains(err.Error(), "already started") {
			t.Fatalf("started fence did not precede private target reads: %v", err)
		}
	}
}
