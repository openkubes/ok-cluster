package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pre-existing chart (including a suspicious one) is never changed by
// automatic preparation. Its identity remains the provision verifier's job.
func TestPrepareMissingProvisionChartExistingArtifactsAreNotRepaired(t *testing.T) {
	for _, test := range []struct {
		name    string
		symlink bool
	}{
		{name: "regular"},
		{name: "symlink", symlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			cache := filepath.Join(root, ".tools")
			if err := os.Mkdir(cache, 0o700); err != nil {
				t.Fatal(err)
			}
			chart := filepath.Join(cache, "cilium-1.19.6.tgz")
			source := filepath.Join(root, "source")
			if err := os.WriteFile(source, []byte("not a verified chart"), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.symlink {
				if err := os.Symlink(source, chart); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(chart, []byte("not a verified chart"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rt := clusterProvisionRuntime{makeRoot: root}
			if err := prepareMissingProvisionChart(context.Background(), rt, &strings.Builder{}); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(chart)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != "not a verified chart" {
				t.Fatalf("unexpected chart mutation: %q", raw)
			}
		})
	}
}

func TestPrepareMissingProvisionChartRejectsUnsafeCacheDirectory(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	if err := os.Symlink(other, filepath.Join(root, ".tools")); err != nil {
		t.Fatal(err)
	}
	rt := clusterProvisionRuntime{makeRoot: root}
	err := prepareMissingProvisionChart(context.Background(), rt, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("expected unsafe cache directory: %v", err)
	}
}

func TestPrepareMissingProvisionChartRejectsUnreviewedSourceBeforeDownload(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".tools"), 0o700); err != nil {
		t.Fatal(err)
	}
	rt := clusterProvisionRuntime{makeRoot: root}
	err := prepareMissingProvisionChart(context.Background(), rt, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "unreviewed CLI checkout") {
		t.Fatalf("expected source rejection: %v", err)
	}
}
