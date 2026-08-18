package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestMaterializePostRuntimeExecutionBundleConvertsProjectionToPrivateWorkspace(t *testing.T) {
	config, index := postRuntimeMaterializerFixture(t)
	receipt, err := MaterializePostRuntimeExecutionBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != PostRuntimeExecutionBundleReceiptFormat || receipt.State != "MATERIALIZED_VERIFIED" ||
		receipt.BundleDigest != config.ExpectedBundleDigest || receipt.ManifestDigest != index.ManifestDigest ||
		receipt.FileCount != len(postRuntimeExecutionBundleFiles) || receipt.TotalBytes == 0 || receipt.KubernetesMutationAllowed {
		t.Fatalf("unexpected post-runtime bundle receipt: %#v", receipt)
	}
	for _, relative := range postRuntimeExecutionBundleFiles {
		info, err := os.Lstat(filepath.Join(config.DestinationDirectory, relative))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("materialized file %q is not private regular input: %v %#v", relative, err, info)
		}
	}
	for _, relative := range []string{".", "activation", "credentials", "input", "work", "work/authorizations", "work/receipts"} {
		info, err := os.Lstat(filepath.Join(config.DestinationDirectory, relative))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			t.Fatalf("materialized directory %q is not private: %v %#v", relative, err, info)
		}
	}
}

func TestMaterializePostRuntimeExecutionBundleFailsClosedBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *PostRuntimeExecutionBundleMaterializationConfig, *postRuntimeExecutionBundleIndex){
		"wrong bundle digest": func(_ *testing.T, config *PostRuntimeExecutionBundleMaterializationConfig, _ *postRuntimeExecutionBundleIndex) {
			config.ExpectedBundleDigest = runnerStageSHA("f")
		},
		"changed file": func(t *testing.T, config *PostRuntimeExecutionBundleMaterializationConfig, _ *postRuntimeExecutionBundleIndex) {
			projected := filepath.Join(config.SourceDirectory, postRuntimeExecutionBundleFiles[1])
			resolved, err := filepath.EvalSymlinks(projected)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(resolved, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"existing destination": func(t *testing.T, config *PostRuntimeExecutionBundleMaterializationConfig, _ *postRuntimeExecutionBundleIndex) {
			if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"nested destination": func(_ *testing.T, config *PostRuntimeExecutionBundleMaterializationConfig, _ *postRuntimeExecutionBundleIndex) {
			config.DestinationDirectory = filepath.Join(config.SourceDirectory, "workspace")
		},
		"escaped projection": func(t *testing.T, config *PostRuntimeExecutionBundleMaterializationConfig, _ *postRuntimeExecutionBundleIndex) {
			path := filepath.Join(config.SourceDirectory, postRuntimeExecutionBundleFiles[1])
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, index := postRuntimeMaterializerFixture(t)
			mutate(t, &config, &index)
			receipt, err := MaterializePostRuntimeExecutionBundle(config)
			if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
				t.Fatalf("unsafe materialization was accepted: %#v %v", receipt, err)
			}
			if _, statErr := os.Lstat(config.DestinationDirectory); name != "existing destination" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed preflight wrote destination: %v", statErr)
			}
		})
	}
}

func TestMaterializePostRuntimeExecutionBundlePreservesPartialState(t *testing.T) {
	config, _ := postRuntimeMaterializerFixture(t)
	// Block one nested output only after the destination has been created by
	// selecting a parent that cannot be written by this process.
	parent := filepath.Dir(config.DestinationDirectory)
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0o700)
	receipt, err := MaterializePostRuntimeExecutionBundle(config)
	if err == nil {
		t.Fatal("read-only destination parent was accepted")
	}
	if receipt.State != "STOPPED_ZERO_WRITE" && receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" {
		t.Fatalf("unexpected stopped materialization state: %#v", receipt)
	}
}

func postRuntimeMaterializerFixture(t *testing.T) (PostRuntimeExecutionBundleMaterializationConfig, postRuntimeExecutionBundleIndex) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	data := filepath.Join(source, "..2026_08_18")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := json.Marshal(postRuntimeExecutionManifestDocument{Format: PostRuntimeExecutionManifestFormat})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(data, postRuntimeExecutionManifestRelativePath)
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestDigest, err := loadPostRuntimeExecutionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	index := postRuntimeExecutionBundleIndex{Format: PostRuntimeExecutionBundleFormat, ManifestDigest: manifestDigest}
	for _, relative := range postRuntimeExecutionBundleFiles {
		path := filepath.Join(data, relative)
		if relative != postRuntimeExecutionManifestRelativePath {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("bound-"+strings.ReplaceAll(relative, "/", "-")), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		index.Files = append(index.Files, postRuntimeExecutionBundleIndexFile{Path: relative, Digest: digest.SHA256(raw)})
		projected := filepath.Join(source, relative)
		if err := os.MkdirAll(filepath.Dir(projected), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, projected); err != nil {
			t.Fatal(err)
		}
	}
	indexDigest, err := canonicalPostRuntimeExecutionBundleIndexDigest(index)
	if err != nil {
		t.Fatal(err)
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	indexDataPath := filepath.Join(data, postRuntimeExecutionBundleIndexName)
	if err := os.WriteFile(indexDataPath, indexRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(indexDataPath, filepath.Join(source, postRuntimeExecutionBundleIndexName)); err != nil {
		t.Fatal(err)
	}
	return PostRuntimeExecutionBundleMaterializationConfig{
		SourceDirectory: source, DestinationDirectory: filepath.Join(root, "workspace"), ExpectedBundleDigest: indexDigest,
	}, index
}
