package runner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeFullRunExecutionBundleCreatesPrivateWorkspace(t *testing.T) {
	config, bundle := fullRunMaterializerFixture(t)
	receipt, err := materializeFullRunExecutionBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != FullRunExecutionBundleMaterializationReceiptFormat || receipt.State != "MATERIALIZED_VERIFIED" ||
		receipt.BundleDigest != bundle.receipt.BundleDigest || receipt.ManifestDigest != bundle.receipt.ManifestDigest ||
		receipt.EvidenceKeyID != bundle.receipt.EvidenceKeyID || receipt.FileCount != len(fullRunExecutionBundleFiles) ||
		receipt.TotalBytes != bundle.receipt.TotalBytes || receipt.KubernetesMutationAllowed {
		t.Fatalf("unexpected full-run materialization receipt: %#v", receipt)
	}
	for _, relative := range fullRunExecutionBundleFiles {
		info, statErr := os.Lstat(filepath.Join(config.DestinationDirectory, relative))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("materialized file %q is not private: %v %#v", relative, statErr, info)
		}
	}
	for _, relative := range []string{".", "activation", "credentials", "input", "input/projection", "work", "work/authorizations", "work/receipts"} {
		info, statErr := os.Lstat(filepath.Join(config.DestinationDirectory, relative))
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			t.Fatalf("materialized directory %q is not private: %v %#v", relative, statErr, info)
		}
	}
}

func TestMaterializeFullRunExecutionBundleCreatesPrivateHandoffAfterVerification(t *testing.T) {
	config, _ := fullRunMaterializerFixture(t)
	if err := os.Remove(config.HandoffDirectory); err != nil {
		t.Fatal(err)
	}
	receipt, err := materializeFullRunExecutionBundle(config)
	if err != nil || receipt.State != "MATERIALIZED_VERIFIED" {
		t.Fatalf("missing handoff was not safely materialized: %#v err=%v", receipt, err)
	}
	info, err := os.Lstat(config.HandoffDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created handoff is not private: %#v err=%v", info, err)
	}
}

func TestMaterializeFullRunExecutionBundleReportsPartialAfterCreatingHandoff(t *testing.T) {
	config, _ := fullRunMaterializerFixture(t)
	if err := os.Remove(config.HandoffDirectory); err != nil {
		t.Fatal(err)
	}
	config.DestinationDirectory = filepath.Join(filepath.Dir(config.DestinationDirectory), "missing-parent", "workspace")
	receipt, err := materializeFullRunExecutionBundle(config)
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" {
		t.Fatalf("local handoff write was not reported as partial: %#v err=%v", receipt, err)
	}
	info, statErr := os.Lstat(config.HandoffDirectory)
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created handoff is not private: %#v err=%v", info, statErr)
	}
}

func TestMaterializeFullRunExecutionBundleFailsClosedBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *FullRunExecutionBundleMaterializationConfig){
		"wrong bundle digest": func(_ *testing.T, config *FullRunExecutionBundleMaterializationConfig) {
			config.ExpectedBundleDigest = runnerStageSHA("f")
		},
		"changed file": func(t *testing.T, config *FullRunExecutionBundleMaterializationConfig) {
			path := filepath.Join(config.SourceDirectory, "input/enablement.yaml")
			if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"existing destination": func(t *testing.T, config *FullRunExecutionBundleMaterializationConfig) {
			if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"public handoff": func(t *testing.T, config *FullRunExecutionBundleMaterializationConfig) {
			if err := os.Chmod(config.HandoffDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"nested handoff": func(_ *testing.T, config *FullRunExecutionBundleMaterializationConfig) {
			config.HandoffDirectory = filepath.Join(config.SourceDirectory, "handoff")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := fullRunMaterializerFixture(t)
			mutate(t, &config)
			receipt, err := materializeFullRunExecutionBundle(config)
			if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
				t.Fatalf("unsafe full-run materialization was accepted: %#v err=%v", receipt, err)
			}
			if _, statErr := os.Lstat(config.DestinationDirectory); name != "existing destination" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed materialization wrote destination: %v", statErr)
			}
		})
	}
}

func TestMaterializeFullRunExecutionBundlePublicEntryRequiresFixedRoots(t *testing.T) {
	config, _ := fullRunMaterializerFixture(t)
	receipt, err := MaterializeFullRunExecutionBundle(config)
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
		t.Fatalf("non-runtime destination was accepted: %#v err=%v", receipt, err)
	}
}

func fullRunMaterializerFixture(t *testing.T) (FullRunExecutionBundleMaterializationConfig, VerifiedFullRunExecutionBundle) {
	t.Helper()
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	t.Cleanup(cleanup)
	publicKeyPath, keyID := fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
	bindFullRunEvidenceKeyID(t, manifestPath, keyID)
	bundle, err := BuildFullRunExecutionBundle(FullRunExecutionBundleConfig{
		ManifestPath: manifestPath, IndependentEvidencePublicKey: publicKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for relative, raw := range bundle.files {
		path := filepath.Join(source, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, fullRunExecutionBundleIndexName), bundle.indexRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	handoff := filepath.Join(root, "handoff")
	if err := os.Mkdir(handoff, 0o700); err != nil {
		t.Fatal(err)
	}
	return FullRunExecutionBundleMaterializationConfig{
		SourceDirectory: source, DestinationDirectory: filepath.Join(root, "workspace"), HandoffDirectory: handoff,
		ExpectedBundleDigest: bundle.receipt.BundleDigest,
	}, bundle
}
