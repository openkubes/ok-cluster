package runner

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeObservabilityEvidenceAuthorityCreatesIsolatedRegularFiles(t *testing.T) {
	config, receipt := observabilityEvidenceAuthorityMaterializerFixture(t)
	materialized, err := materializeObservabilityEvidenceAuthority(config, ObservabilityEvidenceAuthorityMaterializationReceipt{
		Format: ObservabilityEvidenceAuthorityMaterializationReceiptFormat, State: "STOPPED_ZERO_WRITE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if materialized.State != "MATERIALIZED_VERIFIED" || materialized.ActivationDigest != receipt.ActivationDigest ||
		materialized.ManifestDigest != receipt.ManifestDigest || materialized.EvidenceKeyID != receipt.EvidenceKeyID ||
		materialized.CollectorCADigest != receipt.CollectorCADigest || materialized.FileCount != 4 ||
		materialized.TotalBytes == 0 || materialized.KubernetesMutationAllowed {
		t.Fatalf("unexpected evidence authority materialization receipt: %#v", materialized)
	}
	info, err := os.Lstat(config.DestinationDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("authority destination is not private: %v %#v", err, info)
	}
	for _, name := range observabilityEvidenceAuthorityProjectedFiles {
		info, statErr := os.Lstat(filepath.Join(config.DestinationDirectory, name))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("authority file %q is not private regular material: %v %#v", name, statErr, info)
		}
	}
}

func TestMaterializeObservabilityEvidenceAuthorityFailsClosedBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *ObservabilityEvidenceAuthorityMaterializationConfig){
		"wrong activation": func(_ *testing.T, config *ObservabilityEvidenceAuthorityMaterializationConfig) {
			config.ExpectedActivationDigest = runnerStageSHA("f")
		},
		"wrong key": func(_ *testing.T, config *ObservabilityEvidenceAuthorityMaterializationConfig) {
			config.ExpectedEvidenceKeyID = runnerStageSHA("f")
		},
		"wrong CA": func(_ *testing.T, config *ObservabilityEvidenceAuthorityMaterializationConfig) {
			config.ExpectedCollectorCADigest = runnerStageSHA("f")
		},
		"changed token": func(t *testing.T, config *ObservabilityEvidenceAuthorityMaterializationConfig) {
			if err := os.WriteFile(filepath.Join(config.SourceDirectory, observabilityEvidenceAuthorityCollectorToken), []byte(" token "), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"existing destination": func(t *testing.T, config *ObservabilityEvidenceAuthorityMaterializationConfig) {
			if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := observabilityEvidenceAuthorityMaterializerFixture(t)
			mutate(t, &config)
			receipt, err := materializeObservabilityEvidenceAuthority(config, ObservabilityEvidenceAuthorityMaterializationReceipt{
				Format: ObservabilityEvidenceAuthorityMaterializationReceiptFormat, State: "STOPPED_ZERO_WRITE",
			})
			if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
				t.Fatalf("unsafe authority projection was accepted: %#v err=%v", receipt, err)
			}
			if _, statErr := os.Lstat(config.DestinationDirectory); name != "existing destination" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed authority preflight wrote destination: %v", statErr)
			}
		})
	}
}

func TestMaterializeObservabilityEvidenceAuthorityPublicEntryRequiresFixedRoot(t *testing.T) {
	config, _ := observabilityEvidenceAuthorityMaterializerFixture(t)
	receipt, err := MaterializeObservabilityEvidenceAuthority(config)
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
		t.Fatalf("foreign authority destination was accepted: %#v err=%v", receipt, err)
	}
}

func observabilityEvidenceAuthorityMaterializerFixture(t *testing.T) (ObservabilityEvidenceAuthorityMaterializationConfig, ObservabilityEvidenceAuthorityPackageReceipt) {
	t.Helper()
	packageConfig, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
	t.Cleanup(cleanup)
	packaged, err := BuildObservabilityEvidenceAuthorityPackage(packageConfig)
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
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(raw, &secret); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range observabilityEvidenceAuthorityProjectedFiles {
		decoded, decodeErr := base64.StdEncoding.DecodeString(secret.BinaryData[name])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err := os.WriteFile(filepath.Join(source, name), decoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ObservabilityEvidenceAuthorityMaterializationConfig{
		SourceDirectory: source, DestinationDirectory: filepath.Join(root, "authority"),
		ExpectedActivationDigest: receipt.ActivationDigest, ExpectedEvidenceKeyID: receipt.EvidenceKeyID,
		ExpectedCollectorCADigest: receipt.CollectorCADigest,
	}, receipt
}
