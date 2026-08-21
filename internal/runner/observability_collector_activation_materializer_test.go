package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaterializeObservabilityCollectorActivationCreatesPrivateRuntime(t *testing.T) {
	config, receipt, _ := collectorActivationProjectionFixture(t)
	materialized, err := materializeObservabilityCollectorActivation(config, ObservabilityCollectorActivationMaterializationReceipt{
		Format: ObservabilityCollectorActivationMaterializationReceiptFormat, State: "STOPPED_ZERO_WRITE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if materialized.State != "MATERIALIZED_VERIFIED" || materialized.ActivationDigest != receipt.ActivationDigest ||
		materialized.ManifestDigest != receipt.ManifestDigest || materialized.RuntimeBindingDigest != receipt.RuntimeBindingDigest ||
		materialized.TargetClusterUIDDigest != receipt.TargetClusterUIDDigest ||
		materialized.PublicEndpointDigest != receipt.PublicEndpointDigest || materialized.FileCount != 7 ||
		materialized.TotalBytes == 0 || !materialized.PrivateStateReady || materialized.KubernetesMutationAllowed {
		t.Fatalf("unexpected collector materialization receipt: %#v", materialized)
	}
	for _, directory := range []string{config.DestinationDirectory, config.StateDirectory} {
		info, statErr := os.Lstat(directory)
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("collector directory is not private: %q %v %#v", directory, statErr, info)
		}
	}
	for _, name := range observabilityCollectorProjectedFiles {
		info, statErr := os.Lstat(filepath.Join(config.DestinationDirectory, name))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("collector file %q is not private: %v %#v", name, statErr, info)
		}
	}
}

func TestMaterializeObservabilityCollectorActivationFailsClosedBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *ObservabilityCollectorActivationMaterializationConfig){
		"wrong activation": func(_ *testing.T, config *ObservabilityCollectorActivationMaterializationConfig) {
			config.ExpectedActivationDigest = runnerStageSHA("f")
		},
		"wrong runtime": func(_ *testing.T, config *ObservabilityCollectorActivationMaterializationConfig) {
			config.ExpectedRuntimeBinding = runnerStageSHA("f")
		},
		"changed webhook": func(t *testing.T, config *ObservabilityCollectorActivationMaterializationConfig) {
			if err := os.WriteFile(filepath.Join(config.SourceDirectory, observabilityCollectorWebhookKey), []byte("changed-authority-token-value-123456"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"existing destination": func(t *testing.T, config *ObservabilityCollectorActivationMaterializationConfig) {
			if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _, _ := collectorActivationProjectionFixture(t)
			mutate(t, &config)
			receipt, err := materializeObservabilityCollectorActivation(config, ObservabilityCollectorActivationMaterializationReceipt{
				Format: ObservabilityCollectorActivationMaterializationReceiptFormat, State: "STOPPED_ZERO_WRITE",
			})
			if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
				t.Fatalf("unsafe collector projection was accepted: %#v err=%v", receipt, err)
			}
			if _, statErr := os.Lstat(config.DestinationDirectory); name != "existing destination" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed collector preflight wrote destination: %v", statErr)
			}
		})
	}
}

func TestMaterializeObservabilityCollectorActivationPublicEntryRequiresFixedRoots(t *testing.T) {
	config, _, _ := collectorActivationProjectionFixture(t)
	receipt, err := MaterializeObservabilityCollectorActivation(config)
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" {
		t.Fatalf("foreign collector runtime roots were accepted: %#v err=%v", receipt, err)
	}
}

func TestOpenObservabilityCollectorActivationIsInertAndSingleUse(t *testing.T) {
	config, _, at := collectorActivationProjectionFixture(t)
	if err := os.Mkdir(config.StateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	execution, err := openObservabilityCollectorActivation(
		filepath.Join(config.SourceDirectory, observabilityCollectorActivationKey), config.StateDirectory,
		ObservabilityCollectorActivationRuntime{Clock: func() time.Time { return at }},
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Receipt()
	if err != nil || receipt.State != "VERIFIED" || receipt.MutationAllowed || !receipt.SeparateAuthorities {
		t.Fatalf("unexpected activated collector receipt: %#v err=%v", receipt, err)
	}
	calls := 0
	serve := func(ctx context.Context, address string, handler http.Handler, certRaw, keyRaw []byte) error {
		calls++
		if address != "0.0.0.0:8443" || handler == nil || len(certRaw) == 0 || len(keyRaw) == 0 {
			t.Fatal("collector activation lost its bound serving identity")
		}
		return nil
	}
	if err := execution.Serve(context.Background(), serve); err != nil {
		t.Fatal(err)
	}
	if err := execution.Serve(context.Background(), serve); err == nil || calls != 1 {
		t.Fatal("collector activation was not single-use")
	}
}

func TestOpenObservabilityCollectorActivationFailsClosed(t *testing.T) {
	config, _, at := collectorActivationProjectionFixture(t)
	if err := os.Mkdir(config.StateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config.SourceDirectory, observabilityCollectorActivationKey)
	if err := os.WriteFile(filepath.Join(config.SourceDirectory, observabilityCollectorQueryKey), []byte("changed-query-authority-value-123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openObservabilityCollectorActivation(path, config.StateDirectory, ObservabilityCollectorActivationRuntime{Clock: func() time.Time { return at }}); err == nil {
		t.Fatal("tampered collector activation was opened")
	}
	if _, err := OpenObservabilityCollectorActivation(path, ObservabilityCollectorActivationRuntime{Clock: func() time.Time { return at }}); err == nil {
		t.Fatal("collector activation outside the fixed runtime root was opened")
	}
}

func collectorActivationProjectionFixture(t *testing.T) (ObservabilityCollectorActivationMaterializationConfig, ObservabilityCollectorActivationPackageReceipt, time.Time) {
	t.Helper()
	packageConfig, cleanup := observabilityCollectorActivationFixture(t)
	t.Cleanup(cleanup)
	packaged, err := BuildObservabilityCollectorActivationPackage(packageConfig)
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
	for _, name := range observabilityCollectorProjectedFiles {
		decoded, decodeErr := base64.StdEncoding.DecodeString(secret.BinaryData[name])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err := os.WriteFile(filepath.Join(source, name), decoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ObservabilityCollectorActivationMaterializationConfig{
		SourceDirectory: source, DestinationDirectory: filepath.Join(root, "collector"),
		StateDirectory: filepath.Join(root, "state"), ExpectedActivationDigest: receipt.ActivationDigest,
		ExpectedManifestDigest: receipt.ManifestDigest, ExpectedRuntimeBinding: receipt.RuntimeBindingDigest,
		ExpectedPublicEndpoint: receipt.PublicEndpointDigest,
	}, receipt, packageConfig.MaterializationTime
}
