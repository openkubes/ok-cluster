package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObservabilityEvidenceAuthorityActivationRunsOneBoundedProduction(t *testing.T) {
	config, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
	defer cleanup()
	runtimeRoot := t.TempDir()
	authorityRoot := filepath.Join(runtimeRoot, "authority")
	handoffRoot := filepath.Join(runtimeRoot, "handoff")
	for _, directory := range []string{runtimeRoot, authorityRoot, handoffRoot} {
		if err := os.Chmod(directory, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if directory != runtimeRoot {
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	config.RuntimeAuthorityRoot, config.RuntimeHandoffRoot = authorityRoot, handoffRoot
	config.IdentityPollInterval, config.IdentityWaitTimeout = time.Millisecond, time.Second
	packaged, err := BuildObservabilityEvidenceAuthorityPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packageReceipt, _ := packaged.Receipt()
	raw, _ := packaged.PrivateBytes()
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(raw, &secret); err != nil {
		t.Fatal(err)
	}
	for key, encoded := range secret.BinaryData {
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(authorityRoot, key), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	material := ObservabilityIndependentEvidenceIdentityMaterial{
		Format: ObservabilityIndependentEvidenceIdentityFormat, State: "RUNTIME_BOUND",
		ManifestDigest: packageReceipt.ManifestDigest, RuntimeBindingDigest: evidenceIdentitySHA("2"),
		RunID: "ok147-0123456789abcdef01234567", TargetClusterUID: "cluster-uid-runtime-a",
		FixtureDigest: evidenceIdentitySHA("3"), ProfileDigest: profile.Digest(),
	}
	identityPath := filepath.Join(handoffRoot, "observability-evidence-identity.json")
	identityReceiptPath := filepath.Join(handoffRoot, "observability-evidence-identity-receipt.json")
	identityReceipt, err := persistObservabilityIndependentEvidenceIdentity(material, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	identityReceiptRaw, err := canonicalObservabilityIndependentEvidenceIdentityReceipt(identityReceipt)
	if err != nil || os.WriteFile(identityReceiptPath, identityReceiptRaw, 0o600) != nil {
		t.Fatal("write evidence identity receipt")
	}
	clock := func() time.Time { return time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC) }
	execution, err := OpenObservabilityEvidenceAuthorityActivation(
		filepath.Join(authorityRoot, observabilityEvidenceAuthorityActivationKey),
		ObservabilityEvidenceAuthorityActivationRuntime{Clock: clock, Wait: WaitWithTimer},
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := execution.Run(context.Background())
	if err != nil || receipt.State != "WRITTEN_VERIFIED" || receipt.KeyID != packageReceipt.EvidenceKeyID {
		t.Fatalf("evidence authority activation did not complete: receipt=%#v err=%v", receipt, err)
	}
	evidencePath := filepath.Join(handoffRoot, "observability-evidence.json")
	info, statErr := os.Lstat(evidencePath)
	if statErr != nil || info.Mode().Perm() != 0o600 || info.Size() <= 0 {
		t.Fatalf("evidence authority output is not private: info=%#v err=%v", info, statErr)
	}
	if second, err := execution.Run(context.Background()); err == nil || second.State != "STOPPED_ZERO_WRITE" {
		t.Fatalf("evidence authority execution was reusable: receipt=%#v err=%v", second, err)
	}
}

func TestOpenObservabilityEvidenceAuthorityActivationFailsClosed(t *testing.T) {
	config, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
	defer cleanup()
	runtimeRoot := t.TempDir()
	authorityRoot, handoffRoot := filepath.Join(runtimeRoot, "authority"), filepath.Join(runtimeRoot, "handoff")
	if err := os.Chmod(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{authorityRoot, handoffRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config.RuntimeAuthorityRoot, config.RuntimeHandoffRoot = authorityRoot, handoffRoot
	packaged, err := BuildObservabilityEvidenceAuthorityPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := packaged.PrivateBytes()
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(raw, &secret); err != nil {
		t.Fatal(err)
	}
	for key, encoded := range secret.BinaryData {
		content, _ := base64.StdEncoding.DecodeString(encoded)
		if err := os.WriteFile(filepath.Join(authorityRoot, key), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	activationPath := filepath.Join(authorityRoot, observabilityEvidenceAuthorityActivationKey)
	clock := func() time.Time { return time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC) }
	if err := os.WriteFile(activationPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObservabilityEvidenceAuthorityActivation(activationPath, ObservabilityEvidenceAuthorityActivationRuntime{Clock: clock, Wait: WaitWithTimer}); err == nil {
		t.Fatal("tampered evidence authority activation was accepted")
	}
}
