package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildLifecycleObservationStageLaunchMaterialSealsPrivateComponents(t *testing.T) {
	config, ledgerToken, observerToken := lifecycleObservationStageLaunchMaterialConfig(t)
	material, err := BuildLifecycleObservationStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != LifecycleObservationStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "lifecycle-observation" || receipt.Authority != "ok-mgmt" || receipt.ObservationPackageDigest != candidate.ObservationPackageDigest || receipt.CandidateDigest != candidate.CandidateDigest || receipt.ValidUntil != candidate.ValidUntil || receipt.MutationAllowed {
		t.Fatalf("unexpected lifecycle observation launch material: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{ledgerToken, observerToken, material.packaged.raw, material.credentials.objects[0].raw, material.runtime.raw, []byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest)} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("launch material receipt exposed private source content")
		}
	}
	changed := material
	changed.receipt.CandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed launch material identity accepted")
	}
}

func TestLifecycleObservationStageLaunchMaterialOpenRetainsExactComponents(t *testing.T) {
	config, _, _ := lifecycleObservationStageLaunchMaterialConfig(t)
	material, err := BuildLifecycleObservationStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := material.Receipt()
	launcher, err := material.Open(LifecycleObservationStageLaunchOpenConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: "http://127.0.0.1:12345", AuthorityIdentity: "ok-mgmt",
		},
		Clock:                   func() time.Time { return time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC) },
		ExpectedCandidateDigest: receipt.CandidateDigest,
	})
	if err == nil || launcher != nil {
		// Public Open requires the real bound endpoint and credential files; the
		// in-memory client path is intentionally unavailable here.
		t.Fatalf("unbound public launcher was opened: %v", err)
	}
	if _, err := material.Open(LifecycleObservationStageLaunchOpenConfig{ExpectedCandidateDigest: digest.SHA256([]byte("foreign"))}); err == nil {
		t.Fatal("wrong exact candidate digest accepted")
	}

	api := newSubmissionStageLauncherAPI(t)
	internal, err := newKubernetesLifecycleObservationStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt",
		Client: api.client(), Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC) },
		ValidUntil: time.Date(2026, 8, 16, 12, 15, 0, 0, time.UTC),
	}, material.packaged, material.credentials, material.runtime)
	if err != nil {
		t.Fatal(err)
	}
	launchReceipt, err := internal.Launch(context.Background())
	if err == nil || launchReceipt.State != "STOPPED_ZERO_WRITE" || launchReceipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
		t.Fatalf("expired sealed material reached API: %#v %v", launchReceipt, err)
	}
}

func lifecycleObservationStageLaunchMaterialConfig(t *testing.T) (LifecycleObservationStageLaunchMaterialConfig, []byte, []byte) {
	t.Helper()
	credentialConfig, ledgerToken, observerToken := lifecycleObservationCredentialConfig(t)
	manifest := submissionStageRuntimeManifest(t)
	return LifecycleObservationStageLaunchMaterialConfig{
		Package: credentialConfig.PackageConfigForTest(t), MaterializationTime: credentialConfig.MaterializationTime,
		Ledger: credentialConfig.Ledger, ManagementObserver: credentialConfig.ManagementObserver,
		RuntimeManifest: manifest, RuntimeManifestDigest: digest.SHA256(manifest),
		Candidate: submissionStageLaunchCandidateConfig(),
	}, ledgerToken, observerToken
}

func (config LifecycleObservationStageCredentialPackageConfig) PackageConfigForTest(t *testing.T) LifecycleObservationStagePackageConfig {
	t.Helper()
	// Test helpers rebuild the deterministic package inputs; production code
	// never extracts configuration from a verified package.
	return lifecycleObservationStagePackageConfig(t)
}
