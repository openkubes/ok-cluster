package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildEnablementStageLaunchMaterialSealsPrivateComponents(t *testing.T) {
	config, installerToken, ledgerToken, writerToken := enablementStageLaunchMaterialConfig(t)
	material, err := BuildEnablementStageLaunchMaterial(config)
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
	again, err := BuildEnablementStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	againReceipt, _ := again.Receipt()
	if receipt.Format != EnablementStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "enablement" || receipt.Authority != "ok-mgmt" || receipt.EnablementPackageDigest != candidate.EnablementPackageDigest || receipt.CandidateDigest != candidate.CandidateDigest || receipt.ValidUntil != candidate.ValidUntil || receipt.MutationAllowed || receipt.CandidateDigest != againReceipt.CandidateDigest {
		t.Fatalf("unexpected enablement launch material: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		installerToken, ledgerToken, writerToken, material.packaged.raw, material.credentials.objects[0].raw,
		material.credentials.objects[1].raw, material.runtime.raw, []byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest),
	} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("enablement launch material receipt exposed private source content")
		}
	}
	tampered := material
	tampered.receipt.CandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := tampered.Receipt(); err == nil {
		t.Fatal("changed enablement launch material identity accepted")
	}
}

func TestEnablementStageLaunchMaterialOpenRetainsExactComponents(t *testing.T) {
	config, _, _, _ := enablementStageLaunchMaterialConfig(t)
	material, err := BuildEnablementStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := material.Receipt()
	launcher, err := material.Open(EnablementStageLaunchOpenConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: "http://127.0.0.1:12345", AuthorityIdentity: "ok-mgmt",
		},
		Clock:                   func() time.Time { return time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC) },
		ExpectedCandidateDigest: receipt.CandidateDigest,
	})
	if err == nil || launcher != nil {
		// Public Open requires the bound endpoint and credential files; the
		// in-memory client path is intentionally unavailable here.
		t.Fatalf("unbound public launcher was opened: %v", err)
	}
	if _, err := material.Open(EnablementStageLaunchOpenConfig{ExpectedCandidateDigest: digest.SHA256([]byte("foreign"))}); err == nil {
		t.Fatal("wrong exact candidate digest accepted")
	}

	api := newSubmissionStageLauncherAPI(t)
	internal, err := newKubernetesEnablementStageLauncher(submissionStageLauncherClientConfig{
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

func TestBuildEnablementStageLaunchMaterialRejectsChangedSources(t *testing.T) {
	config, _, _, _ := enablementStageLaunchMaterialConfig(t)
	config.RuntimeManifestDigest = digest.SHA256([]byte("other-runtime"))
	if _, err := BuildEnablementStageLaunchMaterial(config); err == nil {
		t.Fatal("changed enablement runtime source was accepted")
	}
	config, _, _, _ = enablementStageLaunchMaterialConfig(t)
	config.Candidate.PreparedAt = time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC)
	if _, err := BuildEnablementStageLaunchMaterial(config); err == nil {
		t.Fatal("expired enablement candidate input was accepted")
	}
	if _, err := (VerifiedEnablementStageLaunchMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified enablement launch material receipt was exposed")
	}
}

func enablementStageLaunchMaterialConfig(t *testing.T) (EnablementStageLaunchMaterialConfig, []byte, []byte, []byte) {
	t.Helper()
	credentialConfig, ledgerToken, writerToken := enablementCredentialConfig(t)
	manifest := submissionStageRuntimeManifest(t)
	installerToken := []byte("enablement-installer-token-v1")
	return EnablementStageLaunchMaterialConfig{
		Package:             enablementStagePackageConfig(t, enablementBundleFixture(t)),
		MaterializationTime: credentialConfig.MaterializationTime,
		Ledger:              credentialConfig.Ledger, ManagementWriter: credentialConfig.ManagementWriter,
		RuntimeManifest: manifest, RuntimeManifestDigest: digest.SHA256(manifest),
		Candidate: SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: "https://192.0.2.10:6443", CABundleDigest: credentialConfig.Ledger.CABundleDigest,
			InstallerTokenDigest: digest.SHA256(installerToken), InstallerCredentialEvidenceDigest: digest.SHA256([]byte("enablement-installer-evidence")),
			PreparedAt: time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC),
		},
	}, installerToken, ledgerToken, writerToken
}
