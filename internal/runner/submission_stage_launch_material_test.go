package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildSubmissionStageLaunchMaterialProducesOneRedactedIdentity(t *testing.T) {
	config, installerToken, ledgerToken, authorityToken := submissionStageLaunchMaterialConfig(t)
	material, err := BuildSubmissionStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildSubmissionStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	againReceipt, _ := again.Receipt()
	if receipt.Format != SubmissionStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "provider-prerequisites" || receipt.Authority != "ok-mgmt" || receipt.ValidUntil != "2026-08-16T12:15:00Z" || receipt.MutationAllowed || receipt.CandidateDigest != againReceipt.CandidateDigest {
		t.Fatalf("launch material identity differs: %#v", receipt)
	}
	for _, value := range []string{receipt.StagePackageDigest, receipt.CredentialPackageDigest, receipt.RuntimeManifestDigest, receipt.LaunchPlanDigest, receipt.CandidateDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			t.Fatalf("launch material digest is invalid: %q", value)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		installerToken, ledgerToken, authorityToken, config.RuntimeManifest, config.Package.JobTemplate,
		[]byte(config.Ledger.TokenFile), []byte(config.Ledger.CAFile), []byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest),
	} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("launch material receipt exposed private source content")
		}
	}

	tampered := material
	tampered.receipt.CandidateDigest = digest.SHA256([]byte("foreign-candidate"))
	if _, err := tampered.Receipt(); err == nil {
		t.Fatal("changed launch material identity was accepted")
	}
}

func TestSubmissionStageLaunchMaterialOpensOnlyExactCandidate(t *testing.T) {
	config, installerToken, _, _ := submissionStageLaunchMaterialConfig(t)
	material, err := BuildSubmissionStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := material.Receipt()
	root := t.TempDir()
	tokenPath := filepath.Join(root, "installer-token")
	if err := os.WriteFile(tokenPath, installerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	openConfig := SubmissionStageLaunchOpenConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: config.Candidate.AuthorityEndpoint, AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath,
			CAFile: config.Ledger.CAFile, CABundleDigest: config.Candidate.CABundleDigest,
		},
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC) }, ExpectedCandidateDigest: receipt.CandidateDigest,
	}
	launcher, err := material.Open(openConfig)
	if err != nil {
		t.Fatal(err)
	}
	launchReceipt, err := launcher.Launch(context.Background())
	if err == nil || launchReceipt.State != "STOPPED_ZERO_WRITE" || launchReceipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("expired material reached API: %#v %v", launchReceipt, err)
	}

	openConfig.ExpectedCandidateDigest = digest.SHA256([]byte("wrong-candidate"))
	if _, err := material.Open(openConfig); err == nil {
		t.Fatal("wrong explicit candidate digest was accepted")
	}
}

func TestBuildSubmissionStageLaunchMaterialRejectsChangedSources(t *testing.T) {
	config, _, _, _ := submissionStageLaunchMaterialConfig(t)
	config.RuntimeManifestDigest = digest.SHA256([]byte("other-runtime"))
	if _, err := BuildSubmissionStageLaunchMaterial(config); err == nil {
		t.Fatal("changed runtime source was accepted")
	}

	config, _, _, _ = submissionStageLaunchMaterialConfig(t)
	config.Candidate.PreparedAt = time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC)
	if _, err := BuildSubmissionStageLaunchMaterial(config); err == nil {
		t.Fatal("expired candidate input was accepted")
	}
}

func submissionStageLaunchMaterialConfig(t *testing.T) (SubmissionStageLaunchMaterialConfig, []byte, []byte, []byte) {
	t.Helper()
	credentialConfig, ledgerToken, authorityToken := submissionStageCredentialConfig(t)
	fixture := submissionBundleFixture(t, false, "")
	packageConfig := submissionStagePackageConfig(t, fixture, "provider-prerequisites")
	runtimeManifest := submissionStageRuntimeManifest(t)
	installerToken := []byte("material-installer-token-v1")
	return SubmissionStageLaunchMaterialConfig{
		Package: packageConfig, MaterializationTime: credentialConfig.MaterializationTime,
		Ledger: credentialConfig.Ledger, SelectedAuthority: credentialConfig.SelectedAuthority,
		RuntimeManifest: runtimeManifest, RuntimeManifestDigest: digest.SHA256(runtimeManifest),
		Candidate: SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: "https://192.0.2.10:6443", CABundleDigest: credentialConfig.Ledger.CABundleDigest,
			InstallerTokenDigest: digest.SHA256(installerToken), InstallerCredentialEvidenceDigest: digest.SHA256([]byte("material-installer-evidence")),
			PreparedAt: time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC),
		},
	}, installerToken, ledgerToken, authorityToken
}
