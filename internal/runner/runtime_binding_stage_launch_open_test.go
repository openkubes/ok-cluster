package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestOpenRuntimeBindingStageLaunchConsumesExactInstallerMaterialOffline(t *testing.T) {
	material, config, installerToken := runtimeBindingOpenedLaunchFixture(t)
	opened, err := material.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := opened.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != RuntimeBindingStageLaunchOpenReceiptFormat || receipt.State != "OPENED" || receipt.StageID != "runtime-binding" || receipt.Authority != "ok-mgmt" || receipt.CandidateDigest != config.ExpectedCandidateDigest || receipt.ValidUntil != material.receipt.ValidUntil || receipt.MutationAllowed {
		t.Fatalf("unexpected runtime binding open receipt: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{installerToken, []byte(config.Authority.Endpoint), material.credentials.objects[0].raw, material.credentials.objects[1].raw, material.credentials.objects[2].raw} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("runtime binding open receipt exposed private material")
		}
	}
}

func TestOpenRuntimeBindingStageLaunchFailsClosed(t *testing.T) {
	material, valid, installerToken := runtimeBindingOpenedLaunchFixture(t)
	for name, mutate := range map[string]func(*RuntimeBindingStageLaunchOpenConfig){
		"foreign candidate": func(config *RuntimeBindingStageLaunchOpenConfig) {
			config.ExpectedCandidateDigest = digest.SHA256([]byte("foreign"))
		},
		"foreign authority": func(config *RuntimeBindingStageLaunchOpenConfig) {
			config.Authority.AuthorityIdentity = "ok-infra"
		},
		"foreign endpoint": func(config *RuntimeBindingStageLaunchOpenConfig) {
			config.Authority.Endpoint = "https://192.0.2.11:6443"
		},
		"missing clock": func(config *RuntimeBindingStageLaunchOpenConfig) { config.Clock = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := material.Open(config); err == nil {
				t.Fatal("unsafe runtime binding launch material opened")
			}
		})
	}
	shared := valid
	_, secrets, err := prepareRuntimeBindingStageCredentialInstallation(material.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shared.Authority.TokenFile, secrets[0].token, 0o600); err != nil {
		t.Fatal(err)
	}
	sharedMaterial := material
	sharedMaterial.candidate.installerTokenDigest = digest.SHA256(secrets[0].token)
	sharedMaterial.candidate.receipt.InstallerCredentialBindingDigest = installerCredentialBindingDigest(t, sharedMaterial.candidate.installerTokenDigest, sharedMaterial.candidate.receipt.InstallerCredentialEvidenceDigest)
	sharedMaterial.candidate.receipt.CandidateDigest = runtimeBindingCandidateDigest(t, sharedMaterial.candidate.receipt)
	sharedMaterial.receipt.CandidateDigest = sharedMaterial.candidate.receipt.CandidateDigest
	shared.ExpectedCandidateDigest = sharedMaterial.receipt.CandidateDigest
	if _, err := sharedMaterial.Open(shared); err == nil {
		t.Fatal("shared installer and Job credential accepted")
	}
	_ = installerToken
	if _, err := (*OpenedRuntimeBindingStageLaunch)(nil).Receipt(); err == nil {
		t.Fatal("nil opened launch exposed a receipt")
	}
}

func runtimeBindingOpenedLaunchFixture(t *testing.T) (VerifiedRuntimeBindingStageLaunchMaterial, RuntimeBindingStageLaunchOpenConfig, []byte) {
	t.Helper()
	launchConfig, _ := runtimeBindingStageLaunchMaterialConfig(t)
	installerToken := []byte("runtime-binding-installer-token-v1")
	ca := testCA(t)
	launchConfig.Candidate.CABundleDigest = digest.SHA256(ca)
	launchConfig.Candidate.InstallerTokenDigest = digest.SHA256(installerToken)
	material, err := BuildRuntimeBindingStageLaunchMaterial(launchConfig)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tokenPath, caPath := filepath.Join(root, "installer-token"), filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, installerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	return material, RuntimeBindingStageLaunchOpenConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: launchConfig.Candidate.AuthorityEndpoint, AuthorityIdentity: "ok-mgmt",
			TokenFile: tokenPath, CAFile: caPath, CABundleDigest: launchConfig.Candidate.CABundleDigest,
		},
		Clock:                   func() time.Time { return time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC) },
		ExpectedCandidateDigest: material.receipt.CandidateDigest,
	}, installerToken
}

func installerCredentialBindingDigest(t *testing.T, tokenDigest, evidenceDigest string) string {
	t.Helper()
	return digest.SHA256(mustJSON(t, submissionStageInstallerCredentialIdentity{TokenDigest: tokenDigest, EvidenceDigest: evidenceDigest}))
}

func runtimeBindingCandidateDigest(t *testing.T, receipt RuntimeBindingStageLaunchCandidateReceipt) string {
	t.Helper()
	return digest.SHA256(mustJSON(t, runtimeBindingStageLaunchCandidateIdentity{
		StageID: receipt.StageID, Authority: receipt.Authority, StagePackageDigest: receipt.StagePackageDigest,
		CredentialPackageDigest: receipt.CredentialPackageDigest, RuntimeManifestDigest: receipt.RuntimeManifestDigest,
		LaunchPlanDigest: receipt.LaunchPlanDigest, AuthorityEndpointDigest: receipt.AuthorityEndpointDigest,
		CABundleDigest: receipt.CABundleDigest, InstallerCredentialBindingDigest: receipt.InstallerCredentialBindingDigest,
		InstallerCredentialEvidenceDigest: receipt.InstallerCredentialEvidenceDigest,
		PreparedAt:                        receipt.PreparedAt, ValidUntil: receipt.ValidUntil,
	}))
}
