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

func TestPrepareSubmissionStageLaunchCandidateBindsExactDestinationAndCredential(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	config := submissionStageLaunchCandidateConfig()
	candidate, err := PrepareSubmissionStageLaunchCandidate(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := candidate.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareSubmissionStageLaunchCandidate(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	againReceipt, _ := again.Receipt()
	if receipt.Format != SubmissionStageLaunchCandidateFormat || receipt.State != "PREPARED" || receipt.StageID != "provider-prerequisites" || receipt.Authority != "ok-mgmt" || receipt.PreparedAt != "2026-08-16T12:01:00Z" || receipt.ValidUntil != "2026-08-16T12:15:00Z" || receipt.MutationAllowed || receipt.CandidateDigest != againReceipt.CandidateDigest {
		t.Fatalf("candidate identity differs: %#v", receipt)
	}
	for _, value := range []string{receipt.StagePackageDigest, receipt.CredentialPackageDigest, receipt.RuntimeManifestDigest, receipt.LaunchPlanDigest, receipt.AuthorityEndpointDigest, receipt.CABundleDigest, receipt.InstallerCredentialBindingDigest, receipt.InstallerCredentialEvidenceDigest, receipt.CandidateDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			t.Fatalf("candidate digest is invalid: %q", value)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{config.AuthorityEndpoint, config.InstallerTokenDigest, "installer-token-v1"} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("candidate receipt exposed private launch input %q", forbidden)
		}
	}

	changed := config
	changed.AuthorityEndpoint = "https://192.0.2.11:6443"
	other, err := PrepareSubmissionStageLaunchCandidate(changed, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	otherReceipt, _ := other.Receipt()
	if otherReceipt.CandidateDigest == receipt.CandidateDigest {
		t.Fatal("changed endpoint retained candidate identity")
	}
	changed = config
	changed.InstallerTokenDigest = digest.SHA256([]byte("other-installer-token"))
	other, err = PrepareSubmissionStageLaunchCandidate(changed, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	otherReceipt, _ = other.Receipt()
	if otherReceipt.CandidateDigest == receipt.CandidateDigest {
		t.Fatal("changed installer token retained candidate identity")
	}
	tampered := candidate
	tampered.receipt.ValidUntil = "2026-08-16T12:16:00Z"
	if _, err := tampered.Receipt(); err == nil {
		t.Fatal("changed candidate receipt was accepted")
	}
	tampered = candidate
	tampered.installerTokenDigest = digest.SHA256([]byte("foreign-private-token"))
	if _, err := tampered.Receipt(); err == nil {
		t.Fatal("changed private credential binding was accepted")
	}
}

func TestPrepareSubmissionStageLaunchCandidateFailsClosed(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	valid := submissionStageLaunchCandidateConfig()
	for name, mutate := range map[string]func(*SubmissionStageLaunchCandidateConfig){
		"DNS endpoint": func(config *SubmissionStageLaunchCandidateConfig) {
			config.AuthorityEndpoint = "https://ok-mgmt.example:6443"
		},
		"HTTP endpoint": func(config *SubmissionStageLaunchCandidateConfig) {
			config.AuthorityEndpoint = "http://192.0.2.10:6443"
		},
		"missing CA":       func(config *SubmissionStageLaunchCandidateConfig) { config.CABundleDigest = "" },
		"missing evidence": func(config *SubmissionStageLaunchCandidateConfig) { config.InstallerCredentialEvidenceDigest = "" },
		"fractional time": func(config *SubmissionStageLaunchCandidateConfig) {
			config.PreparedAt = config.PreparedAt.Add(time.Nanosecond)
		},
		"expired credentials": func(config *SubmissionStageLaunchCandidateConfig) {
			config.PreparedAt = time.Date(2026, 8, 16, 12, 15, 1, 0, time.UTC)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := PrepareSubmissionStageLaunchCandidate(config, stage, credentials, runtime); err == nil {
				t.Fatal("invalid launch candidate was accepted")
			}
		})
	}
}

func TestOpenSubmissionStageLauncherRequiresExactCandidateBeforeCredentialUse(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	installerToken := []byte("installer-token-v1")
	ca := testCA(t)
	config := submissionStageLaunchCandidateConfig()
	config.CABundleDigest = digest.SHA256(ca)
	config.InstallerTokenDigest = digest.SHA256(installerToken)
	candidate, err := PrepareSubmissionStageLaunchCandidate(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := candidate.Receipt()
	root := t.TempDir()
	tokenPath, caPath := filepath.Join(root, "installer-token"), filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, installerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	launcherConfig := SubmissionStageLauncherConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: config.AuthorityEndpoint, AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, CAFile: caPath, CABundleDigest: config.CABundleDigest,
		},
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC) }, Candidate: candidate, ExpectedCandidateDigest: receipt.CandidateDigest,
	}
	launcher, err := OpenKubernetesSubmissionStageLauncher(launcherConfig, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	launchReceipt, err := launcher.Launch(context.Background())
	if err == nil || launchReceipt.State != "STOPPED_ZERO_WRITE" || launchReceipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("expired candidate did not stop before API contact: %#v %v", launchReceipt, err)
	}

	wrong := launcherConfig
	wrong.ExpectedCandidateDigest = digest.SHA256([]byte("other-candidate"))
	if _, err := OpenKubernetesSubmissionStageLauncher(wrong, stage, credentials, runtime); err == nil {
		t.Fatal("wrong expected candidate digest was accepted")
	}
	wrong = launcherConfig
	wrong.Authority.Endpoint = "https://192.0.2.11:6443"
	if _, err := OpenKubernetesSubmissionStageLauncher(wrong, stage, credentials, runtime); err == nil {
		t.Fatal("wrong launch endpoint was accepted")
	}
	if err := os.WriteFile(tokenPath, []byte("changed-installer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesSubmissionStageLauncher(launcherConfig, stage, credentials, runtime); err == nil {
		t.Fatal("changed installer credential was accepted")
	}
}

func submissionStageLaunchCandidateConfig() SubmissionStageLaunchCandidateConfig {
	return SubmissionStageLaunchCandidateConfig{
		AuthorityEndpoint: "https://192.0.2.10:6443", CABundleDigest: digest.SHA256([]byte("candidate-ca")),
		InstallerTokenDigest:              digest.SHA256([]byte("installer-token-v1")),
		InstallerCredentialEvidenceDigest: digest.SHA256([]byte("installer-tokenrequest-evidence")),
		PreparedAt:                        time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC),
	}
}
