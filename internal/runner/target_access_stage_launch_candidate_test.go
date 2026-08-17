package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPrepareTargetAccessStageLaunchCandidateBindsDestinationAndCredential(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	config := targetAccessLaunchCandidateConfig()
	candidate, err := PrepareTargetAccessStageLaunchCandidate(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := candidate.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareTargetAccessStageLaunchCandidate(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	againReceipt, _ := again.Receipt()
	if receipt.Format != TargetAccessStageLaunchCandidateFormat || receipt.State != "PREPARED" || receipt.StageID != "target-access" || receipt.Authority != "ok-shared" || receipt.PreparedAt != "2026-08-16T14:01:00Z" || receipt.ValidUntil != "2026-08-16T14:15:00Z" || receipt.MutationAllowed || receipt.CandidateDigest != againReceipt.CandidateDigest {
		t.Fatalf("unexpected target-access candidate: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{config.AuthorityEndpoint, config.InstallerTokenDigest, "installer-token-v1"} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("target-access candidate receipt exposed private input %q", forbidden)
		}
	}
	changed := candidate
	changed.receipt.ValidUntil = "2026-08-16T14:16:00Z"
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed target-access candidate receipt accepted")
	}
	changed = candidate
	changed.installerTokenDigest = digest.SHA256([]byte("foreign-token"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed private target-access installer binding accepted")
	}
}

func TestPrepareTargetAccessStageLaunchCandidateFailsClosed(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	valid := targetAccessLaunchCandidateConfig()
	for name, mutate := range map[string]func(*SubmissionStageLaunchCandidateConfig){
		"DNS endpoint": func(config *SubmissionStageLaunchCandidateConfig) {
			config.AuthorityEndpoint = "https://ok-shared.example:6443"
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
			config.PreparedAt = time.Date(2026, 8, 16, 14, 15, 1, 0, time.UTC)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := PrepareTargetAccessStageLaunchCandidate(config, stage, credentials, runtime); err == nil {
				t.Fatal("invalid target-access launch candidate accepted")
			}
		})
	}
}

func targetAccessLaunchCandidateConfig() SubmissionStageLaunchCandidateConfig {
	config := submissionStageLaunchCandidateConfig()
	config.PreparedAt = time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC)
	return config
}
