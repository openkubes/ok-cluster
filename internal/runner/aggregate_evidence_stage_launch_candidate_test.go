package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPrepareAggregateEvidenceStageLaunchCandidateBindsDestinationAndCredential(t *testing.T) {
	stage, credentials, privateInputs, runtime, _ := aggregateEvidenceStageLaunchFixture(t)
	config := submissionStageLaunchCandidateConfig()
	candidate, err := PrepareAggregateEvidenceStageLaunchCandidate(config, stage, credentials, privateInputs, runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := candidate.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareAggregateEvidenceStageLaunchCandidate(config, stage, credentials, privateInputs, runtime)
	if err != nil {
		t.Fatal(err)
	}
	againReceipt, _ := again.Receipt()
	if receipt.Format != AggregateEvidenceStageLaunchCandidateFormat || receipt.State != "PREPARED" || receipt.StageID != "aggregate-evidence" || receipt.Authority != "ok-mgmt" || receipt.PreparedAt != "2026-08-16T12:01:00Z" || receipt.ValidUntil != "2026-08-16T12:15:00Z" || receipt.MutationAllowed || receipt.CandidateDigest != againReceipt.CandidateDigest {
		t.Fatalf("unexpected aggregate evidence candidate: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{config.AuthorityEndpoint, config.InstallerTokenDigest, "installer-token-v1"} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("aggregate candidate receipt exposed private input %q", forbidden)
		}
	}
	changed := candidate
	changed.receipt.ValidUntil = "2026-08-16T12:16:00Z"
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed aggregate candidate receipt accepted")
	}
	changed = candidate
	changed.installerTokenDigest = digest.SHA256([]byte("foreign-token"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed private aggregate installer binding accepted")
	}
}

func TestPrepareAggregateEvidenceStageLaunchCandidateFailsClosed(t *testing.T) {
	stage, credentials, privateInputs, runtime, _ := aggregateEvidenceStageLaunchFixture(t)
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
			if _, err := PrepareAggregateEvidenceStageLaunchCandidate(config, stage, credentials, privateInputs, runtime); err == nil {
				t.Fatal("invalid aggregate evidence launch candidate accepted")
			}
		})
	}
}
