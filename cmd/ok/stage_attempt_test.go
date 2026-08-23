package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/stageattempt"
)

func TestClusterStageAttemptVerifyEmitsNonAuthorizingIdentity(t *testing.T) {
	document := map[string]any{
		"format": stageattempt.Format, "attemptId": "ok147-full-run-r11",
		"sourceFixtureDigest": testSHA("1"), "sourcePlanSemanticDigest": testSHA("2"),
		"runnerImage":             "ghcr.io/openkubes/ok-cluster-runner@" + testSHA("3"),
		"activationPackageDigest": testSHA("4"), "mode": stageattempt.Mode,
		"predecessorAttemptDigest": testSHA("5"), "stoppedEvidenceDigest": testSHA("6"),
		"decisionWindowDigest": testSHA("7"), "maxAttempts": 1,
	}
	raw, _ := json.Marshal(document)
	path := filepath.Join(t.TempDir(), "attempt.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"cluster", "stage", "attempt", "verify", "--attempt", path, "--attempt-id", "ok147-full-run-r11",
		"--source-fixture-digest", testSHA("1"), "--source-plan-semantic-digest", testSHA("2"),
		"--runner-image", "ghcr.io/openkubes/ok-cluster-runner@" + testSHA("3"), "--activation-package-digest", testSHA("4"),
		"--predecessor-attempt-digest", testSHA("5"), "--stopped-evidence-digest", testSHA("6"), "--decision-window-digest", testSHA("7"),
	}
	var stdout bytes.Buffer
	if err := run(arguments, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt stageattempt.Receipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "VERIFIED" || receipt.MutationAllowed || receipt.ExecutionAttemptDigest == "" {
		t.Fatalf("unexpected attempt receipt: %#v %v", receipt, err)
	}
	if err := run(removeArgumentWithValue(arguments, "--stopped-evidence-digest"), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete recovery lineage was accepted")
	}
}
