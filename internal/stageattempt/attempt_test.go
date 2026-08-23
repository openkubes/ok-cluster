package stageattempt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyIsDeterministicAndInputBound(t *testing.T) {
	document, expected := fixture()
	raw, _ := json.Marshal(document)
	first, err := Verify(raw, expected)
	if err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(document, "", "  ")
	second, err := Verify(pretty, expected)
	if err != nil || first != second || first.State != "VERIFIED" || first.MutationAllowed || first.MaxAttempts != 1 || !first.RecoveryBound {
		t.Fatalf("attempt identity is not deterministic: %#v %#v %v", first, second, err)
	}

	changed := document
	changed.RunnerImage = "ghcr.io/openkubes/ok-cluster-runner@" + sha("9")
	changedExpected := expected
	changedExpected.RunnerImage = changed.RunnerImage
	changedRaw, _ := json.Marshal(changed)
	changedReceipt, err := Verify(changedRaw, changedExpected)
	if err != nil || changedReceipt.ExecutionAttemptDigest == first.ExecutionAttemptDigest {
		t.Fatalf("changed attempt input retained its identity: %#v %v", changedReceipt, err)
	}
	if _, err := Verify(changedRaw, expected); err == nil {
		t.Fatal("foreign attempt input was accepted")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	document, expected := fixture()
	tests := map[string]func(*Document){
		"unknown format":        func(value *Document) { value.Format = "ok147-execution-attempt/v2" },
		"arbitrary mode":        func(value *Document) { value.Mode = "retry-forever" },
		"more than one attempt": func(value *Document) { value.MaxAttempts = 2 },
		"mutable image":         func(value *Document) { value.RunnerImage = "ghcr.io/openkubes/ok-cluster-runner:latest" },
		"missing predecessor":   func(value *Document) { value.PredecessorAttemptDigest = "" },
		"missing stopped proof": func(value *Document) { value.StoppedEvidenceDigest = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := document
			mutate(&candidate)
			raw, _ := json.Marshal(candidate)
			if _, err := Verify(raw, expected); err == nil {
				t.Fatal("unsafe attempt was accepted")
			}
		})
	}
	raw := []byte(`{"format":"ok147-execution-attempt/v1","unknown":true}`)
	if _, err := Verify(raw, expected); err == nil {
		t.Fatal("unknown attempt field was accepted")
	}
}

func fixture() (Document, Expected) {
	document := Document{
		Format: Format, AttemptID: "ok147-full-run-r11", SourceFixtureDigest: sha("1"), SourcePlanSemanticDigest: sha("2"),
		RunnerImage: "ghcr.io/openkubes/ok-cluster-runner@" + sha("3"), ActivationPackageDigest: sha("4"), Mode: Mode,
		PredecessorAttemptDigest: sha("5"), StoppedEvidenceDigest: sha("6"), DecisionWindowDigest: sha("7"), MaxAttempts: 1,
	}
	expected := Expected{
		AttemptID: document.AttemptID, SourceFixtureDigest: document.SourceFixtureDigest, SourcePlanSemanticDigest: document.SourcePlanSemanticDigest,
		RunnerImage: document.RunnerImage, ActivationPackageDigest: document.ActivationPackageDigest,
		PredecessorAttemptDigest: document.PredecessorAttemptDigest, StoppedEvidenceDigest: document.StoppedEvidenceDigest,
		DecisionWindowDigest: document.DecisionWindowDigest,
	}
	return document, expected
}

func sha(value string) string { return "sha256:" + strings.Repeat(value, 64) }
