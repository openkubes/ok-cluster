package runner

import (
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestInspectStageResumeSelectsReadOnlyStageFromVerifiedPrefix(t *testing.T) {
	fixture := submissionBundleFixture(t, true, "")
	provider, err := stagereceipt.Load(fixture.config.Receipts[0].Path, fixture.config.Receipts[0].Digest, fixture.plan, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := stagereceipt.New(fixture.plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", bundleSHA("6"), bundleSHA("7"), time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := lifecycle.Bytes()
	digest, _ := lifecycle.Digest()
	source := StageReceiptSource{Path: writeBundleFile(t, t.TempDir(), "lifecycle-receipt.json", raw), Digest: digest}

	decision, err := InspectStageResume(StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected,
		Receipts: append(append([]StageReceiptSource{}, fixture.config.Receipts...), source),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.State != "NEXT" || decision.StageID != "lifecycle-observation" || decision.Kind != "Observation" || decision.Authority != "management" || decision.RequiresAuthorization || decision.Operation != "" || decision.CompletedStages != 2 {
		t.Fatalf("unexpected resume decision: %#v", decision)
	}
}

func TestInspectStageResumeRejectsImplicitOrChangedPrefix(t *testing.T) {
	fixture := submissionBundleFixture(t, true, "")
	config := StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected}
	if _, err := InspectStageResume(config); err == nil {
		t.Fatal("implicit receipt prefix was accepted")
	}

	config.Receipts = append([]StageReceiptSource{}, fixture.config.Receipts...)
	config.Receipts[0].Digest = bundleSHA("f")
	if _, err := InspectStageResume(config); err == nil || !strings.Contains(err.Error(), "digest differs") {
		t.Fatalf("changed receipt identity was accepted: %v", err)
	}
}

func TestInspectStageResumeReportsTerminalPlanWithoutExecution(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	predecessors := []stagereceipt.Verified{}
	sources := []StageReceiptSource{}
	root := t.TempDir()
	started := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	for index, stage := range fixture.plan.Stages {
		state, mutation, operationDigest := "SUCCEEDED", "NOT_APPLICABLE", ""
		if stage.GrantOperation != "" {
			mutation, operationDigest = "ATTEMPTED", bundleSHA("8")
		}
		verified, err := stagereceipt.New(fixture.plan, stage.ID, predecessors, state, mutation, operationDigest, bundleSHA("9"), started.Add(time.Duration(index)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := verified.Bytes()
		receiptDigest, _ := verified.Digest()
		sources = append(sources, StageReceiptSource{Path: writeBundleFile(t, root, stage.ID+".json", raw), Digest: receiptDigest})
		predecessors = []stagereceipt.Verified{verified}
	}
	decision, err := InspectStageResume(StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: sources})
	if err != nil {
		t.Fatal(err)
	}
	if decision.State != "COMPLETED" || decision.CompletedStages != 12 || decision.RequiresAuthorization || decision.StageID != "" {
		t.Fatalf("completed plan decision differs: %#v", decision)
	}
}
