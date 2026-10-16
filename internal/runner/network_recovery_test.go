package runner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"gopkg.in/yaml.v3"
)

// Synthetic receipts below test offline lineage only, not an executable recovery.
func TestNetworkRecoveryOfflineInspectionPreservesOriginalsAndSuccessorLineage(t *testing.T) {
	config := networkRecoveryFixture(t)
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := VerifyNetworkRecovery(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stagecursor.Evaluate(recovered.Plan, []stagereceipt.Verified{}); err == nil {
		t.Fatal("recovery can replay Stage 1")
	}
	for i, inherited := range recovered.prefix {
		raw, _ := inherited.Bytes()
		original, _ := os.ReadFile(config.Receipts[i].Path)
		r, _ := inherited.Receipt()
		if string(raw) != string(original) || r.PlanDigest != recovered.Plan.RecoverySourcePlanDigest || r.Format != stagereceipt.Format {
			t.Fatal("original outcome was relabeled")
		}
	}
	for _, stage := range []string{"network-observation", "runtime-binding", "target-access"} {
		plan, cursor, prefix, err := loadStageResumeWithPrefix(config)
		if err != nil {
			t.Fatal(err)
		}
		decision, _ := cursor.Decision()
		if decision.StageID != stage || decision.State != "NEXT" {
			t.Fatalf("wrong successor cursor: %#v", decision)
		}
		assertRecoveryExecutionDenied(t, plan, cursor)
		var bundleErr error
		switch stage {
		case "network-observation":
			_, bundleErr = LoadNetworkObservationStageBundle(config)
		case "runtime-binding":
			_, bundleErr = LoadRuntimeBindingStageBundle(config)
		case "target-access":
			bundleConfig := TargetAccessStageBundleConfig{PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: config.Receipts,
				RecoveryBindingPath: config.RecoveryBindingPath, RecoveryBindingDigest: config.RecoveryBindingDigest, EvaluationTime: time.Now()}
			_, bundleErr = LoadTargetAccessStageBundle(bundleConfig)
			if input, err := BuildTargetAccessStageInput(bundleConfig, "ok147-recovery-test"); !errors.Is(err, stageplan.ErrRecoveryExecutionDisabled) || input.verified {
				t.Fatalf("runnable recovery Job input emitted: %v", err)
			}
		}
		if !errors.Is(bundleErr, stageplan.ErrRecoveryExecutionDisabled) {
			t.Fatalf("recovery stage bundle enabled: %v", bundleErr)
		}
		previous := []stagereceipt.Verified{prefix[len(prefix)-1]}
		if stage == "target-access" {
			if _, err := newStageAuthorizationRequest(plan, decision); !errors.Is(err, stageplan.ErrRecoveryExecutionDisabled) {
				t.Fatalf("recovery grant request enabled without atomic source reservation: %v", err)
			}
		}
		mutation, outcome := "NOT_APPLICABLE", ""
		if stage == "target-access" {
			mutation, outcome = "ATTEMPTED", runnerStageSHA("b")
		}
		v, err := stagereceipt.New(plan, stage, previous, "SUCCEEDED", mutation, outcome, runnerStageSHA("a"), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		r, _ := v.Receipt()
		if r.Format != stagereceipt.RecoveryFormat || r.PlanDigest != plan.PlanDigest || r.RecoveryBindingDigest != config.RecoveryBindingDigest {
			t.Fatal("successor lacks explicit recovery identity")
		}
		raw, _ := v.Bytes()
		d, _ := v.Digest()
		if persisted, err := l.StoreStageReceipt(context.Background(), plan, v, previous); err != nil || persisted != d {
			t.Fatalf("persist recovery outcome: %s %v", persisted, err)
		}
		loaded, err := l.LoadStageReceipt(context.Background(), plan, stage, d, previous)
		if err != nil {
			t.Fatal(err)
		}
		loadedRaw, _ := loaded.Bytes()
		if string(loadedRaw) != string(raw) {
			t.Fatal("durable recovery outcome changed")
		}
		path := writeBundleFile(t, filepath.Dir(config.PlanPath), stage+"-successor.json", raw)
		config.Receipts = append(config.Receipts, StageReceiptSource{Path: path, Digest: d})
	}
	d, err := InspectStageResume(config)
	if err != nil || d.State != "COMPLETED" || d.CompletedStages != 7 {
		t.Fatalf("suffix completion differs: %#v %v", d, err)
	}
	config.RecoveryBindingPath, config.RecoveryBindingDigest = "", ""
	if _, err := InspectStageResume(config); err == nil {
		t.Fatal("ordinary resume accepted recovery without the binding")
	}
}

func TestNetworkRecoveryTerminalSuffixNeverCompletesOrReplays(t *testing.T) {
	for _, state := range []string{"FAILED", "STOPPED"} {
		t.Run(state, func(t *testing.T) {
			config := networkRecoveryFixture(t)
			plan, cursor, prefix, err := loadStageResumeWithPrefix(config)
			if err != nil {
				t.Fatal(err)
			}
			previous := []stagereceipt.Verified{prefix[3]}
			v, err := stagereceipt.New(plan, "network-observation", previous, state, "NOT_APPLICABLE", "", runnerStageSHA("a"), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := v.Bytes()
			d, _ := v.Digest()
			path := writeBundleFile(t, filepath.Dir(config.PlanPath), "terminal-suffix.json", raw)
			config.Receipts = append(config.Receipts, StageReceiptSource{Path: path, Digest: d})
			decision, err := InspectStageResume(config)
			if err != nil || decision.State != "STOPPED" || decision.CompletedStages != 4 || decision.TerminalOutcome != state {
				t.Fatalf("terminal suffix reopened: %#v %v", decision, err)
			}
			if _, err := stagereceipt.New(plan, "runtime-binding", []stagereceipt.Verified{v}, "SUCCEEDED", "NOT_APPLICABLE", "", runnerStageSHA("a"), time.Now().UTC()); err == nil {
				t.Fatal("terminal suffix admitted a later stage")
			}
			if _, err := (execution.ObservationStageOperation{}).Retry(context.Background(), plan, cursor, d); err == nil || !strings.Contains(err.Error(), "single-use") {
				t.Fatalf("recovery observation retry was not rejected before opening capabilities: %v", err)
			}
			if _, err := (execution.BindingStageOperation{}).Retry(context.Background(), plan, cursor, d); err == nil || !strings.Contains(err.Error(), "single-use") {
				t.Fatalf("recovery binding retry was not rejected before opening capabilities: %v", err)
			}
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			changed["recoveryBindingDigest"] = runnerStageSHA("f")
			foreign := mustJSON(t, changed)
			if _, err := stagereceipt.Verify(foreign, digest.SHA256(foreign), plan, previous); err == nil {
				t.Fatal("foreign recovery binding accepted")
			}
		})
	}
}

func TestNetworkRecoveryFailsClosedOnIdentityScopeAndEvidenceDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *StageResumeConfig, *NetworkRecoveryDocument)
	}{
		{"authorization-state", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) { d.AuthorizationState = "GO" }},
		{"source-plan-digest", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.SourcePlanDigest = runnerStageSHA("f")
		}},
		{"successor-plan-digest", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.SuccessorPlanDigest = runnerStageSHA("f")
		}},
		{"stop-category", func(t *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			mutateRecoveryStop(t, d, func(s *FullRunExecutionActivationReceipt) { s.Execution.StopCategory = "TIMEOUT" })
		}},
		{"stop-checkpoint", func(t *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			mutateRecoveryStop(t, d, func(s *FullRunExecutionActivationReceipt) {
				s.Execution.Checkpoints[3].StageReceiptDigest = runnerStageSHA("f")
			})
		}},
		{"stop-checkpoint-state", func(t *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			mutateRecoveryStop(t, d, func(s *FullRunExecutionActivationReceipt) { s.Execution.Checkpoints[3].State = "COMPLETED_FAILED" })
		}},
		{"arbitrary-terminal-bytes", func(t *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			raw := []byte("retained-source-terminal")
			if err := os.WriteFile(d.SourceTerminalPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			d.SourceTerminalDigest = digest.SHA256(raw)
		}},
		{"missing-source-prefix", func(_ *testing.T, c *StageResumeConfig, _ *NetworkRecoveryDocument) { c.Receipts = c.Receipts[:3] }},
		{"mixed-source-path", func(_ *testing.T, c *StageResumeConfig, _ *NetworkRecoveryDocument) { c.Receipts[0].Path += "-foreign" }},
		{"target-uid", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.TargetClusterUIDDigest = runnerStageSHA("f")
		}},
		{"former-cluster", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.FormerClusterIdentity.Name = "wrong-cluster"
		}},
		{"source-stop-digest", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.SourceStopReceiptDigest = runnerStageSHA("f")
		}},
		{"source-terminal-digest", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.SourceTerminalDigest = runnerStageSHA("f")
		}},
		{"source-manifest-digest", func(_ *testing.T, _ *StageResumeConfig, d *NetworkRecoveryDocument) {
			d.SourceManifestDigest = runnerStageSHA("f")
		}},
		{"missing-lifecycle-uid", func(t *testing.T, c *StageResumeConfig, d *NetworkRecoveryDocument) {
			// A pinned foreign receipt still has to verify against the exact source chain.
			raw, _ := os.ReadFile(d.SourceReceipts[1].Path)
			var r map[string]any
			_ = json.Unmarshal(raw, &r)
			delete(r, "targetClusterUidDigest")
			raw, _ = contract.JCS(r)
			_ = os.WriteFile(d.SourceReceipts[1].Path, raw, 0o600)
			d.SourceReceipts[1].Digest = digest.SHA256(raw)
			c.Receipts[1].Digest = d.SourceReceipts[1].Digest
		}},
		{"changed-node-count", func(t *testing.T, c *StageResumeConfig, d *NetworkRecoveryDocument) {
			var profile observation.NetworkProfile
			raw, _ := os.ReadFile(d.CorrectedProfilePath)
			_ = json.Unmarshal(raw, &profile)
			profile.ExpectedNodeCount++
			writeBundleFile(t, filepath.Dir(d.CorrectedProfilePath), filepath.Base(d.CorrectedProfilePath), mustJSON(t, profile))
			pd, _ := observation.NetworkProfileDigest(profile)
			updateRecoverySuccessor(t, c, d, func(plan map[string]any) {
				plan["stages"].([]any)[4].(map[string]any)["inputs"].([]any)[0].(map[string]any)["digest"] = pd
			})
		}},
		{"changed-target-access", func(t *testing.T, c *StageResumeConfig, d *NetworkRecoveryDocument) {
			updateRecoverySuccessor(t, c, d, func(plan map[string]any) {
				plan["stages"].([]any)[6].(map[string]any)["inputs"].([]any)[0].(map[string]any)["digest"] = runnerStageSHA("f")
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := networkRecoveryFixture(t)
			raw, _ := os.ReadFile(config.RecoveryBindingPath)
			var doc NetworkRecoveryDocument
			_ = json.Unmarshal(raw, &doc)
			test.mutate(t, &config, &doc)
			raw = mustJSON(t, doc)
			_ = os.WriteFile(config.RecoveryBindingPath, raw, 0o600)
			config.RecoveryBindingDigest = digest.SHA256(raw)
			if _, err := InspectStageResume(config); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
		})
	}
}

func updateRecoverySuccessor(t *testing.T, c *StageResumeConfig, d *NetworkRecoveryDocument, mutate func(map[string]any)) {
	t.Helper()
	raw, _ := os.ReadFile(c.PlanPath)
	var plan map[string]any
	_ = json.Unmarshal(raw, &plan)
	mutate(plan)
	raw = mustJSON(t, plan)
	_ = os.WriteFile(c.PlanPath, raw, 0o600)
	e := c.PlanExpected
	e.RecoverySourcePlanDigest = d.SourcePlanDigest
	p, err := stageplan.Verify(raw, e)
	if err != nil {
		t.Fatal(err)
	}
	d.SuccessorPlanDigest = p.PlanDigest
}

func networkRecoveryFixture(t *testing.T) StageResumeConfig {
	t.Helper()
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	t.Cleanup(cleanup)
	m, _, err := loadFullRunExecutionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(manifestPath)
	m.Plan.Expected.CompletionMode = stageplan.CompletionModeBareClusterMVP
	expected := fullRunPlanExpected(m.Plan.Expected)
	var hcp struct {
		Spec map[string]any `yaml:"spec"`
	}
	hcpRaw, _ := os.ReadFile(m.Enablement.ArtifactPath)
	if err := yaml.Unmarshal(hcpRaw, &hcp); err != nil {
		t.Fatal(err)
	}
	former := contract.Identity{Name: "old-cluster", Namespace: "old-cluster"}
	oldHRP, err := observation.ExpectedLiteralReleaseSpecDigest(hcp.Spec, former.Namespace, former.Name)
	if err != nil {
		t.Fatal(err)
	}
	newHRP, err := observation.ExpectedLiteralReleaseSpecDigest(hcp.Spec, expected.ContractIdentity.Namespace, expected.ContractIdentity.Name)
	if err != nil {
		t.Fatal(err)
	}
	profileRaw, _ := os.ReadFile(m.Profiles.Network.Path)
	var profile observation.NetworkProfile
	_ = json.Unmarshal(profileRaw, &profile)
	profile.ExpectedHRPSpecDigest = oldHRP
	oldProfileDigest, err := observation.NetworkProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(m.Profiles.Network.Path, mustJSON(t, profile), 0o600)
	m.Profiles.Network.Digest = oldProfileDigest
	profile.ExpectedHRPSpecDigest = newHRP
	newProfilePath := writeBundleFile(t, root, "corrected-network.json", mustJSON(t, profile))
	newProfileDigest, _ := observation.NetworkProfileDigest(profile)
	planRaw, _ := os.ReadFile(m.Plan.Path)
	var plan map[string]any
	_ = json.Unmarshal(planRaw, &plan)
	plan["completionMode"] = stageplan.CompletionModeBareClusterMVP
	plan["stages"] = plan["stages"].([]any)[:7]
	plan["stages"].([]any)[4].(map[string]any)["inputs"].([]any)[0].(map[string]any)["digest"] = oldProfileDigest
	planRaw = mustJSON(t, plan)
	_ = os.WriteFile(m.Plan.Path, planRaw, 0o600)
	source, err := stageplan.Verify(planRaw, expected)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(manifestPath, mustJSON(t, m), 0o600)
	_, manifestDigest, err := loadFullRunExecutionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sources := []StageReceiptSource{}
	docSources := []RecoveryReceiptSource{}
	previous := []stagereceipt.Verified{}
	checkpoints := []FullRunStageCheckpoint{}
	uid := digest.SHA256([]byte("target-cluster-uid"))
	at := time.Now().UTC().Add(-time.Minute)
	for i, stage := range source.Stages[:4] {
		state, outcome, target := "NOT_APPLICABLE", "", ""
		if stageplan.IsMutating(stage) {
			state, outcome = "ATTEMPTED", runnerStageSHA("a")
		}
		if i == 1 {
			target = uid
		}
		v, err := stagereceipt.NewWithTargetClusterUIDDigest(source, stage.ID, previous, "SUCCEEDED", state, outcome, runnerStageSHA("b"), target, at.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := v.Bytes()
		d, _ := v.Digest()
		p := writeBundleFile(t, root, stage.ID+".json", raw)
		sources = append(sources, StageReceiptSource{Path: p, Digest: d})
		docSources = append(docSources, RecoveryReceiptSource{Path: p, Digest: d})
		checkpoints = append(checkpoints, FullRunStageCheckpoint{StageID: stage.ID, State: "COMPLETED_SUCCEEDED", StageReceiptDigest: d})
		previous = []stagereceipt.Verified{v}
	}
	stop := FullRunExecutionActivationReceipt{Format: FullRunExecutionActivationReceiptFormat, State: "STOPPED",
		Manifest: FullRunExecutionManifestReceipt{State: "VERIFIED", ManifestDigest: manifestDigest, PlanDigest: source.PlanDigest},
		Execution: &FullRunOrchestrationReceipt{Format: FullRunOrchestrationReceiptFormat, State: "STOPPED", PlanDigest: source.PlanDigest,
			CompletionMode: stageplan.CompletionModeBareClusterMVP, StoppedAt: "network-observation", StopCategory: "OBSERVATION_SOURCE_ERROR", Checkpoints: checkpoints}}
	stopRaw := mustJSON(t, stop)
	stopPath := writeBundleFile(t, root, "stop.json", stopRaw)
	terminalRaw := []byte("TERMINAL\n")
	terminalPath := writeBundleFile(t, root, "executor-terminal", terminalRaw)
	plan["format"] = stageplan.FormatRecovery
	plan["recoverySourcePlanDigest"] = source.PlanDigest
	plan["stages"].([]any)[4].(map[string]any)["inputs"].([]any)[0].(map[string]any)["digest"] = newProfileDigest
	newPlanRaw := mustJSON(t, plan)
	successorPath := writeBundleFile(t, root, "successor-plan.json", newPlanRaw)
	successorExpected := expected
	successorExpected.RecoverySourcePlanDigest = source.PlanDigest
	successor, err := stageplan.Verify(newPlanRaw, successorExpected)
	if err != nil {
		t.Fatal(err)
	}
	doc := NetworkRecoveryDocument{Format: NetworkRecoveryFormat, AuthorizationState: "NO-GO", SourceManifestPath: manifestPath, SourceManifestDigest: manifestDigest,
		SourcePlanDigest: source.PlanDigest, SuccessorPlanDigest: successor.PlanDigest, SourceStopReceiptPath: stopPath, SourceStopReceiptDigest: digest.SHA256(stopRaw),
		SourceTerminalPath: terminalPath, SourceTerminalDigest: digest.SHA256(terminalRaw), SourceReceipts: docSources, TargetClusterUIDDigest: uid,
		FormerClusterIdentity: former, CorrectedProfilePath: newProfilePath}
	docRaw := mustJSON(t, doc)
	docPath := writeBundleFile(t, root, "recovery.json", docRaw)
	return StageResumeConfig{PlanPath: successorPath, PlanExpected: expected, Receipts: sources, RecoveryBindingPath: docPath, RecoveryBindingDigest: digest.SHA256(docRaw)}
}

func mutateRecoveryStop(t *testing.T, d *NetworkRecoveryDocument, mutate func(*FullRunExecutionActivationReceipt)) {
	t.Helper()
	raw, err := os.ReadFile(d.SourceStopReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var stop FullRunExecutionActivationReceipt
	if err := json.Unmarshal(raw, &stop); err != nil {
		t.Fatal(err)
	}
	mutate(&stop)
	raw = mustJSON(t, stop)
	if err := os.WriteFile(d.SourceStopReceiptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	d.SourceStopReceiptDigest = digest.SHA256(raw)
}
