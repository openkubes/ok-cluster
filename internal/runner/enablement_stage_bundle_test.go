package runner

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestLoadEnablementStageBundleBindsCursorGrantAndHCP(t *testing.T) {
	fixture := enablementBundleFixture(t)
	bundle, err := LoadEnablementStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "enablement" || decision.Operation != "CreateEnablement" || !decision.RequiresAuthorization {
		t.Fatalf("unexpected enablement decision: %#v %v", decision, err)
	}
	bound, err := bundle.Open(submissionBundleRuntime(t, fixture.plan, "cluster-lifecycle"))
	if err != nil || !bound.verified {
		t.Fatalf("enablement bundle did not open offline: %#v %v", bound, err)
	}
}

func TestLoadEnablementStageBundleFailsClosed(t *testing.T) {
	fixture := enablementBundleFixture(t)
	fixture.config.Receipts = nil
	if _, err := LoadEnablementStageBundle(fixture.config); err == nil {
		t.Fatal("implicit enablement prefix was accepted")
	}

	fixture = enablementBundleFixture(t)
	raw, err := os.ReadFile(fixture.config.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.config.ArtifactPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnablementStageBundle(fixture.config); err == nil {
		t.Fatal("changed enablement artifact was accepted")
	}

	fixture = enablementBundleFixture(t)
	fixture.config.ExpectedObject.Name = "other-cilium"
	if _, err := LoadEnablementStageBundle(fixture.config); err == nil {
		t.Fatal("foreign enablement object was accepted")
	}

	if _, err := (VerifiedEnablementStageBundle{}).Open(SubmissionStageRuntimeConfig{}); err == nil {
		t.Fatal("unverified enablement bundle was opened")
	}
}

type enablementBundleTestFixture struct {
	config EnablementStageBundleConfig
	plan   stageplan.Binding
}

func enablementBundleFixture(t *testing.T) enablementBundleTestFixture {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC)
	expected := stageplan.Expected{
		ContractIdentity: runnerStagedPlan(t).ContractIdentity,
		IntentRevision:   runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	hcp := runnerEnablementYAML(expected)
	planRaw := submissionBundlePlan(t, expected, runnerStageSHA("1"), runnerStageSHA("2"))
	var document map[string]any
	if err := json.Unmarshal(planRaw, &document); err != nil {
		t.Fatal(err)
	}
	stages := document["stages"].([]any)
	enablement := stages[3].(map[string]any)
	enablement["inputs"] = []any{map[string]any{"name": "stage.enablement", "digest": digest.SHA256(hcp)}}
	planPath := writeBundleFile(t, root, "staged-plan.json", mustJSON(t, document))
	plan, err := stageplan.Load(planPath, expected)
	if err != nil {
		t.Fatal(err)
	}

	receipts := make([]StageReceiptSource, 0, 3)
	predecessors := []stagereceipt.Verified{}
	provider, err := stagereceipt.New(plan, "provider-prerequisites", predecessors, "SUCCEEDED", "ATTEMPTED", runnerStageSHA("4"), runnerStageSHA("5"), at.Add(-3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipts = appendStageReceipt(t, root, receipts, provider, "provider.json")
	predecessors = []stagereceipt.Verified{provider}
	lifecycle, err := stagereceipt.NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", predecessors, "SUCCEEDED", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7"), runnerStageSHA("8"), at.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipts = appendStageReceipt(t, root, receipts, lifecycle, "lifecycle.json")
	predecessors = []stagereceipt.Verified{lifecycle}
	observed, err := stagereceipt.New(plan, "lifecycle-observation", predecessors, "SUCCEEDED", "NOT_APPLICABLE", "", runnerStageSHA("0"), at.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipts = appendStageReceipt(t, root, receipts, observed, "observation.json")
	grantPath, keyPath := writeSubmissionStageGrant(t, root, plan, "enablement", []stagereceipt.Verified{observed}, at)
	return enablementBundleTestFixture{
		config: EnablementStageBundleConfig{
			PlanPath: planPath, PlanExpected: expected, Receipts: receipts,
			GrantPath: grantPath, GrantPublicKeyPath: keyPath, EvaluationTime: at,
			ArtifactPath:   writeBundleFile(t, root, "enablement.yaml", hcp),
			ExpectedObject: projection.ResourceIdentity{APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: expected.ContractIdentity.Namespace, Name: expected.ContractIdentity.Name + "-cilium"},
		},
		plan: plan,
	}
}

func appendStageReceipt(t *testing.T, root string, sources []StageReceiptSource, receipt stagereceipt.Verified, name string) []StageReceiptSource {
	t.Helper()
	raw, err := receipt.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return append(sources, StageReceiptSource{Path: writeBundleFile(t, root, name, raw), Digest: receiptDigest})
}

func runnerEnablementYAML(expected stageplan.Expected) []byte {
	return []byte(`apiVersion: addons.cluster.x-k8s.io/v1alpha1
kind: HelmChartProxy
metadata:
  name: disposable-ok147-cilium
  namespace: disposable-ok147
  annotations:
    openkubes.io/contract-name: disposable-ok147
    openkubes.io/contract-namespace: disposable-ok147
    openkubes.io/intent-revision: ` + expected.IntentRevision + `
    openkubes.io/enablement-revision: ` + expected.EnablementRevision + `
    openkubes.io/execution-fixture: ` + expected.ExecutionFixture + `
    openkubes.io/oci-manifest-digest: ` + runnerStageSHA("4") + `
    openkubes.io/chart-artifact-digest: ` + runnerStageSHA("5") + `
    openkubes.io/values-digest: ` + runnerStageSHA("6") + `
    openkubes.io/digest-enforcement: external-evidence-required
spec:
  clusterSelector:
    matchLabels:
      openkubes.io/type: talos
  chartName: cilium
  repoURL: oci://quay.io/cilium/charts
  releaseName: cilium
  namespace: kube-system
  version: 1.19.6
  reconcileStrategy: Continuous
  valuesTemplate: |
    operator:
      replicas: 1
  options:
    atomic: true
    wait: true
    waitForJobs: true
`)
}
