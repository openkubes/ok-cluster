package runner

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestLoadPlatformApplicationsStageBundleBindsPrefixGrantProfileAndObjects(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, err := LoadPlatformApplicationsStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "platform-applications" || decision.Kind != "Submission" || decision.Operation != "CreatePlatformApplications" || decision.Authority != "gitops" || !decision.RequiresAuthorization {
		t.Fatalf("unexpected platform-applications decision: %#v %v", decision, err)
	}
	receipt, err := bundle.Receipt()
	if err != nil || receipt.Format != PlatformApplicationsStageBundleReceiptFormat || receipt.State != "VERIFIED" || receipt.PlanDigest != fixture.plan.PlanDigest || receipt.ArtifactDigest != fixture.artifactDigest || receipt.TargetIdentityDigest != digest.SHA256([]byte(targetAccessRuntimeUID)) || receipt.ProfileDigest != fixture.profileDigest || receipt.AuthorizationDigest == "" || receipt.Authority != "ok-shared" || receipt.MutationAllowed || len(receipt.ApplicationDigests) != 3 {
		t.Fatalf("unexpected platform-applications receipt: %#v %v", receipt, err)
	}
	if !sort.StringsAreSorted(receipt.ApplicationDigests) {
		t.Fatal("Application digests are not canonical")
	}
	receipt.ApplicationDigests[0] = runnerStageSHA("f")
	again, err := bundle.Receipt()
	if err != nil || again.ApplicationDigests[0] == receipt.ApplicationDigests[0] {
		t.Fatal("receipt exposed mutable Application digest storage")
	}
}

func TestLoadPlatformApplicationsStageBundleFailsClosed(t *testing.T) {
	tests := map[string]func(*platformApplicationsBundleTestFixture){
		"implicit prefix":   func(f *platformApplicationsBundleTestFixture) { f.config.Receipts = nil },
		"incomplete prefix": func(f *platformApplicationsBundleTestFixture) { f.config.Receipts = f.config.Receipts[:8] },
		"changed artifact": func(f *platformApplicationsBundleTestFixture) {
			raw, _ := os.ReadFile(f.config.ArtifactPath)
			_ = os.WriteFile(f.config.ArtifactPath, append(raw, '\n'), 0o600)
		},
		"foreign target": func(f *platformApplicationsBundleTestFixture) {
			f.config.Expected.TargetIdentityDigest = runnerStageSHA("f")
		},
		"foreign authority": func(f *platformApplicationsBundleTestFixture) { f.config.Expected.ArgoAuthority = "foreign-gitops" },
		"foreign platform revision": func(f *platformApplicationsBundleTestFixture) {
			f.config.Expected.Profile.PlatformRevision = runnerStageSHA("f")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := platformApplicationsBundleFixture(t)
			mutate(&fixture)
			if _, err := LoadPlatformApplicationsStageBundle(fixture.config); err == nil {
				t.Fatal("invalid platform-applications bundle was accepted")
			}
		})
	}
	if _, err := (VerifiedPlatformApplicationsStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified platform-applications bundle exposed decision")
	}
	if _, err := (VerifiedPlatformApplicationsStageBundle{}).Receipt(); err == nil {
		t.Fatal("unverified platform-applications bundle exposed receipt")
	}
}

func TestPlatformApplicationsStageBundleDetectsPostVerificationMutation(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, err := LoadPlatformApplicationsStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	bundle.projection.Applications[0].Raw[0] ^= 1
	if _, err := bundle.Receipt(); err == nil {
		t.Fatal("mutated verified Application was accepted")
	}

	bundle, err = LoadPlatformApplicationsStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	bundle.profile.RequiredApplications[0].SpecDigest = runnerStageSHA("f")
	if _, err := bundle.Decision(); err == nil {
		t.Fatal("mutated verified Platform profile was accepted")
	}

	bundle, err = LoadPlatformApplicationsStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	bundle.receipt.PlanDigest = runnerStageSHA("f")
	if _, err := bundle.Receipt(); err == nil {
		t.Fatal("mutated verified plan binding was accepted")
	}
}

type platformApplicationsBundleTestFixture struct {
	config         PlatformApplicationsStageBundleConfig
	plan           stageplan.Binding
	artifactDigest string
	profileDigest  string
}

func platformApplicationsBundleFixture(t *testing.T) platformApplicationsBundleTestFixture {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 17, 20, 0, 0, 0, time.UTC)
	expectedPlan := stageplan.Expected{
		ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision:   runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	applications, profile := runnerPlatformApplications(t, expectedPlan)
	artifactDigest := digest.SHA256(applications)
	profileDigest, err := observation.PlatformProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	planRaw := submissionBundlePlan(t, expectedPlan, runnerStageSHA("1"), runnerStageSHA("2"))
	var document map[string]any
	if err := json.Unmarshal(planRaw, &document); err != nil {
		t.Fatal(err)
	}
	stages := document["stages"].([]any)
	stages[6].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-access", "digest": runnerStageSHA("3")}}
	stages[7].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-credential", "digest": runnerStageSHA("4")}}
	stages[8].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.target-registration", "digest": runnerStageSHA("5")}}
	stages[9].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.platform-applications", "digest": artifactDigest}}
	stages[10].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.platform-observation", "digest": profileDigest}}
	planPath := writeBundleFile(t, root, "staged-plan.json", mustJSON(t, document))
	plan, err := stageplan.Load(planPath, expectedPlan)
	if err != nil {
		t.Fatal(err)
	}

	receipts := make([]StageReceiptSource, 0, 9)
	predecessors := []stagereceipt.Verified{}
	results := []struct{ id, mutation, operation, evidence string }{
		{"provider-prerequisites", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2")},
		{"cluster-lifecycle", "ATTEMPTED", runnerStageSHA("3"), runnerStageSHA("4")},
		{"lifecycle-observation", "NOT_APPLICABLE", "", runnerStageSHA("5")},
		{"enablement", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7")},
		{"network-observation", "NOT_APPLICABLE", "", runnerStageSHA("8")},
		{"runtime-binding", "NOT_APPLICABLE", "", runnerStageSHA("9")},
		{"target-access", "ATTEMPTED", runnerStageSHA("0"), runnerStageSHA("a")},
		{"target-credential", "ATTEMPTED", runnerStageSHA("b"), runnerStageSHA("c")},
		{"target-registration", "ATTEMPTED", runnerStageSHA("d"), runnerStageSHA("e")},
	}
	for index, result := range results {
		var receipt stagereceipt.Verified
		if result.id == "cluster-lifecycle" {
			receipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, digest.SHA256([]byte(targetAccessRuntimeUID)), at.Add(time.Duration(index-9)*time.Minute))
		} else {
			receipt, err = stagereceipt.New(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, at.Add(time.Duration(index-9)*time.Minute))
		}
		if err != nil {
			t.Fatal(err)
		}
		receipts = appendStageReceipt(t, root, receipts, receipt, result.id+".json")
		predecessors = []stagereceipt.Verified{receipt}
	}
	grantPath, keyPath := writeSubmissionStageGrant(t, root, plan, "platform-applications", predecessors, at)
	expected := submission.PlatformApplicationsExpected{
		ArtifactDigest: artifactDigest, ContractIdentity: expectedPlan.ContractIdentity,
		IntentRevision: expectedPlan.IntentRevision, PlatformRevision: expectedPlan.PlatformRevision, ExecutionFixture: expectedPlan.ExecutionFixture,
		TargetIdentityDigest: digest.SHA256([]byte(targetAccessRuntimeUID)), ArgoAuthority: "ok-shared", ArgoNamespace: "argocd",
		ProjectName: "openkubes-disposable", RegistrationName: "disposable-ok147", SourceRepository: "https://github.com/openkubes/ok-observability.git", Profile: profile,
	}
	return platformApplicationsBundleTestFixture{
		config: PlatformApplicationsStageBundleConfig{
			PlanPath: planPath, PlanExpected: expectedPlan, Receipts: receipts,
			GrantPath: grantPath, GrantPublicKeyPath: keyPath, EvaluationTime: at,
			ArtifactPath: writeBundleFile(t, root, "platform-applications.yaml", applications), Expected: expected,
		},
		plan: plan, artifactDigest: artifactDigest, profileDigest: profileDigest,
	}
}

func runnerPlatformApplications(t *testing.T, expected stageplan.Expected) ([]byte, observation.PlatformProfile) {
	t.Helper()
	names := []string{"disposable-ok147-observability-alerting", "disposable-ok147-observability-core", "disposable-ok147-observability-dashboards"}
	paths := []string{"profiles/minimal-observability/alerting", "profiles/minimal-observability/core", "profiles/minimal-observability/dashboards"}
	annotations := map[string]any{
		"openkubes.io/intent-revision": expected.IntentRevision, "openkubes.io/platform-revision": expected.PlatformRevision,
		"openkubes.io/execution-fixture": expected.ExecutionFixture, "openkubes.io/target-identity-digest": digest.SHA256([]byte(targetAccessRuntimeUID)),
	}
	documents := make([][]byte, 0, len(names))
	expectations := make([]observation.PlatformApplicationExpectation, 0, len(names))
	for index, name := range names {
		spec := map[string]any{
			"project":     "openkubes-disposable",
			"source":      map[string]any{"repoURL": "https://github.com/openkubes/ok-observability.git", "path": paths[index], "targetRevision": strings.Repeat("6", 40)},
			"destination": map[string]any{"name": "disposable-ok147", "namespace": "ok-observability"},
			"syncPolicy":  map[string]any{"automated": map[string]any{"prune": true, "selfHeal": true}, "syncOptions": []any{"CreateNamespace=true"}},
		}
		if index == 1 {
			spec["ignoreDifferences"] = []any{map[string]any{"group": "apps", "kind": "Deployment", "jsonPointers": []any{"/spec/replicas"}}}
		}
		specDigest, _, err := observation.PlatformApplicationSpecIdentity(spec)
		if err != nil {
			t.Fatal(err)
		}
		expectations = append(expectations, observation.PlatformApplicationExpectation{Name: name, SpecDigest: specDigest})
		document := map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"metadata": map[string]any{"name": name, "namespace": "argocd", "annotations": annotations}, "spec": spec,
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		documents = append(documents, raw)
	}
	profile := observation.PlatformProfile{
		Format: observation.PlatformProfileFormat, IntentRevision: expected.IntentRevision, PlatformRevision: expected.PlatformRevision,
		ExecutionFixture: expected.ExecutionFixture, TargetIdentityScheme: "capi-cluster-uid/v1", ArgoNamespace: "argocd",
		RegistrationName: "disposable-ok147", RequiredApplications: expectations,
		CapabilityContractDigest: runnerStageSHA("7"), CapabilityExecutableDigest: runnerStageSHA("8"), MaximumCapabilityAgeSeconds: 900,
	}
	return []byte(strings.Join([]string{string(documents[0]), string(documents[1]), string(documents[2])}, "\n---\n")), profile
}
