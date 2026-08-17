package submission

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestLoadPlatformApplicationsBindsExactProfileSet(t *testing.T) {
	fixture := platformApplicationsFixture(t)
	plan, err := LoadPlatformApplications(fixture.path, fixture.expected)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != PlatformApplicationsPlanFormat || plan.IntentRevision != fixture.expected.IntentRevision ||
		plan.PlatformRevision != fixture.expected.PlatformRevision || plan.ExecutionFixture != fixture.expected.ExecutionFixture ||
		plan.TargetIdentityDigest != fixture.expected.TargetIdentityDigest || plan.ArtifactDigest != fixture.expected.ArtifactDigest ||
		plan.Authority != "ok-shared" || plan.MutationAllowed || len(plan.Applications) != 3 {
		t.Fatalf("unexpected platform Applications plan: %#v", plan)
	}
	wantNames := []string{"disposable-ok147-observability-alerting", "disposable-ok147-observability-core", "disposable-ok147-observability-dashboards"}
	for index, object := range plan.Applications {
		if object.Identity.Name != wantNames[index] || object.Identity.Namespace != "argocd" || object.Identity.Kind != "Application" ||
			object.CollectionPath != "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications" ||
			object.ObjectPath != object.CollectionPath+"/"+object.Identity.Name || digest.SHA256(object.Raw) != object.Digest {
			t.Fatalf("unexpected platform Application %d: %#v", index, object)
		}
	}
}

func TestPlatformApplicationSpecIdentityIncludesIgnoreDifferences(t *testing.T) {
	fixture := platformApplicationsFixture(t)
	spec := fixture.documents[0]["spec"].(map[string]any)
	first, revision, err := observation.PlatformApplicationSpecIdentity(spec)
	if err != nil || revision != strings.Repeat("6", 40) {
		t.Fatalf("unexpected spec identity: %s %s %v", first, revision, err)
	}
	spec["ignoreDifferences"] = []any{map[string]any{"group": "apps", "kind": "StatefulSet", "jsonPointers": []any{"/spec/template"}}}
	second, _, err := observation.PlatformApplicationSpecIdentity(spec)
	if err != nil || first == second {
		t.Fatal("ignoreDifferences change did not change semantic spec identity")
	}
}

func TestLoadPlatformApplicationsFailsClosed(t *testing.T) {
	tests := map[string]func(*platformApplicationsTestFixture){
		"missing Application": func(f *platformApplicationsTestFixture) { f.documents = f.documents[:2] },
		"duplicate Application": func(f *platformApplicationsTestFixture) {
			f.documents[2]["metadata"].(map[string]any)["name"] = f.documents[1]["metadata"].(map[string]any)["name"]
		},
		"mutable source revision": func(f *platformApplicationsTestFixture) {
			f.documents[0]["spec"].(map[string]any)["source"].(map[string]any)["targetRevision"] = "main"
		},
		"foreign target": func(f *platformApplicationsTestFixture) {
			f.documents[0]["spec"].(map[string]any)["destination"].(map[string]any)["name"] = "foreign-target"
		},
		"wrong revision carrier": func(f *platformApplicationsTestFixture) {
			f.documents[0]["metadata"].(map[string]any)["annotations"].(map[string]any)["openkubes.io/platform-revision"] = platformApplicationsSHA("f")
		},
		"unprofiled semantic change": func(f *platformApplicationsTestFixture) {
			f.documents[0]["spec"].(map[string]any)["syncPolicy"] = map[string]any{"automated": map[string]any{"enabled": true, "prune": false, "selfHeal": true, "allowEmpty": false}}
		},
		"unknown metadata": func(f *platformApplicationsTestFixture) {
			f.documents[0]["metadata"].(map[string]any)["labels"] = map[string]any{"unexpected": "value"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := platformApplicationsFixture(t)
			mutate(&fixture)
			fixture.write(t)
			if _, err := LoadPlatformApplications(fixture.path, fixture.expected); err == nil {
				t.Fatal("invalid platform Applications artifact was accepted")
			}
		})
	}
}

type platformApplicationsTestFixture struct {
	path      string
	documents []map[string]any
	expected  PlatformApplicationsExpected
}

func platformApplicationsFixture(t *testing.T) platformApplicationsTestFixture {
	t.Helper()
	intent, platform, execution, target := platformApplicationsSHA("a"), platformApplicationsSHA("b"), platformApplicationsSHA("c"), platformApplicationsSHA("d")
	commit := strings.Repeat("6", 40)
	names := []string{"disposable-ok147-observability-core", "disposable-ok147-observability-alerting", "disposable-ok147-observability-dashboards"}
	paths := []string{"profiles/ok-observability-standard", "alerting", "dashboards"}
	documents := make([]map[string]any, 0, 3)
	profileApplications := make([]observation.PlatformApplicationExpectation, 0, 3)
	for index, name := range names {
		spec := map[string]any{
			"project":     "openkubes-disposable",
			"source":      map[string]any{"repoURL": "https://github.com/openkubes/ok-observability.git", "path": paths[index], "targetRevision": commit},
			"destination": map[string]any{"name": "disposable-ok147", "namespace": "ok-observability"},
			"syncPolicy":  map[string]any{"automated": map[string]any{"enabled": true, "prune": true, "selfHeal": true, "allowEmpty": false}},
		}
		if index == 0 {
			spec["ignoreDifferences"] = []any{map[string]any{"group": "apps", "kind": "StatefulSet", "jsonPointers": []any{"/spec/revisionHistoryLimit"}}}
		}
		specDigest, _, err := observation.PlatformApplicationSpecIdentity(spec)
		if err != nil {
			t.Fatal(err)
		}
		profileApplications = append(profileApplications, observation.PlatformApplicationExpectation{Name: name, SpecDigest: specDigest})
		documents = append(documents, map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"metadata": map[string]any{
				"name": name, "namespace": "argocd",
				"annotations": map[string]any{
					"openkubes.io/intent-revision": intent, "openkubes.io/platform-revision": platform,
					"openkubes.io/execution-fixture": execution, "openkubes.io/target-identity-digest": target,
				},
			},
			"spec": spec,
		})
	}
	profile := observation.PlatformProfile{
		Format: observation.PlatformProfileFormat, IntentRevision: intent, PlatformRevision: platform,
		ExecutionFixture: execution, TargetIdentityScheme: "capi-cluster-uid/v1", ArgoNamespace: "argocd",
		RegistrationName: "disposable-ok147", RequiredApplications: profileApplications,
		CapabilityContractDigest: platformApplicationsSHA("e"), CapabilityExecutableDigest: platformApplicationsSHA("f"), MaximumCapabilityAgeSeconds: 3600,
	}
	fixture := platformApplicationsTestFixture{
		path: t.TempDir() + "/platform-applications.yaml", documents: documents,
		expected: PlatformApplicationsExpected{
			ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
			IntentRevision:   intent, PlatformRevision: platform, ExecutionFixture: execution, TargetIdentityDigest: target,
			ArgoAuthority: "ok-shared", ArgoNamespace: "argocd", ProjectName: "openkubes-disposable",
			RegistrationName: "disposable-ok147", SourceRepository: "https://github.com/openkubes/ok-observability.git", Profile: profile,
		},
	}
	fixture.write(t)
	return fixture
}

func platformApplicationsSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }

func (fixture *platformApplicationsTestFixture) write(t *testing.T) {
	t.Helper()
	raw := []byte{}
	for index, document := range fixture.documents {
		if index > 0 {
			raw = append(raw, []byte("\n---\n")...)
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded...)
	}
	if err := os.WriteFile(fixture.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.expected.ArtifactDigest = digest.SHA256(raw)
}
