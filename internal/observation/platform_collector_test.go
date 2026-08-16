package observation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPlatformCollectorReadsExactApplicationsAndComposes(t *testing.T) {
	policy, profile, capability, getter := platformCollectorFixture(t)
	source := &fakePlatformCapabilitySource{capability: capability}
	collector, err := NewPlatformSourceCollector(getter, source, PlatformCollectorConfig{
		Profile: profile, TargetClusterUID: policy.TargetClusterUID, Clock: func() time.Time { return time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := collector.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != "True" || evidence.Reason != "PlatformReady" || source.calls != 1 || len(getter.paths) != len(profile.RequiredApplications) {
		t.Fatalf("unexpected platform collection: evidence=%#v paths=%v capabilityCalls=%d", evidence, getter.paths, source.calls)
	}
	for index, application := range profile.RequiredApplications {
		expected := platformApplicationPath(profile.ArgoNamespace, application.Name)
		if getter.paths[index] != expected {
			t.Fatalf("unexpected Application path %d: %q", index, getter.paths[index])
		}
	}
}

func TestPlatformCollectorRejectsRawIdentityAndMutableSource(t *testing.T) {
	policy, profile, capability, getter := platformCollectorFixture(t)
	first := platformApplicationPath(profile.ArgoNamespace, profile.RequiredApplications[0].Name)
	for name, mutate := range map[string]func(map[string]any){
		"foreign name": func(object map[string]any) { object["metadata"].(map[string]any)["name"] = "other" },
		"missing uid":  func(object map[string]any) { delete(object["metadata"].(map[string]any), "uid") },
		"mutable branch": func(object map[string]any) {
			object["spec"].(map[string]any)["source"].(map[string]any)["targetRevision"] = "main"
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, localProfile, localCapability, localGetter := platformCollectorFixture(t)
			var object map[string]any
			if err := json.Unmarshal(localGetter.responses[first], &object); err != nil {
				t.Fatal(err)
			}
			mutate(object)
			localGetter.responses[first], _ = json.Marshal(object)
			collector, err := NewPlatformSourceCollector(localGetter, &fakePlatformCapabilitySource{capability: localCapability}, PlatformCollectorConfig{Profile: localProfile, TargetClusterUID: policy.TargetClusterUID, Clock: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := collector.Observe(context.Background(), policy); err == nil {
				t.Fatal("unsafe Argo Application accepted")
			}
		})
	}
	_ = capability
	_ = getter
}

func TestPlatformCollectorRedactsSourceErrorsAndDoesNotRunCapabilityEarly(t *testing.T) {
	policy, profile, capability, getter := platformCollectorFixture(t)
	getter.err = errors.New("secret endpoint detail")
	source := &fakePlatformCapabilitySource{capability: capability}
	collector, err := NewPlatformSourceCollector(getter, source, PlatformCollectorConfig{Profile: profile, TargetClusterUID: policy.TargetClusterUID, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Observe(context.Background(), policy); err == nil || strings.Contains(err.Error(), "secret endpoint") {
		t.Fatalf("raw source failure leaked or was accepted: %v", err)
	}
	if source.calls != 0 {
		t.Fatal("capability source ran after Application collection failed")
	}
}

func TestPlatformCollectorBindsRuntimeTargetAfterSubmission(t *testing.T) {
	policy, profile, capability, getter := platformCollectorFixture(t)
	if _, err := NewPlatformSourceCollector(getter, &fakePlatformCapabilitySource{capability: capability}, PlatformCollectorConfig{Profile: profile, Clock: time.Now}); err == nil {
		t.Fatal("platform collector accepted no runtime target")
	}
	collector, err := NewPlatformSourceCollector(getter, &fakePlatformCapabilitySource{capability: capability}, PlatformCollectorConfig{Profile: profile, TargetClusterUID: "different-cluster-uid", Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(context.Background(), policy); err == nil {
		t.Fatal("platform collector accepted a target different from the post-submission policy")
	}
	if len(getter.paths) != 0 {
		t.Fatal("platform collector contacted Argo before rejecting runtime target mismatch")
	}
}

func platformCollectorFixture(t *testing.T) (Policy, PlatformProfile, PlatformCapabilityState, *fakePlatformRawGetter) {
	t.Helper()
	policy, profile, snapshot := validPlatformFixture(t)
	getter := &fakePlatformRawGetter{responses: map[string][]byte{}}
	for index := range profile.RequiredApplications {
		name := profile.RequiredApplications[index].Name
		path := "profiles/ok-observability-standard"
		if index == 1 {
			path = "alerting"
		} else if index == 2 {
			path = "dashboards"
		}
		spec := map[string]any{
			"project":     "openkubes-disposable",
			"source":      map[string]any{"repoURL": "https://github.com/openkubes/ok-observability.git", "path": path, "targetRevision": strings.Repeat("6", 40)},
			"destination": map[string]any{"name": profile.RegistrationName, "namespace": "ok-observability"},
			"syncPolicy":  map[string]any{"automated": map[string]any{"enabled": true, "prune": true, "selfHeal": true, "allowEmpty": false}},
		}
		normalized, _, err := normalizedPlatformApplicationSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		profile.RequiredApplications[index].SpecDigest, err = canonicalDigest(normalized)
		if err != nil {
			t.Fatal(err)
		}
		object := map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"metadata": map[string]any{
				"namespace": profile.ArgoNamespace, "name": name, "uid": "application-uid-" + string(rune('a'+index)), "resourceVersion": "17",
				"annotations": map[string]any{
					"openkubes.io/intent-revision": policy.IntentRevision, "openkubes.io/platform-revision": policy.PlatformRevision,
					"openkubes.io/execution-fixture": profile.ExecutionFixture,
				},
			},
			"spec":   spec,
			"status": map[string]any{"sync": map[string]any{"status": "Synced", "revision": strings.Repeat("6", 40)}, "health": map[string]any{"status": "Healthy"}},
		}
		getter.responses[platformApplicationPath(profile.ArgoNamespace, name)], _ = json.Marshal(object)
	}
	return policy, profile, snapshot.Capability, getter
}

type fakePlatformRawGetter struct {
	responses map[string][]byte
	paths     []string
	err       error
}

func (getter *fakePlatformRawGetter) Get(_ context.Context, path string) ([]byte, error) {
	getter.paths = append(getter.paths, path)
	if getter.err != nil {
		return nil, getter.err
	}
	return append([]byte(nil), getter.responses[path]...), nil
}

type fakePlatformCapabilitySource struct {
	capability PlatformCapabilityState
	err        error
	calls      int
}

func (source *fakePlatformCapabilitySource) Capability(context.Context) (PlatformCapabilityState, error) {
	source.calls++
	return source.capability, source.err
}
