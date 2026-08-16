package runner

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildObservabilitySyntheticFixtureProducesExactImmutableObjects(t *testing.T) {
	run, err := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	config := ObservabilitySyntheticFixtureConfig{
		PushgatewayImage: "registry.example.test/prom/pushgateway@sha256:" + strings.Repeat("1", 64),
		LogEmitterImage:  "registry.example.test/library/busybox@sha256:" + strings.Repeat("2", 64),
	}
	fixture, err := BuildObservabilitySyntheticFixture(run, config)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Format != ObservabilitySyntheticFixtureFormat || fixture.RunID != run.RunID || fixture.Namespace != run.Namespace || len(fixture.Objects) != 4 || !platformInputDigestPattern.MatchString(fixture.FixtureDigest) {
		t.Fatalf("unexpected synthetic fixture: %#v", fixture)
	}
	expectedKinds := []string{"Deployment", "Service", "ServiceMonitor", "Pod"}
	expectedResources := []string{"deployments", "services", "servicemonitors", "pods"}
	for index, object := range fixture.Objects {
		if object.Identity.Kind != expectedKinds[index] || !strings.Contains(object.CollectionPath, "/namespaces/"+run.Namespace+"/"+expectedResources[index]) || object.ObjectPath != object.CollectionPath+"/"+object.Identity.Name || !platformInputDigestPattern.MatchString(object.Digest) {
			t.Fatalf("object %d is outside the fixed identity: %#v", index, object)
		}
		if object.Digest != digest.SHA256(object.Raw) {
			t.Fatalf("object %d raw content differs from its digest", index)
		}
		var decoded map[string]any
		if err := json.Unmarshal(object.Raw, &decoded); err != nil {
			t.Fatal(err)
		}
		metadata := decoded["metadata"].(map[string]any)
		annotations := metadata["annotations"].(map[string]any)
		if annotations["openkubes.io/intent-revision"] != run.IntentRevision || annotations["openkubes.io/platform-revision"] != run.PlatformRevision || annotations["openkubes.io/execution-fixture"] != run.ExecutionFixture || annotations["openkubes.io/capability-contract"] != run.ContractDigest || annotations["openkubes.io/capability-executable"] != run.ExecutableDigest {
			t.Fatalf("object %d lost runtime correlation: %#v", index, annotations)
		}
	}
	second, err := BuildObservabilitySyntheticFixture(run, config)
	if err != nil || !reflect.DeepEqual(fixture, second) {
		t.Fatalf("equivalent run changed synthetic projection: %v", err)
	}
}

func TestBuildObservabilitySyntheticFixtureRejectsMutableImages(t *testing.T) {
	run, err := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]ObservabilitySyntheticFixtureConfig{
		"mutable pushgateway": {PushgatewayImage: "prom/pushgateway:v1.9.0", LogEmitterImage: "busybox@sha256:" + strings.Repeat("2", 64)},
		"mutable logger":      {PushgatewayImage: "prom/pushgateway@sha256:" + strings.Repeat("1", 64), LogEmitterImage: "busybox:latest"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildObservabilitySyntheticFixture(run, config); err == nil {
				t.Fatal("mutable image was accepted")
			}
		})
	}
}

func TestObservabilitySyntheticFixtureBindsEverySemanticChange(t *testing.T) {
	run, err := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	config := ObservabilitySyntheticFixtureConfig{
		PushgatewayImage: "prom/pushgateway@sha256:" + strings.Repeat("1", 64),
		LogEmitterImage:  "busybox@sha256:" + strings.Repeat("2", 64),
	}
	first, err := BuildObservabilitySyntheticFixture(run, config)
	if err != nil {
		t.Fatal(err)
	}
	config.LogEmitterImage = "busybox@sha256:" + strings.Repeat("3", 64)
	second, err := BuildObservabilitySyntheticFixture(run, config)
	if err != nil {
		t.Fatal(err)
	}
	if first.FixtureDigest == second.FixtureDigest || first.Objects[3].Digest == second.Objects[3].Digest {
		t.Fatal("image semantic change retained fixture or Pod identity")
	}
	if first.Objects[0].Digest != second.Objects[0].Digest || first.Objects[1].Digest != second.Objects[1].Digest || first.Objects[2].Digest != second.Objects[2].Digest {
		t.Fatal("log image change modified unrelated metrics objects")
	}
}
