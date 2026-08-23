package runner

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestRenderFullRunExecutionJobTemplateIsolatesExecutorAndEvidenceAuthority(t *testing.T) {
	values := validFullRunExecutionJobValues()
	raw, err := RenderFullRunExecutionJobTemplate(fullRunExecutionJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 2 || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected full-run object set: %#v", objects)
	}
	job := objects["Job"]
	annotations := objectAt(t, objectAt(t, job, "metadata"), "annotations")
	if annotations["openkubes.io/bundle-digest"] != values.BundleDigest ||
		annotations["openkubes.io/manifest-digest"] != values.ManifestDigest ||
		annotations["openkubes.io/evidence-activation-digest"] != values.EvidenceActivationDigest ||
		annotations["openkubes.io/evidence-key-id"] != values.EvidenceKeyID {
		t.Fatalf("full-run annotations differ: %#v", annotations)
	}
	spec := objectAt(t, job, "spec")
	if spec["backoffLimit"] != 0 || spec["completions"] != 1 || spec["parallelism"] != 1 || spec["activeDeadlineSeconds"] != 11100 {
		t.Fatalf("full-run retry or deadline differs: %#v", spec)
	}
	podSpec := objectAt(t, objectAt(t, spec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" {
		t.Fatalf("unsafe full-run Pod identity: %#v", podSpec)
	}
	inits := arrayAt(t, podSpec, "initContainers")
	if len(inits) != 2 {
		t.Fatalf("unexpected initializer count: %#v", inits)
	}
	fullInit := inits[0].(map[string]any)
	if got := stringArray(t, fullInit, "args"); !reflect.DeepEqual(got, []string{
		"cluster", "stage", "run", "full", "materialize", "--source", "/var/run/openkubes/source",
		"--destination", "/var/run/openkubes/workspace", "--handoff", "/var/run/openkubes/handoff-volume/private",
		"--expected-bundle-digest", values.BundleDigest, "--materialize",
	}) {
		t.Fatalf("unexpected full-run initializer: %v", got)
	}
	authorityInit := inits[1].(map[string]any)
	if got := stringArray(t, authorityInit, "args"); !reflect.DeepEqual(got, []string{
		"cluster", "stage", "evidence", "observability", "authority", "materialize",
		"--source", "/var/run/openkubes/evidence-source", "--destination", "/var/run/openkubes/evidence-authority",
		"--expected-activation-digest", values.EvidenceActivationDigest, "--expected-evidence-key-id", values.EvidenceKeyID,
		"--expected-collector-ca-digest", values.CollectorCADigest, "--materialize",
	}) {
		t.Fatalf("unexpected authority initializer: %v", got)
	}
	containers := arrayAt(t, podSpec, "containers")
	if len(containers) != 2 {
		t.Fatalf("unexpected full-run container count: %#v", containers)
	}
	executor, authority := containers[0].(map[string]any), containers[1].(map[string]any)
	if got := stringArray(t, executor, "args"); !reflect.DeepEqual(got, []string{
		"cluster", "stage", "run", "full", "execute", "--manifest", "/var/run/openkubes/workspace/activation/full-run-manifest.json",
		"--expected-manifest-digest", values.ManifestDigest, "--independent-evidence-public-key", "/var/run/openkubes/workspace/input/independent-evidence.pub", "--execute",
	}) {
		t.Fatalf("unexpected executor command: %v", got)
	}
	if got := stringArray(t, authority, "args"); !reflect.DeepEqual(got, []string{
		"cluster", "stage", "evidence", "observability", "produce", "--activation", "/var/run/openkubes/evidence-authority/activation.json", "--produce",
	}) {
		t.Fatalf("unexpected evidence authority command: %v", got)
	}
	assertFullRunContainerMounts(t, executor, map[string]string{"executor-private": "workspace", "evidence-handoff": "private"})
	assertFullRunContainerMounts(t, authority, map[string]string{"authority-private": "evidence-authority", "evidence-handoff": "private"})

	volumes := arrayAt(t, podSpec, "volumes")
	if len(volumes) != 5 {
		t.Fatalf("unexpected full-run volume count: %#v", volumes)
	}
	activationSecret := objectAt(t, volumes[0].(map[string]any), "secret")
	if activationSecret["secretName"] != values.ActivationSecret || activationSecret["defaultMode"] != 288 || len(arrayAt(t, activationSecret, "items")) != len(fullRunExecutionBundleFiles)+1 {
		t.Fatalf("full-run activation projection differs: %#v", activationSecret)
	}
	paths := make([]string, 0, len(fullRunExecutionBundleFiles)+1)
	for _, item := range arrayAt(t, activationSecret, "items") {
		paths = append(paths, item.(map[string]any)["path"].(string))
	}
	want := append([]string{fullRunExecutionBundleIndexName}, fullRunExecutionBundleFiles...)
	sort.Strings(paths)
	sort.Strings(want)
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("full-run activation projection path set differs: %v", paths)
	}
	evidenceSecret := objectAt(t, volumes[1].(map[string]any), "secret")
	if evidenceSecret["secretName"] != values.EvidenceAuthoritySecret || len(arrayAt(t, evidenceSecret, "items")) != 4 {
		t.Fatalf("evidence authority projection differs: %#v", evidenceSecret)
	}
	egress := arrayAt(t, objectAt(t, objects["NetworkPolicy"], "spec"), "egress")
	if len(egress) != 6 {
		t.Fatalf("full-run egress is not exact: %#v", egress)
	}
	assertStageAuthorityEgressPeers(t, egress[4].(map[string]any), values.AuthorizationAPICIDR)
	text := string(raw)
	for _, forbidden := range []string{"latest", "system:masters", "privileged: true", "automountServiceAccountToken: true", "restartPolicy: Always"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("full-run Job contains forbidden value %q", forbidden)
		}
	}
}

func assertStageAuthorityEgressPeers(t *testing.T, rule map[string]any, authorizationCIDR string) {
	t.Helper()
	peers := arrayAt(t, rule, "to")
	if len(peers) != 2 {
		t.Fatalf("stage authority egress peers differ: %#v", peers)
	}
	ipBlock := objectAt(t, peers[0].(map[string]any), "ipBlock")
	if ipBlock["cidr"] != authorizationCIDR {
		t.Fatalf("stage authority Service CIDR differs: %#v", ipBlock)
	}
	podSelector := objectAt(t, peers[1].(map[string]any), "podSelector")
	labels := objectAt(t, podSelector, "matchLabels")
	if !reflect.DeepEqual(labels, map[string]any{"app.kubernetes.io/name": "ok147-stage-authority"}) {
		t.Fatalf("stage authority Pod selector differs: %#v", labels)
	}
}

func TestRenderFullRunExecutionJobTemplateFailsClosed(t *testing.T) {
	valid := validFullRunExecutionJobValues()
	for name, mutate := range map[string]func(*FullRunExecutionJobValues){
		"mutable image":             func(values *FullRunExecutionJobValues) { values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"foreign run":               func(values *FullRunExecutionJobValues) { values.RunID = "foreign-run" },
		"same Secrets":              func(values *FullRunExecutionJobValues) { values.EvidenceAuthoritySecret = values.ActivationSecret },
		"bad bundle":                func(values *FullRunExecutionJobValues) { values.BundleDigest = "sha256:bad" },
		"broad infrastructure CIDR": func(values *FullRunExecutionJobValues) { values.InfrastructureAPICIDR = "192.0.2.0/24" },
		"shared authority": func(values *FullRunExecutionJobValues) {
			values.CollectorAPIURL, values.CollectorAPICIDR = values.ArgoAPIURL, values.ArgoAPICIDR
		},
		"authorization without path": func(values *FullRunExecutionJobValues) { values.AuthorizationAPIURL = "https://192.0.2.50:8443" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderFullRunExecutionJobTemplate(fullRunExecutionJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe full-run Job values were accepted")
			}
		})
	}
	template := append(fullRunExecutionJobTemplate(t), []byte("\n${UNKNOWN}")...)
	if _, err := RenderFullRunExecutionJobTemplate(template, valid); err == nil {
		t.Fatal("unknown full-run Job placeholder was accepted")
	}
}

func assertFullRunContainerMounts(t *testing.T, container map[string]any, expected map[string]string) {
	t.Helper()
	mounts := arrayAt(t, container, "volumeMounts")
	if len(mounts) != len(expected) {
		t.Fatalf("container mount count differs: %#v", mounts)
	}
	for _, raw := range mounts {
		mount := raw.(map[string]any)
		name := mount["name"].(string)
		wantSubPath, ok := expected[name]
		if !ok {
			t.Fatalf("container received foreign mount %q", name)
		}
		gotSubPath, _ := mount["subPath"].(string)
		if gotSubPath != wantSubPath {
			t.Fatalf("container mount %q subPath differs: %q", name, gotSubPath)
		}
	}
}

func validFullRunExecutionJobValues() FullRunExecutionJobValues {
	return FullRunExecutionJobValues{
		RunID: "ok147-full-run-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		ActivationSecret: "ok147-full-run-activation-01", EvidenceAuthoritySecret: "ok147-evidence-authority-01",
		BundleDigest: bundleSHA("b"), ManifestDigest: bundleSHA("c"), EvidenceActivationDigest: bundleSHA("d"),
		EvidenceKeyID: bundleSHA("e"), CollectorCADigest: bundleSHA("f"),
		InfrastructureAPIURL: "https://192.0.2.10:6443", InfrastructureAPICIDR: "192.0.2.10/32",
		ManagementAPIURL: "https://192.0.2.20:6443", ManagementAPICIDR: "192.0.2.20/32",
		WorkloadAPIURL: "https://192.0.2.30:6443", WorkloadAPICIDR: "192.0.2.30/32",
		ArgoAPIURL: "https://192.0.2.40:6443", ArgoAPICIDR: "192.0.2.40/32",
		AuthorizationAPIURL: "https://192.0.2.50:8443/v1/stage-authorizations", AuthorizationAPICIDR: "192.0.2.50/32",
		CollectorAPIURL: "https://192.0.2.60:8443", CollectorAPICIDR: "192.0.2.60/32",
	}
}

func fullRunExecutionJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/contract-executor-full-run-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
