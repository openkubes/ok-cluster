package runner

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestRenderPostRuntimeExecutionJobTemplateBindsPrivateInitAndSingleExecution(t *testing.T) {
	values := validPostRuntimeExecutionJobValues()
	raw, err := RenderPostRuntimeExecutionJobTemplate(postRuntimeExecutionJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 2 || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected post-runtime object set: %#v", objects)
	}
	job := objects["Job"]
	metadata := objectAt(t, job, "metadata")
	annotations := objectAt(t, metadata, "annotations")
	if annotations["openkubes.io/bundle-digest"] != values.BundleDigest || annotations["openkubes.io/manifest-digest"] != values.ManifestDigest {
		t.Fatalf("post-runtime Job annotations differ: %#v", annotations)
	}
	spec := objectAt(t, job, "spec")
	if spec["backoffLimit"] != 0 || spec["completions"] != 1 || spec["parallelism"] != 1 || spec["activeDeadlineSeconds"] != 11100 {
		t.Fatalf("post-runtime Job retry or deadline differs: %#v", spec)
	}
	podSpec := objectAt(t, objectAt(t, spec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" {
		t.Fatalf("unsafe post-runtime Pod identity: %#v", podSpec)
	}
	init := arrayAt(t, podSpec, "initContainers")[0].(map[string]any)
	initArgs := stringArray(t, init, "args")
	if !reflect.DeepEqual(initArgs, []string{
		"cluster", "stage", "run", "post-runtime", "materialize", "--source", "/var/run/openkubes/source",
		"--destination", "/var/run/openkubes/workspace", "--expected-bundle-digest", values.BundleDigest, "--materialize",
	}) {
		t.Fatalf("unexpected post-runtime materializer command: %v", initArgs)
	}
	executor := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	executeArgs := stringArray(t, executor, "args")
	if !reflect.DeepEqual(executeArgs, []string{
		"cluster", "stage", "run", "post-runtime", "execute", "--manifest",
		"/var/run/openkubes/workspace/activation/post-runtime-manifest.json",
		"--expected-manifest-digest", values.ManifestDigest, "--execute",
	}) {
		t.Fatalf("unexpected post-runtime execution command: %v", executeArgs)
	}
	if len(arrayAt(t, executor, "volumeMounts")) != 1 || len(arrayAt(t, init, "volumeMounts")) != 2 {
		t.Fatal("executor can access projected source or initializer lacks isolated mounts")
	}
	volumes := arrayAt(t, podSpec, "volumes")
	if len(volumes) != 2 {
		t.Fatalf("unexpected post-runtime volume count: %#v", volumes)
	}
	secret := objectAt(t, volumes[0].(map[string]any), "secret")
	if secret["secretName"] != values.ActivationSecret || secret["defaultMode"] != 288 || len(arrayAt(t, secret, "items")) != len(postRuntimeExecutionBundleFiles)+1 {
		t.Fatalf("post-runtime Secret projection differs: %#v", secret)
	}
	paths := make([]string, 0, len(postRuntimeExecutionBundleFiles)+1)
	for _, item := range arrayAt(t, secret, "items") {
		paths = append(paths, item.(map[string]any)["path"].(string))
	}
	wantPaths := append([]string{postRuntimeExecutionBundleIndexName}, postRuntimeExecutionBundleFiles...)
	sort.Strings(paths)
	sort.Strings(wantPaths)
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("post-runtime Secret projection path set differs: %v", paths)
	}
	egress := arrayAt(t, objectAt(t, objects["NetworkPolicy"], "spec"), "egress")
	if len(egress) != 4 {
		t.Fatalf("post-runtime Job egress is not exact: %#v", egress)
	}
	assertStageAuthorityEgressPeers(t, egress[3].(map[string]any), values.AuthorizationAPICIDR)
	text := string(raw)
	for _, forbidden := range []string{"latest", "system:masters", "privileged: true", "automountServiceAccountToken: true", "restartPolicy: Always"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("post-runtime Job contains forbidden value %q", forbidden)
		}
	}
}

func TestRenderPostRuntimeExecutionJobTemplateProjectsRecoveryReceipts(t *testing.T) {
	values := validPostRuntimeExecutionJobValues()
	values.RecoveryMode = "target-registration"
	raw, err := RenderPostRuntimeExecutionJobTemplate(postRuntimeExecutionJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	job := decodeJobObjects(t, raw)["Job"]
	podSpec := objectAt(t, objectAt(t, objectAt(t, job, "spec"), "template"), "spec")
	secret := objectAt(t, arrayAt(t, podSpec, "volumes")[0].(map[string]any), "secret")
	paths := make(map[string]bool)
	for _, item := range arrayAt(t, secret, "items") {
		paths[item.(map[string]any)["path"].(string)] = true
	}
	if len(paths) != len(postRuntimeExecutionBundleFiles)+len(postRuntimeExecutionRecoveryReceiptFiles)+1 ||
		!paths[postRuntimeExecutionRecoveryReceiptFiles[0]] || !paths[postRuntimeExecutionRecoveryReceiptFiles[1]] {
		t.Fatalf("recovery receipts are not projected exactly: %#v", paths)
	}
}

func TestRenderPostRuntimeExecutionJobTemplateFailsClosed(t *testing.T) {
	valid := validPostRuntimeExecutionJobValues()
	for name, mutate := range map[string]func(*PostRuntimeExecutionJobValues){
		"mutable image": func(values *PostRuntimeExecutionJobValues) {
			values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"foreign run":           func(values *PostRuntimeExecutionJobValues) { values.RunID = "foreign-run" },
		"foreign secret":        func(values *PostRuntimeExecutionJobValues) { values.ActivationSecret = "foreign-secret" },
		"bad bundle":            func(values *PostRuntimeExecutionJobValues) { values.BundleDigest = "sha256:bad" },
		"broad management CIDR": func(values *PostRuntimeExecutionJobValues) { values.ManagementAPICIDR = "192.0.2.0/24" },
		"shared target": func(values *PostRuntimeExecutionJobValues) {
			values.ArgoAPIURL, values.ArgoAPICIDR = values.WorkloadAPIURL, values.WorkloadAPICIDR
		},
		"authority without path": func(values *PostRuntimeExecutionJobValues) { values.AuthorizationAPIURL = "https://192.0.2.40:8443" },
		"unknown recovery mode":  func(values *PostRuntimeExecutionJobValues) { values.RecoveryMode = "retry-everything" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderPostRuntimeExecutionJobTemplate(postRuntimeExecutionJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe post-runtime Job values were accepted")
			}
		})
	}
	template := append(postRuntimeExecutionJobTemplate(t), []byte("\n${UNKNOWN}")...)
	if _, err := RenderPostRuntimeExecutionJobTemplate(template, valid); err == nil {
		t.Fatal("unknown post-runtime Job placeholder was accepted")
	}
}

func validPostRuntimeExecutionJobValues() PostRuntimeExecutionJobValues {
	return PostRuntimeExecutionJobValues{
		RunID: "ok147-post-runtime-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		ActivationSecret: "ok147-post-runtime-activation-01", BundleDigest: bundleSHA("b"), ManifestDigest: bundleSHA("c"),
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32",
		WorkloadAPIURL: "https://192.0.2.20:6443", WorkloadAPICIDR: "192.0.2.20/32",
		ArgoAPIURL: "https://192.0.2.30:6443", ArgoAPICIDR: "192.0.2.30/32",
		AuthorizationAPIURL: "https://192.0.2.40:8443/v1/stage-authorizations", AuthorizationAPICIDR: "192.0.2.40/32",
	}
}

func postRuntimeExecutionJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/contract-executor-post-runtime-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
