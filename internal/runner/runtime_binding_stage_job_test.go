package runner

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRenderRuntimeBindingStageJobTemplateBindsExactEnvelope(t *testing.T) {
	values := validRuntimeBindingStageJobValues()
	raw, err := RenderRuntimeBindingStageJobTemplate(runtimeBindingJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 2 || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected runtime binding object set: %#v", objects)
	}
	job := objects["Job"]
	spec := objectAt(t, job, "spec")
	if spec["backoffLimit"] != 0 || spec["activeDeadlineSeconds"] != 180 {
		t.Fatalf("runtime binding retry or deadline differs: %#v", spec)
	}
	podSpec := objectAt(t, objectAt(t, spec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" {
		t.Fatalf("unsafe runtime binding Pod identity: %#v", podSpec)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if !reflect.DeepEqual(args[:5], []string{"cluster", "stage", "bind", "runtime", "--execute"}) || argumentValue(args, "--persistence-mode") != "immutable-secret" || argumentValue(args, "--receipt-prefix-digest") != values.ReceiptPrefixDigest || argumentValue(args, "--workload-binding-digest") != values.WorkloadBindingDigest {
		t.Fatalf("runtime binding command differs: %v", args)
	}
	if argumentValue(args, "--ledger-api-endpoint") != values.LedgerAPIURL || argumentValue(args, "--output") != "" {
		t.Fatalf("runtime binding persistence mode is ambiguous: %v", args)
	}
	volumes := arrayAt(t, podSpec, "volumes")
	if len(volumes) != 4 {
		t.Fatalf("runtime binding volume boundary differs: %#v", volumes)
	}
	egress := arrayAt(t, objectAt(t, objects["NetworkPolicy"], "spec"), "egress")
	if len(egress) != 2 {
		t.Fatalf("runtime binding Job has unexpected egress: %#v", egress)
	}
	for _, forbidden := range []string{"stage-grant", "projection-manifest", "authority-map", "runtime-binding.json", "--output"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("runtime binding Job contains forbidden input %q", forbidden)
		}
	}
}

func TestRenderRuntimeBindingStageJobTemplateFailsClosed(t *testing.T) {
	valid := validRuntimeBindingStageJobValues()
	for name, mutate := range map[string]func(*RuntimeBindingStageJobValues){
		"mutable image": func(values *RuntimeBindingStageJobValues) { values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"shared credentials": func(values *RuntimeBindingStageJobValues) {
			values.PersistenceCredentialSecret = values.LedgerCredentialSecret
		},
		"same workload endpoint": func(values *RuntimeBindingStageJobValues) {
			values.WorkloadAPIURL, values.WorkloadAPICIDR = values.LedgerAPIURL, values.LedgerAPICIDR
		},
		"foreign binding digest": func(values *RuntimeBindingStageJobValues) { values.WorkloadBindingDigest = bundleSHA("z") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderRuntimeBindingStageJobTemplate(runtimeBindingJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe runtime binding Job values were accepted")
			}
		})
	}
	template := append(runtimeBindingJobTemplate(t), []byte("\n${UNKNOWN}")...)
	if _, err := RenderRuntimeBindingStageJobTemplate(template, valid); err == nil {
		t.Fatal("unknown runtime binding Job placeholder was accepted")
	}
}

func validRuntimeBindingStageJobValues() RuntimeBindingStageJobValues {
	return RuntimeBindingStageJobValues{
		RunID: "ok147-runtime-binding-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		Expected: validSubmissionStageJobValues().Expected, InputConfigMap: "ok147-runtime-binding-input", ReceiptPrefixDigest: bundleSHA("b"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-binding",
		PersistenceCredentialSecret: "ok147-persistence-binding",
		WorkloadAPIURL:              "https://192.0.2.20:6443", WorkloadAPICIDR: "192.0.2.20/32", WorkloadCredentialSecret: "ok147-workload-binding",
		WorkloadBindingDigest: bundleSHA("c"),
	}
}

func runtimeBindingJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/contract-executor-runtime-binding-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
