package runner

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRenderAggregateEvidenceStageJobTemplateBindsExactEnvelope(t *testing.T) {
	values := validAggregateEvidenceStageJobValues()
	raw, err := RenderAggregateEvidenceStageJobTemplate(aggregateEvidenceJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 2 || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected aggregate evidence object set: %#v", objects)
	}
	job := objects["Job"]
	spec := objectAt(t, job, "spec")
	if spec["backoffLimit"] != 0 || spec["activeDeadlineSeconds"] != 600 {
		t.Fatalf("aggregate evidence Job retry or deadline differs: %#v", spec)
	}
	podSpec := objectAt(t, objectAt(t, spec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" {
		t.Fatalf("unsafe aggregate evidence Pod identity or restart policy: %#v", podSpec)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if !reflect.DeepEqual(args[:5], []string{"cluster", "stage", "evaluate", "aggregate", "--execute"}) {
		t.Fatalf("unexpected aggregate evidence command: %v", args)
	}
	for flag, want := range map[string]string{
		"--receipt-prefix-digest":    values.ReceiptPrefixDigest,
		"--aggregate-profile-digest": values.AggregateProfileDigest,
		"--network-profile-digest":   values.NetworkProfileDigest,
		"--platform-profile-digest":  values.PlatformProfileDigest,
		"--runtime-binding":          "/var/run/openkubes/runtime/runtime-binding.json",
		"--runtime-binding-receipt":  "/var/run/openkubes/runtime/runtime-binding-receipt.json",
		"--platform-capability":      "/var/run/openkubes/capability/platform-capability.json",
	} {
		if got := argumentValue(args, flag); got != want {
			t.Fatalf("%s=%q, want %q", flag, got, want)
		}
	}
	volumes := arrayAt(t, podSpec, "volumes")
	if len(volumes) != 7 {
		t.Fatalf("aggregate evidence Job volume count differs: %#v", volumes)
	}
	inputItems := arrayAt(t, objectAt(t, volumes[0].(map[string]any), "configMap"), "items")
	if len(inputItems) != 16 {
		t.Fatalf("aggregate evidence public input key set differs: %#v", inputItems)
	}
	egress := arrayAt(t, objectAt(t, objects["NetworkPolicy"], "spec"), "egress")
	if len(egress) != 3 {
		t.Fatalf("aggregate evidence Job must have exact management, workload and Argo egress: %#v", egress)
	}
	text := string(raw)
	for _, forbidden := range []string{"stage-grant", "authority-map", "system:masters", "privileged: true", "serviceAccountToken: true"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("aggregate evidence Job contains forbidden input %q", forbidden)
		}
	}
}

func TestRenderAggregateEvidenceStageJobTemplateFailsClosed(t *testing.T) {
	valid := validAggregateEvidenceStageJobValues()
	for name, mutate := range map[string]func(*AggregateEvidenceStageJobValues){
		"mutable image": func(values *AggregateEvidenceStageJobValues) {
			values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"shared credential": func(values *AggregateEvidenceStageJobValues) {
			values.ArgoCredentialSecret = values.ManagementCredentialSecret
		},
		"foreign management endpoint": func(values *AggregateEvidenceStageJobValues) {
			values.ManagementAPIURL, values.ManagementAPICIDR = "https://192.0.2.13:6443", "192.0.2.13/32"
		},
		"shared API endpoint": func(values *AggregateEvidenceStageJobValues) {
			values.ArgoAPIURL, values.ArgoAPICIDR = values.ManagementAPIURL, values.ManagementAPICIDR
		},
		"broad workload CIDR": func(values *AggregateEvidenceStageJobValues) { values.WorkloadAPICIDR = "192.0.2.0/24" },
		"bad profile digest":  func(values *AggregateEvidenceStageJobValues) { values.PlatformProfileDigest = "sha256:bad" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderAggregateEvidenceStageJobTemplate(aggregateEvidenceJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe aggregate evidence Job values were accepted")
			}
		})
	}
	template := append(aggregateEvidenceJobTemplate(t), []byte("\n${UNKNOWN}")...)
	if _, err := RenderAggregateEvidenceStageJobTemplate(template, valid); err == nil {
		t.Fatal("unknown aggregate evidence placeholder was accepted")
	}
}

func validAggregateEvidenceStageJobValues() AggregateEvidenceStageJobValues {
	return AggregateEvidenceStageJobValues{
		RunID: "ok147-aggregate-evidence-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		Expected: validSubmissionStageJobValues().Expected, InputConfigMap: "ok147-aggregate-evidence-input",
		ReceiptPrefixDigest: bundleSHA("b"), AggregateProfileDigest: bundleSHA("c"),
		NetworkProfileDigest: bundleSHA("d"), PlatformProfileDigest: bundleSHA("e"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-aggregate",
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32", ManagementCredentialSecret: "ok147-management-aggregate",
		WorkloadAPIURL: "https://192.0.2.20:6443", WorkloadAPICIDR: "192.0.2.20/32", WorkloadCredentialSecret: "ok147-workload-aggregate",
		ArgoAPIURL: "https://192.0.2.30:6443", ArgoAPICIDR: "192.0.2.30/32", ArgoCredentialSecret: "ok147-argo-aggregate",
		RuntimeBindingSecret: "ok147-runtime-binding-run-01", PlatformCapabilitySecret: "ok147-platform-capability-01",
	}
}

func aggregateEvidenceJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/contract-executor-aggregate-evidence-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
