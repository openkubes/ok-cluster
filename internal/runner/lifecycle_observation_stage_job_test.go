package runner

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRenderLifecycleObservationStageJobTemplateBindsExactEnvelope(t *testing.T) {
	values := validLifecycleObservationStageJobValues()
	raw, err := RenderLifecycleObservationStageJobTemplate(lifecycleObservationJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 2 || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected lifecycle observation object set: %#v", objects)
	}
	job := objects["Job"]
	spec := objectAt(t, job, "spec")
	if spec["backoffLimit"] != 0 || spec["activeDeadlineSeconds"] != 360 {
		t.Fatalf("Job retry or deadline differs: %#v", spec)
	}
	podSpec := objectAt(t, objectAt(t, spec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" {
		t.Fatalf("unsafe Pod identity or restart policy: %#v", podSpec)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if !reflect.DeepEqual(args[:5], []string{"cluster", "stage", "observe", "lifecycle", "--execute"}) {
		t.Fatalf("unexpected lifecycle command: %v", args)
	}
	if argumentValue(args, "--receipt-prefix-digest") != values.ReceiptPrefixDigest || argumentValue(args, "--poll-interval") != "15s" || argumentValue(args, "--poll-timeout") != "5m0s" {
		t.Fatalf("observation inputs differ: %v", args)
	}
	if argumentValue(args, "--management-api-endpoint") != values.ManagementAPIURL || argumentValue(args, "--ledger-api-endpoint") != values.LedgerAPIURL {
		t.Fatalf("management endpoint binding differs: %v", args)
	}
	policy := objects["NetworkPolicy"]
	egress := arrayAt(t, objectAt(t, policy, "spec"), "egress")
	if len(egress) != 1 {
		t.Fatalf("observation Job has unexpected egress: %#v", egress)
	}
	if strings.Contains(string(raw), "stage-grant") || strings.Contains(string(raw), "projection-manifest") || strings.Contains(string(raw), "authority-map") {
		t.Fatal("read-only observation Job contains mutating-stage inputs")
	}
}

func TestRenderLifecycleObservationStageJobTemplateFailsClosed(t *testing.T) {
	valid := validLifecycleObservationStageJobValues()
	for name, mutate := range map[string]func(*LifecycleObservationStageJobValues){
		"mutable image": func(values *LifecycleObservationStageJobValues) {
			values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"shared credential": func(values *LifecycleObservationStageJobValues) {
			values.ManagementCredentialSecret = values.LedgerCredentialSecret
		},
		"foreign management endpoint": func(values *LifecycleObservationStageJobValues) {
			values.ManagementAPIURL, values.ManagementAPICIDR = "https://192.0.2.13:6443", "192.0.2.13/32"
		},
		"subsecond polling":       func(values *LifecycleObservationStageJobValues) { values.PollInterval = 500 * time.Millisecond },
		"timeout before interval": func(values *LifecycleObservationStageJobValues) { values.PollTimeout = 10 * time.Second },
		"fractional duration":     func(values *LifecycleObservationStageJobValues) { values.PollInterval = 1500 * time.Millisecond },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderLifecycleObservationStageJobTemplate(lifecycleObservationJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe lifecycle observation Job values were accepted")
			}
		})
	}
	template := append(lifecycleObservationJobTemplate(t), []byte("\n${UNKNOWN}")...)
	if _, err := RenderLifecycleObservationStageJobTemplate(template, valid); err == nil {
		t.Fatal("unknown observation Job placeholder was accepted")
	}
}

func validLifecycleObservationStageJobValues() LifecycleObservationStageJobValues {
	return LifecycleObservationStageJobValues{
		RunID: "ok147-lifecycle-observation-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		Expected: validSubmissionStageJobValues().Expected, InputConfigMap: "ok147-lifecycle-observation-input", ReceiptPrefixDigest: bundleSHA("b"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-observation",
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32", ManagementCredentialSecret: "ok147-management-observer",
		PollInterval: 15 * time.Second, PollTimeout: 5 * time.Minute,
	}
}

func lifecycleObservationJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/contract-executor-lifecycle-observation-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
