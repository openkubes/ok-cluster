package runner

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRenderNetworkObservationStageJobTemplateBindsExactEnvelope(t *testing.T) {
	values := validNetworkObservationStageJobValues()
	raw, err := RenderNetworkObservationStageJobTemplate(networkObservationJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 2 || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected network observation object set: %#v", objects)
	}
	job := objects["Job"]
	spec := objectAt(t, job, "spec")
	if spec["backoffLimit"] != 0 || spec["activeDeadlineSeconds"] != 360 {
		t.Fatalf("network Job retry or deadline differs: %#v", spec)
	}
	podSpec := objectAt(t, objectAt(t, spec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" {
		t.Fatalf("unsafe network Pod identity or restart policy: %#v", podSpec)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if !reflect.DeepEqual(args[:5], []string{"cluster", "stage", "observe", "network", "--execute"}) {
		t.Fatalf("unexpected network command: %v", args)
	}
	for flag, want := range map[string]string{
		"--receipt-prefix-digest":   values.ReceiptPrefixDigest,
		"--workload-binding":        "/var/run/openkubes/workload/binding.json",
		"--workload-binding-digest": values.WorkloadBindingDigest,
		"--network-profile":         "/var/run/openkubes/input/network-profile.json",
		"--network-profile-digest":  values.NetworkProfileDigest,
		"--poll-timeout":            "5m0s",
	} {
		if got := argumentValue(args, flag); got != want {
			t.Fatalf("%s=%q, want %q", flag, got, want)
		}
	}
	volumes := arrayAt(t, podSpec, "volumes")
	if len(volumes) != 4 {
		t.Fatalf("network Job volume count differs: %#v", volumes)
	}
	policy := objects["NetworkPolicy"]
	egress := arrayAt(t, objectAt(t, policy, "spec"), "egress")
	if len(egress) != 2 {
		t.Fatalf("network Job must have exact management and workload egress: %#v", egress)
	}
	text := string(raw)
	for _, forbidden := range []string{"stage-grant", "projection-manifest", "authority-map", "system:masters", "privileged: true"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("network observation Job contains forbidden input %q", forbidden)
		}
	}
}

func TestRenderNetworkObservationStageJobTemplateFailsClosed(t *testing.T) {
	valid := validNetworkObservationStageJobValues()
	for name, mutate := range map[string]func(*NetworkObservationStageJobValues){
		"mutable image": func(values *NetworkObservationStageJobValues) {
			values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"shared credential": func(values *NetworkObservationStageJobValues) {
			values.WorkloadCredentialSecret = values.ManagementCredentialSecret
		},
		"foreign management endpoint": func(values *NetworkObservationStageJobValues) {
			values.ManagementAPIURL, values.ManagementAPICIDR = "https://192.0.2.13:6443", "192.0.2.13/32"
		},
		"shared authority endpoint": func(values *NetworkObservationStageJobValues) {
			values.WorkloadAPIURL, values.WorkloadAPICIDR = values.ManagementAPIURL, values.ManagementAPICIDR
		},
		"broad workload CIDR": func(values *NetworkObservationStageJobValues) {
			values.WorkloadAPICIDR = "192.0.2.0/24"
		},
		"bad binding digest": func(values *NetworkObservationStageJobValues) {
			values.WorkloadBindingDigest = "sha256:bad"
		},
		"subsecond polling": func(values *NetworkObservationStageJobValues) {
			values.PollInterval = 500 * time.Millisecond
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderNetworkObservationStageJobTemplate(networkObservationJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe network observation Job values were accepted")
			}
		})
	}
	template := append(networkObservationJobTemplate(t), []byte("\n${UNKNOWN}")...)
	if _, err := RenderNetworkObservationStageJobTemplate(template, valid); err == nil {
		t.Fatal("unknown network observation placeholder was accepted")
	}
}

func validNetworkObservationStageJobValues() NetworkObservationStageJobValues {
	return NetworkObservationStageJobValues{
		RunID: "ok147-network-observation-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
		Expected: validSubmissionStageJobValues().Expected, InputConfigMap: "ok147-network-observation-input",
		ReceiptPrefixDigest: bundleSHA("b"), NetworkProfileDigest: bundleSHA("c"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-network",
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32", ManagementCredentialSecret: "ok147-management-network",
		WorkloadAPIURL: "https://192.0.2.20:6443", WorkloadAPICIDR: "192.0.2.20/32", WorkloadCredentialSecret: "ok147-workload-network",
		WorkloadBindingDigest: bundleSHA("d"), PollInterval: 15 * time.Second, PollTimeout: 5 * time.Minute,
	}
}

func networkObservationJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/contract-executor-network-observation-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
