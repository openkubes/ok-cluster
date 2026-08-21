package runner

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestRenderObservabilityCollectorJobTemplateIsExactAndNonRetrying(t *testing.T) {
	values := validObservabilityCollectorJobValues()
	raw, err := RenderObservabilityCollectorJobTemplate(observabilityCollectorJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	objects := decodeJobObjects(t, raw)
	if len(objects) != 3 || objects["Service"] == nil || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected collector runtime object set: %#v", objects)
	}
	serviceSpec := objectAt(t, objects["Service"], "spec")
	if serviceSpec["type"] != "LoadBalancer" || serviceSpec["loadBalancerIP"] != "192.0.2.44" || serviceSpec["externalTrafficPolicy"] != "Local" {
		t.Fatalf("collector Service identity differs: %#v", serviceSpec)
	}
	policySpec := objectAt(t, objects["NetworkPolicy"], "spec")
	if len(arrayAt(t, policySpec, "ingress")) != 2 || len(arrayAt(t, policySpec, "egress")) != 1 {
		t.Fatalf("collector network boundary differs: %#v", policySpec)
	}
	jobSpec := objectAt(t, objects["Job"], "spec")
	if jobSpec["backoffLimit"] != 0 || jobSpec["completions"] != 1 || jobSpec["parallelism"] != 1 || jobSpec["activeDeadlineSeconds"] != 10800 {
		t.Fatalf("collector retry or deadline differs: %#v", jobSpec)
	}
	podSpec := objectAt(t, objectAt(t, jobSpec, "template"), "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" {
		t.Fatalf("collector Pod authority differs: %#v", podSpec)
	}
	init := arrayAt(t, podSpec, "initContainers")[0].(map[string]any)
	if got := stringArray(t, init, "args"); !reflect.DeepEqual(got, []string{
		"cluster", "stage", "evidence", "observability", "collector", "materialize",
		"--source", "/var/run/openkubes/collector-source", "--destination", "/var/run/openkubes/collector",
		"--state-directory", "/var/lib/openkubes/observability-evidence",
		"--expected-activation-digest", values.ActivationDigest,
		"--expected-manifest-digest", values.ManifestDigest,
		"--expected-runtime-binding-digest", values.RuntimeBindingDigest,
		"--expected-public-endpoint-digest", values.PublicEndpointDigest, "--materialize",
	}) {
		t.Fatalf("collector initializer differs: %v", got)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	if got := stringArray(t, container, "args"); !reflect.DeepEqual(got, []string{
		"evidence", "observability", "serve", "--activation", "/var/run/openkubes/collector/activation.json",
	}) {
		t.Fatalf("collector serving command differs: %v", got)
	}
	text := string(raw)
	for _, forbidden := range []string{"latest", "system:masters", "privileged: true", "automountServiceAccountToken: true", "restartPolicy: Always"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("collector Job contains forbidden value %q", forbidden)
		}
	}
}

func TestRenderObservabilityCollectorJobTemplateFailsClosed(t *testing.T) {
	valid := validObservabilityCollectorJobValues()
	for name, mutate := range map[string]func(*ObservabilityCollectorJobValues){
		"mutable image": func(values *ObservabilityCollectorJobValues) {
			values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"foreign run":        func(values *ObservabilityCollectorJobValues) { values.RunID = "foreign-run" },
		"broad alert source": func(values *ObservabilityCollectorJobValues) { values.AlertSourceCIDR = "0.0.0.0/0" },
		"broad workload":     func(values *ObservabilityCollectorJobValues) { values.WorkloadAPICIDR = "192.0.2.0/24" },
		"DNS endpoint": func(values *ObservabilityCollectorJobValues) {
			values.PublicEndpoint = "https://collector.example.test:8443"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := RenderObservabilityCollectorJobTemplate(observabilityCollectorJobTemplate(t), candidate); err == nil {
				t.Fatal("unsafe collector Job values were accepted")
			}
		})
	}
}

func validObservabilityCollectorJobValues() ObservabilityCollectorJobValues {
	return ObservabilityCollectorJobValues{
		RunID: "ok147-evidence-collector-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + runnerStageSHA("a"),
		ActivationSecret: "ok147-evidence-collector-activation", ActivationDigest: runnerStageSHA("1"),
		ManifestDigest: runnerStageSHA("2"), RuntimeBindingDigest: runnerStageSHA("3"), PublicEndpointDigest: runnerStageSHA("4"),
		PublicEndpoint: "https://192.0.2.44:8443", WorkloadAPIURL: "https://192.0.2.147:6443",
		WorkloadAPICIDR: "192.0.2.147/32", AlertSourceCIDR: "10.244.0.0/16",
	}
}

func observabilityCollectorJobTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/observability-evidence-collector-job.yaml.tpl")
	if err != nil {
		t.Fatal(err)
	}
	if digest.SHA256(raw) == "" {
		t.Fatal("collector Job template identity missing")
	}
	return raw
}
