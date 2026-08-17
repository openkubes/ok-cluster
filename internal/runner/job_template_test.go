package runner

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestJobTemplateIsBoundedAndReadOnly(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-job.yaml.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("system:masters")) || bytes.Contains(raw, []byte("privileged: true")) {
		t.Fatal("job template contains a privileged execution boundary")
	}
	values := validJobTemplateValues()
	materializedRaw, err := RenderJobTemplate(raw, values)
	if err != nil {
		t.Fatal(err)
	}
	materialized := string(materializedRaw)
	if strings.Contains(materialized, "${") {
		t.Fatal("job template has an unbound placeholder")
	}

	decoder := yaml.NewDecoder(strings.NewReader(materialized))
	objects := map[string]map[string]any{}
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		kind, _ := object["kind"].(string)
		objects[kind] = object
	}
	job := objects["Job"]
	policy := objects["NetworkPolicy"]
	if job == nil || policy == nil {
		t.Fatal("template must contain one Job and one NetworkPolicy")
	}
	jobSpec := objectAt(t, job, "spec")
	if jobSpec["backoffLimit"] != 0 || jobSpec["parallelism"] != 1 || jobSpec["completions"] != 1 {
		t.Fatalf("job retry/singleton boundary differs: %#v", jobSpec)
	}
	podSpec := objectAt(t, objectAt(t, jobSpec, "template"), "spec")
	if podSpec["serviceAccountName"] != "ok147-contract-executor-preflight" || podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" {
		t.Fatalf("pod identity/restart boundary differs: %#v", podSpec)
	}
	podSecurity := objectAt(t, podSpec, "securityContext")
	if podSecurity["runAsNonRoot"] != true || podSecurity["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
		t.Fatalf("pod security context differs: %#v", podSecurity)
	}
	containers := arrayAt(t, podSpec, "containers")
	if len(containers) != 1 {
		t.Fatalf("containers=%d, want 1", len(containers))
	}
	container := containers[0].(map[string]any)
	image, _ := container["image"].(string)
	if !strings.Contains(image, "@sha256:") {
		t.Fatalf("image is not digest-bound: %q", image)
	}
	command := stringArray(t, container, "command")
	if len(command) != 1 || command[0] != "/ok" {
		t.Fatalf("command=%v, want only /ok", command)
	}
	args := stringArray(t, container, "args")
	for _, required := range []string{"cluster", "create", "--dry-run", "--projection-manifest", "--authorization", "--ledger-inspect"} {
		if !contains(args, required) {
			t.Fatalf("job args do not bind %s: %v", required, args)
		}
	}
	for _, forbidden := range []string{"shell", "apply", "delete", "--command"} {
		if contains(args, forbidden) {
			t.Fatalf("job args contain forbidden operation %s", forbidden)
		}
	}
	containerSecurity := objectAt(t, container, "securityContext")
	if containerSecurity["allowPrivilegeEscalation"] != false || containerSecurity["readOnlyRootFilesystem"] != true {
		t.Fatalf("container security context differs: %#v", containerSecurity)
	}
	resources := objectAt(t, container, "resources")
	if len(objectAt(t, resources, "requests")) == 0 || len(objectAt(t, resources, "limits")) == 0 {
		t.Fatal("job lacks explicit resource requests or limits")
	}

	policySpec := objectAt(t, policy, "spec")
	if ingress, ok := policySpec["ingress"].([]any); !ok || len(ingress) != 0 {
		t.Fatalf("NetworkPolicy ingress is not deny-all: %#v", policySpec["ingress"])
	}
	if len(arrayAt(t, policySpec, "egress")) != 1 {
		t.Fatal("NetworkPolicy must contain exactly one API egress rule")
	}
}

func TestRenderJobTemplateFailsClosed(t *testing.T) {
	template := []byte(strings.Join([]string{
		"${OK147_RUN_ID}", "${OK147_IMAGE_DIGEST}", "${OK147_EVALUATION_TIME}",
		"${OK147_KUBERNETES_API_URL}", "${OK147_KUBERNETES_API_CIDR}", "${OK147_INPUT_CONFIGMAP}",
	}, "\n"))
	for name, mutate := range map[string]func(*JobTemplateValues){
		"shell-like run ID": func(values *JobTemplateValues) { values.RunID = "ok147-x;id" },
		"mutable image":     func(values *JobTemplateValues) { values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"DNS API endpoint":  func(values *JobTemplateValues) { values.KubernetesAPIURL = "https://kubernetes.default.svc:443" },
		"broad API CIDR":    func(values *JobTemplateValues) { values.KubernetesAPICIDR = "10.43.0.0/24" },
	} {
		t.Run(name, func(t *testing.T) {
			values := validJobTemplateValues()
			candidate := append([]byte(nil), template...)
			mutate(&values)
			if _, err := RenderJobTemplate(candidate, values); err == nil {
				t.Fatal("unsafe Job template input was accepted")
			}
		})
	}
	if _, err := RenderJobTemplate(append(template, []byte("\n${UNKNOWN}")...), validJobTemplateValues()); err == nil {
		t.Fatal("unknown template placeholder was accepted")
	}
}

func validJobTemplateValues() JobTemplateValues {
	return JobTemplateValues{
		RunID:             "ok147-create-20260816-01",
		ImageDigest:       "ghcr.io/openkubes/ok-cluster@sha256:" + strings.Repeat("a", 64),
		EvaluationTime:    "2026-08-16T10:00:00Z",
		KubernetesAPIURL:  "https://10.43.0.1:443",
		KubernetesAPICIDR: "10.43.0.1/32",
		InputConfigMap:    "ok147-create-20260816-01-input",
	}
}

func objectAt(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", key)
	}
	return value
}

func arrayAt(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, ok := object[key].([]any)
	if !ok {
		t.Fatalf("%s is not an array", key)
	}
	return value
}

func stringArray(t *testing.T, object map[string]any, key string) []string {
	t.Helper()
	values := arrayAt(t, object, key)
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s contains non-string %T", key, value)
		}
		result = append(result, text)
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
