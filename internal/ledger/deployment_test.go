package ledger

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestKubernetesLedgerDeploymentBoundary(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-ledger.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
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

	for _, kind := range []string{"Namespace", "ServiceAccount", "Role", "RoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		if objects[kind] == nil {
			t.Fatalf("deployment lacks %s", kind)
		}
	}
	roleRules := nestedSlice(t, objects["Role"], "rules")
	if len(roleRules) != 1 {
		t.Fatalf("ledger Role has %d rules, want 1", len(roleRules))
	}
	rule := roleRules[0].(map[string]any)
	verbs := stringsFrom(t, rule["verbs"])
	sort.Strings(verbs)
	if len(verbs) != 2 || verbs[0] != "create" || verbs[1] != "get" {
		t.Fatalf("ledger Role verbs = %v, want only create/get", verbs)
	}
	resources := stringsFrom(t, rule["resources"])
	if len(resources) != 1 || resources[0] != "configmaps" {
		t.Fatalf("ledger Role resources = %v, want only configmaps", resources)
	}

	policy := objects["ValidatingAdmissionPolicy"]
	spec := nestedMap(t, policy, "spec")
	if spec["failurePolicy"] != "Fail" {
		t.Fatalf("admission failurePolicy = %v, want Fail", spec["failurePolicy"])
	}
	conditions := nestedSlice(t, spec, "matchConditions")
	if len(conditions) != 1 {
		t.Fatalf("admission matchConditions = %d, want 1", len(conditions))
	}
	conditionExpression := conditions[0].(map[string]any)["expression"].(string)
	if !bytes.Contains([]byte(conditionExpression), []byte("openkubes-execution-system")) {
		t.Fatal("admission match condition does not bind the ledger namespace")
	}
	validations := nestedSlice(t, spec, "validations")
	if len(validations) < 7 {
		t.Fatalf("admission has %d validations, want at least 7", len(validations))
	}
	serviceAccountBound := false
	for _, validation := range validations {
		expression, _ := validation.(map[string]any)["expression"].(string)
		if bytes.Contains([]byte(expression), []byte("ok147-contract-executor")) {
			serviceAccountBound = true
		}
	}
	if !serviceAccountBound {
		t.Fatal("admission validations do not bind the exact ServiceAccount")
	}
}

func nestedMap(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", key)
	}
	return value
}

func nestedSlice(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, ok := object[key].([]any)
	if !ok {
		t.Fatalf("%s is not an array", key)
	}
	return value
}

func stringsFrom(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value %T is not an array", value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("array item %T is not a string", item)
		}
		result = append(result, text)
	}
	return result
}
