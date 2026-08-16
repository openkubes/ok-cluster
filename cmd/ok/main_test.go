package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "internal", "contract", "testdata", name)
}

func TestVersionIncludesExecutableRevision(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "0.0.0-dev unknown\n" {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestCreateDryRunProducesNonMutatingPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"cluster", "create",
		"--contract", fixturePath(t, "ok141-contract-v5.yaml"),
		"--schema", fixturePath(t, "ok141-contract-v3.schema.json"),
		"--dry-run",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	var plan createPlan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Format != "ok147-create-plan/v1" || plan.Operation != "CreateCluster" || plan.MutationAllowed {
		t.Fatalf("unsafe plan: %#v", plan)
	}
	if plan.AuthorizationState != "NOT_EVALUATED" {
		t.Fatalf("authorization = %s", plan.AuthorizationState)
	}
}

func TestCreateWithoutDryRunFailsClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"cluster", "create",
		"--contract", fixturePath(t, "ok141-contract-v5.yaml"),
		"--schema", fixturePath(t, "ok141-contract-v3.schema.json"),
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestCreateRejectsIncompleteProjectionAndAuthorizationInputs(t *testing.T) {
	base := []string{
		"cluster", "create",
		"--contract", fixturePath(t, "ok141-contract-v5.yaml"),
		"--schema", fixturePath(t, "ok141-contract-v3.schema.json"),
		"--dry-run",
	}
	for name, extra := range map[string][]string{
		"projection root without manifest":     {"--projection-root", "/tmp/projection"},
		"authorization without projection":     {"--authorization", "/tmp/grant.json", "--authorization-key", "/tmp/key", "--evaluation-time", "2026-08-16T10:00:00Z"},
		"ledger inspect without authorization": {"--ledger-inspect", "--ledger-api-endpoint", "https://10.43.0.1:443", "--ledger-token-file", "/tmp/token", "--ledger-ca-file", "/tmp/ca"},
		"ledger inputs without inspect":        {"--ledger-api-endpoint", "https://10.43.0.1:443"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			arguments := append(append([]string{}, base...), extra...)
			if err := run(arguments, &stdout, &stderr); err == nil {
				t.Fatal("unsafe incomplete input was accepted")
			}
		})
	}
}

func TestArbitraryCommandsAreAbsent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, arguments := range [][]string{
		{"shell", "echo", "unsafe"},
		{"cluster", "apply", "--file", "anything.yaml"},
		{"cluster", "create", "unexpected-positional-command"},
	} {
		if err := run(arguments, &stdout, &stderr); err == nil {
			t.Fatalf("arguments unexpectedly accepted: %v", arguments)
		}
	}
}
