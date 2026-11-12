package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const legacyClusterManifestYAML = `apiVersion: cli.openkubes.io/v1alpha1
kind: Cluster
metadata:
  name: legacy-one
spec:
  profile: talos-kubevirt-mvp
`

type fakeSimpleUp struct {
	calls        int
	requestPath  string
	workload     string
	presentation clusterProvisionPresentation
	env          map[string]string
	makeOutput   string
	err          error
}

func newFakeSimpleUp(t *testing.T) (*fakeSimpleUp, simpleUpRuntime, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSimpleUp{env: map[string]string{"XDG_CONFIG_HOME": filepath.Join(base, "xdg"), "HOME": filepath.Join(base, "home"),
		"KUBECONFIG": filepath.Join(base, "ambient-admin.yaml")}}
	rt := simpleUpRuntime{
		input:    strings.NewReader(""),
		terminal: true,
		getenv:   func(key string) (string, bool) { value, ok := fake.env[key]; return value, ok },
		setenv:   func(key, value string) error { fake.env[key] = value; return nil },
		now:      func() time.Time { return time.Date(2026, 11, 13, 1, 2, 3, 0, time.UTC) },
		provision: func(_ context.Context, requestPath, workload string, _ io.Reader, stdout, _ io.Writer, presentation clusterProvisionPresentation) error {
			fake.calls++
			fake.requestPath, fake.workload, fake.presentation = requestPath, workload, presentation
			if fake.makeOutput != "" {
				io.WriteString(presentation.makeLog, fake.makeOutput)
			}
			io.WriteString(stdout, "PLAN-OUTPUT\n")
			return fake.err
		},
	}
	return fake, rt, base
}

func writeSimpleUpRequest(t *testing.T, dir, contents string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cluster.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s must not be created: %v", path, err)
	}
}

func TestSimpleUpRoutingByKind(t *testing.T) {
	dir := t.TempDir()
	request := writeSimpleUpRequest(t, filepath.Join(dir, "request"), validClusterRequestYAML)
	legacy := writeSimpleUpRequest(t, filepath.Join(dir, "legacy"), legacyClusterManifestYAML)
	if !isClusterRequestUp([]string{"-f", request}) || !isClusterRequestUp([]string{"--file=" + request, "-v"}) {
		t.Fatal("ClusterRequest file not routed to the simple UX")
	}
	for _, args := range [][]string{{"-f", legacy}, {"--file", legacy, "--dry-run"}, {"-f", filepath.Join(dir, "missing.yaml")}, {"cluster-template"}, {}} {
		if isClusterRequestUp(args) {
			t.Fatalf("%v must stay on the legacy route", args)
		}
	}
	// Through the public dispatcher (tests run without a terminal).
	xdg := filepath.Join(dir, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	var out, errOut bytes.Buffer
	err := run([]string{"up", "-f", request}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "ok up needs an interactive terminal") {
		t.Fatalf("ClusterRequest did not reach the simple UX: %v", err)
	}
	err = run([]string{"up", "-f", legacy}, &out, &errOut)
	if err == nil || strings.Contains(err.Error(), "ok up needs an interactive terminal") {
		t.Fatalf("legacy kind: Cluster left the Runner route: %v", err)
	}
	assertNotExist(t, xdg)
}

func TestSimpleUpHelpAndPlanCreateNothing(t *testing.T) {
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	for _, args := range [][]string{{"up"}, {"up", "--help"}, {"help", "up"}} {
		var out bytes.Buffer
		if err := run(args, &out, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "ok up -f <cluster.yaml>") || !strings.Contains(out.String(), "--mode operator --topology same-plane") {
			t.Fatalf("%v: help lacks simple or explicit form:\n%s", args, out.String())
		}
	}
	request := writeSimpleUpRequest(t, t.TempDir(), validClusterRequestYAML)
	if err := run([]string{"cluster", "plan", "--file", request}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	assertNotExist(t, xdg)
}

func TestSimpleUpRequiresExplicitManagementCluster(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	request := writeSimpleUpRequest(t, filepath.Join(base, "requests"), validClusterRequestYAML)
	err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), "no management cluster selected") || !strings.Contains(err.Error(), "never uses KUBECONFIG") {
		t.Fatalf("ambient KUBECONFIG was not refused: %v", err)
	}
	if fake.calls != 0 {
		t.Fatal("provisioning started without an explicit management cluster")
	}
	assertNotExist(t, filepath.Join(base, "xdg"))

	fake.env["TALOS_INFRA_KUBECONFIG"] = "/explicit/env.yaml"
	var out bytes.Buffer
	if err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request}, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.env["TALOS_INFRA_KUBECONFIG"] != "/explicit/env.yaml" || !strings.Contains(out.String(), "management kubeconfig from TALOS_INFRA_KUBECONFIG") {
		t.Fatalf("environment selection not shown: %q\n%s", fake.env["TALOS_INFRA_KUBECONFIG"], out.String())
	}
	out.Reset()
	if err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request, "--management", "/explicit/flag.yaml"}, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.env["TALOS_INFRA_KUBECONFIG"] != "/explicit/flag.yaml" || !strings.Contains(out.String(), "management kubeconfig from --management") {
		t.Fatal("--management did not take precedence over the environment")
	}
	// Both runs started in the same second: logs are kept side by side.
	logs, _ := filepath.Glob(filepath.Join(base, "xdg", "ok", "logs", "preview-one-20261113-010203*.log"))
	if len(logs) != 2 {
		t.Fatalf("same-second runs did not keep separate logs: %v", logs)
	}
}

func TestSimpleUpDefaultPathsArePrivateAndNeverWidened(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	fake.env["TALOS_INFRA_KUBECONFIG"] = "/explicit/env.yaml"
	request := writeSimpleUpRequest(t, filepath.Join(base, "requests"), validClusterRequestYAML)
	if err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "xdg", "ok")
	if fake.workload != filepath.Join(home, "kubeconfigs", "preview-one.yaml") {
		t.Fatalf("unexpected default workload kubeconfig %s", fake.workload)
	}
	for _, dir := range []string{home, filepath.Join(home, "kubeconfigs"), filepath.Join(home, "logs")} {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s not created private: %v %v", dir, err, info)
		}
	}
	if !fake.presentation.concise || fake.presentation.makeLog == nil {
		t.Fatal("default output must be concise with Make output going to the log")
	}

	// HOME fallback is ~/.config/ok when XDG_CONFIG_HOME is unset.
	delete(fake.env, "XDG_CONFIG_HOME")
	if err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.workload != filepath.Join(base, "home", ".config", "ok", "kubeconfigs", "preview-one.yaml") {
		t.Fatalf("unexpected HOME fallback %s", fake.workload)
	}

	// An existing, too-open directory is refused and left unchanged.
	open := filepath.Join(base, "open-xdg")
	if err := os.MkdirAll(filepath.Join(open, "ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(open, "ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	fake.env["XDG_CONFIG_HOME"] = open
	calls := fake.calls
	err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), "chmod 700") || fake.calls != calls {
		t.Fatalf("too-open directory accepted: %v", err)
	}
	if info, _ := os.Stat(filepath.Join(open, "ok")); info.Mode().Perm() != 0o755 {
		t.Fatal("ok up changed existing permissions")
	}

	// An explicit output path creates no kubeconfigs directory.
	fresh := filepath.Join(base, "fresh-xdg")
	fake.env["XDG_CONFIG_HOME"] = fresh
	if err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request, "--workload-kubeconfig", "/private/out/preview-one.yaml"}, io.Discard, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.workload != "/private/out/preview-one.yaml" {
		t.Fatalf("override ignored: %s", fake.workload)
	}
	assertNotExist(t, filepath.Join(fresh, "ok", "kubeconfigs"))
}

func TestSimpleUpBareDiscoversOrCreatesRequest(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	fake.env["TALOS_INFRA_KUBECONFIG"] = "/explicit/env.yaml"
	requests := filepath.Join(base, "xdg", "ok", "requests")

	rt.input = strings.NewReader("Bad Name!\n")
	if err := runSimpleUpWithRuntime(context.Background(), nil, io.Discard, io.Discard, rt); err == nil || !strings.Contains(err.Error(), "not a valid cluster name") {
		t.Fatalf("invalid name accepted: %v", err)
	}
	assertNotExist(t, requests)

	rt.input = strings.NewReader("demo-one\n")
	var out bytes.Buffer
	if err := runSimpleUpWithRuntime(context.Background(), nil, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(requests, "demo-one.yaml")
	info, err := os.Stat(created)
	if err != nil || info.Mode().Perm() != 0o600 || fake.calls != 0 || !strings.Contains(out.String(), "ok up -f "+created) {
		t.Fatalf("starter request not written privately or provisioning started: %v calls=%d\n%s", err, fake.calls, out.String())
	}
	if _, err := readClusterRequest(created); err != nil {
		t.Fatalf("starter request is invalid: %v", err)
	}

	out.Reset()
	if err := runSimpleUpWithRuntime(context.Background(), nil, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 || fake.requestPath != created || !strings.Contains(out.String(), "Using "+created) {
		t.Fatalf("single request not used: calls=%d path=%s", fake.calls, fake.requestPath)
	}

	if err := os.WriteFile(filepath.Join(requests, "other.yaml"), []byte(validClusterRequestYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runSimpleUpWithRuntime(context.Background(), nil, io.Discard, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), "several cluster requests") || fake.calls != 1 {
		t.Fatalf("ambiguous requests not refused: %v", err)
	}
}

func TestSimpleUpLogIsPrivateAndRedactsSecrets(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	fake.env["TALOS_INFRA_KUBECONFIG"] = "/explicit/env.yaml"
	request := writeSimpleUpRequest(t, filepath.Join(base, "requests"), validClusterRequestYAML)
	fake.makeOutput = "rendering\n    token: abc123secret\n  client-key-data: S3CR3TKEY\nAuthorization: Bearer eyJhbGciOi\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\npassword=hunter2\nmake: *** [bootstrap] Error 2"
	fake.err = errors.New("make bootstrap failed or was interrupted")
	var out bytes.Buffer
	err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request}, &out, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), "full log: ") {
		t.Fatalf("failure did not point to the log: %v", err)
	}
	logPath := filepath.Join(base, "xdg", "ok", "logs", "preview-one-20261113-010203.log")
	info, statErr := os.Stat(logPath)
	if statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("log not private: %v", statErr)
	}
	raw, _ := os.ReadFile(logPath)
	for _, secret := range []string{"abc123secret", "S3CR3TKEY", "eyJhbGciOi", "MIIEowIBAAKCAQEA", "hunter2"} {
		if strings.Contains(string(raw), secret) || strings.Contains(out.String(), secret) {
			t.Fatalf("secret %q leaked:\nlog:\n%s\nterminal:\n%s", secret, raw, out.String())
		}
	}
	for _, expected := range []string{"PLAN-OUTPUT", "rendering", "make: *** [bootstrap] Error 2", "result: stopped"} {
		if !strings.Contains(string(raw), expected) {
			t.Fatalf("log lacks %q:\n%s", expected, raw)
		}
	}
	if !strings.Contains(out.String(), "Last lines of Make output") || !strings.Contains(out.String(), "Error 2") {
		t.Fatalf("concise failure lacks a Make tail:\n%s", out.String())
	}

	// Verbose streams (redacted) Make output to the terminal.
	fake.err = nil
	rt.now = func() time.Time { return time.Date(2026, 11, 13, 1, 2, 4, 0, time.UTC) }
	out.Reset()
	if err := runSimpleUpWithRuntime(context.Background(), []string{"-f", request, "-v"}, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.presentation.concise || !strings.Contains(out.String(), "token: [REDACTED]") || strings.Contains(out.String(), "abc123secret") {
		t.Fatalf("verbose output not detailed and redacted:\n%s", out.String())
	}
}

func TestClusterProvisionConciseOutputKeepsBothConfirmations(t *testing.T) {
	fixture, request := newProvisionFixture(t)
	var makeLog bytes.Buffer
	fixture.runtime.concise, fixture.runtime.makeLog = true, &makeLog
	fixture.makeStdout = "MAKE-OUTPUT-MARKER\n"
	var output bytes.Buffer
	err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\nbootstrap preview-one\n"), &output, io.Discard, fixture.runtime)
	if err != nil {
		t.Fatalf("%v\n%s", err, output.String())
	}
	text := output.String()
	for _, expected := range []string{"Checks passed", "Plan", "[1/2] Generating cluster scaffold", "[2/2] Bootstrapping cluster",
		`type exactly "provision preview-one"`, `type exactly "bootstrap preview-one"`, "Kubernetes readiness is NOT verified"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("concise output lacks %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "tool make:") || strings.Contains(text, "MAKE-OUTPUT-MARKER") || !strings.Contains(makeLog.String(), "MAKE-OUTPUT-MARKER") {
		t.Fatalf("Make output or tool details leaked into concise output:\n%s", text)
	}

	cancelled, request := newProvisionFixture(t)
	cancelled.runtime.concise, cancelled.runtime.makeLog = true, io.Discard
	err = runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\nnope\n"), io.Discard, io.Discard, cancelled.runtime)
	if err == nil || cancelled.makeCount["new"] != 1 || cancelled.makeCount["bootstrap"] != 0 {
		t.Fatalf("concise mode weakened the bootstrap confirmation: %v %#v", err, cancelled.makeCount)
	}
}

func TestProvisionCheckoutErrorNamesChangedPaths(t *testing.T) {
	runtime := realGitProvisionRuntime(t)
	root := provisionTestCheckoutRoot(t)
	head := initProvisionTestRepo(t, root, provisionTestCheckoutFiles)
	writeProvisionTestFiles(t, root, map[string]string{"cluster.yaml": validClusterRequestYAML})
	err := verifyProvisionCheckout(context.Background(), runtime, root, head, false, "preview-one", true)
	if err == nil || !strings.Contains(err.Error(), "cluster.yaml") {
		t.Fatalf("error does not name the offending file: %v", err)
	}
}
