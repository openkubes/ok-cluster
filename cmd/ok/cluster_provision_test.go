package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type provisionCall struct {
	executable string
	args       []string
	dir        string
	env        []string
}

type provisionFixture struct {
	t                      *testing.T
	root, okLinux          string
	management             string
	workload               string
	chartHash              string
	runtime                clusterProvisionRuntime
	calls                  []provisionCall
	makeFailure            map[string]error
	partialOnError         bool
	makeCount              map[string]int
	gitRevisionOverride    string
	kubectlCount           int
	clusterAppearsAt       int
	makeStdout, makeStderr string
	clusterQueryFailure    error
}

const (
	provisionMakefileBaselineFixture = "# fixture\nTestClusterPlan|TestClusterCreateManifestTemplateIsMachineReadableAndNonAuthorizing\n"
	provisionMakefileCurrentFixture  = "# fixture\nTestClusterPlan|TestClusterProvision|TestClusterCreateManifestTemplateIsMachineReadableAndNonAuthorizing\n"
)

func newProvisionFixture(t *testing.T) (*provisionFixture, clusterRequest) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "ok-cluster")
	okLinux := filepath.Join(base, "ok-linux")
	for _, directory := range []string{root, filepath.Join(root, ".git"), filepath.Join(root, ".tools"), okLinux, filepath.Join(okLinux, ".git"), filepath.Join(okLinux, "profiles", "kubevirt")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(provisionMakefileCurrentFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(okLinux, "profiles", "kubevirt", "profile.yaml"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgmt := filepath.Join(base, "management.kubeconfig")
	managementConfig := `apiVersion: v1
kind: Config
current-context: ok-management
clusters:
- name: management
  cluster:
    server: https://management.example.test:6443
    certificate-authority-data: Y2E=
contexts:
- name: ok-management
  context:
    cluster: management
    user: management-user
users:
- name: management-user
  user:
    token: fixture-token
`
	if err := os.WriteFile(mgmt, []byte(managementConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	canonicalBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	base = canonicalBase
	root = filepath.Join(base, "ok-cluster")
	okLinux = filepath.Join(base, "ok-linux")
	workloadDir := filepath.Join(base, "private-kubeconfigs")
	if err := os.Mkdir(workloadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	chart := []byte("fixture chart bytes")
	chartHashArray := sha256.Sum256(chart)
	chartHash := hex.EncodeToString(chartHashArray[:])
	if err := os.WriteFile(filepath.Join(root, ".tools", "cilium-1.19.6.tgz"), chart, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	tools := make(map[string]string)
	for _, name := range clusterProvisionRequiredTools {
		path := filepath.Join(bin, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		tools[name] = path
	}
	workload := filepath.Join(workloadDir, "preview-one.yaml")
	fixture := &provisionFixture{t: t, root: root, okLinux: okLinux, management: mgmt, workload: workload, chartHash: chartHash,
		makeFailure: make(map[string]error), makeCount: make(map[string]int)}
	fixture.runtime = clusterProvisionRuntime{
		makeRoot: root, okLinuxRoot: okLinux, makeExecutable: tools["make"], makeRevision: strings.Repeat("a", 40),
		okLinuxRevision: strings.Repeat("b", 40), reviewedMakeSource: strings.Repeat("c", 40), expectedChartHash: chartHash,
		managementKubeconfig: mgmt, workloadKubeconfig: workload, environmentPath: bin, toolPaths: tools,
		isTerminal: true, newTimeout: time.Second, bootstrapTimeout: time.Second,
	}
	fixture.runtime.command = fixture.run
	requestPath := writeClusterPlanRequest(t, validClusterRequestYAML)
	request, err := readClusterRequest(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, request
}

func (fixture *provisionFixture) run(ctx context.Context, executable string, args []string, dir string, environment []string, stdout, stderr io.Writer) error {
	fixture.calls = append(fixture.calls, provisionCall{executable: executable, args: append([]string(nil), args...), dir: dir, env: append([]string(nil), environment...)})
	base := filepath.Base(executable)
	switch base {
	case "git":
		subcommand := provisionGitSubcommand(args)
		if subcommand == "rev-parse" {
			revision := fixture.runtime.makeRevision
			if dir == fixture.okLinux {
				revision = fixture.runtime.okLinuxRevision
			}
			if fixture.gitRevisionOverride != "" {
				revision = fixture.gitRevisionOverride
			}
			fmt.Fprintln(stdout, revision)
			return nil
		}
		if subcommand == "status" {
			if dir == fixture.root {
				fmt.Fprintln(stdout, " M Makefile")
			}
			if fixture.makeCount["new"] > 0 && dir == fixture.root {
				fmt.Fprintf(stdout, "?? preview-one/cluster-config.yaml\n?? preview-one/cluster-base.yaml\n")
			}
			return nil
		}
		if subcommand == "show" {
			fmt.Fprint(stdout, provisionMakefileBaselineFixture)
			return nil
		}
		return nil
	case "kubectl":
		fixture.kubectlCount++
		if fixture.clusterQueryFailure != nil {
			return fixture.clusterQueryFailure
		}
		if fixture.clusterAppearsAt > 0 && fixture.kubectlCount >= fixture.clusterAppearsAt {
			fmt.Fprintln(stdout, "cluster.cluster.x-k8s.io/preview-one")
		}
		return nil
	case "python3":
		return nil
	case "make":
		if len(args) < 2 {
			return errors.New("missing target")
		}
		target := args[1]
		fixture.makeCount[target]++
		if fixture.makeStdout != "" {
			fmt.Fprint(stdout, fixture.makeStdout)
		}
		if fixture.makeStderr != "" {
			fmt.Fprint(stderr, fixture.makeStderr)
		}
		if target == "new" && (fixture.makeFailure[target] == nil || fixture.partialOnError) {
			fixture.writeScaffold()
		}
		if target == "bootstrap" && fixture.makeFailure[target] == nil {
			if err := os.WriteFile(fixture.workload, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
				return err
			}
		}
		return fixture.makeFailure[target]
	default:
		return fmt.Errorf("unexpected subprocess %s", base)
	}
}

func provisionGitSubcommand(args []string) string {
	for _, arg := range args {
		switch arg {
		case "rev-parse", "status", "diff", "show":
			return arg
		}
	}
	return ""
}

func (fixture *provisionFixture) writeScaffold() {
	fixture.t.Helper()
	directory := filepath.Join(fixture.root, "preview-one")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		fixture.t.Fatal(err)
	}
	config := `name: preview-one
type: talos
providerProfile:
  name: ok-infra
  identity: %s
  nodeSelector: ok-infra
  cloneTargetStorageClass: ok-storage-block
  replicaCount: 2
  snapshotClass: ok-storage-block-snapshot
controlPlane:
  replicas: 1
  cores: 2
  memory: 4Gi
  disk: 20Gi
workers:
  replicas: 1
  cores: 2
  memory: 4Gi
  disk: 15Gi
versions:
  kubernetes: v1.34.1
  talos: v1.9.6
os:
  distribution: ok-linux
  profile: kubevirt
  schematic_id: %s
  architecture: amd64
  imageDigest: %s
  identity: %s
  goldenImage:
    namespace: ok-images
    claim: talos-image-fixture
    published: true
    storageClass: ok-storage-block
network:
  endpoint: 192.168.100.200
  podCIDR: 10.33.0.0/16
  serviceCIDR: 10.96.16.0/20
nodeSelector: ok-infra
upgrade:
  strategy: blue-green
  workloadMigration:
    stateless: gitops
    stateful: app-native
`
	config = fmt.Sprintf(config, expectedProvisionProviderIdentity(), clusterRequestSchematic,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64))
	for name, contents := range map[string]string{"cluster-config.yaml": config, "cluster-base.yaml": "apiVersion: cluster.x-k8s.io/v1beta1\nkind: Cluster\n"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
			fixture.t.Fatal(err)
		}
	}
}

func (fixture *provisionFixture) provision(input string) (bytes.Buffer, error) {
	fixture.t.Helper()
	var output bytes.Buffer
	err := runClusterProvisionWithRuntime(context.Background(), mustProvisionRequest(fixture.t), strings.NewReader(input), &output, io.Discard, fixture.runtime)
	return output, err
}

func mustProvisionRequest(t *testing.T) clusterRequest {
	t.Helper()
	path := writeClusterPlanRequest(t, validClusterRequestYAML)
	request, err := readClusterRequest(path)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestClusterProvisionRunsOnlyNewThenBootstrapWithPinnedInputs(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/ambient-kubeconfig")
	t.Setenv("MAKEFLAGS", "--touch")
	t.Setenv("GNUMAKEFLAGS", "--debug")
	t.Setenv("DOCKER_HOST", "tcp://ambient.invalid")
	t.Setenv("DOCKER_CONTEXT", "ambient")
	t.Setenv("COLIMA_PROFILE", "ambient")
	t.Setenv("PYTHONPATH", "/tmp/ambient-python")
	fixture, request := newProvisionFixture(t)
	prepared, err := prepareClusterProvision(request, fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = runClusterProvisionWithRuntime(context.Background(), request,
		strings.NewReader("provision preview-one\nbootstrap preview-one\n"), &output, io.Discard, fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 1 || len(fixture.calls) == 0 {
		t.Fatalf("unexpected command counts: %#v", fixture.makeCount)
	}
	entries, err := os.ReadDir(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	var rootNames []string
	for _, entry := range entries {
		rootNames = append(rootNames, entry.Name())
	}
	if !reflect.DeepEqual(rootNames, []string{".git", ".tools", "Makefile", "preview-one"}) {
		t.Fatalf("unexpected files were created in Make checkout: %v", rootNames)
	}
	var makeCalls []provisionCall
	for _, call := range fixture.calls {
		if filepath.Base(call.executable) == "make" {
			makeCalls = append(makeCalls, call)
		}
	}
	if len(makeCalls) != 2 {
		t.Fatalf("expected exactly two Make calls, got %d", len(makeCalls))
	}
	for i, expected := range [][]string{prepared.newArgs, prepared.bootstrapArgs} {
		if !reflect.DeepEqual(makeCalls[i].args, expected) {
			t.Fatalf("Make call %d argv mismatch:\n got %#v\nwant %#v", i, makeCalls[i].args, expected)
		}
		if makeCalls[i].dir != fixture.root {
			t.Fatalf("Make call %d cwd=%q", i, makeCalls[i].dir)
		}
		env := make(map[string]string)
		for _, entry := range makeCalls[i].env {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				t.Fatalf("malformed child environment entry %q", entry)
			}
			env[key] = value
		}
		for _, forbidden := range []string{"KUBECONFIG", "MAKEFLAGS", "GNUMAKEFLAGS", "DOCKER_HOST", "DOCKER_CONTEXT", "PYTHONPATH", "BASH_ENV", "COLIMA_PROFILE"} {
			if _, present := env[forbidden]; present {
				t.Fatalf("restricted Make environment contains %q", forbidden)
			}
		}
		if env["TALOS_INFRA_KUBECONFIG"] != fixture.management {
			t.Fatal("explicit management kubeconfig is missing from Make environment")
		}
	}
	if strings.Count(strings.Join(makeCalls[0].args, "\n"), "OK76_REQUIRE_LIVE_METALLB_INVENTORY=true") != 1 || strings.Count(strings.Join(makeCalls[1].args, "\n"), "OK76_REQUIRE_LIVE_METALLB_INVENTORY=true") != 1 {
		t.Fatal("strict live inventory mode was not forced once per target")
	}
	if _, err := os.Stat(fixture.workload); err != nil {
		t.Fatalf("workload kubeconfig was not produced: %v", err)
	}
	if !strings.Contains(output.String(), "not independent verification") {
		t.Fatal("success output claimed more than Make completion")
	}
	if !strings.Contains(output.String(), "context=ok-management apiServer=https://management.example.test:6443") {
		t.Fatal("confirmed plan did not identify the explicit management target")
	}
	for _, call := range fixture.calls {
		switch filepath.Base(call.executable) {
		case "git", "kubectl", "python3", "make":
		default:
			t.Fatalf("unexpected subprocess %q", call.executable)
		}
	}
}

func TestClusterProvisionFirstConfirmationPrecedesMake(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	_, err := fixture.provision("no\n")
	if err == nil || fixture.makeCount["new"] != 0 || fixture.makeCount["bootstrap"] != 0 {
		t.Fatalf("declined first prompt executed Make: %v %#v", err, fixture.makeCount)
	}
}

func TestClusterProvisionSecondConfirmationPreservesScaffold(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	output, err := fixture.provision("provision preview-one\nno\n")
	if err == nil || fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 0 {
		t.Fatalf("second confirmation boundary failed: err=%v calls=%#v", err, fixture.makeCount)
	}
	if _, statErr := os.Stat(filepath.Join(fixture.root, "preview-one", "cluster-config.yaml")); statErr != nil {
		t.Fatal("completed scaffold was not preserved")
	}
	if !strings.Contains(output.String(), "endpoint: 192.168.100.200") {
		t.Fatalf("resolved network was not presented: %s", output.String())
	}
}

func TestClusterProvisionRechecksClusterAbsenceAfterSecondConfirmation(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	fixture.clusterAppearsAt = 4
	_, err := fixture.provision("provision preview-one\nbootstrap preview-one\n")
	if err == nil || fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 0 {
		t.Fatalf("appeared Cluster reached bootstrap: err=%v calls=%#v", err, fixture.makeCount)
	}
}

func TestClusterProvisionFailsClosedOnClusterAbsenceQueryError(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	fixture.clusterQueryFailure = errors.New("API unavailable")
	_, err := fixture.provision("provision preview-one\n")
	if err == nil || fixture.makeCount["new"] != 0 || fixture.makeCount["bootstrap"] != 0 {
		t.Fatalf("unverified Cluster absence reached Make: err=%v calls=%#v", err, fixture.makeCount)
	}
}

func TestClusterProvisionFailureDoesNotRetryOrCleanScaffold(t *testing.T) {
	t.Run("new partial failure", func(t *testing.T) {
		fixture, _ := newProvisionFixture(t)
		fixture.makeFailure["new"] = errors.New("make failure")
		fixture.partialOnError = true
		fixture.makeStdout, fixture.makeStderr = "safe progress\n", "safe error detail\n"
		var stdout, stderr bytes.Buffer
		err := runClusterProvisionWithRuntime(context.Background(), mustProvisionRequest(t), strings.NewReader("provision preview-one\n"), &stdout, &stderr, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 0 {
			t.Fatalf("unexpected retry/continuation: %v %#v", err, fixture.makeCount)
		}
		if !strings.Contains(stdout.String(), "safe progress") || !strings.Contains(stderr.String(), "safe error detail") {
			t.Fatalf("Make diagnostics were not preserved: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if _, statErr := os.Stat(filepath.Join(fixture.root, "preview-one", "cluster-config.yaml")); statErr != nil {
			t.Fatal("partial published scaffold was cleaned")
		}
	})
	t.Run("bootstrap partial failure", func(t *testing.T) {
		fixture, _ := newProvisionFixture(t)
		fixture.makeFailure["bootstrap"] = errors.New("bootstrap failure")
		_, err := fixture.provision("provision preview-one\nbootstrap preview-one\n")
		if err == nil || fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 1 {
			t.Fatalf("unexpected command counts: %v %#v", err, fixture.makeCount)
		}
		if _, statErr := os.Stat(filepath.Join(fixture.root, "preview-one", "cluster-config.yaml")); statErr != nil {
			t.Fatal("scaffold was cleaned after bootstrap failure")
		}
	})
}

func TestClusterProvisionTimeoutAndCancellationDoNotAdvance(t *testing.T) {
	fixture, request := newProvisionFixture(t)
	fixture.runtime.newTimeout = 10 * time.Millisecond
	fixture.runtime.command = func(ctx context.Context, executable string, args []string, dir string, env []string, stdout, stderr io.Writer) error {
		if filepath.Base(executable) == "make" && len(args) > 1 && args[1] == "new" {
			<-ctx.Done()
			return ctx.Err()
		}
		return fixture.run(ctx, executable, args, dir, env, stdout, stderr)
	}
	err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
	if err == nil || !strings.Contains(err.Error(), "timed out") || fixture.makeCount["bootstrap"] != 0 {
		t.Fatalf("timeout did not fail-stop: %v %#v", err, fixture.makeCount)
	}

	fixture2, request2 := newProvisionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture2.runtime.command = func(ctx context.Context, executable string, args []string, dir string, env []string, stdout, stderr io.Writer) error {
		if filepath.Base(executable) == "make" && len(args) > 1 && args[1] == "new" {
			cancel()
			return context.Canceled
		}
		return fixture2.run(ctx, executable, args, dir, env, stdout, stderr)
	}
	err = runClusterProvisionWithRuntime(ctx, request2, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture2.runtime)
	if err == nil || fixture2.makeCount["bootstrap"] != 0 {
		t.Fatalf("cancellation did not fail-stop: %v %#v", err, fixture2.makeCount)
	}

	fixture3, request3 := newProvisionFixture(t)
	fixture3.runtime.bootstrapTimeout = 10 * time.Millisecond
	fixture3.runtime.command = func(ctx context.Context, executable string, args []string, dir string, env []string, stdout, stderr io.Writer) error {
		if filepath.Base(executable) == "make" && len(args) > 1 && args[1] == "bootstrap" {
			fixture3.makeCount["bootstrap"]++
			<-ctx.Done()
			return ctx.Err()
		}
		return fixture3.run(ctx, executable, args, dir, env, stdout, stderr)
	}
	err = runClusterProvisionWithRuntime(context.Background(), request3, strings.NewReader("provision preview-one\nbootstrap preview-one\n"), io.Discard, io.Discard, fixture3.runtime)
	if err == nil || !strings.Contains(err.Error(), "timed out") || fixture3.makeCount["new"] != 1 || fixture3.makeCount["bootstrap"] != 1 {
		t.Fatalf("bootstrap timeout did not stop without retry: %v %#v", err, fixture3.makeCount)
	}
	if _, statErr := os.Stat(filepath.Join(fixture3.root, "preview-one", "cluster-config.yaml")); statErr != nil {
		t.Fatal("scaffold was not preserved after bootstrap timeout")
	}
}

func TestClusterProvisionRejectsPrerequisitesAndUnsafeScaffold(t *testing.T) {
	t.Run("nonterminal", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		fixture.runtime.isTerminal = false
		if err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader(""), io.Discard, io.Discard, fixture.runtime); err == nil {
			t.Fatal("nonterminal execution accepted")
		}
	})
	t.Run("bad chart digest", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		fixture.runtime.expectedChartHash = strings.Repeat("0", 64)
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("bad chart reached Make: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("missing chart", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		if err := os.Remove(filepath.Join(fixture.root, ".tools", "cilium-1.19.6.tgz")); err != nil {
			t.Fatal(err)
		}
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("missing chart reached Make: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("missing management kubeconfig", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		if err := os.Remove(fixture.management); err != nil {
			t.Fatal(err)
		}
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("missing management kubeconfig reached Make: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("management kubeconfig changed after preparation", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		prepared, err := prepareClusterProvision(request, fixture.runtime)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.management, []byte("replacement kubeconfig\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyProvisionInputs(context.Background(), prepared, fixture.runtime, false); err == nil {
			t.Fatal("changed management kubeconfig passed the preflight binding")
		}
	})
	t.Run("missing required tool", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		delete(fixture.runtime.toolPaths, "helm")
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("missing tool reached Make: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("invalid request has no subprocess", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		request.Spec.Profile = "unsupported"
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || len(fixture.calls) != 0 {
			t.Fatalf("invalid request reached subprocess: err=%v calls=%#v", err, fixture.calls)
		}
	})
	t.Run("checkout revision mismatch", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		fixture.gitRevisionOverride = strings.Repeat("d", 40)
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("wrong revision reached Make: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("nonprivate management kubeconfig", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		if err := os.Chmod(fixture.management, 0o644); err != nil {
			t.Fatal(err)
		}
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("unsafe kubeconfig reached Make: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("existing scaffold", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		fixture.writeScaffold()
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader("provision preview-one\n"), io.Discard, io.Discard, fixture.runtime)
		if err == nil || fixture.makeCount["new"] != 0 {
			t.Fatalf("existing scaffold was overwritten: %v %#v", err, fixture.makeCount)
		}
	})
	t.Run("nonwritable workload kubeconfig parent", func(t *testing.T) {
		fixture, _ := newProvisionFixture(t)
		parent := filepath.Dir(fixture.workload)
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700)
		if err := verifyWorkloadKubeconfigDestination(fixture.workload, "preview-one"); err == nil {
			t.Fatal("nonwritable private destination was accepted")
		}
	})
	t.Run("unexpected generated config field", func(t *testing.T) {
		fixture, request := newProvisionFixture(t)
		fixture.writeScaffold()
		path := filepath.Join(fixture.root, "preview-one", "cluster-config.yaml")
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(contents, "unexpectedField: true\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareClusterProvision(request, fixture.runtime)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := inspectProvisionScaffold(fixture.runtime, prepared); err == nil {
			t.Fatal("unexpected generated configuration field was accepted")
		}
	})
}

func TestClusterProvisionCommandUsesExactExecutableArgumentsDirectoryAndEnvironment(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "capture")
	script := filepath.Join(root, "fake-make")
	contents := "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$0\" \"$#\" \"$1\" \"$2\" \"$ONLY_ALLOWED\" > \"$CAPTURE_FILE\"\nprintf 'fake output\\n'\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(context.Background(), script, "new", "CLUSTER=preview-one")
	command.Dir = work
	command.Env = []string{"PATH=/bin:/usr/bin", "ONLY_ALLOWED=ok", "CAPTURE_FILE=" + log}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	configureClusterProvisionProcess(command)
	if err := command.Run(); err != nil {
		t.Fatalf("fake executable failed: %v stderr=%s", err, stderr.String())
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{work, script, "2", "new", "CLUSTER=preview-one", "ok"} {
		if !strings.Contains(string(got), expected) {
			t.Fatalf("fake child did not receive %q: %s", expected, got)
		}
	}
	if stdout.String() != "fake output\n" {
		t.Fatalf("stdout was not forwarded exactly: %q", stdout.String())
	}
}

func TestClusterProvisionProcessGroupTimeoutStopsFakeExecutable(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "fake-make")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := clusterProvisionRuntime{
		makeRoot: root, makeExecutable: script, environmentPath: "/bin:/usr/bin",
		command: runClusterProvisionCommand, newTimeout: 50 * time.Millisecond,
	}
	start := time.Now()
	err := runProvisionMake(context.Background(), runtime, []string{"--no-print-directory", "new"}, time.Second, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("fake Make timeout was not classified: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timed out process group was not stopped promptly: %s", elapsed)
	}
}

func TestClusterProvisionKubeconfigRejectsPluginsAndInsecureTLS(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	base, err := os.ReadFile(fixture.management)
	if err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]string{
		"exec credential plugin":  strings.Replace(string(base), "    token: fixture-token", "    exec:\n      command: /tmp/credential-plugin", 1),
		"impersonation":           strings.Replace(string(base), "    token: fixture-token", "    token: fixture-token\n    as: system:admin", 1),
		"insecure TLS":            strings.Replace(string(base), "    server: https://management.example.test:6443", "    server: https://management.example.test:6443\n    insecure-skip-tls-verify: true", 1),
		"HTTP endpoint":           strings.Replace(string(base), "https://management.example.test:6443", "http://management.example.test:6443", 1),
		"missing current context": strings.Replace(string(base), "current-context: ok-management\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "management.yaml")
			if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectProvisionManagementKubeconfig(path); err == nil {
				t.Fatal("unsafe or ambiguous management kubeconfig was accepted")
			}
		})
	}
}

func TestClusterProvisionToolPathContainsOnlyResolvedTools(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	path, cleanup, err := createProvisionToolPath(map[string]string{
		"make": fixture.runtime.toolPaths["make"], "kubectl": fixture.runtime.toolPaths["kubectl"],
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "kubectl" || entries[1].Name() != "make" {
		t.Fatalf("isolated tool PATH contains unexpected entries: %#v", entries)
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("tool lookup %q is not a pinned symlink: %v", entry.Name(), err)
		}
	}
	cleanup()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary tool PATH was not removed: %v", err)
	}
}

func TestClusterProvisionPythonVenvBindingPreservesInstalledDependency(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Python venv PATH binding regression is supported on macOS and Linux")
	}
	hostPython, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	root := t.TempDir()
	venv := filepath.Join(root, "venv")
	command := exec.Command(hostPython, "-m", "venv", venv)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("python3 venv support is unavailable: %v: %s", err, output)
	}
	selectedPython := filepath.Join(venv, "bin", "python3")
	wheel := writeProvisionFixtureWheel(t, root)
	install := exec.Command(selectedPython, "-m", "pip", "install", "--no-index", "--no-deps", wheel)
	if output, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install local fixture dependency into venv: %v: %s", err, output)
	}

	resolvedPython, err := filepath.EvalSymlinks(selectedPython)
	if err != nil {
		t.Fatal(err)
	}
	venvRoot, err := filepath.EvalSymlinks(venv)
	if err != nil {
		t.Fatal(err)
	}
	toolPath, cleanup, err := createProvisionToolPath(map[string]string{"python3": selectedPython})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	pinnedTools := make(map[string]string, len(clusterProvisionRequiredTools))
	for _, name := range clusterProvisionRequiredTools {
		pinnedTools[name] = hostPython
	}
	pinnedTools["python3"] = selectedPython
	runtimeConfig := clusterProvisionRuntime{environmentPath: toolPath, toolPaths: pinnedTools, command: runClusterProvisionCommand}
	if err := verifyProvisionTools(runtimeConfig); err != nil {
		t.Fatalf("CLI PyYAML preflight did not use the selected venv: %v", err)
	}
	selectedResult := exec.Command(provisionPythonExecutable(runtimeConfig), "-c", "import sys, ok76_fixture_dep; print(sys.prefix); print(ok76_fixture_dep.__file__)")
	selectedOutput, err := selectedResult.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated Python PATH did not import the venv-installed dependency: %v: %s", err, selectedOutput)
	}
	selectedLines := strings.Split(strings.TrimSpace(string(selectedOutput)), "\n")
	if len(selectedLines) != 2 || filepath.Clean(selectedLines[0]) != venvRoot || !strings.HasPrefix(filepath.Clean(selectedLines[1]), venvRoot+string(filepath.Separator)) {
		t.Fatalf("isolated Python did not retain venv identity: prefix/module=%q, want root %q", selectedLines, venvRoot)
	}
	basePrefix, err := exec.Command(resolvedPython, "-c", "import sys; print(sys.prefix)").Output()
	if err != nil || filepath.Clean(strings.TrimSpace(string(basePrefix))) == venvRoot {
		t.Fatalf("test setup did not distinguish the resolved base interpreter from its venv: prefix=%q err=%v", basePrefix, err)
	}

	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is unavailable")
	}
	makePath, err = filepath.EvalSymlinks(makePath)
	if err != nil {
		t.Fatal(err)
	}
	makeTools, makeCleanup, err := createProvisionToolPath(map[string]string{"make": makePath, "python3": selectedPython})
	if err != nil {
		t.Fatal(err)
	}
	defer makeCleanup()
	makefile := filepath.Join(root, "Makefile")
	contents := ".PHONY: verify-python\nverify-python:\n\t@python3 -c 'import ok76_fixture_dep; assert ok76_fixture_dep.VALUE == \"installed-in-venv\"'\n"
	if err := os.WriteFile(makefile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	makeCommand := exec.Command(filepath.Join(makeTools, "make"), "-f", makefile, "verify-python")
	makeCommand.Dir = root
	makeCommand.Env = []string{"PATH=" + makeTools, "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1"}
	if output, err := makeCommand.CombinedOutput(); err != nil {
		t.Fatalf("Make did not use the same selected venv Python: %v: %s", err, output)
	}
}

func TestClusterProvisionActualMakefilePathAndRendererUseIsolatedTools(t *testing.T) {
	var pwdRequired bool
	for _, name := range clusterProvisionRequiredTools {
		if name == "pwd" {
			pwdRequired = true
			break
		}
	}
	if !pwdRequired {
		t.Fatal("pwd must remain in the validated provisioning tool allowlist")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Makefile isolated PATH regression is supported on macOS and Linux")
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source checkout")
	}
	makeRoot, err := filepath.EvalSymlinks(filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..")))
	if err != nil {
		t.Fatal(err)
	}
	makefile := filepath.Join(makeRoot, "Makefile")
	info, err := os.Lstat(makefile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("actual Makefile is missing or unsafe: %v", err)
	}
	tools := make(map[string]string)
	for _, name := range []string{"make", "pwd", "git", "cat"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("required test tool %s is unavailable", name)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatalf("cannot resolve test tool %s: %v", name, err)
		}
		tools[name] = resolved
	}
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	venv := filepath.Join(t.TempDir(), "venv")
	if output, err := exec.Command(pythonPath, "-m", "venv", venv).CombinedOutput(); err != nil {
		t.Skipf("python3 venv support is unavailable: %v: %s", err, output)
	}
	selectedPython := filepath.Join(venv, "bin", "python3")
	wheel := writeProvisionFixtureWheel(t, filepath.Dir(venv))
	if output, err := exec.Command(selectedPython, "-m", "pip", "install", "--no-index", "--no-deps", wheel).CombinedOutput(); err != nil {
		t.Fatalf("install local renderer dependency into venv: %v: %s", err, output)
	}
	tools["python3"] = selectedPython
	restrictedPath, cleanup, err := createProvisionToolPath(tools)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	makeRuntime := clusterProvisionRuntime{makeRoot: makeRoot, environmentPath: restrictedPath}
	probeMakefile := filepath.Join(t.TempDir(), "ok76-path-probe.mk")
	probe := "ok76-provision-path-test:\n\t@python3 -c 'import sys; print(sys.argv[1])' '$(SCRIPT_DIR)'\n\t@python3 '$(SCRIPT_DIR)/render.py' --help >/dev/null\n"
	if err := os.WriteFile(probeMakefile, []byte(probe), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(restrictedPath, "make"), "--silent", "--no-print-directory", "--file", makefile, "--file", probeMakefile, "ok76-provision-path-test")
	command.Dir = makeRoot
	command.Env = provisionEnvironment(makeRuntime)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Makefile could not resolve SCRIPT_DIR or invoke render.py through isolated PATH: %v: %s", err, output)
	}
	if strings.TrimSpace(string(output)) != makeRoot {
		t.Fatalf("Make SCRIPT_DIR mismatch: got %q, want %q", strings.TrimSpace(string(output)), makeRoot)
	}
}

func writeProvisionFixtureWheel(t *testing.T, directory string) string {
	t.Helper()
	files := map[string][]byte{
		"ok76_fixture_dep.py": []byte("VALUE = 'installed-in-venv'\n"),
		"yaml.py":             []byte("__version__ = 'ok76-yaml-fixture'\n"),
		"ok76_fixture_dep-1.0.dist-info/METADATA": []byte("Metadata-Version: 2.1\nName: ok76-fixture-dep\nVersion: 1.0\n\n"),
		"ok76_fixture_dep-1.0.dist-info/WHEEL":    []byte("Wheel-Version: 1.0\nGenerator: ok76-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
	}
	var record bytes.Buffer
	for name, content := range files {
		digest := sha256.Sum256(content)
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", name, base64.RawURLEncoding.EncodeToString(digest[:]), len(content))
	}
	recordPath := "ok76_fixture_dep-1.0.dist-info/RECORD"
	fmt.Fprintf(&record, "%s,,\n", recordPath)
	files[recordPath] = record.Bytes()
	wheel := filepath.Join(directory, "ok76_fixture_dep-1.0-py3-none-any.whl")
	file, err := os.Create(wheel)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for name, content := range files {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return wheel
}

func TestClusterProvisionNetworkAndStatusValidation(t *testing.T) {
	if err := validateProvisionNetwork(clusterProvisionNetwork{Endpoint: "192.168.100.200", PodCIDR: "10.33.0.0/16", ServiceCIDR: "10.96.16.0/20"}); err != nil {
		t.Fatal(err)
	}
	for _, network := range []clusterProvisionNetwork{
		{Endpoint: "auto", PodCIDR: "10.33.0.0/16", ServiceCIDR: "10.96.16.0/20"},
		{Endpoint: "192.168.100.200", PodCIDR: "10.0.0.0/8", ServiceCIDR: "10.96.16.0/20"},
		{Endpoint: "192.168.100.200", PodCIDR: "10.33.0.0/16", ServiceCIDR: "10.0.0.0/8"},
	} {
		if err := validateProvisionNetwork(network); err == nil {
			t.Fatalf("invalid network accepted: %#v", network)
		}
	}
	if !provisionStatusContainsOnlyScaffold("?? preview-one/a.yaml\n?? preview-one/b.yaml\n", "preview-one") {
		t.Fatal("expected generated scaffold status rejected")
	}
	if !provisionStatusContainsOnlyScaffoldAndMakefile(" M Makefile\n?? preview-one/a.yaml\n", "preview-one") {
		t.Fatal("exact reviewed Makefile change plus scaffold was rejected")
	}
	if provisionStatusContainsOnlyScaffoldAndMakefile("M  Makefile\n?? preview-one/a.yaml\n", "preview-one") {
		t.Fatal("staged Makefile change was accepted")
	}
	for _, status := range []string{" M Makefile\n", "?? other/file\n", "?? preview-oneevil/file\n", "?? preview-one/../outside\n"} {
		if provisionStatusContainsOnlyScaffold(status, "preview-one") {
			t.Fatalf("unsafe git status accepted: %q", status)
		}
	}
}

func TestClusterProvisionAllowsOnlyExactOfflineSmokeSelectorMakefileChange(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	if err := verifyProvisionCheckout(context.Background(), fixture.runtime, fixture.root, fixture.runtime.makeRevision, false, "", true); err != nil {
		t.Fatalf("exact offline smoke selector change rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "Makefile"), []byte(provisionMakefileCurrentFixture+"# unrelated Makefile change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyProvisionCheckout(context.Background(), fixture.runtime, fixture.root, fixture.runtime.makeRevision, false, "", true); err == nil || !strings.Contains(err.Error(), "offline-smoke selector") {
		t.Fatalf("unrelated Makefile change was not rejected precisely: %v", err)
	}
}

func TestProvisionMakefileHasOnlyOfflineSmokeSelectorChangeRejectsAmbiguousBaseline(t *testing.T) {
	baseline := []byte(provisionMakefileBaselineFixture + "TestClusterPlan|TestClusterCreateManifestTemplateIsMachineReadableAndNonAuthorizing\n")
	if provisionMakefileHasOnlyOfflineSmokeSelectorChange(baseline, []byte(provisionMakefileCurrentFixture)) {
		t.Fatal("ambiguous reviewed Makefile baseline accepted")
	}
}

func TestClusterProvisionHelpIsReadOnlyAndDocumented(t *testing.T) {
	var output bytes.Buffer
	if err := runContext(context.Background(), []string{"cluster", "provision", "--help"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"--workload-kubeconfig", "interactive terminal", "two", "make new", "make bootstrap", "not independent cluster-readiness verification"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("help omits %q:\n%s", expected, output.String())
		}
	}
}

func TestClusterProvisionDetectsScaffoldChangedAfterReview(t *testing.T) {
	fixture, request := newProvisionFixture(t)
	fixture.writeScaffold()
	prepared, err := prepareClusterProvision(request, fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, _, err := inspectProvisionScaffold(fixture.runtime, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "preview-one", "cluster-config.yaml"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyProvisionArtifactsUnchanged(fixture.runtime, prepared, artifacts); err == nil {
		t.Fatal("modified scaffold passed post-review integrity check")
	}
}
