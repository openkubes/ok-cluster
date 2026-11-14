package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type simpleDestroyFixture struct {
	root, state, management string
	rt                      simpleDestroyRuntime
	calls                   [][]string
	stdin                   []io.Reader
	sourced, cleaned        int
}

func newSimpleDestroyFixture(t *testing.T) *simpleDestroyFixture {
	t.Helper()
	isolatedConfigHome(t)
	t.Setenv("TALOS_INFRA_KUBECONFIG", "")
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "never-used.yaml"))
	base := t.TempDir()
	f := &simpleDestroyFixture{root: filepath.Join(base, "ok-cluster"), state: filepath.Join(base, "state", "ok", "clusters")}
	directory := filepath.Join(f.root, "ok-v1-test")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, contents string) {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(directory, ".same-plane-lifecycle.json"),
		`{"format":"ok76-same-plane-preparation/v1","topology":"same-plane","cluster":"ok-v1-test"}`)
	write(filepath.Join(directory, ".same-plane-provisioned.json"), `{}`)
	f.management = filepath.Join(t.TempDir(), "infra.yaml")
	write(f.management, "# fixture only\n")
	input := strings.NewReader("typed by the operator\n")
	f.rt = simpleDestroyRuntime{
		input: input, terminal: true,
		sources: func(ctx context.Context, name string) (clusterProvisionRuntime, error) {
			f.sourced++
			return clusterProvisionRuntime{makeRoot: f.root, clustersDir: f.state, okLinuxRoot: "/src/ok-linux", makeRevision: strings.Repeat("a", 40),
				environmentPath: "/tmp/tools", managementKubeconfig: os.Getenv("TALOS_INFRA_KUBECONFIG"),
				cleanupToolPath: func() { f.cleaned++ }}, nil
		},
		execute: func(ctx context.Context, python, root string, env, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
			f.calls = append(f.calls, append([]string{python, root}, args...))
			f.stdin = append(f.stdin, stdin)
			return nil
		},
	}
	return f
}

func (f *simpleDestroyFixture) run(arguments ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	err := runSimpleDestroyWith(context.Background(), "ok-v1-test", arguments, &stdout, &stderr, f.rt)
	return stdout.String() + stderr.String(), err
}

func TestSimpleDestroyRunsExistingSamePlaneTeardownOnce(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	t.Setenv("TALOS_INFRA_KUBECONFIG", filepath.Join(t.TempDir(), "env-loses-to-flag.yaml"))
	output, err := f.run("--management", f.management)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(f.root, "ok-v1-test")
	expected := [][]string{{"/tmp/tools/python3", f.root, filepath.Join(f.root, "scripts", "talos_golden_lifecycle.py"),
		"--teardown", "--topology", "same-plane", "--cluster", "ok-v1-test", "--cluster-dir", directory,
		"--kubeconfig", f.management, "--provider-kubeconfig", f.management, "--ok-linux-path", "/src/ok-linux",
		"--preserve-local", "--confirm", "cluster-name"}}
	if !reflect.DeepEqual(f.calls, expected) {
		t.Fatalf("lifecycle calls:\n%q\nwant\n%q", f.calls, expected)
	}
	if f.stdin[0] != f.rt.input || f.cleaned != 1 || os.Getenv("TALOS_INFRA_KUBECONFIG") != f.management {
		t.Fatalf("stdin=%v cleaned=%d env=%s", f.stdin[0], f.cleaned, os.Getenv("TALOS_INFRA_KUBECONFIG"))
	}
	for _, want := range []string{"ok destroy · Same-Plane", "ok up evidence " + directory, "from --management"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output lacks %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "destroyed") || strings.Contains(output, "complete") {
		t.Fatalf("CLI must leave success reporting to the lifecycle:\n%s", output)
	}
}

func TestSimpleDestroyManagementIsExplicit(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "never uses KUBECONFIG") {
		t.Fatalf("missing management: %v", err)
	}
	if _, err := f.run("--management", filepath.Join(t.TempDir(), "absent.yaml")); err == nil || !strings.Contains(err.Error(), "not a readable file") {
		t.Fatalf("absent management: %v", err)
	}
	if f.sourced != 0 || len(f.calls) != 0 {
		t.Fatalf("checks after a bad management selection: sourced=%d calls=%d", f.sourced, len(f.calls))
	}
	t.Setenv("TALOS_INFRA_KUBECONFIG", f.management)
	output, err := f.run()
	if err != nil || !strings.Contains(output, "from TALOS_INFRA_KUBECONFIG") || len(f.calls) != 1 {
		t.Fatalf("env management: %v %d\n%s", err, len(f.calls), output)
	}
}

func TestSimpleDestroyRefusesBeforeAnyCheckWithoutTerminal(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	f.rt.terminal = false
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("non-terminal: %v", err)
	}
	if f.sourced != 0 || len(f.calls) != 0 {
		t.Fatal("non-terminal run reached source checks or the lifecycle")
	}
}

func TestSimpleDestroyRequiresOperatorEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(t *testing.T, directory string)
	}{
		{"no directory", "no cluster provisioned by ok up", func(t *testing.T, d string) { os.RemoveAll(d) }},
		{"symlinked directory", "not a real directory", func(t *testing.T, d string) {
			target := t.TempDir()
			os.RemoveAll(d)
			if err := os.Symlink(target, d); err != nil {
				t.Fatal(err)
			}
		}},
		{"no preparation", "no ok up Same-Plane preparation", func(t *testing.T, d string) { os.Remove(filepath.Join(d, ".same-plane-lifecycle.json")) }},
		{"no provisioned UIDs", "no provisioned UID record", func(t *testing.T, d string) { os.Remove(filepath.Join(d, ".same-plane-provisioned.json")) }},
		{"symlinked evidence", "not a regular evidence file", func(t *testing.T, d string) {
			path := filepath.Join(d, ".same-plane-provisioned.json")
			os.Remove(path)
			if err := os.Symlink(filepath.Join(t.TempDir(), "x"), path); err != nil {
				t.Fatal(err)
			}
		}},
		{"other cluster's preparation", "not an ok up Same-Plane record", func(t *testing.T, d string) {
			os.WriteFile(filepath.Join(d, ".same-plane-lifecycle.json"), []byte(`{"format":"ok76-same-plane-preparation/v1","topology":"same-plane","cluster":"ok-ai"}`), 0o600)
		}},
		{"split-plane preparation", "not an ok up Same-Plane record", func(t *testing.T, d string) {
			os.WriteFile(filepath.Join(d, ".same-plane-lifecycle.json"), []byte(`{"format":"ok76-same-plane-preparation/v1","topology":"split-plane","cluster":"ok-v1-test"}`), 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSimpleDestroyFixture(t)
			tc.mutate(t, filepath.Join(f.root, "ok-v1-test"))
			_, err := f.run("--management", f.management)
			if err == nil || !strings.Contains(err.Error(), tc.want) || len(f.calls) != 0 {
				t.Fatalf("err=%v calls=%d", err, len(f.calls))
			}
		})
	}
}

func TestSimpleDestroyRefusesSameNameOnOtherDestroyRoutes(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	runs := filepath.Join(base, "ok", "runs", "ok-v1-test")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), runs) {
		t.Fatalf("managed run conflict: %v", err)
	}
	os.RemoveAll(filepath.Join(base, "ok", "runs"))
	writeConfig := func(clustersDir string) {
		raw := `{"format":"` + localConfigFormat + `","lifecycleRoot":"/src/ok-cluster","okLinuxPath":"/src/ok-linux",` +
			`"managementKubeconfig":"/k/m.yaml","providerKubeconfig":"/k/p.yaml","clustersDir":"` + clustersDir + `"}`
		if err := os.WriteFile(filepath.Join(base, "ok", "config.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(base, "ok"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, "ok-v1-test"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeConfig(other)
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), "will not choose") {
		t.Fatalf("clustersDir conflict: %v", err)
	}
	writeConfig(f.root) // the saved clusters directory is this checkout: one directory, no conflict
	if _, err := f.run("--management", f.management); err != nil {
		t.Fatalf("same directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "ok", "config.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), "cannot load local configuration") {
		t.Fatalf("malformed configuration: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("lifecycle calls = %d, want only the unambiguous run", len(f.calls))
	}
}

func TestSimpleDestroySourceFailureStopsAndCleansUp(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	f.rt.sources = func(ctx context.Context, name string) (clusterProvisionRuntime, error) {
		return clusterProvisionRuntime{cleanupToolPath: func() { f.cleaned++ }}, errors.New("checkout revision does not match its required full commit")
	}
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("source failure: %v", err)
	}
	if f.cleaned != 1 || len(f.calls) != 0 {
		t.Fatalf("cleaned=%d calls=%d", f.cleaned, len(f.calls))
	}
}

type exitStatus int

func (e exitStatus) Error() string { return "exit status" }
func (e exitStatus) ExitCode() int { return int(e) }

func TestSimpleDestroyFailureKeepsChildStatusAndNoRetry(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	f.rt.execute = func(ctx context.Context, python, root string, env, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
		f.calls = append(f.calls, args)
		return exitStatus(7)
	}
	_, err := f.run("--management", f.management)
	if err == nil || cliExitCode(err) != 7 || len(f.calls) != 1 ||
		!strings.Contains(err.Error(), "no automatic retry") || !strings.Contains(err.Error(), "ok destroy ok-v1-test again") {
		t.Fatalf("err=%v code=%d calls=%d", err, cliExitCode(err), len(f.calls))
	}
}

func TestDestroyRoutingKeepsExistingSpellings(t *testing.T) {
	if got := canonicalProductArguments([]string{"destroy", "cluster", "ok-v1-test"}); !reflect.DeepEqual(got, []string{"cluster", "destroy", "ok-v1-test"}) {
		t.Fatalf("destroy cluster alias changed: %q", got)
	}
	if got := canonicalProductArguments([]string{"destroy", "ok-v1-test"}); !reflect.DeepEqual(got, []string{"destroy", "ok-v1-test"}) {
		t.Fatalf("ok destroy <name> rewritten: %q", got)
	}
	isolatedConfigHome(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"destroy", "ok-v1-test"}, "interactive terminal to type the cluster name"}, // the new route (tests have no terminal)
		{[]string{"destroy", "cluster", "ok-v1-test"}, "--management-kubeconfig and --provider-kubeconfig"},
		{[]string{"cluster", "destroy", "ok-v1-test"}, "--management-kubeconfig and --provider-kubeconfig"},
		{[]string{"destroy", "--yes"}, "unknown command"},
	} {
		var stdout, stderr bytes.Buffer
		err := run(tc.args, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error()+stderr.String(), tc.want) {
			t.Fatalf("%q: %v %s", tc.args, err, &stderr)
		}
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"destroy", "ok-v1-test", "--help"}, &stdout, &stderr); err != nil ||
		!strings.Contains(stdout.String(), "ok destroy <name> [--management <kubeconfig>]") {
		t.Fatalf("help: %v %s %s", err, &stdout, &stderr)
	}
}

// v1.0.1 clusters live in the state directory; pre-v1.0.1 clusters stay in
// the checkout and remain destroyable. Both, or neither, deletes nothing.
func TestSimpleDestroyFindsStateOrLegacyClusterAndRefusesBoth(t *testing.T) {
	f := newSimpleDestroyFixture(t)
	legacy, state := filepath.Join(f.root, "ok-v1-test"), filepath.Join(f.state, "ok-v1-test")
	if _, err := f.run("--management", f.management); err != nil || !strings.Contains(strings.Join(f.calls[0], " "), "--cluster-dir "+legacy) {
		t.Fatalf("legacy layout: %v %q", err, f.calls)
	}
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(legacy, state); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run("--management", f.management); err != nil || !strings.Contains(strings.Join(f.calls[1], " "), "--cluster-dir "+state) {
		t.Fatalf("state layout: %v %q", err, f.calls)
	}
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), "will not choose") || len(f.calls) != 2 {
		t.Fatalf("both layouts: %v calls=%d", err, len(f.calls))
	}
	os.RemoveAll(legacy)
	os.RemoveAll(state)
	if _, err := f.run("--management", f.management); err == nil || !strings.Contains(err.Error(), f.state) || !strings.Contains(err.Error(), f.root) {
		t.Fatalf("missing cluster must name both locations: %v", err)
	}
}

// An uninspectable state location never falls back to the legacy checkout.
func TestSimpleDestroyUninspectableStateFailsClosed(t *testing.T) {
	f := newSimpleDestroyFixture(t) // the legacy cluster exists in the checkout
	if err := os.MkdirAll(filepath.Dir(f.state), 0o700); err != nil {
		t.Fatal(err)
	}
	// A file where the clusters directory should be: Lstat fails with ENOTDIR
	// (not ErrNotExist), also when the tests run as root.
	if err := os.WriteFile(f.state, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.run("--management", f.management)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect "+filepath.Join(f.state, "ok-v1-test")) || len(f.calls) != 0 {
		t.Fatalf("legacy chosen despite uninspectable state: %v calls=%d", err, len(f.calls))
	}
}
