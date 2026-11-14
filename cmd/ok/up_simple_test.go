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

type fakeSimpleUp struct {
	calls       int
	requestPath string
	workload    string
	openLog     func() (*os.File, error)
	writeLog    string // when set, open the log and write this, like Make would
	stdin       string // what the engine could still read for its confirmations
	err         error
}

func newFakeSimpleUp(t *testing.T) (*fakeSimpleUp, simpleUpRuntime, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg"))
	t.Setenv("HOME", filepath.Join(base, "home"))
	t.Setenv("KUBECONFIG", filepath.Join(base, "ambient-admin.yaml"))
	t.Setenv("TALOS_INFRA_KUBECONFIG", "")
	fake := &fakeSimpleUp{}
	rt := simpleUpRuntime{input: strings.NewReader(""), terminal: true,
		provision: func(_ context.Context, requestPath, workload string, stdin io.Reader, stdout, _ io.Writer, openLog func() (*os.File, error)) error {
			fake.calls++
			if rest, err := io.ReadAll(stdin); err == nil {
				fake.stdin = string(rest)
			}
			fake.requestPath, fake.workload, fake.openLog = requestPath, workload, openLog
			if fake.writeLog != "" && openLog != nil {
				file, err := openLog()
				if err != nil {
					return err
				}
				io.WriteString(file, fake.writeLog)
			}
			return fake.err
		}}
	return fake, rt, base
}

func writeSimpleUpFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeManagementKubeconfig(t *testing.T, base string) string {
	t.Helper()
	return writeSimpleUpFile(t, filepath.Join(base, "secure"), "ok-infra-operator.yaml", "apiVersion: v1\nkind: Config\n")
}

func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s must not be created: %v", path, err)
	}
}

func TestSimpleUpRoutingKeepsEveryRunnerInput(t *testing.T) {
	dir := t.TempDir()
	request := writeSimpleUpFile(t, dir, "request.yaml", validClusterRequestYAML)
	legacy := writeSimpleUpFile(t, dir, "legacy.yaml", "apiVersion: cli.openkubes.io/v1alpha1\nkind: Cluster\nmetadata:\n  name: legacy-one\n")
	jsonManifest := writeSimpleUpFile(t, dir, "full-run.json", `{"format":"full-run"}`)
	malformed := writeSimpleUpFile(t, dir, "malformed.yaml", "kind: ClusterRequest\n  bad: [indent\n")
	empty := writeSimpleUpFile(t, dir, "empty.yaml", "")
	symlink := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(request, symlink); err != nil {
		t.Fatal(err)
	}
	simple := [][]string{
		{"-f", request}, {"--file=" + request, "-v"}, {"-f", request, "--management", "/m.yaml", "--workload-kubeconfig=/w.yaml"},
		{"-f", malformed}, {"-f", empty}, {"-f", symlink}, {"-f", dir}, {"-f", filepath.Join(dir, "missing.yaml")}, {"-v"},
	}
	for _, args := range simple {
		if !simpleUpHandles(args) {
			t.Errorf("%v must use the simple UX", args)
		}
	}
	runner := [][]string{
		{"-f", legacy}, {"-f", jsonManifest}, {"-f", request, "--dry-run"}, {"--file", request, "--prepare"},
		{"-f", request, "--live", "--execute"}, {"--contract", "c.yaml", "--schema", "s.json", "--dry-run"},
		{"-f", request, "--prepared-dir", "/p"}, {"requirements"}, {"cluster-template"}, {"network-suggest"},
		{"render", "-f", request}, {"bind", "-f", request}, {"-f", request, "extra"}, {"--"},
	}
	for _, args := range runner {
		if simpleUpHandles(args) {
			t.Errorf("%v must keep the Runner route", args)
		}
	}
}

func TestSimpleUpInvalidRequestsFailClearly(t *testing.T) {
	_, _, base := newFakeSimpleUp(t)
	dir := filepath.Join(base, "inputs")
	cases := map[string]string{
		"malformed": writeSimpleUpFile(t, dir, "malformed.yaml", "kind: ClusterRequest\n  bad: [indent\n"),
		"empty":     writeSimpleUpFile(t, dir, "empty.yaml", ""),
		"wrong":     writeSimpleUpFile(t, dir, "wrong.yaml", strings.Replace(validClusterRequestYAML, "talos-kubevirt-reference", "other", 1)),
		"directory": dir,
		"missing":   filepath.Join(dir, "missing.yaml"),
	}
	symlink := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(cases["malformed"], symlink); err != nil {
		t.Fatal(err)
	}
	cases["symlink"] = symlink
	if os.Geteuid() != 0 {
		unreadable := writeSimpleUpFile(t, dir, "unreadable.yaml", validClusterRequestYAML)
		if err := os.Chmod(unreadable, 0); err != nil {
			t.Fatal(err)
		}
		cases["unreadable"] = unreadable
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			err := run([]string{"up", "-f", path}, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "expects a "+clusterRequestAPIVersion+" "+clusterRequestKind) {
				t.Fatalf("unclear error: %v", err)
			}
		})
	}
	assertNotExist(t, filepath.Join(base, "xdg"))
	legacy := writeSimpleUpFile(t, dir, "legacy.yaml", "apiVersion: cli.openkubes.io/v1alpha1\nkind: Cluster\nmetadata:\n  name: legacy-one\n")
	if err := run([]string{"up", "-f", legacy}, io.Discard, io.Discard); err != nil && strings.Contains(err.Error(), "expects a "+clusterRequestAPIVersion) {
		t.Fatalf("legacy kind: Cluster left the Runner route: %v", err)
	}
}

func TestSimpleUpHelpAndPlanCreateNothing(t *testing.T) {
	_, _, base := newFakeSimpleUp(t)
	for _, args := range [][]string{{"up"}, {"up", "--help"}, {"help", "up"}} {
		var out bytes.Buffer
		if err := run(args, &out, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		help := out.String()
		if !strings.Contains(help, "ok up -f <cluster.yaml>") || !strings.Contains(help, "--mode operator --topology same-plane") ||
			!strings.Contains(help, "may contain sensitive information") || strings.Contains(help, "masked;") {
			t.Fatalf("%v: unexpected help:\n%s", args, help)
		}
	}
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	if err := run([]string{"cluster", "plan", "--file", request}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"up", "-f", request}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("non-terminal run not refused: %v", err)
	}
	assertNotExist(t, filepath.Join(base, "xdg"))
}

func TestSimpleUpRequiresExplicitManagementCluster(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	rt.input = strings.NewReader("\n") // an empty answer at the management prompt
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), "no management cluster selected") || !strings.Contains(err.Error(), "never uses KUBECONFIG") {
		t.Fatalf("ambient KUBECONFIG was not refused: %v", err)
	}
	missing := filepath.Join(base, "missing.yaml")
	err = runSimpleUpWith(context.Background(), []string{"-f", request, "--management", missing}, io.Discard, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing management kubeconfig not named: %v", err)
	}
	if fake.calls != 0 {
		t.Fatal("provisioning started without a usable explicit management cluster")
	}
	assertNotExist(t, filepath.Join(base, "xdg"))

	fromEnv := writeManagementKubeconfig(t, base)
	t.Setenv("TALOS_INFRA_KUBECONFIG", fromEnv)
	var out bytes.Buffer
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TALOS_INFRA_KUBECONFIG") != fromEnv || !strings.Contains(out.String(), "management kubeconfig from TALOS_INFRA_KUBECONFIG") {
		t.Fatalf("environment selection not used or shown:\n%s", out.String())
	}
	fromFlag := writeSimpleUpFile(t, filepath.Join(base, "secure"), "other.yaml", "apiVersion: v1\nkind: Config\n")
	out.Reset()
	if err := runSimpleUpWith(context.Background(), []string{"-f", request, "--management", fromFlag}, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TALOS_INFRA_KUBECONFIG") != fromFlag || !strings.Contains(out.String(), "management kubeconfig from --management") {
		t.Fatal("--management did not take precedence over the environment")
	}
}

func TestSimpleUpDefaultPathsArePrivateAndNeverWidened(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	t.Setenv("TALOS_INFRA_KUBECONFIG", writeManagementKubeconfig(t, base))
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "xdg", "ok")
	if fake.workload != filepath.Join(home, "kubeconfigs", "preview-one.yaml") || fake.openLog == nil {
		t.Fatalf("unexpected defaults: %s log=%v", fake.workload, fake.openLog != nil)
	}
	for _, dir := range []string{home, filepath.Join(home, "kubeconfigs")} {
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s not created private: %v", dir, err)
		}
	}
	assertNotExist(t, filepath.Join(home, "logs")) // the fake engine never opened the log

	t.Setenv("XDG_CONFIG_HOME", "")
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.workload != filepath.Join(base, "home", ".config", "ok", "kubeconfigs", "preview-one.yaml") {
		t.Fatalf("unexpected HOME fallback %s", fake.workload)
	}

	open := filepath.Join(base, "open-xdg", "ok")
	if err := os.MkdirAll(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(open))
	calls := fake.calls
	err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt)
	if err == nil || !strings.Contains(err.Error(), "chmod 700") || fake.calls != calls {
		t.Fatalf("too-open directory accepted: %v", err)
	}
	if info, _ := os.Stat(open); info.Mode().Perm() != 0o755 {
		t.Fatal("ok up changed existing permissions")
	}

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "fresh"))
	if err := runSimpleUpWith(context.Background(), []string{"-f", request, "--workload-kubeconfig", "/private/out/preview-one.yaml", "-v"}, io.Discard, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.workload != "/private/out/preview-one.yaml" || fake.openLog != nil {
		t.Fatalf("explicit output or verbose not honoured: %s log=%v", fake.workload, fake.openLog != nil)
	}
	assertNotExist(t, filepath.Join(base, "fresh"))
}

func TestSimpleUpBareChoosesOrCreatesRequest(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	t.Setenv("TALOS_INFRA_KUBECONFIG", writeManagementKubeconfig(t, base))
	requests := filepath.Join(base, "xdg", "ok", "requests")
	up := func(input string) (string, error) {
		var out bytes.Buffer
		rt.input = strings.NewReader(input)
		err := runSimpleUpWith(context.Background(), nil, &out, io.Discard, rt)
		return out.String(), err
	}

	// No requests: Enter selects "new"; an invalid name writes nothing.
	if _, err := up("\nBad Name!\n"); err == nil || !strings.Contains(err.Error(), "not a valid cluster name") {
		t.Fatalf("invalid name accepted: %v", err)
	}
	assertNotExist(t, requests)

	// A new request is written privately from the validated template and used
	// right away; the plan and both typed confirmations stay in the engine.
	out, err := up("\ndemo-one\nprovision demo-one\n")
	created := filepath.Join(requests, "demo-one.yaml")
	if err != nil || fake.calls != 1 || fake.requestPath != created || !strings.Contains(out, "Wrote "+created) {
		t.Fatalf("new request not used: %v calls=%d path=%s\n%s", err, fake.calls, fake.requestPath, out)
	}
	if info, err := os.Stat(created); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("request not private: %v", err)
	}
	if _, err := readClusterRequest(created); err != nil {
		t.Fatalf("starter request is invalid: %v", err)
	}
	if fake.stdin != "provision demo-one\n" {
		t.Fatalf("engine lost typed input after the prompts: %q", fake.stdin)
	}

	// One request: Enter selects it.
	if out, err := up("\n"); err != nil || fake.calls != 2 || fake.requestPath != created || !strings.Contains(out, "1) demo-one.yaml") {
		t.Fatalf("single request not chosen: %v %s\n%s", err, fake.requestPath, out)
	}

	// Several requests are listed in order and chosen by number.
	other := writeSimpleUpFile(t, requests, "other.yaml", validClusterRequestYAML)
	if out, err := up("2\n"); err != nil || fake.requestPath != other || !strings.Contains(out, "2) other.yaml") {
		t.Fatalf("numbered choice: %v %s\n%s", err, fake.requestPath, out)
	}

	// Another path, including ~/ expansion.
	elsewhere := writeSimpleUpFile(t, filepath.Join(base, "home", "inputs"), "c.yaml", validClusterRequestYAML)
	if _, err := up("p\n~/inputs/c.yaml\n"); err != nil || fake.requestPath != elsewhere {
		t.Fatalf("path choice: %v %s", err, fake.requestPath)
	}

	calls := fake.calls
	for _, input := range []string{"9\n", "x\n", "p\n\n"} {
		if _, err := up(input); err == nil {
			t.Fatalf("%q accepted", input)
		}
	}
	// The profile comes from spec.profile, never from the file name.
	writeSimpleUpFile(t, requests, "talos-kubevirt.yaml", strings.Replace(validClusterRequestYAML, "talos-kubevirt-reference", "ubuntu-kubevirt", 1))
	if _, err := up("3\n"); err == nil || !strings.Contains(err.Error(), "unsupported profile") {
		t.Fatalf("unsupported profile accepted: %v", err)
	}
	if fake.calls != calls {
		t.Fatal("provisioning started after an invalid choice")
	}
}

func TestSimpleUpAsksForManagementWhenNotSelected(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	management := writeManagementKubeconfig(t, base)
	rt.input = strings.NewReader(management + "\nprovision preview-one\n")
	var out bytes.Buffer
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, &out, io.Discard, rt); err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 || os.Getenv("TALOS_INFRA_KUBECONFIG") != management || fake.stdin != "provision preview-one\n" ||
		!strings.Contains(out.String(), "KUBECONFIG is never used") || !strings.Contains(out.String(), "management kubeconfig from your input") {
		t.Fatalf("prompted management not used: calls=%d env=%s stdin=%q\n%s", fake.calls, os.Getenv("TALOS_INFRA_KUBECONFIG"), fake.stdin, out.String())
	}
	t.Setenv("TALOS_INFRA_KUBECONFIG", "") // ok up exported the first choice for its engine
	rt.input = strings.NewReader(filepath.Join(base, "absent.yaml") + "\n")
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt); err == nil ||
		!strings.Contains(err.Error(), "from your input") || fake.calls != 1 {
		t.Fatalf("absent prompted management accepted: %v", err)
	}
}

// Ctrl-C or end of input at any prompt cancels; a default is never taken and
// nothing is created or provisioned.
func TestSimpleUpCancelledInputStartsNothing(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	requests := filepath.Join(base, "xdg", "ok", "requests")
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	run := func(ctx context.Context, arguments []string, input io.Reader) error {
		rt.input = input
		return runSimpleUpWith(ctx, arguments, io.Discard, io.Discard, rt)
	}
	// End of input (Ctrl-D) at the menu, the name prompt and the management prompt.
	for _, input := range []string{"", "n\n", "n\ndemo-one"} {
		if err := run(context.Background(), nil, strings.NewReader(input)); !errors.Is(err, errPromptCancelled) {
			t.Fatalf("%q: %v", input, err)
		}
	}
	assertNotExist(t, requests)
	writeSimpleUpFile(t, requests, "existing.yaml", validClusterRequestYAML)
	if err := run(context.Background(), nil, strings.NewReader("")); !errors.Is(err, errPromptCancelled) {
		t.Fatalf("end of input selected the default request: %v", err)
	}
	if err := run(context.Background(), []string{"-f", request}, strings.NewReader("")); !errors.Is(err, errPromptCancelled) {
		t.Fatalf("end of input at the management prompt: %v", err)
	}
	// Ctrl-C while a prompt is waiting returns at once.
	ctx, cancel := context.WithCancel(context.Background())
	waiting, _ := io.Pipe()
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if err := run(ctx, nil, waiting); !errors.Is(err, errPromptCancelled) {
		t.Fatalf("Ctrl-C at the menu: %v", err)
	}
	if fake.calls != 0 || os.Getenv("TALOS_INFRA_KUBECONFIG") != "" {
		t.Fatalf("cancelled input started provisioning: calls=%d", fake.calls)
	}
}

func TestSimpleUpMakeLogIsRawPrivateAndReported(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	t.Setenv("TALOS_INFRA_KUBECONFIG", writeManagementKubeconfig(t, base))
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	fake.writeLog = "rendering\nmake: *** [bootstrap] Error 2\n"
	fake.err = errors.New("make bootstrap failed or was interrupted")
	err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt)
	logs, _ := filepath.Glob(filepath.Join(base, "xdg", "ok", "logs", "preview-one-*.log"))
	if len(logs) != 1 || err == nil || !strings.Contains(err.Error(), fake.err.Error()) || !strings.Contains(err.Error(), "tail -n 50 "+logs[0]) ||
		!strings.Contains(err.Error(), "may contain sensitive data") {
		t.Fatalf("failure does not point to the log: %v %v", err, logs)
	}
	info, _ := os.Stat(logs[0])
	dirInfo, _ := os.Stat(filepath.Dir(logs[0]))
	raw, _ := os.ReadFile(logs[0])
	if info.Mode().Perm() != 0o600 || dirInfo.Mode().Perm() != 0o700 || string(raw) != fake.writeLog {
		t.Fatalf("log not private or not raw Make output: %v %v %q", info.Mode(), dirInfo.Mode(), raw)
	}
	// A second run never overwrites the first log.
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, io.Discard, io.Discard, rt); err == nil {
		t.Fatal("expected failure")
	}
	if logs, _ = filepath.Glob(filepath.Join(base, "xdg", "ok", "logs", "preview-one-*.log")); len(logs) != 2 {
		t.Fatalf("logs overwritten: %v", logs)
	}
}

// The engine must open the log only after the first typed confirmation and
// re-check, immediately before make new, and never on a failed preflight.
func TestClusterProvisionMakeLogOpenedOnlyAfterFirstConfirmation(t *testing.T) {
	type outcome struct {
		opened, newRuns int
	}
	runCase := func(t *testing.T, input string, mutate func(*provisionFixture), openErr error) (outcome, string, error) {
		fixture, request := newProvisionFixture(t)
		fixture.makeStdout = "MAKE-OUTPUT-MARKER\n"
		if mutate != nil {
			mutate(fixture)
		}
		var result outcome
		logPath := filepath.Join(t.TempDir(), "make.log")
		fixture.runtime.openMakeLog = func() (*os.File, error) {
			result.opened++
			if fixture.makeCount["new"] != 0 {
				t.Fatal("log opened after make new started")
			}
			if openErr != nil {
				return nil, openErr
			}
			return os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
		var output bytes.Buffer
		err := runClusterProvisionWithRuntime(context.Background(), request, strings.NewReader(input), &output, io.Discard, fixture.runtime)
		result.newRuns = fixture.makeCount["new"]
		return result, output.String() + "\n--log--\n" + readFileOrEmpty(logPath), err
	}
	t.Run("cancelled at first confirmation", func(t *testing.T) {
		result, _, err := runCase(t, "no\n", nil, nil)
		if err == nil || result != (outcome{0, 0}) {
			t.Fatalf("%v %+v", err, result)
		}
	})
	t.Run("failed preflight", func(t *testing.T) {
		result, _, err := runCase(t, "provision preview-one\n", func(f *provisionFixture) { f.clusterAppearsAt = 1 }, nil)
		if err == nil || result != (outcome{0, 0}) {
			t.Fatalf("%v %+v", err, result)
		}
	})
	t.Run("log cannot be created", func(t *testing.T) {
		result, _, err := runCase(t, "provision preview-one\nbootstrap preview-one\n", nil, errors.New("disk full"))
		if err == nil || !strings.Contains(err.Error(), "Make was not started") || result != (outcome{1, 0}) {
			t.Fatalf("%v %+v", err, result)
		}
	})
	t.Run("success keeps both confirmations and routes Make to the log", func(t *testing.T) {
		result, text, err := runCase(t, "provision preview-one\nbootstrap preview-one\n", nil, nil)
		if err != nil || result != (outcome{1, 1}) {
			t.Fatalf("%v %+v\n%s", err, result, text)
		}
		terminal, log, _ := strings.Cut(text, "\n--log--\n")
		for _, expected := range []string{"Checks passed", `type exactly "provision preview-one"`, `type exactly "bootstrap preview-one"`,
			"[1/2] Generating cluster scaffold", "[2/2] Bootstrapping cluster", "Kubernetes readiness is NOT verified"} {
			if !strings.Contains(terminal, expected) {
				t.Fatalf("concise output lacks %q:\n%s", expected, terminal)
			}
		}
		if strings.Contains(terminal, "MAKE-OUTPUT-MARKER") || strings.Contains(terminal, "tool make:") || strings.Count(log, "MAKE-OUTPUT-MARKER") != 2 {
			t.Fatalf("Make output not confined to the log:\n%s", text)
		}
	})
}

func readFileOrEmpty(path string) string {
	raw, _ := os.ReadFile(path)
	return string(raw)
}

// Make output goes to the log as a plain file descriptor, like `make > log`.
// A failing log write must not kill the step (a Go pipe would SIGPIPE it).
func TestProvisionMakeOutputFileWriteFailureDoesNotKillProcess(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("/dev/full is not available on this platform")
	}
	defer full.Close()
	runtime := clusterProvisionRuntime{command: runClusterProvisionCommand, makeExecutable: "/bin/sh", makeRoot: t.TempDir(),
		environmentPath: "/usr/bin:/bin", makeLog: full}
	script := "i=0; while [ $i -lt 2000 ]; do echo output-line-$i; i=$((i+1)); done; echo done >&2; exit 0"
	var terminal bytes.Buffer
	if err := runProvisionMake(context.Background(), runtime, []string{"-c", script}, time.Minute, &terminal, &terminal); err != nil {
		t.Fatalf("log write failure changed the step result: %v", err)
	}
	if terminal.Len() != 0 {
		t.Fatalf("Make output bypassed the log: %q", terminal.String())
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
