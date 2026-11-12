package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// `ok up` / `ok up -f <ClusterRequest>` is a thin UX layer over the existing
// operator provisioning engine (runClusterProvisionFor). It only resolves
// inputs and default paths; every safeguard stays in the provisioning engine.
// CLI v1.0 supports exactly one workflow: Same-Plane Talos/KubeVirt.

type simpleUpRuntime struct {
	input     io.Reader
	terminal  bool
	getenv    func(string) (string, bool)
	setenv    func(string, string) error
	now       func() time.Time
	provision func(ctx context.Context, requestPath, workloadKubeconfig string, stdin io.Reader, stdout, stderr io.Writer, presentation clusterProvisionPresentation) error
}

var upStdinIsTerminal = stdinIsTerminal

func defaultSimpleUpRuntime() simpleUpRuntime {
	return simpleUpRuntime{input: os.Stdin, terminal: upStdinIsTerminal(), getenv: os.LookupEnv, setenv: os.Setenv,
		now: time.Now, provision: runClusterProvisionFor}
}

func runSimpleUp(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runSimpleUpWithRuntime(ctx, arguments, stdout, stderr, defaultSimpleUpRuntime())
}

func runSimpleUpWithRuntime(ctx context.Context, arguments []string, stdout, stderr io.Writer, rt simpleUpRuntime) error {
	flags := flag.NewFlagSet("ok up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var input clusterPlanInputFlag
	flags.Var(&input, "f", "ClusterRequest YAML file")
	flags.Var(&input, "file", "ClusterRequest YAML file")
	management := flags.String("management", "", "management cluster kubeconfig (or set TALOS_INFRA_KUBECONFIG)")
	workload := flags.String("workload-kubeconfig", "", "where to write the new cluster's kubeconfig (default: <ok config>/kubeconfigs/<name>.yaml)")
	verbose := flags.Bool("verbose", false, "show technical details and stream Make output")
	flags.BoolVar(verbose, "v", false, "show technical details and stream Make output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; usage: ok up [-f cluster.yaml] [--management <kubeconfig>]", flags.Arg(0))
	}
	// Nothing is read from or written to disk before this point.
	if !rt.terminal {
		return errors.New("ok up needs an interactive terminal for its two typed confirmations.\n" +
			"  For a read-only preview run: ok cluster plan -f <cluster.yaml>")
	}
	home, err := okUpHome(rt.getenv)
	if err != nil {
		return err
	}
	requestPath := input.value
	if requestPath == "" {
		path, stop, err := discoverOrCreateClusterRequest(home, rt.input, stdout)
		if err != nil || stop {
			return err
		}
		requestPath = path
	}
	requestPath, err = filepath.Abs(requestPath)
	if err != nil {
		return err
	}
	request, err := readClusterRequest(requestPath)
	if err != nil {
		return fmt.Errorf("%s: %w", requestPath, err)
	}
	name := request.Metadata.Name

	managementPath, source := *management, "--management"
	if managementPath == "" {
		if value, ok := rt.getenv("TALOS_INFRA_KUBECONFIG"); ok && value != "" {
			managementPath, source = value, "TALOS_INFRA_KUBECONFIG"
		}
	}
	if managementPath == "" {
		return errors.New("no management cluster selected.\n" +
			"  ok up never uses KUBECONFIG or your current kubectl context for privileged access.\n" +
			"  Choose it explicitly, for example:\n" +
			"    ok up -f " + requestPath + " --management ~/.kube/ok-infra.yaml\n" +
			"  or: export TALOS_INFRA_KUBECONFIG=~/.kube/ok-infra.yaml")
	}
	if managementPath, err = filepath.Abs(managementPath); err != nil {
		return err
	}
	// The provisioning engine reads the management kubeconfig only from this
	// variable and re-verifies context, API server, CA and kube-system UID.
	if err := rt.setenv("TALOS_INFRA_KUBECONFIG", managementPath); err != nil {
		return err
	}

	workloadPath := *workload
	if workloadPath == "" {
		if err := ensurePrivateDirs(home, filepath.Join(home, "kubeconfigs")); err != nil {
			return err
		}
		workloadPath = filepath.Join(home, "kubeconfigs", name+".yaml")
	} else if workloadPath, err = filepath.Abs(workloadPath); err != nil {
		return err
	}

	logDir := filepath.Join(home, "logs")
	if err := ensurePrivateDirs(home, logDir); err != nil {
		return err
	}
	logPath, logFile, err := createPrivateLog(logDir, name, rt.now())
	if err != nil {
		return err
	}
	defer logFile.Close()
	logWriter := newSecretRedactingWriter(logFile)
	tail := &lineTail{max: 15}
	var makeOutput io.Writer = newSecretRedactingWriter(io.MultiWriter(logFile, tail))
	if *verbose {
		makeOutput = newSecretRedactingWriter(io.MultiWriter(logFile, stdout))
	}
	fmt.Fprintf(logWriter, "ok up %s at %s\nrequest: %s\nmanagement kubeconfig: %s (from %s)\nworkload kubeconfig: %s\n\n",
		shortProvisionRevision(revision), rt.now().Format(time.RFC3339), requestPath, managementPath, source, workloadPath)

	fmt.Fprintf(stdout, "OpenKubes ok up · Same-Plane Talos/KubeVirt · build %s\n", shortProvisionRevision(revision))
	fmt.Fprintf(stdout, "Request %s · management kubeconfig from %s\n", requestPath, source)
	fmt.Fprintf(stdout, "Log %s\n\n", logPath)

	presentation := clusterProvisionPresentation{concise: !*verbose, makeLog: makeOutput}
	err = rt.provision(ctx, requestPath, workloadPath, rt.input, io.MultiWriter(stdout, logWriter), stderr, presentation)
	flushRedacting(makeOutput)
	if err != nil {
		fmt.Fprintf(logWriter, "\nresult: stopped: %v\n", err)
		flushRedacting(logWriter)
		if !*verbose && tail.len() > 0 {
			fmt.Fprintln(stdout, "\nLast lines of Make output:")
			for _, line := range tail.lines() {
				fmt.Fprintf(stdout, "  %s\n", line)
			}
		}
		return fmt.Errorf("%w\n  full log: %s", err, logPath)
	}
	fmt.Fprintln(logWriter, "\nresult: make bootstrap finished; Kubernetes readiness not verified by ok up")
	flushRedacting(logWriter)
	return nil
}

// createPrivateLog creates a new 0600 log and never overwrites an earlier one,
// even when two runs start within the same second.
func createPrivateLog(directory, name string, now time.Time) (string, *os.File, error) {
	base := filepath.Join(directory, fmt.Sprintf("%s-%s", name, now.Format("20060102-150405")))
	for attempt := 1; attempt <= 100; attempt++ {
		path := base + ".log"
		if attempt > 1 {
			path = fmt.Sprintf("%s-%d.log", base, attempt)
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return path, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, fmt.Errorf("cannot create private log %s: %w", path, err)
		}
	}
	return "", nil, fmt.Errorf("cannot create a new private log in %s", directory)
}

// okUpHome is $XDG_CONFIG_HOME/ok, else $HOME/.config/ok, on every OS. On
// macOS this deliberately avoids "Application Support": paths handed to Make
// must pass the shell-safe path check, which rejects spaces.
func okUpHome(getenv func(string) (string, bool)) (string, error) {
	if value, ok := getenv("XDG_CONFIG_HOME"); ok && value != "" {
		if !filepath.IsAbs(value) {
			return "", errors.New("XDG_CONFIG_HOME must be an absolute path")
		}
		return filepath.Join(filepath.Clean(value), "ok"), nil
	}
	home, ok := getenv("HOME")
	if !ok || !filepath.IsAbs(home) {
		return "", errors.New("HOME must be an absolute path")
	}
	return filepath.Join(filepath.Clean(home), ".config", "ok"), nil
}

// ensurePrivateDirs creates missing directories with mode 0700 and refuses
// existing ones that are symlinks or group/world accessible. It never changes
// permissions of anything that already exists.
func ensurePrivateDirs(directories ...string) error {
	for _, directory := range directories {
		info, err := os.Lstat(directory)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
				return err
			}
			if err := os.Mkdir(directory, 0o700); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%s must be a private directory, not a symlink (fix: chmod 700 %s); ok up never changes existing permissions", directory, directory)
		}
	}
	return nil
}

func discoverOrCreateClusterRequest(home string, input io.Reader, stdout io.Writer) (string, bool, error) {
	directory := filepath.Join(home, "requests")
	var found []string
	if entries, err := os.ReadDir(directory); err == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
				found = append(found, filepath.Join(directory, entry.Name()))
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", true, err
	}
	sort.Strings(found)
	switch len(found) {
	case 1:
		fmt.Fprintf(stdout, "Using %s\n\n", found[0])
		return found[0], false, nil
	case 0:
	default:
		var list strings.Builder
		for _, path := range found {
			list.WriteString("\n    ok up -f " + path)
		}
		return "", true, errors.New("several cluster requests found; choose one:" + list.String())
	}
	fmt.Fprintf(stdout, "No cluster request found in %s.\nCluster name: ", directory)
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", true, errors.New("could not read the cluster name")
	}
	name := strings.TrimSpace(line)
	contents := starterClusterRequest(name)
	var request clusterRequest
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if decoder.Decode(&request) != nil || validateClusterRequest(request) != nil {
		return "", true, fmt.Errorf("%q is not a valid cluster name (use lowercase letters, digits and '-')", name)
	}
	if err := ensurePrivateDirs(home, directory); err != nil {
		return "", true, err
	}
	path := filepath.Join(directory, name+".yaml")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", true, fmt.Errorf("cannot create %s: %w", path, err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return "", true, err
	}
	if err := file.Close(); err != nil {
		return "", true, err
	}
	fmt.Fprintf(stdout, "Wrote %s (1 control plane, 1 worker, automatic network).\nReview it, then run:\n  ok up -f %s\n", path, path)
	return "", true, nil
}

func starterClusterRequest(name string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
spec:
  profile: %s
  network:
    endpoint: auto
    podCIDR: auto
    serviceCIDR: auto
`, clusterRequestAPIVersion, clusterRequestKind, name, clusterRequestProfile))
}

// isClusterRequestUp reports whether `ok up` arguments name a ClusterRequest
// file. Legacy `kind: Cluster` files and unreadable inputs stay on the Runner.
func isClusterRequestUp(arguments []string) bool {
	path := ""
	for index, argument := range arguments {
		switch {
		case (argument == "-f" || argument == "--file") && index+1 < len(arguments):
			path = arguments[index+1]
		case strings.HasPrefix(argument, "-f="):
			path = strings.TrimPrefix(argument, "-f=")
		case strings.HasPrefix(argument, "--file="):
			path = strings.TrimPrefix(argument, "--file=")
		}
	}
	if path == "" {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var header struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
	}
	if yaml.Unmarshal(raw, &header) != nil {
		return false
	}
	return header.APIVersion == clusterRequestAPIVersion && header.Kind == clusterRequestKind
}

// secretRedactingWriter masks credential values line by line before they
// reach a log or the terminal. Logs are also private (0600 in a 0700 dir).
type secretRedactingWriter struct {
	out          io.Writer
	pending      []byte
	inPrivateKey bool
}

var secretValuePattern = regexp.MustCompile(`(?i)((?:client-key-data|client-certificate-data|token|password|passwd|secret|api[-_]?key)\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)
var bearerPattern = regexp.MustCompile(`(?i)(bearer\s+)\S+`)

func newSecretRedactingWriter(out io.Writer) *secretRedactingWriter {
	return &secretRedactingWriter{out: out}
}

func (w *secretRedactingWriter) Write(data []byte) (int, error) {
	w.pending = append(w.pending, data...)
	for {
		index := bytes.IndexByte(w.pending, '\n')
		if index < 0 {
			break
		}
		if _, err := io.WriteString(w.out, w.redact(string(w.pending[:index]))+"\n"); err != nil {
			return 0, err
		}
		w.pending = w.pending[index+1:]
	}
	return len(data), nil
}

func (w *secretRedactingWriter) Flush() {
	if len(w.pending) > 0 {
		io.WriteString(w.out, w.redact(string(w.pending))+"\n")
		w.pending = nil
	}
}

func (w *secretRedactingWriter) redact(line string) string {
	if strings.Contains(line, "-----BEGIN") && strings.Contains(line, "PRIVATE KEY") {
		w.inPrivateKey = !strings.Contains(line, "-----END")
		return "[REDACTED PRIVATE KEY]"
	}
	if w.inPrivateKey {
		if strings.Contains(line, "-----END") {
			w.inPrivateKey = false
		}
		return "[REDACTED]"
	}
	line = secretValuePattern.ReplaceAllString(line, "${1}[REDACTED]")
	return bearerPattern.ReplaceAllString(line, "${1}[REDACTED]")
}

func flushRedacting(writer io.Writer) {
	if redacting, ok := writer.(*secretRedactingWriter); ok {
		redacting.Flush()
	}
}

// lineTail keeps the last max lines written, for a short failure summary.
type lineTail struct {
	max     int
	buffer  []string
	partial string
}

func (t *lineTail) Write(data []byte) (int, error) {
	parts := strings.Split(t.partial+string(data), "\n")
	t.partial = parts[len(parts)-1]
	for _, line := range parts[:len(parts)-1] {
		t.buffer = append(t.buffer, line)
		if len(t.buffer) > t.max {
			t.buffer = t.buffer[1:]
		}
	}
	return len(data), nil
}

func (t *lineTail) lines() []string {
	if t.partial != "" {
		return append(append([]string{}, t.buffer...), t.partial)
	}
	return t.buffer
}

func (t *lineTail) len() int { return len(t.lines()) }
