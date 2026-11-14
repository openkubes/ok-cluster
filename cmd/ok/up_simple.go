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
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// `ok up` / `ok up -f <ClusterRequest>` is a thin UX layer over the operator
// provisioning engine (runClusterProvisionFor). It only resolves inputs and
// default paths; every safeguard stays in the engine. CLI v1.0 supports
// exactly one workflow: Same-Plane Talos/KubeVirt.

type simpleUpRuntime struct {
	input     io.Reader
	terminal  bool
	provision func(ctx context.Context, requestPath, workloadKubeconfig string, stdin io.Reader, stdout, stderr io.Writer, openMakeLog func() (*os.File, error)) error
}

var upStdinIsTerminal = stdinIsTerminal

var errSimpleUpNeedsTerminal = errors.New("ok up needs an interactive terminal for its two typed confirmations\n" +
	"  read-only preview: ok cluster plan -f <cluster.yaml>")

func runSimpleUp(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runSimpleUpWith(ctx, arguments, stdout, stderr, simpleUpRuntime{input: os.Stdin, terminal: upStdinIsTerminal(), provision: runClusterProvisionFor})
}

func runSimpleUpWith(ctx context.Context, arguments []string, stdout, stderr io.Writer, rt simpleUpRuntime) error {
	flags := flag.NewFlagSet("ok up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var input clusterPlanInputFlag
	flags.Var(&input, "f", "ClusterRequest YAML file")
	flags.Var(&input, "file", "ClusterRequest YAML file")
	management := flags.String("management", "", "management cluster kubeconfig (or set TALOS_INFRA_KUBECONFIG)")
	workload := flags.String("workload-kubeconfig", "", "output kubeconfig (default: <ok config>/kubeconfigs/<name>.yaml)")
	verbose := flags.Bool("verbose", false, "technical details and live Make output instead of a log file")
	flags.BoolVar(verbose, "v", false, "same as --verbose")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; usage: ok up [-f cluster.yaml] [--management <kubeconfig>]", flags.Arg(0))
	}
	home, err := okUpHome()
	if err != nil {
		return err
	}
	// One buffered reader for every prompt and both engine confirmations; the
	// engine's bufio.NewReader reuses it, so no typed input is lost.
	reader := bufio.NewReaderSize(rt.input, 4096)
	requestPath := input.value
	if requestPath == "" {
		if !rt.terminal {
			return errSimpleUpNeedsTerminal
		}
		if requestPath, err = chooseClusterRequest(home, reader, stdout); err != nil {
			return err
		}
	}
	if requestPath, err = filepath.Abs(requestPath); err != nil {
		return err
	}
	request, err := readClusterRequest(requestPath)
	if err != nil {
		return fmt.Errorf("%s: %w\n  ok up -f expects a %s %s; legacy kind: Cluster manifests use the Runner",
			requestPath, err, clusterRequestAPIVersion, clusterRequestKind)
	}
	if !rt.terminal {
		return errSimpleUpNeedsTerminal
	}

	managementPath, source := *management, "--management"
	if managementPath == "" {
		managementPath, source = os.Getenv("TALOS_INFRA_KUBECONFIG"), "TALOS_INFRA_KUBECONFIG"
	}
	if managementPath == "" {
		fmt.Fprint(stdout, "Management cluster kubeconfig (path; KUBECONFIG is never used): ")
		if managementPath, err = readPromptPath(reader); err != nil {
			return err
		}
		source = "your input"
	}
	if managementPath == "" {
		return errors.New("no management cluster selected\n" +
			"  ok up never uses KUBECONFIG or your current kubectl context for privileged access.\n" +
			"  Choose it explicitly: ok up -f " + requestPath + " --management <management-kubeconfig>\n" +
			"  or: export TALOS_INFRA_KUBECONFIG=<management-kubeconfig>")
	}
	if managementPath, err = filepath.Abs(managementPath); err != nil {
		return err
	}
	// Cheap early check so a wrong path names itself and creates nothing; the
	// engine still performs the full context, API, CA and UID verification.
	if info, err := os.Stat(managementPath); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("management kubeconfig %s (from %s) is not a readable file", managementPath, source)
	}
	// The engine reads the management kubeconfig only from this variable.
	if err := os.Setenv("TALOS_INFRA_KUBECONFIG", managementPath); err != nil {
		return err
	}

	workloadPath := *workload
	if workloadPath == "" {
		// The engine's preflight requires an existing private parent directory.
		if err := ensurePrivateDirs(home, filepath.Join(home, "kubeconfigs")); err != nil {
			return err
		}
		workloadPath = filepath.Join(home, "kubeconfigs", request.Metadata.Name+".yaml")
	} else if workloadPath, err = filepath.Abs(workloadPath); err != nil {
		return err
	}

	// The log is created by the engine only after the first typed confirmation,
	// right before make new. Make writes to the file descriptor directly.
	var makeLog *os.File
	var openMakeLog func() (*os.File, error)
	if !*verbose {
		openMakeLog = func() (*os.File, error) {
			directory := filepath.Join(home, "logs")
			if err := ensurePrivateDirs(home, directory); err != nil {
				return nil, err
			}
			file, err := os.CreateTemp(directory, request.Metadata.Name+"-"+time.Now().Format("20060102-150405")+"-*.log")
			makeLog = file
			return file, err
		}
	}
	fmt.Fprintf(stdout, "OpenKubes ok up · Same-Plane Talos/KubeVirt · build %s\n", shortProvisionRevision(revision))
	fmt.Fprintf(stdout, "Request %s · management kubeconfig from %s\n\n", requestPath, source)
	err = rt.provision(ctx, requestPath, workloadPath, reader, stdout, stderr, openMakeLog)
	if makeLog == nil {
		return err
	}
	closeErr := makeLog.Close()
	if err != nil {
		err = fmt.Errorf("%w\n  Make output (raw, private, may contain sensitive data): %s\n  last lines: tail -n 50 %s", err, makeLog.Name(), makeLog.Name())
	} else {
		fmt.Fprintf(stdout, "  Make output (raw, private, may contain sensitive data): %s\n", makeLog.Name())
	}
	if closeErr != nil {
		return errors.Join(err, fmt.Errorf("Make log %s may be incomplete: %w", makeLog.Name(), closeErr))
	}
	return err
}

// simpleUpHandles reports whether `ok up <arguments>` belongs to the simple
// UX. Any subcommand, any flag the simple UX does not define, and any -f input
// that is a legacy kind: Cluster or JSON manifest keep the Runner route.
// Malformed or unreadable files stay here so they fail with a clear error.
func simpleUpHandles(arguments []string) bool {
	path := ""
	for index := 0; index < len(arguments); index++ {
		if !strings.HasPrefix(arguments[index], "-") {
			return false
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(arguments[index], "-"), "=")
		switch name {
		case "v", "verbose", "h", "help":
		case "f", "file", "management", "workload-kubeconfig":
			if !hasValue && index+1 < len(arguments) {
				index++
				value = arguments[index]
			}
			if name == "f" || name == "file" {
				path = value
			}
		default:
			return false
		}
	}
	return path == "" || !isLegacyRunnerInput(path)
}

func isLegacyRunnerInput(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return true // JSON full-run manifest
	}
	var header struct {
		Kind string `yaml:"kind"`
	}
	return yaml.Unmarshal(raw, &header) == nil && header.Kind == "Cluster"
}

// okUpHome is $XDG_CONFIG_HOME/ok, else $HOME/.config/ok, on every OS. On
// macOS this avoids "Application Support": paths handed to Make must pass the
// shell-safe path check, which rejects spaces.
func okUpHome() (string, error) {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" {
		if !filepath.IsAbs(value) {
			return "", errors.New("XDG_CONFIG_HOME must be an absolute path")
		}
		return filepath.Join(filepath.Clean(value), "ok"), nil
	}
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) {
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
		if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%s must be a private directory, not a symlink (fix: chmod 700 %s); ok up never changes existing permissions", directory, directory)
		}
	}
	return nil
}

// chooseClusterRequest lists <ok config>/requests and lets the operator pick a
// request, give another path, or create one from the validated template. The
// profile always comes from the file's spec.profile, never from its name.
func chooseClusterRequest(home string, input *bufio.Reader, stdout io.Writer) (string, error) {
	directory := filepath.Join(home, "requests")
	found, err := filepath.Glob(filepath.Join(directory, "*.y*ml"))
	if err != nil {
		return "", err
	}
	sort.Strings(found)
	fmt.Fprintf(stdout, "Cluster requests in %s:\n", directory)
	for index, path := range found {
		fmt.Fprintf(stdout, "  %d) %s\n", index+1, filepath.Base(path))
	}
	fmt.Fprint(stdout, "  n) new cluster request\n  p) path to another ClusterRequest file\n")
	choice := "n"
	if len(found) > 0 {
		choice = "1"
	}
	fmt.Fprintf(stdout, "Choose [%s]: ", choice)
	line, err := readPromptLine(input)
	if err != nil {
		return "", err
	}
	if line != "" {
		choice = line
	}
	switch choice {
	case "n":
		return createClusterRequest(home, directory, input, stdout)
	case "p":
		fmt.Fprint(stdout, "ClusterRequest file: ")
		path, err := readPromptPath(input)
		if err == nil && path == "" {
			err = errors.New("no ClusterRequest file given")
		}
		return path, err
	}
	index, err := strconv.Atoi(choice)
	if err != nil || index < 1 || index > len(found) {
		return "", fmt.Errorf("%q is not one of the listed choices", choice)
	}
	return found[index-1], nil
}

func createClusterRequest(home, directory string, input *bufio.Reader, stdout io.Writer) (string, error) {
	fmt.Fprint(stdout, "Cluster name: ")
	name, err := readPromptLine(input)
	if err != nil {
		return "", err
	}
	contents := []byte(fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\nspec:\n  profile: %s\n  network:\n    endpoint: auto\n    podCIDR: auto\n    serviceCIDR: auto\n",
		clusterRequestAPIVersion, clusterRequestKind, name, clusterRequestProfile))
	var request clusterRequest
	if yaml.Unmarshal(contents, &request) != nil || request.Metadata.Name != name || validateClusterRequest(request) != nil {
		return "", fmt.Errorf("%q is not a valid cluster name (use lowercase letters, digits and '-')", name)
	}
	if err := ensurePrivateDirs(home, directory); err != nil {
		return "", err
	}
	path := filepath.Join(directory, name+".yaml")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("cannot create %s: %w", path, err)
	}
	_, writeErr := file.Write(contents)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}
	fmt.Fprintf(stdout, "Wrote %s (1 control plane, 1 worker, automatic network).\n\n", path)
	return path, nil
}

func readPromptLine(input *bufio.Reader) (string, error) {
	line, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("could not read your input")
	}
	return strings.TrimSpace(line), nil
}

// readPromptPath accepts an absolute, relative or ~/ path; empty stays empty.
func readPromptPath(input *bufio.Reader) (string, error) {
	path, err := readPromptLine(input)
	if err != nil || !strings.HasPrefix(path, "~/") {
		return path, err
	}
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) {
		return "", errors.New("HOME must be an absolute path to expand ~/")
	}
	return filepath.Join(home, path[2:]), nil
}
