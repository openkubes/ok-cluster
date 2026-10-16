package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/term"
)

var destroyClusterName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type destroyClusterRuntime struct {
	input       io.Reader
	interactive bool
	execute     func(context.Context, string, []string, io.Writer, io.Writer) error
}

type destroyLifecycleError struct{ cause error }

func (err *destroyLifecycleError) Error() string {
	return "teardown incomplete or interrupted; preserve durable state, no automatic retry: " + err.cause.Error()
}

func (err *destroyLifecycleError) Unwrap() error { return err.cause }

func runDestroyCluster(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runDestroyClusterWithRuntime(ctx, arguments, stdout, stderr, destroyClusterRuntime{
		input: os.Stdin, interactive: term.IsTerminal(int(os.Stdin.Fd())),
		execute: executeLifecycleTeardown,
	})
}

func runDestroyClusterWithRuntime(ctx context.Context, arguments []string, stdout, stderr io.Writer, runtime destroyClusterRuntime) error {
	if len(arguments) == 0 {
		return errors.New("usage: ok destroy cluster <name> [flags]; see --help")
	}
	name := arguments[0]
	if len(name) > 63 || !destroyClusterName.MatchString(name) || name == "default" || strings.HasPrefix(name, "kube-") {
		return errors.New("cluster name must be a non-reserved Kubernetes namespace name (lowercase, at most 63 characters)")
	}
	flags := flag.NewFlagSet("ok destroy cluster", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("lifecycle-root", "", "Trusted ok-cluster checkout (saved path, otherwise current directory)")
	clusterDir := flags.String("cluster-dir", "", "Render/evidence directory (default: <lifecycle-root>/<name>)")
	management := flags.String("management-kubeconfig", "", "Explicit management kubeconfig (required)")
	provider := flags.String("provider-kubeconfig", "", "Explicit separate provider kubeconfig (required)")
	okLinux := flags.String("ok-linux-path", "", "ok-linux checkout (default: sibling of lifecycle-root)")
	configFile := flags.String("config", "", "Local path configuration file (default: user configuration directory/ok/config.json)")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; use ok destroy cluster <name> [flags]")
	}
	explicitEmpty := false
	flags.Visit(func(f *flag.Flag) {
		if f.Value.String() == "" {
			explicitEmpty = true
		}
	})
	if explicitEmpty {
		return errors.New("explicit path flags must not be empty")
	}
	configUsed := "none (explicit flags/current directory)"
	if *configFile != "" || *root == "" || *okLinux == "" || *clusterDir == "" || *management == "" || *provider == "" {
		path, err := localConfigPath(*configFile)
		if err != nil {
			return err
		}
		config, err := loadLocalConfig(path)
		if err != nil && !(os.IsNotExist(err) && *configFile == "") {
			return fmt.Errorf("cannot load local configuration %s: %w", path, err)
		}
		if err == nil {
			configUsed = path
			for destination, value := range map[*string]string{root: config.LifecycleRoot, okLinux: config.OKLinuxPath,
				management: config.ManagementKubeconfig, provider: config.ProviderKubeconfig} {
				if *destination == "" {
					*destination = value
				}
			}
			if *clusterDir == "" {
				*clusterDir = filepath.Join(config.ClustersDir, name)
			}
		}
	}
	if *management == "" || *provider == "" {
		return errors.New("destroy requires explicit --management-kubeconfig and --provider-kubeconfig, or paths saved by ok config init; no default context is used")
	}
	if *root == "" {
		*root = "."
	}
	rootPath, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	script := filepath.Join(rootPath, "scripts", "talos_golden_lifecycle.py")
	if err := destroyRegularFile(script); err != nil {
		return fmt.Errorf("select a trusted current ok-cluster checkout with --lifecycle-root: %w", err)
	}
	if *clusterDir == "" {
		*clusterDir = filepath.Join(rootPath, name)
	}
	directory, err := filepath.Abs(*clusterDir)
	if err != nil {
		return err
	}
	if filepath.Base(directory) != name {
		return errors.New("--cluster-dir basename must match the cluster name")
	}
	managementPath, err := filepath.Abs(*management)
	if err != nil {
		return err
	}
	providerPath, err := filepath.Abs(*provider)
	if err != nil {
		return err
	}
	for _, path := range []string{managementPath, providerPath} {
		if err := destroyRegularFile(path); err != nil {
			return fmt.Errorf("explicit kubeconfig is unavailable: %w", err)
		}
	}
	if managementPath == providerPath {
		return errors.New("management and provider must be separate kubeconfigs; this command supports split-plane teardown")
	}
	if *okLinux == "" {
		*okLinux = filepath.Join(filepath.Dir(rootPath), "ok-linux")
	}
	okLinuxPath, err := filepath.Abs(*okLinux)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !runtime.interactive {
		return errors.New("destroy requires interactive terminal input; piped confirmation and --yes/--force are not supported")
	}
	_, err = fmt.Fprintf(stdout, "Permanently delete cluster %q and its VM/storage data?\nManagement kubeconfig: %s\nProvider kubeconfig:   %s\nLifecycle checkout:    %s\nProfiles checkout:     %s\nPreserve local files:  %s\nPath configuration:    %s\n\nNo credential renewal, force deletion, rollback or automatic retry.\nSeparately installed runner authorities are not removed.\nType ok to delete, or no to cancel [no]: ",
		name, managementPath, providerPath, rootPath, okLinuxPath, directory, configUsed)
	if err != nil {
		return err
	}
	answer, err := readDestroyAnswer(ctx, runtime.input)
	if err != nil {
		return fmt.Errorf("confirmation interrupted; no lifecycle command started: %w", err)
	}
	switch strings.TrimSpace(answer) {
	case "", "no":
		_, err := fmt.Fprintln(stdout, "Cancelled. No lifecycle command started.")
		return err
	case "ok":
	default:
		return errors.New("confirmation must be exactly ok or no; no lifecycle command started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	args := []string{script, "--teardown", "--cluster", name, "--cluster-dir", directory,
		"--kubeconfig", managementPath, "--provider-kubeconfig", providerPath,
		"--ok-linux-path", okLinuxPath, "--preserve-local", "--confirm", "yes"}
	if err := runtime.execute(ctx, rootPath, args, stdout, stderr); err != nil {
		return &destroyLifecycleError{cause: err}
	}
	// The lifecycle owner observes convergence and persists its outcome. Do not
	// synthesize a CLI success receipt merely from a successful child invocation.
	return nil
}

func destroyRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}
	return nil
}

func readDestroyAnswer(ctx context.Context, input io.Reader) (string, error) {
	type response struct {
		line string
		err  error
	}
	result := make(chan response, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 1025)).ReadString('\n')
		result <- response{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case answer := <-result:
		if len(answer.line) > 1024 {
			return "", errors.New("confirmation too long")
		}
		return answer.line, answer.err
	}
}

func executeLifecycleTeardown(ctx context.Context, root string, arguments []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, "python3", arguments...)
	command.Dir = root
	command.Stdout, command.Stderr = stdout, stderr
	// No inherited stdin: only the CLI's explicit confirmation can authorize the
	// invocation. Python receives --confirm yes after (and only after) that gate.
	command.Stdin = nil
	return command.Run()
}

func cliExitCode(err error) int {
	// Preserve child status only for this new delegation surface. Existing
	// commands keep their established exit status of 2 on errors.
	var destroy *destroyLifecycleError
	if !errors.As(err, &destroy) {
		return 2
	}
	var status interface{ ExitCode() int }
	if errors.As(destroy.cause, &status) && status.ExitCode() > 0 && status.ExitCode() < 256 {
		return status.ExitCode()
	}
	return 2
}

func writeDestroyHelp(output io.Writer) {
	fmt.Fprint(output, `Interactively destroy a bounded cluster through the existing lifecycle

Usage:
  ok destroy cluster <name> [flags]

Run "ok destroy cluster --help" for required inputs and confirmation rules.
`)
}

func writeDestroyClusterHelp(output io.Writer) {
	fmt.Fprint(output, `Destroy one split-plane cluster through the existing Python lifecycle

Usage:
  ok destroy cluster <name>                 # after ok config init
  ok destroy cluster <name> --management-kubeconfig <file> --provider-kubeconfig <file> [flags]

Inputs:
  --lifecycle-root          Trusted current ok-cluster checkout (default: current directory)
  --cluster-dir             Render/evidence directory (default: <lifecycle-root>/<name>)
  --management-kubeconfig   Explicit management kubeconfig; never the default context
  --provider-kubeconfig     Explicit separate provider kubeconfig
  --ok-linux-path           Profile checkout (default: sibling of lifecycle-root)
  --config                  Local path configuration file (default: OS user config directory/ok/config.json)

Run "ok config init --help" to save all five paths once. Saved paths fill omitted
flags only; explicit flags override them. Saved clustersDir determines the retained
<clustersDir>/<name> directory unless --cluster-dir is given. A malformed existing
configuration fails closed; explicit --config never falls back if missing.
With all five path flags explicit, no default configuration is read.
Create/runner commands never use this path configuration.

Confirmation:
  An interactive terminal is required. Type exactly ok to delete, or no to cancel.
  Empty input cancels; EOF, invalid answers and interruption never start teardown.
  There is no --yes or --force, and no piped confirmation.

Safety:
  Before confirmation, only local paths are checked; no lifecycle process or API is opened.
  After ok, exactly one Python --teardown invocation performs the existing durable,
  UID-bound lifecycle checks and convergence observations. Local files are always preserved.
  No credential renewal, forced finalizers, rollback or automatic retry is added.
  Separately installed runner authorities are not removed. A failed/interrupted run
  remains incomplete; do not infer success from command execution alone.

Requires Python 3 with PyYAML, kubectl, a trusted current lifecycle checkout and its
ok-linux profile dependency. The binary alone does not bundle that lifecycle runtime.
`)
}
