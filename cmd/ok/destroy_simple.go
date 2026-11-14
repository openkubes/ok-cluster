package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// `ok destroy <name>` is the counterpart of `ok up` for Same-Plane
// Talos/KubeVirt. It acts only on the local evidence `ok up` left in its own
// checkout and runs the existing Python teardown once; that process checks
// identity and UIDs, shows the live inventory, asks for the cluster name and
// deletes. Every other destroy spelling keeps its route and confirmation.

type simpleDestroyRuntime struct {
	input    io.Reader
	terminal bool
	sources  func(ctx context.Context, name string) (clusterProvisionRuntime, error)
	execute  func(ctx context.Context, python, root string, env, args []string, stdin io.Reader, stdout, stderr io.Writer) error
}

func runSimpleDestroy(ctx context.Context, name string, arguments []string, stdout, stderr io.Writer) error {
	return runSimpleDestroyWith(ctx, name, arguments, stdout, stderr, simpleDestroyRuntime{
		input: os.Stdin, terminal: stdinIsTerminal(), sources: verifiedDestroySources, execute: executeSimpleDestroy,
	})
}

func runSimpleDestroyWith(ctx context.Context, name string, arguments []string, stdout, stderr io.Writer, rt simpleDestroyRuntime) error {
	flags := flag.NewFlagSet("ok destroy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { writeSimpleDestroyHelp(stdout) }
	management := flags.String("management", "", "management cluster kubeconfig (or set TALOS_INFRA_KUBECONFIG)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; usage: ok destroy <name> [--management <kubeconfig>]", flags.Arg(0))
	}
	if err := validateDestroyName(name); err != nil {
		return err
	}
	if !rt.terminal {
		return errors.New("ok destroy needs an interactive terminal to type the cluster name; nothing deleted")
	}
	managementPath, source := *management, "--management"
	if managementPath == "" {
		managementPath, source = os.Getenv("TALOS_INFRA_KUBECONFIG"), "TALOS_INFRA_KUBECONFIG"
	}
	if managementPath == "" {
		return errors.New("no management cluster selected\n" +
			"  ok destroy never uses KUBECONFIG or your current kubectl context.\n" +
			"  Choose it explicitly: ok destroy " + name + " --management <management-kubeconfig>\n" +
			"  or: export TALOS_INFRA_KUBECONFIG=<management-kubeconfig>")
	}
	managementPath, err := filepath.Abs(managementPath)
	if err != nil {
		return err
	}
	if info, err := os.Stat(managementPath); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("management kubeconfig %s (from %s) is not a readable file", managementPath, source)
	}
	// The provisioning runtime reads the management kubeconfig only from here.
	if err := os.Setenv("TALOS_INFRA_KUBECONFIG", managementPath); err != nil {
		return err
	}
	runtime, err := rt.sources(ctx, name)
	if runtime.cleanupToolPath != nil {
		defer runtime.cleanupToolPath()
	}
	if err != nil {
		return err
	}
	directory, err := destroyDirectory(runtime, name)
	if err != nil {
		return err
	}
	if err := requireOperatorEvidence(directory, name); err != nil {
		return err
	}
	if err := refuseOtherDestroyRoutes(name, directory); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OpenKubes ok destroy · Same-Plane Talos/KubeVirt · build %s\n", shortProvisionRevision(runtime.makeRevision))
	fmt.Fprintf(stdout, "Cluster %s (ok up evidence %s) · management kubeconfig from %s\n\n", name, directory, source)
	args := []string{filepath.Join(runtime.makeRoot, "scripts", "talos_golden_lifecycle.py"), "--teardown", "--topology", "same-plane",
		"--cluster", name, "--cluster-dir", directory, "--kubeconfig", managementPath, "--provider-kubeconfig", managementPath,
		"--ok-linux-path", runtime.okLinuxRoot, "--preserve-local", "--confirm", "cluster-name"}
	if err := rt.execute(ctx, provisionPythonExecutable(runtime), runtime.makeRoot, provisionEnvironment(runtime), args, rt.input, stdout, stderr); err != nil {
		return &destroyLifecycleError{cause: fmt.Errorf("%w\n  durable teardown state was kept; after reviewing the error, run ok destroy %s again to resume", err, name)}
	}
	// Success, cancellation and "already torn down" are reported by the
	// lifecycle itself, after its own absence checks and ledger persistence.
	return nil
}

// destroyDirectory finds the cluster's evidence in the state directory or, for
// clusters created before v1.0.1, in the checkout. Both present is ambiguous.
func destroyDirectory(runtime clusterProvisionRuntime, name string) (string, error) {
	state, legacy := filepath.Join(runtime.clustersDir, name), filepath.Join(runtime.makeRoot, name)
	_, stateErr := os.Lstat(state)
	_, legacyErr := os.Lstat(legacy)
	// A location that cannot be inspected is never treated as absent.
	switch {
	case stateErr != nil && !errors.Is(stateErr, os.ErrNotExist):
		return "", fmt.Errorf("cannot inspect %s: %w; nothing deleted", state, stateErr)
	case legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist):
		return "", fmt.Errorf("cannot inspect %s: %w; nothing deleted", legacy, legacyErr)
	case stateErr == nil && legacyErr == nil:
		return "", fmt.Errorf("both %s and %s exist for %s; ok destroy will not choose between them; nothing deleted", state, legacy, name)
	case legacyErr == nil:
		return legacy, nil
	case stateErr != nil:
		return "", fmt.Errorf("no cluster provisioned by ok up named %s in %s or %s; nothing deleted\n"+
			"  Runner or split-plane clusters: ok cluster destroy %s --help", name, runtime.clustersDir, runtime.makeRoot, name)
	}
	return state, nil
}

// verifiedDestroySources applies the same source-integrity checks as `ok up`:
// this CLI's own checkout at its build revision and the pinned clean ok-linux
// checkout. Only a cluster in the old checkout layout may be untracked there.
func verifiedDestroySources(ctx context.Context, name string) (clusterProvisionRuntime, error) {
	runtime, err := clusterProvisionRuntimeFromProcess("")
	if err != nil {
		return runtime, err
	}
	_, legacyErr := os.Lstat(filepath.Join(runtime.makeRoot, name))
	allowLegacy, legacyName := legacyErr == nil, ""
	if allowLegacy {
		legacyName = name
	}
	if err := verifyProvisionCheckout(ctx, runtime, runtime.makeRoot, runtime.makeRevision, allowLegacy, legacyName, true); err != nil {
		return runtime, fmt.Errorf("Make checkout is not the reviewed source: %w", err)
	}
	if err := verifyProvisionCheckout(ctx, runtime, runtime.okLinuxRoot, runtime.okLinuxRevision, false, "", false); err != nil {
		return runtime, fmt.Errorf("ok-linux checkout is not the reviewed source: %w", err)
	}
	return runtime, nil
}

// requireOperatorEvidence accepts only the preparation and provisioned records
// that `ok up` writes; the lifecycle re-verifies both completely.
func requireOperatorEvidence(directory, name string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no cluster provisioned by ok up named %s in %s; nothing deleted\n"+
			"  Runner or split-plane clusters: ok cluster destroy %s --help", name, filepath.Dir(directory), name)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory; nothing deleted", directory)
	}
	evidence := map[string]os.FileInfo{}
	for _, file := range []string{".same-plane-lifecycle.json", ".same-plane-provisioned.json"} {
		info, err := os.Lstat(filepath.Join(directory, file))
		if err == nil && (!info.Mode().IsRegular() || info.Size() > 600*1024) {
			return fmt.Errorf("%s/%s is not a regular evidence file; nothing deleted", directory, file)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		evidence[file] = info
	}
	if evidence[".same-plane-lifecycle.json"] == nil {
		return fmt.Errorf("%s has no ok up Same-Plane preparation record; nothing deleted\n"+
			"  ok destroy never infers ownership from a name", directory)
	}
	if evidence[".same-plane-provisioned.json"] == nil {
		return fmt.Errorf("%s has a preparation record but no provisioned UID record: bootstrap did not complete its capture\n"+
			"  nothing deleted; the cluster needs reviewed manual recovery", directory)
	}
	raw, err := os.ReadFile(filepath.Join(directory, ".same-plane-lifecycle.json"))
	if err != nil {
		return err
	}
	var preparation struct{ Format, Topology, Cluster string }
	if json.Unmarshal(raw, &preparation) != nil || preparation.Format != "ok76-same-plane-preparation/v1" ||
		preparation.Topology != "same-plane" || preparation.Cluster != name {
		return fmt.Errorf("%s/.same-plane-lifecycle.json is not an ok up Same-Plane record for %s; nothing deleted", directory, name)
	}
	return nil
}

// refuseOtherDestroyRoutes stops when `ok cluster destroy` could select a
// different directory for the same name, so one name never means two clusters.
func refuseOtherDestroyRoutes(name, directory string) error {
	others := []string{}
	if base, err := os.UserConfigDir(); err == nil {
		others = append(others, filepath.Join(base, "ok", "runs", name))
	}
	path, err := localConfigPath("")
	if err != nil {
		return err
	}
	config, err := loadLocalConfig(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot load local configuration %s: %w; nothing deleted", path, err)
	}
	if err == nil && config.ClustersDir != "" {
		others = append(others, filepath.Join(config.ClustersDir, name))
	}
	for _, other := range others {
		if filepath.Clean(other) == directory {
			continue
		}
		if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s also exists for %s; ok destroy will not choose between them; nothing deleted\n"+
				"  select one explicitly: ok cluster destroy %s --cluster-dir <reviewed directory> ...", other, name, name)
		}
	}
	return nil
}

// executeSimpleDestroy keeps Python in the terminal's foreground process
// group: it reads the cluster name itself, right before deleting.
func executeSimpleDestroy(ctx context.Context, python, root string, env, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, python, args...)
	command.Dir, command.Env = root, env
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	return command.Run()
}

func writeSimpleDestroyHelp(output io.Writer) {
	fmt.Fprint(output, `Destroy a Same-Plane Talos/KubeVirt cluster created by ok up

Usage:
  ok destroy <name> [--management <kubeconfig>]

  --management   management cluster kubeconfig (or set TALOS_INFRA_KUBECONFIG);
                 never KUBECONFIG or the current kubectl context

Only acts on the evidence ok up left in <state>/ok/clusters/<name>/ (state is
$XDG_STATE_HOME, else ~/.local/state) or, for clusters created before v1.0.1, in
this CLI's checkout (<checkout>/<name>/); both present is refused. It runs
the existing Same-Plane teardown once. Before anything is deleted it
checks API identity, original UIDs and the Golden image, shows what will be
deleted, and asks you to type the cluster name. Progress is shown in 5 stages;
success is reported only after independent absence checks and the completed
teardown ledger. A failed or interrupted run keeps its durable state and resumes
when run again. A destroyed name cannot be reused.

Other clusters:
  ok cluster destroy <name> --help   Runner, split-plane or explicit directories
`)
}
