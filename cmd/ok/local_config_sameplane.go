package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// initSamePlaneConfig is bare `ok config init`: it verifies the bundle this ok
// belongs to, reports missing tools, optionally records a management
// kubeconfig reference and writes ok-cli-paths/v2. It never contacts a
// cluster, reads kubeconfig contents, installs anything or overwrites a file.
func initSamePlaneConfig(ctx context.Context, resolved, lifecycleRoot, okLinux, management string, yes bool, rt configInitRuntime, stdout, stderr io.Writer) error {
	expect := runningBundleExpectations()
	if rt.expect != nil {
		expect = *rt.expect
	}
	var bundle verifiedBundle
	var err error
	sourceLabel := "found from this ok's location"
	if lifecycleRoot != "" || okLinux != "" {
		if lifecycleRoot == "" || okLinux == "" {
			return errors.New("explicit Same-Plane sources need both --lifecycle-root and --ok-linux-path")
		}
		var roots [2]string
		for index, value := range []string{lifecycleRoot, okLinux} {
			if roots[index], err = filepath.Abs(value); err == nil {
				roots[index], err = filepath.EvalSymlinks(roots[index])
			}
			if err != nil {
				return fmt.Errorf("explicit source %s is unavailable: %w", value, err)
			}
		}
		bundle, err = verifyBundleSources(ctx, roots[0], roots[1], expect)
		sourceLabel = "explicit (--lifecycle-root/--ok-linux-path), verified"
	} else {
		executable := rt.executable
		if executable == "" {
			if executable, err = os.Executable(); err != nil {
				return errors.New("cannot identify this ok binary")
			}
		}
		bundle, err = discoverRunningBundle(ctx, executable, expect)
	}
	if err != nil {
		return fmt.Errorf("%w\n  nothing saved. Install a verified bundle (install-ok.sh), or for a source checkout pass\n  --topology same-plane --lifecycle-root <ok-cluster> --ok-linux-path <ok-linux>", err)
	}
	clustersDir, err := okClustersDir()
	if err != nil {
		return err
	}
	// A terminal shows the summary and requires a typed ok. Without one,
	// nothing is saved unless --yes was given; --yes skips prompts only.
	var reader *bufio.Reader
	if rt.interactive && rt.input != nil && !yes {
		reader = bufio.NewReaderSize(rt.input, 4096)
	}
	if management == "" && reader != nil {
		fmt.Fprint(stderr, "Management cluster kubeconfig (path; Enter to skip, ok up will ask): ")
		line, err := readConfigPromptLine(ctx, reader)
		if err != nil {
			return err
		}
		if management, err = expandPromptPath(strings.TrimSpace(line)); err != nil {
			return err
		}
	}
	if management != "" {
		if management, err = checkManagementReference(management); err != nil {
			return fmt.Errorf("%w; nothing saved", err)
		}
	}
	missing := rt.missingTools
	if missing == nil {
		missing = missingRuntimeTools
	}
	absent := missing(ctx)

	kind := "source checkout build"
	if bundle.release {
		kind = "release bundle (release.txt matches)"
	}
	managementLine := "not saved - ok up asks, or pass --management"
	if management != "" {
		managementLine = management + " (reference only; contents not read)"
	}
	fmt.Fprintf(stderr, "\nOpenKubes ok config init · Same-Plane Talos/KubeVirt\n"+
		"  ok:            %s %s, %s\n"+
		"  Sources:       %s\n"+
		"  ok-cluster:    %s (at this ok's commit, clean)\n"+
		"  ok-linux:      %s (pinned %s, clean)\n"+
		"  Cilium chart:  verified (pinned SHA-256)\n"+
		"  Cluster state: %s (created by ok up)\n"+
		"  Management:    %s\n"+
		"  Config file:   %s\n",
		version, shortProvisionRevision(expect.revision), kind, sourceLabel, bundle.lifecycleRoot,
		bundle.okLinuxPath, shortProvisionRevision(expect.okLinux), clustersDir, managementLine, resolved)
	if len(absent) > 0 {
		fmt.Fprintf(stderr, "  Missing for ok up: %s\n  (nothing was installed; install them before ok up)\n", strings.Join(absent, ", "))
	}
	if reader == nil && !yes {
		return errors.New("configuration not saved: no terminal to confirm it\n  review the summary above, then run again with --yes (and --management <kubeconfig> if wanted)")
	}
	if reader != nil {
		fmt.Fprint(stderr, "Save this configuration? Type ok or no [no]: ")
		line, err := readConfigPromptLine(ctx, reader)
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) != "ok" {
			return errors.New("configuration not saved (default is no)")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	config := localCLIConfig{Format: localConfigFormatV2, Topology: localConfigSamePlane, LifecycleRoot: bundle.lifecycleRoot,
		OKLinuxPath: bundle.okLinuxPath, ClustersDir: clustersDir, ManagementKubeconfig: management}
	if err := writeLocalConfig(resolved, config); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Saved %s\nNo credentials copied and no cluster contacted. Review with ok config show.\n"+
		"Next: ok up   (it re-verifies everything and asks you to confirm twice)\n", resolved)
	return err
}

// runningBundleStatus is the live check of the ok being run, with the same
// rules as ok up. It is never stored and never re-verifies saved paths.
type runningBundleStatus struct {
	unidentified bool
	err          error
	bundle       verifiedBundle
	expect       bundleExpectations
}

func checkRunningBundle(ctx context.Context, rt configInitRuntime) runningBundleStatus {
	status := runningBundleStatus{expect: runningBundleExpectations()}
	if rt.expect != nil {
		status.expect = *rt.expect
	}
	executable := rt.executable
	if executable == "" {
		var err error
		if executable, err = os.Executable(); err != nil {
			status.unidentified = true
			return status
		}
	}
	status.bundle, status.err = discoverRunningBundle(ctx, executable, status.expect)
	return status
}

func (status runningBundleStatus) kind() string {
	if status.bundle.release {
		return "release bundle, release.txt matches"
	}
	return "source checkout build"
}

// showLocalConfig is read-only: it loads the saved settings (paths only; no
// kubeconfig is opened and no cluster contacted) and, for Same-Plane, checks
// the running ok's bundle live. Text is the default; --output json keeps the
// RC2 contract (JSON object on stdout, diagnostics on stderr).
func showLocalConfig(ctx context.Context, resolved string, asJSON bool, stdout, stderr io.Writer, rt configInitRuntime) error {
	config, err := loadLocalConfig(resolved)
	if err != nil {
		return fmt.Errorf("cannot load local configuration %s: %w", resolved, err)
	}
	var status runningBundleStatus
	if config.Format == localConfigFormatV2 {
		status = checkRunningBundle(ctx, rt)
	}
	if asJSON {
		return showLocalConfigJSON(resolved, config, status, stdout, stderr)
	}
	return showLocalConfigText(resolved, config, status, stdout)
}

// showLocalConfigJSON reproduces the RC2 output byte for byte.
func showLocalConfigJSON(resolved string, config localCLIConfig, status runningBundleStatus, stdout, stderr io.Writer) error {
	if err := json.NewEncoder(stdout).Encode(struct {
		Path   string         `json:"path"`
		Config localCLIConfig `json:"config"`
	}{resolved, config}); err != nil {
		return err
	}
	if config.Format != localConfigFormatV2 {
		return nil
	}
	switch {
	case status.unidentified:
		fmt.Fprintln(stderr, "running ok: cannot identify this binary; not verified")
	case status.err != nil:
		fmt.Fprintf(stderr, "running ok: NOT verified: %v\n  ok up and ok destroy <name> will refuse to run from it\n", status.err)
	default:
		fmt.Fprintf(stderr, "running ok: verified (%s): ok-cluster %s at %s, clean; ok-linux %s at %s, clean; Cilium chart pinned\n",
			status.kind(), status.bundle.lifecycleRoot, shortProvisionRevision(status.expect.revision), status.bundle.okLinuxPath, shortProvisionRevision(status.expect.okLinux))
		if status.bundle.lifecycleRoot != config.LifecycleRoot {
			fmt.Fprintf(stderr, "note: the saved sources are %s, not the running bundle.\n"+
				"  ok up and ok destroy <name> always use the sources of the ok you run; the saved paths\n"+
				"  serve other commands. init never overwrites: move %s aside yourself, then run ok config init\n", config.LifecycleRoot, resolved)
		}
	}
	return nil
}

func showLocalConfigText(resolved string, config localCLIConfig, status runningBundleStatus, stdout io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "OpenKubes ok config show\n  Config file:   %s\n", resolved)
	if config.Format != localConfigFormatV2 {
		fmt.Fprintf(&b, "\nSaved settings (%s, split-plane / legacy):\n"+
			"  ok-cluster:    %s\n  ok-linux:      %s\n  Clusters dir:  %s\n"+
			"  Management:    %s (reference only; contents not read)\n  Provider:      %s (reference only; contents not read)\n"+
			"\nUsed by ok cluster destroy and the offline YAML commands.\n"+
			"ok up and ok destroy <name> do not use these kubeconfigs; for Same-Plane, write a\n"+
			"separate file with ok config init --config <file> (init never overwrites).\n"+
			"\nNothing was changed, no kubeconfig was opened and no cluster was contacted.\n",
			config.Format, config.LifecycleRoot, config.OKLinuxPath, config.ClustersDir, config.ManagementKubeconfig, config.ProviderKubeconfig)
		_, err := io.WriteString(stdout, b.String())
		return err
	}
	management := "not saved - ok up asks, or pass --management"
	if config.ManagementKubeconfig != "" {
		management = config.ManagementKubeconfig + " (reference only; contents not read)"
	}
	fmt.Fprintf(&b, "\nSaved settings (%s, Same-Plane):\n"+
		"  ok-cluster:    %s\n  ok-linux:      %s\n  Cluster state: %s\n  Management:    %s\n",
		config.Format, config.LifecycleRoot, config.OKLinuxPath, config.ClustersDir, management)
	b.WriteString("\nRunning ok (checked now, not saved):\n")
	switch {
	case status.unidentified:
		b.WriteString("  Bundle:        NOT VERIFIED - cannot identify this binary\n")
	case status.err != nil:
		fmt.Fprintf(&b, "  ok:            %s %s\n  Bundle:        NOT VERIFIED\n  Reason:        %v\n"+
			"  ok up and ok destroy <name> will refuse to run from this ok.\n",
			version, shortProvisionRevision(status.expect.revision), status.err)
	default:
		fmt.Fprintf(&b, "  ok:            %s %s\n  Bundle:        verified (%s)\n"+
			"  ok-cluster:    %s (at this ok's commit, clean)\n  ok-linux:      %s (pinned %s, clean)\n  Cilium chart:  verified (pinned SHA-256)\n",
			version, shortProvisionRevision(status.expect.revision), status.kind(), status.bundle.lifecycleRoot,
			status.bundle.okLinuxPath, shortProvisionRevision(status.expect.okLinux))
		if status.bundle.lifecycleRoot != config.LifecycleRoot {
			fmt.Fprintf(&b, "\nWarning: the saved sources (%s) are not the running bundle.\n"+
				"  ok up and ok destroy <name> always use the sources of the ok you run; the saved\n"+
				"  paths serve other commands. init never overwrites: move %s aside yourself,\n"+
				"  then run ok config init.\n", config.LifecycleRoot, resolved)
		}
	}
	b.WriteString("\nNothing was changed, no kubeconfig was opened and no cluster was contacted.\n")
	_, err := io.WriteString(stdout, b.String())
	return err
}

func samePlaneManagement(flagValue, configFlag string) (path, source string, err error) {
	explicit := configFlag != ""
	env := os.Getenv("TALOS_INFRA_KUBECONFIG")
	if !explicit && flagValue != "" {
		return flagValue, "--management", nil
	}
	if !explicit && env != "" {
		return env, "TALOS_INFRA_KUBECONFIG", nil
	}
	configPath, err := localConfigPath(configFlag)
	if err != nil {
		return "", "", err
	}
	saved, err := savedSamePlaneManagement(configPath, explicit)
	if err != nil {
		return "", "", err
	}
	switch {
	case flagValue != "":
		return flagValue, "--management", nil
	case env != "":
		return env, "TALOS_INFRA_KUBECONFIG", nil
	case saved != "":
		return saved, "saved configuration " + configPath, nil
	}
	return "", "", nil
}

func rejectExplicitEmptyConfig(flags *flag.FlagSet) error {
	var err error
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "config" && f.Value.String() == "" {
			err = errors.New("explicit --config path must not be empty")
		}
	})
	return err
}

func expandPromptPath(value string) (string, error) {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("control characters are not accepted in prompted paths; configuration not saved")
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(value, "~"), "/")), nil
	}
	return value, nil
}
