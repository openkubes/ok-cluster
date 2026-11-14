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
func initSamePlaneConfig(ctx context.Context, resolved, lifecycleRoot, okLinux, management string, rt configInitRuntime, stdout, stderr io.Writer) error {
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
	var reader *bufio.Reader
	if rt.interactive && rt.input != nil {
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

// showLocalConfig prints the saved file (paths only) and, for Same-Plane,
// warns when the running ok is a different bundle than the one recorded.
func showLocalConfig(ctx context.Context, resolved string, stdout, stderr io.Writer, rt configInitRuntime) error {
	config, err := loadLocalConfig(resolved)
	if err != nil {
		return fmt.Errorf("cannot load local configuration %s: %w", resolved, err)
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Path   string         `json:"path"`
		Config localCLIConfig `json:"config"`
	}{resolved, config}); err != nil {
		return err
	}
	if config.Format != localConfigFormatV2 {
		return nil
	}
	executable := rt.executable
	if executable == "" {
		if executable, err = os.Executable(); err != nil {
			return nil
		}
	}
	makeRoot, _, _, err := bundleRootsForExecutable(executable)
	if err != nil {
		fmt.Fprintf(stderr, "note: this ok is not inside a release bundle; ok up uses the sources next to the ok it runs from\n")
		return nil
	}
	if makeRoot != config.LifecycleRoot {
		fmt.Fprintf(stderr, "note: this ok runs from %s, the saved sources are %s.\n"+
			"  ok up and ok destroy <name> always use the sources of the ok you run; the saved paths\n"+
			"  serve other commands. init never overwrites: move %s aside yourself, then run ok config init\n", makeRoot, config.LifecycleRoot, resolved)
	}
	return nil
}

// samePlaneManagement selects the management kubeconfig for ok up and
// ok destroy <name>: --management, then TALOS_INFRA_KUBECONFIG, then the
// reference saved by ok config init. KUBECONFIG and the current kubectl
// context are never consulted. An explicit --config is always loaded and must
// be a Same-Plane configuration, even when a flag already selects the file.
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
