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
	goruntime "runtime"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"golang.org/x/term"
)

const (
	localConfigFormat    = "ok-cli-paths/v1"
	localConfigFormatV2  = "ok-cli-paths/v2"
	localConfigSamePlane = "same-plane"
)

// Local configuration selects paths, never credentials, cluster names or authority.
//
// v1 (legacy/split-plane): all five paths. Destroy and offline YAML consume
// only their relevant paths; runtime create credentials are never inferred.
// v2 (Same-Plane, written by bare ok config init): the verified bundle sources,
// the lifecycle state directory and optionally a management kubeconfig
// *reference*. ok up and ok destroy <name> may use that reference when neither
// --management nor TALOS_INFRA_KUBECONFIG is given; it never authorizes anything
// by itself (identity checks and typed confirmations are unchanged).
type localCLIConfig struct {
	Format               string `json:"format"`
	Topology             string `json:"topology,omitempty"`
	LifecycleRoot        string `json:"lifecycleRoot"`
	OKLinuxPath          string `json:"okLinuxPath"`
	ClustersDir          string `json:"clustersDir"`
	ManagementKubeconfig string `json:"managementKubeconfig,omitempty"`
	ProviderKubeconfig   string `json:"providerKubeconfig,omitempty"`
}

func localConfigPath(path string) (string, error) {
	if path != "" {
		return filepath.Abs(path)
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate local configuration; use --config: %w", err)
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("user configuration directory must be absolute; use --config")
	}
	return filepath.Join(root, "ok", "config.json"), nil
}

func privateConfigMode(info os.FileInfo) bool {
	return goruntime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
}

func loadLocalConfig(path string) (localCLIConfig, error) {
	var config localCLIConfig
	info, err := os.Lstat(path)
	if err != nil {
		return config, err
	}
	if !info.Mode().IsRegular() || !privateConfigMode(info) || info.Size() > 64*1024 {
		return config, errors.New("configuration must be a private regular file (0600 or stricter), not a symlink, at most 64 KiB")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || !privateConfigMode(parent) {
		return config, errors.New("configuration directory must be private (0700 or stricter), not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return config, errors.New("configuration changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return config, errors.New("cannot read bounded configuration")
	}
	if err := jsonstrict.Decode(raw, &config); err != nil {
		return config, errors.New("invalid configuration: reject unknown/duplicate fields, wrong types or trailing data")
	}
	// encoding/json matches struct field names case-insensitively; reject aliases.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return config, errors.New("configuration must be an object")
	}
	var required, optional []string
	switch config.Format {
	case localConfigFormat:
		required = []string{"lifecycleRoot", "okLinuxPath", "clustersDir", "managementKubeconfig", "providerKubeconfig"}
	case localConfigFormatV2:
		required, optional = []string{"topology", "lifecycleRoot", "okLinuxPath", "clustersDir"}, []string{"managementKubeconfig"}
	default:
		return config, errors.New("unsupported configuration format; expected ok-cli-paths/v1 or ok-cli-paths/v2")
	}
	allowed := map[string]bool{"format": true}
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	for key := range keys {
		if !allowed[key] {
			return config, errors.New("configuration field names must match the documented schema exactly")
		}
	}
	values := map[string]string{"lifecycleRoot": config.LifecycleRoot, "okLinuxPath": config.OKLinuxPath, "clustersDir": config.ClustersDir,
		"managementKubeconfig": config.ManagementKubeconfig, "providerKubeconfig": config.ProviderKubeconfig}
	if config.Format == localConfigFormat {
		for _, name := range required {
			if value := values[name]; !filepath.IsAbs(value) || filepath.Clean(value) != value {
				return config, errors.New("configuration requires all five paths, absolute and normalized; run ok config init")
			}
		}
		return config, nil
	}
	for _, name := range required {
		if _, present := keys[name]; !present {
			return config, errors.New("configuration is missing required fields; run ok config init")
		}
	}
	if config.Topology != localConfigSamePlane {
		return config, errors.New("ok-cli-paths/v2 supports only topology same-plane")
	}
	for _, name := range []string{"lifecycleRoot", "okLinuxPath", "clustersDir", "managementKubeconfig"} {
		_, present := keys[name]
		if value := values[name]; present && (!filepath.IsAbs(value) || filepath.Clean(value) != value) {
			return config, errors.New("configuration paths must be absolute and normalized; run ok config init")
		}
	}
	return config, nil
}

// savedSamePlaneManagement returns the management kubeconfig reference saved
// by ok config init, for ok up and ok destroy <name>. An explicit --config must
// exist and be Same-Plane; the default file may be absent. A file that exists
// but cannot be loaded always stops: there is no silent fallback.
func savedSamePlaneManagement(path string, explicit bool) (string, error) {
	config, err := loadLocalConfig(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot load local configuration %s: %w\n  fix it, or choose the management cluster with --management", path, err)
	}
	if config.Format != localConfigFormatV2 {
		if explicit {
			return "", fmt.Errorf("%s is a split-plane (%s) configuration; ok up and ok destroy <name> use only Same-Plane configurations from ok config init", path, config.Format)
		}
		return "", nil
	}
	return config.ManagementKubeconfig, nil
}

type configInitRuntime struct {
	input       io.Reader
	interactive bool
	// Same-Plane discovery; zero values select the running process.
	executable   string
	expect       *bundleExpectations
	missingTools func(context.Context) []string
}

func runConfig(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runConfigWithRuntime(ctx, arguments, stdout, stderr, configInitRuntime{input: os.Stdin, interactive: term.IsTerminal(int(os.Stdin.Fd()))})
}

func runConfigWithRuntime(ctx context.Context, arguments []string, stdout, stderr io.Writer, rt configInitRuntime) error {
	if len(arguments) == 0 || (arguments[0] != "init" && arguments[0] != "show") {
		return errors.New("use ok config init or ok config show; see ok config --help")
	}
	flags := flag.NewFlagSet("ok config "+arguments[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "Local path configuration file (default: user configuration directory/ok/config.json)")
	config := localCLIConfig{Format: localConfigFormat}
	interactive := false
	topology, management := "", ""
	if arguments[0] == "init" {
		flags.StringVar(&topology, "topology", "", "same-plane (default) or split-plane (the five-path legacy setup)")
		flags.StringVar(&management, "management", "", "Same-Plane: management cluster kubeconfig reference (contents are not read)")
		flags.BoolVar(&interactive, "interactive", false, "Split-plane: prompt for missing paths and require confirmation on a terminal")
		flags.StringVar(&config.LifecycleRoot, "lifecycle-root", "", "Trusted ok-cluster checkout (Same-Plane: explicit override, verified)")
		flags.StringVar(&config.OKLinuxPath, "ok-linux-path", "", "ok-linux profile checkout (Same-Plane: explicit override, verified)")
		flags.StringVar(&config.ClustersDir, "clusters-dir", "", "Split-plane: parent of rendered cluster/evidence directories")
		flags.StringVar(&config.ManagementKubeconfig, "management-kubeconfig", "", "Split-plane: explicit management kubeconfig path")
		flags.StringVar(&config.ProviderKubeconfig, "provider-kubeconfig", "", "Split-plane: explicit separate provider kubeconfig path")
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; see ok config --help")
	}
	set := map[string]bool{}
	explicitEmpty := ""
	flags.Visit(func(f *flag.Flag) {
		set[f.Name] = true
		if f.Value.String() == "" && explicitEmpty == "" {
			explicitEmpty = f.Name
		}
	})
	if explicitEmpty == "config" {
		return errors.New("explicit --config path must not be empty")
	}
	resolved, err := localConfigPath(*path)
	if err != nil {
		return err
	}
	if arguments[0] == "show" {
		return showLocalConfig(ctx, resolved, stdout, stderr, rt)
	}
	if _, err := os.Lstat(resolved); err == nil {
		return errors.New("configuration is create-only; existing files are never overwritten")
	} else if !os.IsNotExist(err) {
		return err
	}
	if explicitEmpty != "" {
		return errors.New("explicit path flags must not be empty")
	}
	legacy := set["interactive"] || set["clusters-dir"] || set["management-kubeconfig"] || set["provider-kubeconfig"]
	switch topology {
	case "split-plane":
		legacy = true
	case localConfigSamePlane:
		if legacy {
			return errors.New("--topology same-plane uses --management only; --clusters-dir, --management-kubeconfig, --provider-kubeconfig and --interactive belong to --topology split-plane")
		}
	case "":
		if set["lifecycle-root"] || set["ok-linux-path"] {
			legacy = true // unchanged meaning of the existing path flags
		}
	default:
		return errors.New("--topology must be same-plane or split-plane")
	}
	if legacy && set["management"] {
		return errors.New("--management is the Same-Plane reference; split-plane setup uses --management-kubeconfig and --provider-kubeconfig")
	}
	if !legacy {
		return initSamePlaneConfig(ctx, resolved, config.LifecycleRoot, config.OKLinuxPath, management, rt, stdout, stderr)
	}
	pathFlags := 0
	for name := range set {
		if name != "config" && name != "interactive" && name != "topology" {
			pathFlags++
		}
	}
	prompt := interactive || (rt.interactive && pathFlags == 0 && !set["interactive"])
	var reader *bufio.Reader
	if prompt {
		if !rt.interactive || rt.input == nil {
			return errors.New("interactive config init requires a terminal; scripts must supply all five path flags")
		}
		reader = bufio.NewReaderSize(rt.input, 4096)
		if err := promptConfigPaths(ctx, &config, reader, stderr); err != nil {
			return err
		}
	}
	for _, value := range []*string{&config.LifecycleRoot, &config.OKLinuxPath, &config.ClustersDir, &config.ManagementKubeconfig, &config.ProviderKubeconfig} {
		if *value == "" {
			return errors.New("config init requires all five path flags; see ok config init --help")
		}
		*value, err = filepath.Abs(*value)
		if err != nil {
			return err
		}
	}
	if err := destroyRegularFile(filepath.Join(config.LifecycleRoot, "scripts", "talos_golden_lifecycle.py")); err != nil {
		return fmt.Errorf("trusted lifecycle checkout unavailable: %w", err)
	}
	for _, dir := range []string{config.OKLinuxPath, config.ClustersDir} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return errors.New("ok-linux and clusters-dir must be existing directories")
		}
	}
	for _, file := range []string{config.ManagementKubeconfig, config.ProviderKubeconfig} {
		if err := destroyRegularFile(file); err != nil {
			return fmt.Errorf("explicit kubeconfig unavailable: %w", err)
		}
	}
	managementInfo, err := os.Stat(config.ManagementKubeconfig)
	if err != nil {
		return err
	}
	provider, err := os.Stat(config.ProviderKubeconfig)
	if err != nil {
		return err
	}
	if os.SameFile(managementInfo, provider) {
		return errors.New("management and provider must be separate kubeconfigs")
	}
	if prompt {
		if err := confirmConfigPaths(ctx, config, resolved, reader, stderr); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeLocalConfig(resolved, config); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Saved local paths to %s\nNo credentials copied and no cluster contacted. Review with ok config show.\nDestroy still requires interactive ok/no confirmation.\n", resolved)
	return err
}

// writeLocalConfig creates the private directory and the 0600 file; it never
// changes existing directory permissions and never overwrites a file.
func writeLocalConfig(resolved string, config localCLIConfig) error {
	if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(resolved))
	if err != nil || !parent.IsDir() || !privateConfigMode(parent) {
		return errors.New("select a private configuration directory (0700); existing directory permissions are not changed")
	}
	file, err := os.OpenFile(resolved, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("configuration is create-only; existing files are never overwritten: %w", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return err
	}
	return file.Sync()
}

func writeConfigHelp(output io.Writer) {
	fmt.Fprint(output, `Save local settings once; never stores credentials or authorizes an operation

Usage:
  ok config init [--management <kubeconfig>]          Same-Plane (ok up / ok destroy <name>)
  ok config init --topology split-plane ...           legacy five-path setup (see below)
  ok config show

All forms accept --config <file>. The default is <OS user configuration directory>/ok/config.json
(macOS: ~/Library/Application Support/ok/config.json;
Linux: $XDG_CONFIG_HOME/ok/config.json or ~/.config/ok/config.json).
An explicit --config is never replaced by another file.

Same-Plane (default):
  Finds the sources from where this ok really is (symlinks resolved, e.g. through
  ~/.local/bin/ok) and verifies them like ok up: ok-cluster at this binary's
  commit and clean, ok-linux at the pinned commit and clean, the pinned Cilium
  chart and, for release bundles, release.txt. No other checkout is searched.
  It reports missing tools (nothing is installed) and asks for the management
  kubeconfig path (Enter skips; ok up then asks). Only a reference is saved:
  the file must be a private regular file, its contents are not read and no
  cluster is contacted. No provider kubeconfig is needed for Same-Plane.
  ok up and ok destroy <name> use the saved reference only when neither
  --management nor TALOS_INFRA_KUBECONFIG is given; KUBECONFIG and the current
  kubectl context are never used. Identity checks and typed confirmations stay.
  Source developers: --topology same-plane --lifecycle-root <ok-cluster>
  --ok-linux-path <ok-linux> (verified the same way).
  Lifecycle state stays in $XDG_STATE_HOME/ok/clusters (else
  ~/.local/state/ok/clusters); requests, workload kubeconfigs and logs stay in
  $XDG_CONFIG_HOME/ok (else ~/.config/ok). This file only holds settings.

Split-plane / legacy:
  ok config init --interactive [path flags]
  ok config init --lifecycle-root <trusted-checkout> --ok-linux-path <profiles> \
    --clusters-dir <render-parent> --management-kubeconfig <file> --provider-kubeconfig <file>
  ok config init --topology split-plane              prompts for all five paths
  --interactive prompts only for missing paths, then displays all paths for an
  explicit ok/no confirmation (empty/no cancels). Enter literal paths; ~/ expands
  only in prompted answers. Without a terminal, supply all five path flags.

Init is local and create-only. It never overwrites an existing file, copies
credential contents, invokes the lifecycle or contacts an API.
Config file/directory must be private (0600/0700); symlinks are not accepted.

ok cluster destroy uses saved split-plane paths when flags are omitted. Command
flags override saved paths; --cluster-dir overrides clustersDir for one
invocation. YAML uses only saved lifecycle/ok-linux source paths. Runtime
credentials for other workflows are never inferred from config; the explicit
--runtime-inputs boundary is unchanged.
`)
}
