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
	"runtime"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"golang.org/x/term"
)

const localConfigFormat = "ok-cli-paths/v1"

// Local configuration selects paths, never credentials, cluster names or authority.
// Destroy and offline YAML consume only their relevant paths. Runtime create
// credential references are never inferred from this general configuration.
type localCLIConfig struct {
	Format               string `json:"format"`
	LifecycleRoot        string `json:"lifecycleRoot"`
	OKLinuxPath          string `json:"okLinuxPath"`
	ClustersDir          string `json:"clustersDir"`
	ManagementKubeconfig string `json:"managementKubeconfig"`
	ProviderKubeconfig   string `json:"providerKubeconfig"`
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
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
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
	fields := map[string]*string{"format": &config.Format, "lifecycleRoot": &config.LifecycleRoot,
		"okLinuxPath": &config.OKLinuxPath, "clustersDir": &config.ClustersDir,
		"managementKubeconfig": &config.ManagementKubeconfig, "providerKubeconfig": &config.ProviderKubeconfig}
	// encoding/json matches struct field names case-insensitively; reject aliases.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return config, errors.New("configuration must be an object")
	}
	for key := range keys {
		if fields[key] == nil {
			return config, errors.New("configuration field names must match the documented schema exactly")
		}
	}
	if config.Format != localConfigFormat {
		return config, errors.New("unsupported configuration format; expected ok-cli-paths/v1")
	}
	for name, value := range fields {
		if name != "format" && (!filepath.IsAbs(*value) || filepath.Clean(*value) != *value) {
			return config, errors.New("configuration requires all five paths, absolute and normalized; run ok config init")
		}
	}
	return config, nil
}

type configInitRuntime struct {
	input       io.Reader
	interactive bool
}

func runConfig(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runConfigWithRuntime(ctx, arguments, stdout, stderr, configInitRuntime{input: os.Stdin, interactive: term.IsTerminal(int(os.Stdin.Fd()))})
}

func runConfigWithRuntime(ctx context.Context, arguments []string, stdout, stderr io.Writer, runtime configInitRuntime) error {
	if len(arguments) == 0 || (arguments[0] != "init" && arguments[0] != "show") {
		return errors.New("use ok config init or ok config show; see ok config --help")
	}
	flags := flag.NewFlagSet("ok config "+arguments[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "Local path configuration file (default: user configuration directory/ok/config.json)")
	config := localCLIConfig{Format: localConfigFormat}
	interactive := false
	if arguments[0] == "init" {
		flags.BoolVar(&interactive, "interactive", false, "Prompt for missing paths and require confirmation on a terminal")
		flags.StringVar(&config.LifecycleRoot, "lifecycle-root", "", "Trusted ok-cluster checkout")
		flags.StringVar(&config.OKLinuxPath, "ok-linux-path", "", "ok-linux profile checkout")
		flags.StringVar(&config.ClustersDir, "clusters-dir", "", "Parent of rendered cluster/evidence directories")
		flags.StringVar(&config.ManagementKubeconfig, "management-kubeconfig", "", "Explicit management kubeconfig path")
		flags.StringVar(&config.ProviderKubeconfig, "provider-kubeconfig", "", "Explicit separate provider kubeconfig path")
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; see ok config --help")
	}
	explicitEmptyConfig := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "config" && f.Value.String() == "" {
			explicitEmptyConfig = true
		}
	})
	if explicitEmptyConfig {
		return errors.New("explicit --config path must not be empty")
	}
	resolved, err := localConfigPath(*path)
	if err != nil {
		return err
	}
	if arguments[0] == "show" {
		config, err := loadLocalConfig(resolved)
		if err != nil {
			return fmt.Errorf("cannot load local configuration %s: %w", resolved, err)
		}
		return json.NewEncoder(stdout).Encode(struct {
			Path   string         `json:"path"`
			Config localCLIConfig `json:"config"`
		}{resolved, config})
	}
	if _, err := os.Lstat(resolved); err == nil {
		return errors.New("configuration is create-only; existing files are never overwritten")
	} else if !os.IsNotExist(err) {
		return err
	}
	pathFlags := 0
	interactiveSelected := false
	explicitEmptyPath := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "interactive" {
			interactiveSelected = true
		}
		if f.Name != "config" && f.Name != "interactive" {
			pathFlags++
			if f.Value.String() == "" {
				explicitEmptyPath = true
			}
		}
	})
	if explicitEmptyPath {
		return errors.New("explicit path flags must not be empty")
	}
	prompt := interactive || (runtime.interactive && pathFlags == 0 && !interactiveSelected)
	var reader *bufio.Reader
	if prompt {
		if !runtime.interactive || runtime.input == nil {
			return errors.New("interactive config init requires a terminal; scripts must supply all five path flags")
		}
		reader = bufio.NewReaderSize(runtime.input, 4096)
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
	management, err := os.Stat(config.ManagementKubeconfig)
	if err != nil {
		return err
	}
	provider, err := os.Stat(config.ProviderKubeconfig)
	if err != nil {
		return err
	}
	if os.SameFile(management, provider) {
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
	if err := file.Sync(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Saved local paths to %s\nNo credentials copied and no cluster contacted. Review with ok config show.\nDestroy still requires interactive ok/no confirmation.\n", resolved)
	return err
}

func writeConfigHelp(output io.Writer) {
	fmt.Fprint(output, `Save local paths once; never stores credentials or authorizes an operation

Usage:
  ok config init
  ok config init --interactive [path flags]
  ok config init --lifecycle-root <trusted-checkout> --ok-linux-path <profiles> \
    --clusters-dir <render-parent> --management-kubeconfig <file> --provider-kubeconfig <file>
  ok config show

Both accept --config <file>. The default is <OS user configuration directory>/ok/config.json
(macOS: ~/Library/Application Support/ok/config.json;
Linux: $XDG_CONFIG_HOME/ok/config.json or ~/.config/ok/config.json).
Bare init on a terminal prompts for all five paths. --interactive prompts only
for missing paths, then displays all paths for an explicit ok/no confirmation
(empty/no cancels). Enter literal paths; ~/ expands only in prompted answers.
Without a terminal, supply all five path flags; --interactive rejects piped input.
Init is local and create-only. It never overwrites an
existing file, copies credential contents, invokes the lifecycle or contacts an API.
Config file/directory must be private (0600/0700); symlinks are not accepted.

Destroy uses these explicitly saved paths when flags are omitted. Command flags
override saved paths; --cluster-dir overrides clustersDir for one invocation.
YAML uses only saved lifecycle/ok-linux source paths. Runtime credentials are
never inferred from config; the explicit --runtime-inputs boundary is unchanged.
`)
}
