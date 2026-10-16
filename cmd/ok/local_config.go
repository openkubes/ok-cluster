package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const localConfigFormat = "ok-cli-paths/v1"

// Local configuration selects paths, never credentials, cluster names or authority.
// Only destroy consumes it; create remains bound to its reviewed manifest.
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

func runConfig(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 || (arguments[0] != "init" && arguments[0] != "show") {
		return errors.New("use ok config init or ok config show; see ok config --help")
	}
	flags := flag.NewFlagSet("ok config "+arguments[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "Local path configuration file (default: user configuration directory/ok/config.json)")
	config := localCLIConfig{Format: localConfigFormat}
	if arguments[0] == "init" {
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
  ok config init --lifecycle-root <trusted-checkout> --ok-linux-path <profiles> \
    --clusters-dir <render-parent> --management-kubeconfig <file> --provider-kubeconfig <file>
  ok config show

Both accept --config <file>. The default is <OS user configuration directory>/ok/config.json
(macOS: ~/Library/Application Support/ok/config.json;
Linux: $XDG_CONFIG_HOME/ok/config.json or ~/.config/ok/config.json).
Init is local, create-only, and requires all five paths. It never overwrites an
existing file, copies credential contents, invokes the lifecycle or contacts an API.
Config file/directory must be private (0600/0700); symlinks are not accepted.

Destroy uses these explicitly saved paths when flags are omitted. Command flags
override saved paths; --cluster-dir overrides clustersDir for one invocation.
Create and expert runner commands do not read this configuration.
`)
}
