package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func isolatedConfigHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
}

func privateConfigTestDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func configFixture(t *testing.T) (localCLIConfig, []string) {
	t.Helper()
	root, _ := destroyFixture(t)
	profiles := filepath.Join(root, "profiles")
	clusters := filepath.Join(root, "rendered clusters")
	for _, path := range []string{profiles, clusters} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := localCLIConfig{localConfigFormat, root, profiles, clusters, filepath.Join(root, "management.yaml"), filepath.Join(root, "provider.yaml")}
	return config, []string{"config", "init", "--lifecycle-root", root, "--ok-linux-path", profiles,
		"--clusters-dir", clusters, "--management-kubeconfig", config.ManagementKubeconfig,
		"--provider-kubeconfig", config.ProviderKubeconfig}
}

func TestLocalConfigHelpNeverReadsConfiguration(t *testing.T) {
	isolatedConfigHome(t)
	for _, args := range [][]string{{"config"}, {"config", "--help"}, {"help", "config"},
		{"help", "config", "init"}, {"help", "config", "show"}, {"config", "init", "--help"},
		{"config", "show", "--help"}, {"destroy", "cluster", "demo", "--config", "/absent", "--help"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("args=%v err=%v stdout=%s stderr=%s", args, err, &stdout, &stderr)
		}
	}
}

func TestLocalConfigInitAndShowArePrivateCreateOnlyAndPathOnly(t *testing.T) {
	config, args := configFixture(t)
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	path, _ := localConfigPath("")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLocalConfig(path)
	if err != nil || loaded != config {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if runtime.GOOS != "windows" {
		for name, mode := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
			info, err := os.Stat(name)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("private permissions: %s %v", name, err)
			}
		}
	}
	if err := run(args, &stdout, &stderr); err == nil {
		t.Fatal("init overwrote existing configuration")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte("fixture only")) {
		t.Fatal("existing config changed or credential contents copied")
	}
	// Show only reads saved paths, not credential or lifecycle contents.
	if err := os.Remove(config.ManagementKubeconfig); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run([]string{"config", "show"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "managementKubeconfig") {
		t.Fatalf("show err=%v stdout=%s", err, &stdout)
	}
}

func TestLocalConfigInitRejectsIncompleteOrUnsafePaths(t *testing.T) {
	config, args := configFixture(t)
	for _, extra := range [][]string{{"--ok-linux-path", "/nonexistent"},
		{"--clusters-dir", config.ManagementKubeconfig},
		{"--management-kubeconfig", "/missing"},
		{"--provider-kubeconfig", config.ManagementKubeconfig},
		{"--config", ""},
		{"--force"}, {"extra"}} {
		var stdout, stderr bytes.Buffer
		if err := run(append(append([]string{}, args...), extra...), &stdout, &stderr); err == nil {
			t.Fatalf("accepted %v", extra)
		}
	}
	for _, args := range [][]string{{"config", "init"}, {"config", "unknown"}, {"config", "show"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	path, _ := localConfigPath("")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid initialization created a config")
	}
}

func TestLocalConfigStrictSchemaAndPermissions(t *testing.T) {
	config, _ := configFixture(t)
	raw, _ := json.Marshal(config)
	for _, bad := range []string{"[]", "null", "{", string(raw) + "{}",
		strings.Replace(string(raw), localConfigFormat, "future/v2", 1),
		strings.Replace(string(raw), `"format":`, `"unknown":`, 1),
		strings.Replace(string(raw), `"format":`, `"Format":`, 1),
		strings.Replace(string(raw), `"format":`, `"format":"ok-cli-paths/v1","format":`, 1),
		`{"format":"ok-cli-paths/v1"}`,
		strings.Replace(string(raw), config.ClustersDir, "relative/path", 1),
		strings.Repeat(" ", 64*1024+1)} {
		path := filepath.Join(privateConfigTestDir(t), "config.json")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadLocalConfig(path); err == nil {
			t.Fatalf("accepted bad config %.80s", bad)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions and symlink checks")
	}
	path := filepath.Join(privateConfigTestDir(t), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLocalConfig(path); err == nil {
		t.Fatal("accepted non-private config")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(privateConfigTestDir(t), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLocalConfig(link); err == nil {
		t.Fatal("accepted config symlink")
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLocalConfig(path); err == nil {
		t.Fatal("accepted non-private config directory")
	}
}

func TestDestroyLocalConfigResolvesPathsAndKeepsConfirmation(t *testing.T) {
	config, args := configFixture(t)
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	calls := 0
	execute := func(_ context.Context, dir string, argv []string, _, _ io.Writer) error {
		calls++
		expected := []string{filepath.Join(config.LifecycleRoot, "scripts", "talos_golden_lifecycle.py"),
			"--teardown", "--cluster", "demo", "--cluster-dir", filepath.Join(config.ClustersDir, "demo"),
			"--kubeconfig", config.ManagementKubeconfig, "--provider-kubeconfig", config.ProviderKubeconfig,
			"--ok-linux-path", config.OKLinuxPath, "--preserve-local", "--confirm", "yes"}
		if dir != config.LifecycleRoot || !reflect.DeepEqual(argv, expected) {
			t.Fatalf("dir=%s argv=%v", dir, argv)
		}
		if !strings.Contains(stdout.String(), "Path configuration:") || !strings.Contains(stdout.String(), config.ProviderKubeconfig) {
			t.Fatal("selected paths not displayed before invocation")
		}
		return nil
	}
	for _, answer := range []string{"no\n", "ok\n"} {
		if err := runDestroyClusterWithRuntime(context.Background(), []string{"demo"}, &stdout, &stderr,
			destroyClusterRuntime{strings.NewReader(answer), true, execute}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	stdout.Reset()
	if err := runDestroyClusterWithRuntime(context.Background(), []string{"demo"}, &stdout, &stderr,
		destroyClusterRuntime{strings.NewReader("ok\n"), false, execute}); err == nil || stdout.Len() != 0 || calls != 1 {
		t.Fatal("saved config bypassed terminal gate")
	}
}

func TestDestroyLocalConfigOverridesAndExplicitMissingFailClosed(t *testing.T) {
	config, args := configFixture(t)
	path := filepath.Join(privateConfigTestDir(t), "custom.json")
	var stdout, stderr bytes.Buffer
	if err := run(append(args, "--config", path), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	overrideRoot, _ := destroyFixture(t)
	overrideProfiles := filepath.Join(overrideRoot, "profiles")
	if err := os.Mkdir(overrideProfiles, 0o700); err != nil {
		t.Fatal(err)
	}
	flags := []string{"demo", "--config", path, "--cluster-dir", filepath.Join(config.LifecycleRoot, "demo"),
		"--management-kubeconfig", config.ProviderKubeconfig, "--provider-kubeconfig", config.ManagementKubeconfig,
		"--lifecycle-root", overrideRoot, "--ok-linux-path", overrideProfiles}
	err := runDestroyClusterWithRuntime(context.Background(), flags, &stdout, &stderr,
		destroyClusterRuntime{strings.NewReader("ok\n"), true, func(_ context.Context, dir string, argv []string, _, _ io.Writer) error {
			if dir != overrideRoot || argv[0] != filepath.Join(overrideRoot, "scripts", "talos_golden_lifecycle.py") || argv[11] != overrideProfiles || argv[7] != config.ProviderKubeconfig || argv[9] != config.ManagementKubeconfig || argv[5] != filepath.Join(config.LifecycleRoot, "demo") {
				t.Fatalf("overrides ignored: %v", argv)
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{{"demo", "--config", path + ".missing"}, {"demo", "--config", ""}, {"demo", "--config", path, "--provider-kubeconfig", ""}} {
		stdout.Reset()
		err := runDestroyClusterWithRuntime(context.Background(), flags, &stdout, &stderr, destroyClusterRuntime{input: strings.NewReader("ok\n"), interactive: true})
		if err == nil || stdout.Len() != 0 {
			t.Fatalf("invalid config accepted: %v %v", flags, err)
		}
	}
}

func TestDestroyFullyExplicitPathsIgnoreDefaultConfig(t *testing.T) {
	config, args := configFixture(t)
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	path, _ := localConfigPath("")
	if err := os.WriteFile(path, []byte("invalid ambient configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"demo", "--lifecycle-root", config.LifecycleRoot, "--ok-linux-path", config.OKLinuxPath,
		"--cluster-dir", filepath.Join(config.ClustersDir, "demo"), "--management-kubeconfig", config.ManagementKubeconfig, "--provider-kubeconfig", config.ProviderKubeconfig}
	if err := runDestroyClusterWithRuntime(context.Background(), flags, &stdout, &stderr, destroyClusterRuntime{input: strings.NewReader("no\n"), interactive: true}); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runDestroyClusterWithRuntime(context.Background(), []string{"demo"}, &stdout, &stderr, destroyClusterRuntime{input: strings.NewReader("ok\n"), interactive: true}); err == nil || stdout.Len() != 0 {
		t.Fatal("malformed config fell back to implicit defaults")
	}
}
