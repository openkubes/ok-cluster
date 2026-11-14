package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBundle is a release-bundle layout with real Git copies, so discovery
// runs the same checkout checks ok up uses (HEAD, clean tree, pins, chart).
type fakeBundle struct {
	root, okCluster, okLinux, executable string
	expect                               bundleExpectations
}

func gitTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func newFakeBundle(t *testing.T) *fakeBundle {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBundle{root: filepath.Join(base, "share", "ok-v1.0.1-rc2-test")}
	b.okCluster, b.okLinux = filepath.Join(b.root, "ok-cluster"), filepath.Join(b.root, "ok-linux")
	writeTestFile(t, filepath.Join(b.okCluster, "Makefile"), "all:\n", 0o644)
	writeTestFile(t, filepath.Join(b.okCluster, ".gitignore"), "/.tools/\n", 0o644)
	gitTest(t, b.okCluster, "init", "-q")
	gitTest(t, b.okCluster, "add", ".")
	gitTest(t, b.okCluster, "commit", "-q", "-m", "fixture")
	writeTestFile(t, filepath.Join(b.okLinux, "profiles", "kubevirt", "profile.yaml"), "profile: fixture\n", 0o644)
	gitTest(t, b.okLinux, "init", "-q")
	gitTest(t, b.okLinux, "add", ".")
	gitTest(t, b.okLinux, "commit", "-q", "-m", "fixture")
	chart := "pinned chart bytes"
	writeTestFile(t, filepath.Join(b.okCluster, ".tools", "cilium-1.19.6.tgz"), chart, 0o644)
	b.executable = filepath.Join(b.okCluster, ".tools", "bin", "ok")
	writeTestFile(t, b.executable, "#!/bin/sh\n", 0o755)
	sum := sha256.Sum256([]byte(chart))
	b.expect = bundleExpectations{revision: gitTest(t, b.okCluster, "rev-parse", "HEAD"),
		okLinux: gitTest(t, b.okLinux, "rev-parse", "HEAD"), chartSHA256: hex.EncodeToString(sum[:])}
	return b
}

func (b *fakeBundle) writeRelease(t *testing.T, binarySHA string) {
	t.Helper()
	if binarySHA == "" {
		var err error
		if binarySHA, err = fileSHA256(b.executable); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(b.root, "release.txt"), fmt.Sprintf("version: v1.0.1-rc2\nplatform: test\n"+
		"ok-cluster commit: %s   (embedded)\nok-linux commit: %s   (pinned)\nbin/ok sha256: %s\ncilium-1.19.6.tgz sha256: %s\ngo: go1.24.13\n",
		b.expect.revision, b.expect.okLinux, binarySHA, b.expect.chartSHA256), 0o644)
}

// link exposes the bundle like install-ok.sh --link: ~/.local/bin/ok -> bundle.
func (b *fakeBundle) link(t *testing.T) string {
	t.Helper()
	link := filepath.Join(os.Getenv("HOME"), ".local", "bin", "ok")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b.executable, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func (b *fakeBundle) runtime(executable, input string, interactive bool, missing ...string) configInitRuntime {
	expect := b.expect
	return configInitRuntime{input: strings.NewReader(input), interactive: interactive, executable: executable, expect: &expect,
		missingTools: func(context.Context) []string { return missing }}
}

func samePlaneHome(t *testing.T) string {
	t.Helper()
	isolatedConfigHome(t)
	home := os.Getenv("HOME")
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("TALOS_INFRA_KUBECONFIG", "")
	t.Setenv("KUBECONFIG", filepath.Join(home, "ambient-admin.yaml"))
	return home
}

func privateKubeconfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "mgmt.yaml")
	writeTestFile(t, path, "fixture only - contents must never be copied\n", 0o600)
	return path
}

func configInit(rt configInitRuntime, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := runConfigWithRuntime(context.Background(), append([]string{"init"}, args...), &stdout, &stderr, rt)
	return stdout.String(), stderr.String(), err
}

func TestSamePlaneInitDiscoversBundleThroughSymlinkWithoutProvider(t *testing.T) {
	home := samePlaneHome(t)
	b := newFakeBundle(t)
	b.writeRelease(t, "")
	link := b.link(t)
	management := privateKubeconfig(t, t.TempDir())
	path, _ := localConfigPath("")
	_, stderr, err := configInit(b.runtime(link, "", false), "--management", management)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	config, err := loadLocalConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := localCLIConfig{Format: localConfigFormatV2, Topology: localConfigSamePlane, LifecycleRoot: b.okCluster, OKLinuxPath: b.okLinux,
		ClustersDir: filepath.Join(home, ".local", "state", "ok", "clusters"), ManagementKubeconfig: management}
	if config != want {
		t.Fatalf("config %+v\nwant   %+v", config, want)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("providerKubeconfig")) || bytes.Contains(raw, []byte("fixture only")) {
		t.Fatalf("provider requested or credential contents copied:\n%s", raw)
	}
	if !strings.Contains(stderr, "release bundle (release.txt matches)") || !strings.Contains(stderr, path) {
		t.Fatalf("summary does not show bundle kind or config path:\n%s", stderr)
	}
	for name, mode := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		if info, err := os.Stat(name); err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s not private: %v", name, err)
		}
	}
	if _, err := os.Stat(want.ClustersDir); !os.IsNotExist(err) {
		t.Fatal("config init created lifecycle state; only ok up may")
	}
	// Create-only: a second init changes nothing.
	if _, _, err := configInit(b.runtime(link, "", false)); err == nil || !strings.Contains(err.Error(), "create-only") {
		t.Fatalf("repeated init: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(raw, after) {
		t.Fatal("existing configuration changed")
	}
	var shown bytes.Buffer
	if err := runConfigWithRuntime(context.Background(), []string{"show"}, &shown, io.Discard, b.runtime(link, "", false)); err != nil ||
		!strings.Contains(shown.String(), `"topology":"same-plane"`) || strings.Contains(shown.String(), "fixture only") {
		t.Fatalf("show: %v %s", err, shown.String())
	}
}

func TestSamePlaneInitAlternativePrefixAndSourceBuild(t *testing.T) {
	samePlaneHome(t)
	b := newFakeBundle(t) // no release.txt: a source checkout build
	config := filepath.Join(privateConfigTestDir(t), "custom.json")
	_, stderr, err := configInit(b.runtime(b.executable, "", false, "helm", "PyYAML (for /usr/bin/python3)"), "--config", config)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "source checkout build") || !strings.Contains(stderr, "Missing for ok up: helm, PyYAML") ||
		!strings.Contains(stderr, "nothing was installed") {
		t.Fatalf("summary:\n%s", stderr)
	}
	loaded, err := loadLocalConfig(config)
	if err != nil || loaded.ManagementKubeconfig != "" || loaded.LifecycleRoot != b.okCluster {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if raw, _ := os.ReadFile(config); bytes.Contains(raw, []byte("managementKubeconfig")) {
		t.Fatal("empty management reference written")
	}
	if path, _ := localConfigPath(""); fileExists(path) {
		t.Fatal("explicit --config also wrote the default file")
	}
}

func fileExists(path string) bool { _, err := os.Lstat(path); return err == nil }

func TestSamePlaneInitRefusesUnverifiableSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, b *fakeBundle) string // returns the executable to run
		want   string
	}{
		{"untracked file in ok-cluster", func(t *testing.T, b *fakeBundle) string {
			writeTestFile(t, filepath.Join(b.okCluster, "extra.txt"), "x", 0o644)
			return b.executable
		}, "local changes or untracked files"},
		{"modified ok-linux", func(t *testing.T, b *fakeBundle) string {
			writeTestFile(t, filepath.Join(b.okLinux, "profiles", "kubevirt", "profile.yaml"), "changed\n", 0o644)
			return b.executable
		}, "ok-linux sources"},
		{"wrong ok-linux pin", func(t *testing.T, b *fakeBundle) string {
			b.expect.okLinux = strings.Repeat("b", 40)
			return b.executable
		}, "ok-linux sources"},
		{"other revision than this ok", func(t *testing.T, b *fakeBundle) string {
			b.expect.revision = strings.Repeat("c", 40)
			return b.executable
		}, "not the reviewed source"},
		{"tampered chart", func(t *testing.T, b *fakeBundle) string {
			writeTestFile(t, filepath.Join(b.okCluster, ".tools", "cilium-1.19.6.tgz"), "tampered", 0o644)
			return b.executable
		}, "Cilium chart"},
		{"missing ok-linux", func(t *testing.T, b *fakeBundle) string {
			if err := os.Rename(b.okLinux, b.okLinux+".moved"); err != nil {
				t.Fatal(err)
			}
			return b.executable
		}, "ok-linux"},
		{"release.txt for another binary", func(t *testing.T, b *fakeBundle) string {
			b.writeRelease(t, strings.Repeat("d", 64))
			return b.executable
		}, "release.txt does not match"},
		{"ok outside a bundle", func(t *testing.T, b *fakeBundle) string {
			other := filepath.Join(t.TempDir(), "ok")
			writeTestFile(t, other, "#!/bin/sh\n", 0o755)
			return other
		}, "not inside an OpenKubes release bundle"},
		{"no full revision", func(t *testing.T, b *fakeBundle) string {
			b.expect.revision = "unknown"
			return b.executable
		}, "exact full source revision"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			samePlaneHome(t)
			b := newFakeBundle(t)
			executable := tc.break_(t, b)
			_, _, err := configInit(b.runtime(executable, "", false))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing saved") {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if path, _ := localConfigPath(""); fileExists(filepath.Dir(path)) {
				t.Fatal("a refused init created the configuration directory")
			}
		})
	}
}

func TestSamePlaneInitManagementReferenceIsMetadataOnly(t *testing.T) {
	samePlaneHome(t)
	b := newFakeBundle(t)
	dir := t.TempDir()
	good := privateKubeconfig(t, dir)
	public := filepath.Join(dir, "public.yaml")
	writeTestFile(t, public, "x", 0o644)
	symlink := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(good, symlink); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{public: "chmod 600", symlink: "not a symlink", filepath.Join(dir, "absent.yaml"): "does not exist",
		filepath.Join(dir, "bad name.yaml"): "shell-safe"} {
		if _, _, err := configInit(b.runtime(b.executable, "", false), "--management", path); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", path, want, err)
		}
	}
	// A kubeconfig without read permission for us is still only referenced.
	unreadable := filepath.Join(dir, "unreadable.yaml")
	writeTestFile(t, unreadable, "secret", 0o600)
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := configInit(b.runtime(b.executable, "", false), "--management", unreadable); err != nil {
		t.Fatalf("contents were needed: %v\n%s", err, stderr)
	}
}

func TestSamePlaneInitInteractiveConfirmation(t *testing.T) {
	for _, tc := range []struct {
		input string
		saved bool
	}{{"MGMT\nok\n", true}, {"\nok\n", true}, {"MGMT\nno\n", false}, {"MGMT\n\n", false}, {"MGMT\nyes\n", false}, {"MGMT\n", false}} {
		t.Run(strings.ReplaceAll(tc.input, "\n", "|"), func(t *testing.T) {
			samePlaneHome(t)
			b := newFakeBundle(t)
			management := privateKubeconfig(t, t.TempDir())
			_, stderr, err := configInit(b.runtime(b.executable, strings.ReplaceAll(tc.input, "MGMT", management), true))
			path, _ := localConfigPath("")
			if tc.saved {
				config, loadErr := loadLocalConfig(path)
				if err != nil || loadErr != nil {
					t.Fatalf("err=%v load=%v\n%s", err, loadErr, stderr)
				}
				if strings.HasPrefix(tc.input, "MGMT") != (config.ManagementKubeconfig == management) {
					t.Fatalf("management=%q", config.ManagementKubeconfig)
				}
			} else if err == nil || fileExists(filepath.Dir(path)) {
				t.Fatalf("unconfirmed init saved or created directories: %v", err)
			}
		})
	}
}

func TestSamePlaneInitFlagCombinations(t *testing.T) {
	samePlaneHome(t)
	b := newFakeBundle(t)
	management := privateKubeconfig(t, t.TempDir())
	for _, args := range [][]string{
		{"--topology", "same-plane", "--provider-kubeconfig", management},
		{"--topology", "same-plane", "--clusters-dir", t.TempDir()},
		{"--topology", "same-plane", "--interactive"},
		{"--topology", "split-plane", "--management", management},
		{"--management-kubeconfig", management, "--management", management},
		{"--topology", "dual-plane"},
		{"--topology", "same-plane", "--lifecycle-root", b.okCluster},
		{"--management", ""},
	} {
		if _, _, err := configInit(b.runtime(b.executable, "", false), args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	// Source developers name both sources; they are verified the same way.
	other := filepath.Join(t.TempDir(), "ok")
	writeTestFile(t, other, "#!/bin/sh\n", 0o755)
	_, stderr, err := configInit(b.runtime(other, "", false), "--topology", "same-plane", "--lifecycle-root", b.okCluster, "--ok-linux-path", b.okLinux)
	if err != nil || !strings.Contains(stderr, "explicit (--lifecycle-root/--ok-linux-path), verified") {
		t.Fatalf("explicit sources: %v\n%s", err, stderr)
	}
}

func TestSplitPlaneInitUnchanged(t *testing.T) {
	config, args := configFixture(t)
	path := filepath.Join(privateConfigTestDir(t), "legacy.json")
	if _, _, err := configInit(configInitRuntime{}, append(args[2:], "--config", path)...); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLocalConfig(path)
	if err != nil || loaded != config {
		t.Fatalf("v1 changed: %+v %v", loaded, err)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte(`"format": "ok-cli-paths/v1"`)) || bytes.Contains(raw, []byte("topology")) {
		t.Fatalf("v1 file format changed:\n%s", raw)
	}
}

func TestLocalConfigV2Schema(t *testing.T) {
	dir := privateConfigTestDir(t)
	valid := `{"format":"ok-cli-paths/v2","topology":"same-plane","lifecycleRoot":"/b/ok-cluster","okLinuxPath":"/b/ok-linux","clustersDir":"/s/ok/clusters"`
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"minimal":            {valid + `}`, true},
		"with management":    {valid + `,"managementKubeconfig":"/k/mgmt.yaml"}`, true},
		"provider forbidden": {valid + `,"providerKubeconfig":"/k/p.yaml"}`, false},
		"empty management":   {valid + `,"managementKubeconfig":""}`, false},
		"relative path":      {strings.Replace(valid, "/b/ok-linux", "b/ok-linux", 1) + `}`, false},
		"other topology":     {strings.Replace(valid, "same-plane", "split-plane", 1) + `}`, false},
		"missing state dir":  {strings.Replace(valid, `,"clustersDir":"/s/ok/clusters"`, "", 1) + `}`, false},
		"unknown field":      {valid + `,"extra":"x"}`, false},
		"v1 with topology":   {strings.Replace(valid, "v2", "v1", 1) + `,"managementKubeconfig":"/a","providerKubeconfig":"/b"}`, false},
		"unknown format":     {strings.Replace(valid, "v2", "v3", 1) + `}`, false},
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		writeTestFile(t, path, tc.body, 0o600)
		if _, err := loadLocalConfig(path); (err == nil) != tc.ok {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

func writeSamePlaneConfig(t *testing.T, path, management string) {
	t.Helper()
	if err := writeLocalConfig(path, localCLIConfig{Format: localConfigFormatV2, Topology: localConfigSamePlane, LifecycleRoot: "/b/ok-cluster",
		OKLinuxPath: "/b/ok-linux", ClustersDir: "/s/ok/clusters", ManagementKubeconfig: management}); err != nil {
		t.Fatal(err)
	}
}

func TestSamePlaneManagementPrecedenceAndNoSilentFallback(t *testing.T) {
	samePlaneHome(t)
	dir := t.TempDir()
	saved, flagFile, envFile := filepath.Join(dir, "saved.yaml"), filepath.Join(dir, "flag.yaml"), filepath.Join(dir, "env.yaml")
	defaultPath, _ := localConfigPath("")
	check := func(flagValue, configFlag, wantPath, wantSource string) {
		t.Helper()
		path, source, err := samePlaneManagement(flagValue, configFlag)
		if err != nil || path != wantPath || !strings.Contains(source, wantSource) {
			t.Fatalf("flag=%q config=%q: %q %q %v", flagValue, configFlag, path, source, err)
		}
	}
	check("", "", "", "") // no config, nothing selected
	writeSamePlaneConfig(t, defaultPath, saved)
	check("", "", saved, "saved configuration "+defaultPath)
	t.Setenv("TALOS_INFRA_KUBECONFIG", envFile)
	check("", "", envFile, "TALOS_INFRA_KUBECONFIG")
	check(flagFile, "", flagFile, "--management")

	t.Setenv("TALOS_INFRA_KUBECONFIG", "")
	missing := filepath.Join(dir, "missing.json")
	if _, _, err := samePlaneManagement(flagFile, missing); err == nil {
		t.Fatal("explicit missing --config fell back")
	}
	legacy := filepath.Join(privateConfigTestDir(t), "v1.json")
	if err := writeLocalConfig(legacy, localCLIConfig{Format: localConfigFormat, LifecycleRoot: "/a", OKLinuxPath: "/b", ClustersDir: "/c",
		ManagementKubeconfig: "/m", ProviderKubeconfig: "/p"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := samePlaneManagement("", legacy); err == nil || !strings.Contains(err.Error(), "split-plane") {
		t.Fatalf("explicit v1: %v", err)
	}
	other := filepath.Join(privateConfigTestDir(t), "other.json")
	writeSamePlaneConfig(t, other, flagFile)
	check("", other, flagFile, "saved configuration "+other)

	// A default v1 file is never used for Same-Plane; an unreadable default stops.
	if err := os.Remove(defaultPath); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalConfig(defaultPath, localCLIConfig{Format: localConfigFormat, LifecycleRoot: "/a", OKLinuxPath: "/b", ClustersDir: "/c",
		ManagementKubeconfig: "/m", ProviderKubeconfig: "/p"}); err != nil {
		t.Fatal(err)
	}
	check("", "", "", "")
	if err := os.Chmod(defaultPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := samePlaneManagement("", ""); err == nil || !strings.Contains(err.Error(), "--management") {
		t.Fatalf("invalid default config ignored: %v", err)
	}
	check(flagFile, "", flagFile, "--management") // a flag never needs the default file
}

func TestSimpleUpAndDestroyUseSavedManagementReference(t *testing.T) {
	fake, rt, base := newFakeSimpleUp(t)
	request := writeSimpleUpFile(t, filepath.Join(base, "inputs"), "cluster.yaml", validClusterRequestYAML)
	saved := writeManagementKubeconfig(t, base)
	configPath, _ := localConfigPath("")
	writeSamePlaneConfig(t, configPath, saved)
	var out bytes.Buffer
	if err := runSimpleUpWith(context.Background(), []string{"-f", request}, &out, io.Discard, rt); err != nil || fake.calls != 1 {
		t.Fatalf("%v calls=%d", err, fake.calls)
	}
	if os.Getenv("TALOS_INFRA_KUBECONFIG") != saved || !strings.Contains(out.String(), "management kubeconfig from saved configuration "+configPath) {
		t.Fatalf("saved reference not used or not shown:\n%s", out.String())
	}
	t.Setenv("TALOS_INFRA_KUBECONFIG", "")
	if err := runSimpleUpWith(context.Background(), []string{"-f", request, "--config", filepath.Join(base, "missing.json")}, io.Discard, io.Discard, rt); err == nil || fake.calls != 1 {
		t.Fatalf("explicit missing config: %v calls=%d", err, fake.calls)
	}
	if err := runSimpleUpWith(context.Background(), []string{"-f", request, "--config="}, io.Discard, io.Discard, rt); err == nil {
		t.Fatal("empty --config accepted")
	}

	f := newSimpleDestroyFixture(t)
	destroyConfig, _ := localConfigPath("")
	writeSamePlaneConfig(t, destroyConfig, f.management)
	output, err := f.run()
	if err != nil || len(f.calls) != 1 || !strings.Contains(output, "from saved configuration "+destroyConfig) ||
		os.Getenv("TALOS_INFRA_KUBECONFIG") != f.management {
		t.Fatalf("destroy did not use the saved reference: %v\n%s", err, output)
	}
	if _, err := f.run("--config", filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "nothing deleted") || len(f.calls) != 1 {
		t.Fatalf("destroy explicit missing config: %v", err)
	}
}

func TestLegacyDestroyRefusesSamePlaneConfiguration(t *testing.T) {
	samePlaneHome(t)
	path, _ := localConfigPath("")
	writeSamePlaneConfig(t, path, privateKubeconfig(t, t.TempDir()))
	var out bytes.Buffer
	err := runDestroyCluster(context.Background(), []string{"ok-v1-test"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "Same-Plane configuration") || !strings.Contains(err.Error(), "ok destroy ok-v1-test") {
		t.Fatalf("legacy destroy with v2 config: %v", err)
	}
}

func TestConfigShowWarnsWhenRunningAnotherBundle(t *testing.T) {
	samePlaneHome(t)
	b := newFakeBundle(t)
	path := filepath.Join(privateConfigTestDir(t), "config.json")
	writeSamePlaneConfig(t, path, "")
	var stdout, stderr bytes.Buffer
	if err := runConfigWithRuntime(context.Background(), []string{"show", "--config", path}, &stdout, &stderr, b.runtime(b.executable, "", false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "this ok runs from "+b.okCluster) || !strings.Contains(stderr.String(), "never overwrites") {
		t.Fatalf("no stale-bundle note:\n%s", stderr.String())
	}
}
