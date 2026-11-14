package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func showConfig(t *testing.T, rt configInitRuntime, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := runConfigWithRuntime(context.Background(), append([]string{"show"}, args...), &stdout, &stderr, rt)
	return stdout.String(), stderr.String(), err
}

// samePlaneShowFixture: a verified release bundle and a v2 file that records it,
// with a management kubeconfig whose contents must never appear or be needed.
func samePlaneShowFixture(t *testing.T) (*fakeBundle, string, string) {
	t.Helper()
	samePlaneHome(t)
	b := newFakeBundle(t)
	b.writeRelease(t, "")
	management := privateKubeconfig(t, t.TempDir())
	path := filepath.Join(privateConfigTestDir(t), "config.json")
	if err := writeLocalConfig(path, localCLIConfig{Format: localConfigFormatV2, Topology: localConfigSamePlane, LifecycleRoot: b.okCluster,
		OKLinuxPath: b.okLinux, ClustersDir: "/s/ok/clusters", ManagementKubeconfig: management}); err != nil {
		t.Fatal(err)
	}
	return b, path, management
}

func TestConfigShowTextSamePlaneVerified(t *testing.T) {
	b, path, management := samePlaneShowFixture(t)
	if err := os.Chmod(management, 0o000); err != nil { // contents are never opened
		t.Fatal(err)
	}
	stdout, stderr, err := showConfig(t, b.runtime(b.executable, "", false), "--config", path)
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	for _, want := range []string{
		"OpenKubes ok config show", "Config file:   " + path,
		"Saved settings (ok-cli-paths/v2, Same-Plane):", "ok-cluster:    " + b.okCluster, "Cluster state: /s/ok/clusters",
		"Management:    " + management + " (reference only; contents not read)",
		"Running ok (checked now, not saved):", "Bundle:        verified (release bundle, release.txt matches)",
		"Cilium chart:  verified", "Nothing was changed, no kubeconfig was opened and no cluster was contacted.",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("missing %q in:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "fixture only") || strings.Contains(stdout, "Warning") || strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Fatalf("unexpected content:\n%s", stdout)
	}
}

func TestConfigShowTextWarnsAndReportsUnverified(t *testing.T) {
	b, path, _ := samePlaneShowFixture(t)
	other := newFakeBundle(t) // running ok is a different, verified bundle
	stdout, _, err := showConfig(t, other.runtime(other.executable, "", false), "--config", path)
	if err != nil || !strings.Contains(stdout, "Bundle:        verified") ||
		!strings.Contains(stdout, "Warning: the saved sources ("+b.okCluster+") are not the running bundle.") ||
		!strings.Contains(stdout, "always use the sources of the ok you run") {
		t.Fatalf("no stale-sources warning: %v\n%s", err, stdout)
	}
	writeTestFile(t, filepath.Join(b.okCluster, ".tools", "cilium-1.19.6.tgz"), "tampered", 0o644)
	stdout, _, err = showConfig(t, b.runtime(b.executable, "", false), "--config", path)
	if err != nil || !strings.Contains(stdout, "Bundle:        NOT VERIFIED") || !strings.Contains(stdout, "Reason:") ||
		!strings.Contains(stdout, "will refuse to run from this ok") || strings.Contains(stdout, "verified (") {
		t.Fatalf("tampered bundle not clearly reported: %v\n%s", err, stdout)
	}
}

// --output json and -o json reproduce the RC2 contract exactly: one JSON
// object {path, config} on stdout, diagnostics on stderr.
func TestConfigShowJSONKeepsRC2Contract(t *testing.T) {
	b, path, _ := samePlaneShowFixture(t)
	rt := b.runtime(b.executable, "", false)
	outLong, errLong, err := showConfig(t, rt, "--config", path, "--output", "json")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--config", path, "-o", "json"}, {"--config", path, "--output=json"}, {"-o=json", "--config", path}} {
		out, errOut, err := showConfig(t, rt, args...)
		if err != nil || out != outLong || errOut != errLong {
			t.Fatalf("%v differs from --output json: %v\n%s\n%s", args, err, out, errOut)
		}
	}
	config, err := loadLocalConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(struct {
		Path   string         `json:"path"`
		Config localCLIConfig `json:"config"`
	}{path, config})
	if outLong != string(want)+"\n" {
		t.Fatalf("JSON stdout changed:\n%s\nwant\n%s", outLong, want)
	}
	if !strings.HasPrefix(errLong, "running ok: verified (release bundle, release.txt matches): ok-cluster "+b.okCluster+" at ") ||
		strings.Count(errLong, "\n") != 1 {
		t.Fatalf("JSON diagnostics changed:\n%s", errLong)
	}
	writeTestFile(t, filepath.Join(b.okCluster, ".tools", "cilium-1.19.6.tgz"), "tampered", 0o644)
	if _, errOut, _ := showConfig(t, rt, "--config", path, "-o", "json"); !strings.HasPrefix(errOut, "running ok: NOT verified: ") {
		t.Fatalf("JSON unverified diagnostic changed:\n%s", errOut)
	}
}

func TestConfigShowSplitPlaneV1(t *testing.T) {
	config, _ := configFixture(t)
	path := filepath.Join(privateConfigTestDir(t), "legacy.json")
	if err := writeLocalConfig(path, config); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := showConfig(t, configInitRuntime{}, "--config", path)
	if err != nil || stderr != "" || !strings.Contains(stdout, "Saved settings (ok-cli-paths/v1, split-plane / legacy):") ||
		!strings.Contains(stdout, "Provider:      "+config.ProviderKubeconfig+" (reference only; contents not read)") ||
		!strings.Contains(stdout, "ok up and ok destroy <name> do not use these kubeconfigs") || strings.Contains(stdout, "Running ok") {
		t.Fatalf("v1 text: %v %q\n%s", err, stderr, stdout)
	}
	out, errOut, err := showConfig(t, configInitRuntime{}, "--config", path, "-o", "json")
	var decoded struct {
		Path   string         `json:"path"`
		Config localCLIConfig `json:"config"`
	}
	if err != nil || errOut != "" || json.Unmarshal([]byte(out), &decoded) != nil || decoded.Config != config || decoded.Path != path {
		t.Fatalf("v1 JSON: %v %q %s", err, errOut, out)
	}
}

func TestConfigShowFailsSafelyAndIsReadOnly(t *testing.T) {
	b, path, _ := samePlaneShowFixture(t)
	rt := b.runtime(b.executable, "", false)
	dir := filepath.Dir(path)
	before, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--config", path}, {"--config", path, "-o", "json"}} {
		if _, _, err := showConfig(t, rt, args...); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.ReadFile(path)
	if now, _ := os.Stat(path); !bytes.Equal(before, after) || !now.ModTime().Equal(past) || now.Mode() != info.Mode() {
		t.Fatal("show modified the configuration")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("show created files: %v", entries)
	}
	missing := filepath.Join(t.TempDir(), "absent", "config.json")
	for _, args := range [][]string{{"--config", missing}, {"--config", missing, "-o", "json"}} {
		if out, _, err := showConfig(t, rt, args...); err == nil || out != "" || fileExists(filepath.Dir(missing)) {
			t.Fatalf("missing config: %v %q", err, out)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--config", path}, {"--config", path, "-o", "json"}} {
		if out, _, err := showConfig(t, rt, args...); err == nil || out != "" {
			t.Fatalf("non-private config shown: %v %q", err, out)
		}
	}
	for _, args := range [][]string{{"--config", path, "-o", "yaml"}, {"--config", path, "--output", ""}, {"--config", path, "extra"}} {
		if _, _, err := showConfig(t, rt, args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
