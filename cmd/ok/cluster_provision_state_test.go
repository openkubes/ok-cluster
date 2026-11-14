package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOkClustersDirFollowsXDGStateHome(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", filepath.Join(base, "home"))
	t.Setenv("XDG_STATE_HOME", "")
	if got, err := okClustersDir(); err != nil || got != filepath.Join(base, "home", ".local", "state", "ok", "clusters") {
		t.Fatalf("HOME fallback: %q %v", got, err)
	}
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, "xdg-state"))
	if got, err := okClustersDir(); err != nil || got != filepath.Join(base, "xdg-state", "ok", "clusters") {
		t.Fatalf("XDG_STATE_HOME: %q %v", got, err)
	}
	for _, unsafe := range []string{"relative/state", filepath.Join(base, "with space")} {
		t.Setenv("XDG_STATE_HOME", unsafe)
		if _, err := okClustersDir(); err == nil {
			t.Fatalf("unsafe XDG_STATE_HOME %q accepted", unsafe)
		}
	}
}

func TestProvisionAllocationLockIsExclusiveAndPrivate(t *testing.T) {
	clusters := filepath.Join(t.TempDir(), "state", "ok", "clusters")
	unlock, err := lockProvisionAllocation(clusters)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Dir(clusters), clusters} {
		if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s not private: %v", directory, err)
		}
	}
	if _, err := lockProvisionAllocation(clusters); err == nil || !strings.Contains(err.Error(), "another ok up") {
		t.Fatalf("second allocation not refused: %v", err)
	}
	unlock()
	unlock() // idempotent: released after make new and again on return
	again, err := lockProvisionAllocation(clusters)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again()
}

func TestClusterProvisionKeepsStateOutsideCheckoutAndSerializesAllocation(t *testing.T) {
	fixture, _ := newProvisionFixture(t)
	unlock, err := lockProvisionAllocation(fixture.runtime.clustersDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.provision("provision preview-one\nbootstrap preview-one\n"); err == nil ||
		!strings.Contains(err.Error(), "another ok up") || fixture.makeCount["new"] != 0 {
		t.Fatalf("concurrent allocation not refused: %v %#v", err, fixture.makeCount)
	}
	unlock()
	if _, err := fixture.provision("provision preview-one\nbootstrap preview-one\n"); err != nil {
		t.Fatal(err)
	}
	clustersDir := "CLUSTERS_DIR=" + fixture.runtime.clustersDir
	for _, call := range fixture.calls {
		if filepath.Base(call.executable) == "make" && !strings.Contains(strings.Join(call.args, " "), clustersDir) {
			t.Fatalf("make %v without %s", call.args, clustersDir)
		}
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, "preview-one")); err == nil {
		t.Fatal("scaffold written into the checkout")
	}
}

func TestClusterProvisionRefusesNameInStateOrCheckout(t *testing.T) {
	for _, where := range []string{"state", "checkout"} {
		t.Run(where, func(t *testing.T) {
			fixture, _ := newProvisionFixture(t)
			existing := filepath.Join(fixture.runtime.clustersDir, "preview-one")
			if where == "checkout" {
				existing = filepath.Join(fixture.root, "preview-one") // committed or pre-v1.0.1 cluster
			}
			if err := os.MkdirAll(existing, 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := fixture.provision("provision preview-one\nbootstrap preview-one\n")
			if err == nil || !strings.Contains(err.Error(), existing) || fixture.makeCount["new"] != 0 {
				t.Fatalf("existing name not refused: %v %#v", err, fixture.makeCount)
			}
			if entries, _ := os.ReadDir(existing); len(entries) != 0 {
				t.Fatal("existing evidence was changed")
			}
		})
	}
}

// OK-228 R1: the lifecycle records the creating CLI's version and binary hash
// as informational metadata; enforcement is by source commit in Python.
func TestProvisionEnvironmentCarriesCreatorMetadata(t *testing.T) {
	env := strings.Join(provisionEnvironment(clusterProvisionRuntime{environmentPath: "/tools", cliBinarySHA256: strings.Repeat("b", 64)}), "\n")
	for _, want := range []string{"OK_CLI_VERSION=" + version, "OK_CLI_BINARY_SHA256=" + strings.Repeat("b", 64)} {
		if !strings.Contains(env, want) {
			t.Fatalf("environment lacks %s:\n%s", want, env)
		}
	}
	if strings.Contains(strings.Join(provisionEnvironment(clusterProvisionRuntime{environmentPath: "/tools"}), "\n"), "OK_CLI_BINARY_SHA256") {
		t.Fatal("an unknown binary hash must be omitted, not passed empty")
	}
}
