package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests use a real git binary and real repositories, so they exercise
// the same `git rev-parse` / `git status` calls the operator workflow makes.

func provisionTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-c", "user.name=ok-test", "-c", "user.email=ok-test@example.invalid", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeProvisionTestFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, contents := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// initProvisionTestRepo turns root into a git repository holding files and
// returns the full commit ID of HEAD.
func initProvisionTestRepo(t *testing.T, root string, files map[string]string) string {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	provisionTestGit(t, root, "init", "-q")
	writeProvisionTestFiles(t, root, files)
	return commitProvisionTestRepo(t, root, "initial")
}

func commitProvisionTestRepo(t *testing.T, root, message string) string {
	t.Helper()
	provisionTestGit(t, root, "add", "-A")
	provisionTestGit(t, root, "commit", "-q", "-m", message)
	return provisionTestGit(t, root, "rev-parse", "HEAD")
}

// realGitProvisionRuntime runs git through the production command runner and
// isolated environment, exactly as operator provisioning does.
func realGitProvisionRuntime(t *testing.T) clusterProvisionRuntime {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is required for real checkout verification tests")
	}
	gitPath, err = filepath.EvalSymlinks(gitPath)
	if err != nil {
		t.Fatal(err)
	}
	toolPath, cleanup, err := createProvisionToolPath(map[string]string{"git": gitPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return clusterProvisionRuntime{toolPaths: map[string]string{"git": gitPath}, environmentPath: toolPath, command: runClusterProvisionCommand}
}

func provisionTestCheckoutRoot(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "ok-cluster")
}

var provisionTestCheckoutFiles = map[string]string{
	".gitignore":                       ".tools/\n",
	"Makefile":                         "new:\n\t@true\n",
	"cmd/ok/main.go":                   "package main\n",
	"scripts/talos_lifecycle.py":       "print('lifecycle')\n",
	"docs/operator.md":                 "# operator\n",
	"internal/desiredauthority/a.go":   "package desiredauthority\n",
	".github/workflows/ok-cli-ci.yaml": "name: ok CLI checks\n",
}

func TestProvisionCheckoutAcceptsOnlyCleanBuildCommit(t *testing.T) {
	runtime := realGitProvisionRuntime(t)
	root := provisionTestCheckoutRoot(t)
	head := initProvisionTestRepo(t, root, provisionTestCheckoutFiles)
	// The built CLI binary and the digest-pinned chart live in the ignored .tools directory.
	writeProvisionTestFiles(t, root, map[string]string{".tools/bin/ok": "binary", ".tools/cilium-1.19.6.tgz": "chart"})
	verify := func(revision string, allowScaffold bool) error {
		return verifyProvisionCheckout(context.Background(), runtime, root, revision, allowScaffold, "preview-one", true)
	}
	if err := verify(head, false); err != nil {
		t.Fatalf("clean checkout at the build commit was rejected: %v", err)
	}
	if err := verify(head, true); err != nil {
		t.Fatalf("clean checkout at the build commit was rejected after make new: %v", err)
	}
	if err := verify(strings.Repeat("a", 40), false); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("binary built from another commit was accepted: %v", err)
	}
}

// Regression for the pin treadmill: a reviewed commit that changes unrelated
// files outside cmd/ok must work after rebuilding, without editing any pin or
// allowlist. A binary from the previous commit must still be refused.
func TestProvisionCheckoutAcceptsUnrelatedCommittedChangesAfterRebuild(t *testing.T) {
	runtime := realGitProvisionRuntime(t)
	root := provisionTestCheckoutRoot(t)
	previous := initProvisionTestRepo(t, root, provisionTestCheckoutFiles)
	writeProvisionTestFiles(t, root, map[string]string{
		"docs/operator.md":                 "# operator\n\nTypo fixed.\n",
		"docs/new-design-note.md":          "# new note\n",
		"internal/desiredauthority/a.go":   "package desiredauthority\n\nconst changed = true\n",
		"internal/unrelated/b.go":          "package unrelated\n",
		"scripts/talos_lifecycle.py":       "print('reviewed lifecycle change')\n",
		"Makefile":                         "new:\n\t@true\nbootstrap:\n\t@true\n",
		".github/workflows/ok-cli-ci.yaml": "name: ok CLI checks\non: pull_request\n",
	})
	current := commitProvisionTestRepo(t, root, "unrelated reviewed changes")
	if err := verifyProvisionCheckout(context.Background(), runtime, root, current, false, "preview-one", true); err != nil {
		t.Fatalf("unrelated committed changes required a pin update: %v", err)
	}
	if err := verifyProvisionCheckout(context.Background(), runtime, root, previous, false, "preview-one", true); err == nil {
		t.Fatal("stale binary from the previous commit was accepted")
	}
}

func TestProvisionCheckoutRejectsLocalChanges(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"modified tracked file outside cmd/ok": func(t *testing.T, root string) {
			writeProvisionTestFiles(t, root, map[string]string{"scripts/talos_lifecycle.py": "print('local edit')\n"})
		},
		"modified tracked file in cmd/ok": func(t *testing.T, root string) {
			writeProvisionTestFiles(t, root, map[string]string{"cmd/ok/main.go": "package main\n// local edit\n"})
		},
		"uncommitted Makefile change": func(t *testing.T, root string) {
			writeProvisionTestFiles(t, root, map[string]string{"Makefile": "new:\n\t@echo changed\n"})
		},
		"staged change": func(t *testing.T, root string) {
			writeProvisionTestFiles(t, root, map[string]string{"docs/operator.md": "# staged\n"})
			provisionTestGit(t, root, "add", "docs/operator.md")
		},
		"deleted tracked file": func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "scripts", "talos_lifecycle.py")); err != nil {
				t.Fatal(err)
			}
		},
		"untracked file": func(t *testing.T, root string) {
			writeProvisionTestFiles(t, root, map[string]string{"scripts/extra.py": "print('untracked')\n"})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			runtime := realGitProvisionRuntime(t)
			root := provisionTestCheckoutRoot(t)
			head := initProvisionTestRepo(t, root, provisionTestCheckoutFiles)
			mutate(t, root)
			for _, allowScaffold := range []bool{false, true} {
				if err := verifyProvisionCheckout(context.Background(), runtime, root, head, allowScaffold, "preview-one", true); err == nil {
					t.Fatalf("local change accepted (allowScaffold=%v)", allowScaffold)
				}
			}
		})
	}
}

// Before `make new` the checkout must be completely clean; after `make new`
// only untracked files inside <checkout>/<cluster>/ are tolerated.
func TestProvisionCheckoutScaffoldWindowBeforeAndAfterMakeNew(t *testing.T) {
	scaffold := map[string]string{"preview-one/cluster-config.yaml": "name: preview-one\n", "preview-one/cluster-base.yaml": "kind: Cluster\n"}
	cases := []struct {
		name          string
		files         map[string]string
		modifyTracked bool
		allowScaffold bool
		wantOK        bool
	}{
		{name: "before make new: scaffold present", files: scaffold, allowScaffold: false, wantOK: false},
		{name: "after make new: scaffold only", files: scaffold, allowScaffold: true, wantOK: true},
		{name: "after make new: stray file outside scaffold", files: map[string]string{"preview-one/cluster-config.yaml": "x", "stray.txt": "x"}, allowScaffold: true, wantOK: false},
		{name: "after make new: sibling with scaffold-name prefix", files: map[string]string{"preview-oneevil/cluster-config.yaml": "x"}, allowScaffold: true, wantOK: false},
		{name: "after make new: other cluster scaffold", files: map[string]string{"preview-two/cluster-config.yaml": "x"}, allowScaffold: true, wantOK: false},
		{name: "after make new: scaffold plus tracked change", files: scaffold, modifyTracked: true, allowScaffold: true, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := realGitProvisionRuntime(t)
			root := provisionTestCheckoutRoot(t)
			head := initProvisionTestRepo(t, root, provisionTestCheckoutFiles)
			writeProvisionTestFiles(t, root, tc.files)
			if tc.modifyTracked {
				writeProvisionTestFiles(t, root, map[string]string{"Makefile": "new:\n\t@echo changed\n"})
			}
			err := verifyProvisionCheckout(context.Background(), runtime, root, head, tc.allowScaffold, "preview-one", true)
			if tc.wantOK && err != nil {
				t.Fatalf("expected acceptance: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("unsafe checkout state was accepted")
			}
		})
	}
	t.Run("staged scaffold", func(t *testing.T) {
		runtime := realGitProvisionRuntime(t)
		root := provisionTestCheckoutRoot(t)
		head := initProvisionTestRepo(t, root, provisionTestCheckoutFiles)
		writeProvisionTestFiles(t, root, scaffold)
		provisionTestGit(t, root, "add", "preview-one")
		if err := verifyProvisionCheckout(context.Background(), runtime, root, head, true, "preview-one", true); err == nil {
			t.Fatal("staged scaffold was accepted; only untracked generated files are allowed")
		}
	})
}

func TestProvisionOKLinuxCheckoutMustBePinnedAndClean(t *testing.T) {
	files := map[string]string{"profiles/kubevirt/profile.yaml": "profile: kubevirt\n", "README.md": "# ok-linux\n"}
	setup := func(t *testing.T) (clusterProvisionRuntime, string, string) {
		runtime := realGitProvisionRuntime(t)
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(base, "ok-linux")
		return runtime, root, initProvisionTestRepo(t, root, files)
	}
	t.Run("pinned and clean", func(t *testing.T) {
		runtime, root, pinned := setup(t)
		if err := verifyProvisionCheckout(context.Background(), runtime, root, pinned, false, "", false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("different commit", func(t *testing.T) {
		runtime, root, pinned := setup(t)
		writeProvisionTestFiles(t, root, map[string]string{"README.md": "# newer\n"})
		commitProvisionTestRepo(t, root, "newer")
		if err := verifyProvisionCheckout(context.Background(), runtime, root, pinned, false, "", false); err == nil {
			t.Fatal("ok-linux checkout at a different commit was accepted")
		}
	})
	t.Run("dirty", func(t *testing.T) {
		runtime, root, pinned := setup(t)
		writeProvisionTestFiles(t, root, map[string]string{"profiles/kubevirt/profile.yaml": "profile: changed\n"})
		if err := verifyProvisionCheckout(context.Background(), runtime, root, pinned, false, "", false); err == nil {
			t.Fatal("dirty ok-linux checkout was accepted")
		}
	})
	t.Run("missing profile", func(t *testing.T) {
		runtime, root, pinned := setup(t)
		if err := os.Remove(filepath.Join(root, "profiles", "kubevirt", "profile.yaml")); err != nil {
			t.Fatal(err)
		}
		if err := verifyProvisionCheckout(context.Background(), runtime, root, pinned, false, "", false); err == nil {
			t.Fatal("ok-linux checkout without the KubeVirt profile was accepted")
		}
	})
}

// End-to-end through the provisioning flow with real git repositories for
// both checkouts. Make, kubectl and python remain fakes, so no cluster is
// contacted and no Make recipe runs. afterNew runs right after the fake
// `make new` has written the scaffold.
func newRealGitProvisionFixture(t *testing.T, afterNew func(root string)) *provisionFixture {
	t.Helper()
	fixture, _ := newProvisionFixture(t)
	fixture.runtime.makeRevision = initProvisionTestRepo(t, fixture.root, map[string]string{".gitignore": ".tools/\n", "Makefile": "# fixture\n"})
	fixture.runtime.okLinuxRevision = initProvisionTestRepo(t, fixture.okLinux, map[string]string{"profiles/kubevirt/profile.yaml": "fixture\n"})
	gitRuntime := realGitProvisionRuntime(t)
	fixture.runtime.toolPaths["git"] = gitRuntime.toolPaths["git"]
	fixture.runtime.command = func(ctx context.Context, executable string, args []string, dir string, environment []string, stdout, stderr io.Writer) error {
		if executable == gitRuntime.toolPaths["git"] {
			fixture.calls = append(fixture.calls, provisionCall{executable: executable, args: append([]string(nil), args...), dir: dir})
			return runClusterProvisionCommand(ctx, executable, args, dir, provisionEnvironment(gitRuntime), stdout, stderr)
		}
		err := fixture.run(ctx, executable, args, dir, environment, stdout, stderr)
		if err == nil && filepath.Base(executable) == "make" && len(args) > 1 && args[1] == "new" && afterNew != nil {
			afterNew(fixture.root)
		}
		return err
	}
	return fixture
}

func TestClusterProvisionRealGitScaffoldOnlyAfterMakeNewReachesBootstrap(t *testing.T) {
	fixture := newRealGitProvisionFixture(t, nil)
	output, err := fixture.provision("provision preview-one\nbootstrap preview-one\n")
	if err != nil {
		t.Fatalf("clean checkout with generated scaffold did not reach bootstrap: %v\n%s", err, output.String())
	}
	if fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 1 {
		t.Fatalf("unexpected Make calls: %#v", fixture.makeCount)
	}
	if !strings.Contains(output.String(), "exact commit this CLI was built from") {
		t.Fatalf("plan does not state the integrity basis:\n%s", output.String())
	}
}

func TestClusterProvisionRealGitRejectsChangesOutsideScaffoldBeforeBootstrap(t *testing.T) {
	for name, afterNew := range map[string]func(string){
		"stray untracked file": func(root string) {
			if err := os.WriteFile(filepath.Join(root, "stray.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"tracked Makefile modified": func(root string) {
			if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte("# changed during make new\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRealGitProvisionFixture(t, afterNew)
			_, err := fixture.provision("provision preview-one\nbootstrap preview-one\n")
			if err == nil || !strings.Contains(err.Error(), "scaffold is preserved") {
				t.Fatalf("change outside the scaffold was not stopped before bootstrap: %v", err)
			}
			if fixture.makeCount["new"] != 1 || fixture.makeCount["bootstrap"] != 0 {
				t.Fatalf("bootstrap ran despite unsafe checkout: %#v", fixture.makeCount)
			}
			if _, statErr := os.Stat(filepath.Join(fixture.runtime.clustersDir, "preview-one", "cluster-config.yaml")); statErr != nil {
				t.Fatalf("scaffold was not preserved: %v", statErr)
			}
		})
	}
}

func TestClusterProvisionRealGitDirtyCheckoutNeverStartsMake(t *testing.T) {
	fixture := newRealGitProvisionFixture(t, nil)
	if err := os.WriteFile(filepath.Join(fixture.root, "Makefile"), []byte("# local edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.provision("provision preview-one\nbootstrap preview-one\n")
	if err == nil || fixture.makeCount["new"] != 0 {
		t.Fatalf("dirty checkout reached make new: %v %#v", err, fixture.makeCount)
	}
}
