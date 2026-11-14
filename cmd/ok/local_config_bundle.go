package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// bundleExpectations are the identities a running CLI may accept for its
// sources. Production uses the embedded revision and the reviewed pins.
type bundleExpectations struct {
	revision, okLinux, chartSHA256 string
}

func runningBundleExpectations() bundleExpectations {
	return bundleExpectations{revision: revision, okLinux: clusterProvisionReviewedOKLinux, chartSHA256: clusterProvisionCiliumSHA256}
}

// verifiedBundle is a lifecycle source pair whose identity was checked with
// the same rules `ok up` enforces: ok-cluster at this CLI's full revision and
// clean, ok-linux at the pinned commit and clean, the pinned Cilium chart.
type verifiedBundle struct {
	lifecycleRoot, okLinuxPath string
	// release is true when release.txt next to the sources matches this
	// binary, both commits and the chart; false for a source checkout build.
	release bool
}

// discoverRunningBundle derives the sources only from the executable's real
// location. It never searches $HOME, the current directory or other checkouts.
func discoverRunningBundle(ctx context.Context, executable string, expect bundleExpectations) (verifiedBundle, error) {
	makeRoot, okLinuxRoot, resolved, err := bundleRootsForExecutable(executable)
	if err != nil {
		return verifiedBundle{}, fmt.Errorf("this ok is not inside an OpenKubes release bundle: %w", err)
	}
	bundle, err := verifyBundleSources(ctx, makeRoot, okLinuxRoot, expect)
	if err != nil {
		return verifiedBundle{}, err
	}
	release, err := verifyReleaseMetadata(filepath.Join(filepath.Dir(makeRoot), "release.txt"), resolved, expect)
	if err != nil {
		return verifiedBundle{}, err
	}
	bundle.release = release
	return bundle, nil
}

// verifyBundleSources checks an ok-cluster/ok-linux pair, discovered or given
// explicitly, exactly like the lifecycle does before it changes anything.
func verifyBundleSources(ctx context.Context, makeRoot, okLinuxRoot string, expect bundleExpectations) (verifiedBundle, error) {
	if !clusterProvisionRevisionPattern.MatchString(expect.revision) {
		return verifiedBundle{}, errors.New("this ok was not built with an exact full source revision (make ok-cli-build or a release bundle)")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return verifiedBundle{}, errors.New("git is required to verify the bundled sources; install git and run ok config init again")
	}
	if git, err = filepath.EvalSymlinks(git); err != nil || !filepath.IsAbs(git) {
		return verifiedBundle{}, errors.New("git cannot be resolved safely")
	}
	toolPath, cleanup, err := createProvisionToolPath(map[string]string{"git": git})
	if err != nil {
		return verifiedBundle{}, err
	}
	defer cleanup()
	check := clusterProvisionRuntime{makeRoot: makeRoot, okLinuxRoot: okLinuxRoot, environmentPath: toolPath,
		toolPaths: map[string]string{"git": git}, command: runClusterProvisionCommand, expectedChartHash: expect.chartSHA256}
	if err := verifyProvisionCheckout(ctx, check, makeRoot, expect.revision, false, "", true); err != nil {
		return verifiedBundle{}, fmt.Errorf("ok-cluster sources %s are not the reviewed source of this ok: %w", makeRoot, err)
	}
	if err := verifyProvisionCheckout(ctx, check, okLinuxRoot, expect.okLinux, false, "", false); err != nil {
		return verifiedBundle{}, fmt.Errorf("ok-linux sources %s are not the pinned profile source: %w", okLinuxRoot, err)
	}
	if err := verifyProvisionChart(check); err != nil {
		return verifiedBundle{}, err
	}
	return verifiedBundle{lifecycleRoot: makeRoot, okLinuxPath: okLinuxRoot}, nil
}

// verifyReleaseMetadata cross-checks release.txt when it exists. Absent means
// a source checkout build; present but inconsistent is refused.
func verifyReleaseMetadata(path, executable string, expect bundleExpectations) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return false, errors.New("release.txt is not a regular bounded file")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(file, 64*1024))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) > 0 {
			values[strings.TrimSpace(key)] = fields[0]
		}
	}
	binary, err := fileSHA256(executable)
	if err != nil {
		return false, errors.New("cannot hash this ok binary")
	}
	for key, want := range map[string]string{"ok-cluster commit": expect.revision, "ok-linux commit": expect.okLinux,
		"bin/ok sha256": binary, "cilium-1.19.6.tgz sha256": expect.chartSHA256} {
		if values[key] != want {
			return false, fmt.Errorf("release.txt does not match this bundle (%s); reinstall from a verified archive", key)
		}
	}
	return true, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// missingRuntimeTools reports, never installs, what ok up will require.
func missingRuntimeTools(ctx context.Context) []string {
	missing := []string{}
	for _, tool := range clusterProvisionRequiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if python, err := exec.LookPath("python3"); err == nil {
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		command := exec.CommandContext(check, python, "-c", "import yaml")
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1"}
		if command.Run() != nil {
			missing = append(missing, "PyYAML (for "+python+")")
		}
	}
	return missing
}

// checkManagementReference inspects only file metadata: the contents are not
// read and no cluster is contacted. ok up validates the kubeconfig in full.
func checkManagementReference(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !clusterProvisionSafePathPattern.MatchString(path) {
		return "", errors.New("management kubeconfig path must use shell-safe characters")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("management kubeconfig %s does not exist", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("management kubeconfig %s must be a regular file, not a symlink", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("management kubeconfig %s must be private: chmod 600 %s", path, path)
	}
	return path, nil
}
