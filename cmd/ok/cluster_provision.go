package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	clusterProvisionReviewedMakeSource = "13dfc9803164d4b3d83b0da14bc285d1540e077e"
	// The newer profile source is recorded in the repository's OK-147 evidence;
	// the earlier OK-130 runtime commit predates provider_profiles required by
	// the current resolver and fails the existing offline profile contract.
	clusterProvisionReviewedOKLinux  = "a1687263d46c48e47c14f5bf202c9a652d7c1a71"
	clusterProvisionCiliumSHA256     = "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
	clusterProvisionNewTimeout       = 10 * time.Minute
	clusterProvisionBootstrapTimeout = 2 * time.Hour
	clusterProvisionCheckTimeout     = 30 * time.Second
)

var (
	clusterProvisionRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	clusterProvisionSafePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	clusterProvisionToolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

type clusterProvisionRuntime struct {
	makeRoot, okLinuxRoot, makeExecutable    string
	makeRevision, okLinuxRevision            string
	reviewedMakeSource, expectedChartHash    string
	managementKubeconfig, workloadKubeconfig string
	environmentPath                          string
	toolPaths                                map[string]string
	cleanupToolPath                          func()
	command                                  clusterProvisionCommand
	isTerminal                               bool
	newTimeout, bootstrapTimeout             time.Duration
}

type clusterProvisionCommand func(context.Context, string, []string, string, []string, io.Writer, io.Writer) error

type clusterProvisionPrepared struct {
	name, kubernetesVersion, talosVersion               string
	workers                                             int
	newArgs, bootstrapArgs                              []string
	managementKubeconfig, workloadKubeconfig, chartPath string
	managementKubeconfigSHA256                          string
	managementContext, managementAPIServer              string
}

type clusterProvisionKubeconfig struct {
	APIVersion     string `yaml:"apiVersion"`
	Kind           string `yaml:"kind"`
	CurrentContext string `yaml:"current-context"`
	Contexts       []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                string `yaml:"server"`
			InsecureSkipTLSVerify bool   `yaml:"insecure-skip-tls-verify"`
			ProxyURL              string `yaml:"proxy-url"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Exec         *yaml.Node `yaml:"exec"`
			AuthProvider *yaml.Node `yaml:"auth-provider"`
			As           string     `yaml:"as"`
			AsUID        string     `yaml:"as-uid"`
			AsGroups     []string   `yaml:"as-groups"`
		} `yaml:"user"`
	} `yaml:"users"`
}

type clusterProvisionArtifact struct{ name, digest string }
type clusterProvisionNetwork struct {
	Endpoint    string `yaml:"endpoint"`
	PodCIDR     string `yaml:"podCIDR"`
	ServiceCIDR string `yaml:"serviceCIDR"`
}

type clusterProvisionConfig struct {
	Name         string `yaml:"name"`
	Type         string `yaml:"type"`
	ControlPlane struct {
		Replicas int    `yaml:"replicas"`
		Cores    int    `yaml:"cores"`
		Memory   string `yaml:"memory"`
		Disk     string `yaml:"disk"`
	} `yaml:"controlPlane"`
	Workers struct {
		Replicas int    `yaml:"replicas"`
		Cores    int    `yaml:"cores"`
		Memory   string `yaml:"memory"`
		Disk     string `yaml:"disk"`
	} `yaml:"workers"`
	Versions struct {
		Kubernetes string `yaml:"kubernetes"`
		Talos      string `yaml:"talos"`
	} `yaml:"versions"`
	OS struct {
		Distribution string `yaml:"distribution"`
		Profile      string `yaml:"profile"`
		SchematicID  string `yaml:"schematic_id"`
		Architecture string `yaml:"architecture"`
		ImageDigest  string `yaml:"imageDigest"`
		Identity     string `yaml:"identity"`
		GoldenImage  struct {
			Namespace    string `yaml:"namespace"`
			Claim        string `yaml:"claim"`
			Published    bool   `yaml:"published"`
			StorageClass string `yaml:"storageClass"`
		} `yaml:"goldenImage"`
	} `yaml:"os"`
	ProviderProfile struct {
		Name                    string `yaml:"name"`
		Identity                string `yaml:"identity"`
		NodeSelector            string `yaml:"nodeSelector"`
		CloneTargetStorageClass string `yaml:"cloneTargetStorageClass"`
		ReplicaCount            int    `yaml:"replicaCount"`
		SnapshotClass           string `yaml:"snapshotClass"`
	} `yaml:"providerProfile"`
	Network      clusterProvisionNetwork `yaml:"network"`
	NodeSelector string                  `yaml:"nodeSelector"`
	Upgrade      struct {
		Strategy          string `yaml:"strategy"`
		WorkloadMigration struct {
			Stateless string `yaml:"stateless"`
			Stateful  string `yaml:"stateful"`
		} `yaml:"workloadMigration"`
	} `yaml:"upgrade"`
}

var clusterProvisionRequiredTools = []string{
	"make", "git", "kubectl", "clusterctl", "helm", "python3", "bash", "sh",
	"grep", "head", "seq", "sleep", "mktemp", "mv", "rm", "chmod", "basename", "dirname", "mkdir", "cat", "tr", "wc",
}

func runClusterProvision(ctx context.Context, arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster provision", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var input clusterPlanInputFlag
	flags.Var(&input, "file", "ClusterRequest YAML file")
	flags.Var(&input, "f", "ClusterRequest YAML file")
	workloadKubeconfig := flags.String("workload-kubeconfig", "", "private output path ending in <cluster>.yaml")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || input.value == "" || *workloadKubeconfig == "" {
		return errors.New("ok cluster provision requires -f <cluster.yaml> and --workload-kubeconfig <private-path>")
	}
	request, err := readClusterRequest(input.value)
	if err != nil {
		return err
	}
	runtime, err := clusterProvisionRuntimeFromProcess(*workloadKubeconfig)
	if err != nil {
		return err
	}
	if runtime.cleanupToolPath != nil {
		defer runtime.cleanupToolPath()
	}
	return runClusterProvisionWithRuntime(ctx, request, stdin, stdout, stderr, runtime)
}

func clusterProvisionRuntimeFromProcess(workloadKubeconfig string) (clusterProvisionRuntime, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return clusterProvisionRuntime{}, errors.New("operator provisioning currently supports only macOS and Linux process-group cancellation")
	}
	if revision == "unknown" || !clusterProvisionRevisionPattern.MatchString(revision) {
		return clusterProvisionRuntime{}, errors.New("provision requires a CLI built by make ok-cli-build with an exact full source revision")
	}
	executable, err := os.Executable()
	if err != nil {
		return clusterProvisionRuntime{}, errors.New("cannot identify the built CLI location")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return clusterProvisionRuntime{}, errors.New("cannot resolve the built CLI location")
	}
	binDir := filepath.Dir(executable)
	if filepath.Base(binDir) != "bin" || filepath.Base(filepath.Dir(binDir)) != ".tools" || filepath.Base(executable) != "ok" {
		return clusterProvisionRuntime{}, errors.New("build the CLI at <ok-cluster>/.tools/bin/ok using make ok-cli-build")
	}
	makeRoot, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(binDir)))
	if err != nil || !clusterProvisionSafePathPattern.MatchString(makeRoot) {
		return clusterProvisionRuntime{}, errors.New("Make checkout path is missing or contains unsupported shell-sensitive characters")
	}
	okLinuxRoot := filepath.Join(filepath.Dir(makeRoot), "ok-linux")
	if resolved, resolveErr := filepath.EvalSymlinks(okLinuxRoot); resolveErr == nil {
		okLinuxRoot = resolved
	}
	if !clusterProvisionSafePathPattern.MatchString(okLinuxRoot) {
		return clusterProvisionRuntime{}, errors.New("ok-linux checkout path contains unsupported shell-sensitive characters")
	}
	pathValue := os.Getenv("PATH")
	if pathValue == "" {
		return clusterProvisionRuntime{}, errors.New("PATH must explicitly contain the reviewed provisioning tools")
	}
	for _, entry := range filepath.SplitList(pathValue) {
		if entry == "" || !filepath.IsAbs(entry) {
			return clusterProvisionRuntime{}, errors.New("PATH entries must be absolute; current-directory tool lookup is not allowed")
		}
	}
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || !clusterProvisionSafePathPattern.MatchString(home) {
		return clusterProvisionRuntime{}, errors.New("HOME must be an explicit absolute path with shell-safe characters")
	}
	managementKubeconfig, ok := os.LookupEnv("TALOS_INFRA_KUBECONFIG")
	if !ok || managementKubeconfig == "" {
		return clusterProvisionRuntime{}, errors.New("set TALOS_INFRA_KUBECONFIG explicitly to the private management kubeconfig")
	}
	toolPaths := make(map[string]string)
	for _, tool := range clusterProvisionRequiredTools {
		path, lookupErr := exec.LookPath(tool)
		if lookupErr != nil {
			return clusterProvisionRuntime{}, fmt.Errorf("required provisioning tool is unavailable: %s", tool)
		}
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil || !filepath.IsAbs(resolved) {
			return clusterProvisionRuntime{}, fmt.Errorf("required provisioning tool cannot be safely resolved: %s", tool)
		}
		info, statErr := os.Stat(resolved)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			return clusterProvisionRuntime{}, fmt.Errorf("required provisioning tool is not an executable regular file: %s", tool)
		}
		toolPaths[tool] = resolved
	}
	restrictedPath, cleanup, err := createProvisionToolPath(toolPaths)
	if err != nil {
		return clusterProvisionRuntime{}, err
	}
	return clusterProvisionRuntime{
		makeRoot: makeRoot, okLinuxRoot: okLinuxRoot, makeExecutable: toolPaths["make"],
		makeRevision: revision, okLinuxRevision: clusterProvisionReviewedOKLinux,
		reviewedMakeSource: clusterProvisionReviewedMakeSource, expectedChartHash: clusterProvisionCiliumSHA256,
		managementKubeconfig: managementKubeconfig, workloadKubeconfig: workloadKubeconfig,
		environmentPath: restrictedPath,
		toolPaths:       toolPaths, command: runClusterProvisionCommand, isTerminal: stdinIsTerminal(),
		cleanupToolPath: cleanup,
	}, nil
}

func createProvisionToolPath(toolPaths map[string]string) (string, func(), error) {
	directory, err := os.MkdirTemp("", "ok76-provision-tools-")
	if err != nil {
		return "", nil, errors.New("cannot create isolated command lookup directory")
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	for name, target := range toolPaths {
		if !clusterProvisionToolNamePattern.MatchString(name) || !filepath.IsAbs(target) {
			cleanup()
			return "", nil, errors.New("required tool binding is invalid")
		}
		if err := os.Symlink(target, filepath.Join(directory, name)); err != nil {
			cleanup()
			return "", nil, errors.New("cannot create isolated command lookup binding")
		}
	}
	return directory, cleanup, nil
}

func runClusterProvisionWithRuntime(ctx context.Context, request clusterRequest, stdin io.Reader, stdout, stderr io.Writer, runtime clusterProvisionRuntime) error {
	if !runtime.isTerminal {
		return errors.New("cluster provision requires an interactive terminal; privileged Make execution is not available through non-interactive input")
	}
	if err := validateClusterRequest(request); err != nil {
		return err
	}
	if request.Spec.Profile != clusterRequestProfile {
		return errors.New("cluster provision supports only talos-kubevirt-reference")
	}
	prepared, err := prepareClusterProvision(request, runtime)
	if err != nil {
		return err
	}
	if err := verifyProvisionInputs(ctx, prepared, runtime, false); err != nil {
		return err
	}
	if err := verifyProvisionScaffoldAbsent(runtime, prepared.name); err != nil {
		return err
	}
	if err := verifyProvisionClusterAbsent(ctx, prepared, runtime); err != nil {
		return err
	}
	printClusterProvisionPlan(stdout, prepared, runtime)
	confirmations := bufio.NewReader(stdin)
	if err := requireProvisionConfirmation(confirmations, stdout, "provision "+prepared.name); err != nil {
		return fmt.Errorf("provisioning cancelled before Make was started: %w", err)
	}
	if err := verifyProvisionInputs(ctx, prepared, runtime, false); err != nil {
		return fmt.Errorf("preflight changed after confirmation; Make was not started: %w", err)
	}
	if err := verifyProvisionScaffoldAbsent(runtime, prepared.name); err != nil {
		return fmt.Errorf("preflight changed after confirmation; Make was not started: %w", err)
	}
	if err := verifyProvisionClusterAbsent(ctx, prepared, runtime); err != nil {
		return fmt.Errorf("preflight changed after confirmation; Make was not started: %w", err)
	}
	if err := runProvisionMake(ctx, runtime, prepared.newArgs, clusterProvisionNewTimeout, stdout, stderr); err != nil {
		return fmt.Errorf("make new did not complete successfully; no retry, rollback or cleanup was performed; inspect command output and any scaffold at %s: %w", filepath.Join(runtime.makeRoot, prepared.name), err)
	}
	artifacts, network, err := inspectProvisionScaffold(runtime, prepared)
	if err != nil {
		return fmt.Errorf("make new returned success but its scaffold could not be verified; preserve it and stop without bootstrap: %w", err)
	}
	if err := verifyProvisionInputs(ctx, prepared, runtime, true); err != nil {
		return fmt.Errorf("scaffold is preserved; trusted inputs changed before bootstrap: %w", err)
	}
	if err := verifyProvisionClusterAbsent(ctx, prepared, runtime); err != nil {
		return fmt.Errorf("scaffold is preserved; management Cluster preflight failed before bootstrap: %w", err)
	}
	if err := verifyProvisionChart(runtime); err != nil {
		return fmt.Errorf("scaffold is preserved; Cilium chart changed before bootstrap: %w", err)
	}
	if err := verifyWorkloadKubeconfigDestination(runtime.workloadKubeconfig, prepared.name); err != nil {
		return fmt.Errorf("scaffold is preserved; workload kubeconfig destination changed: %w", err)
	}
	fmt.Fprintf(stdout, "\nScaffold review for %s (bootstrap has not run):\n", prepared.name)
	fmt.Fprintf(stdout, "  endpoint: %s\n  pod CIDR: %s\n  service CIDR: %s\n", network.Endpoint, network.PodCIDR, network.ServiceCIDR)
	for _, artifact := range artifacts {
		fmt.Fprintf(stdout, "  artifact: %s sha256:%s\n", artifact.name, artifact.digest)
	}
	fmt.Fprintf(stdout, "\nNext target: make bootstrap CLUSTER=%s\n", prepared.name)
	fmt.Fprintln(stdout, "Bootstrap may apply CAPI resources, annotate management PVCs, generate the private workload kubeconfig, and install the pinned Cilium chart on the workload cluster.")
	if err := requireProvisionConfirmation(confirmations, stdout, "bootstrap "+prepared.name); err != nil {
		return fmt.Errorf("bootstrap cancelled; completed scaffold is preserved and no bootstrap command was started: %w", err)
	}
	if err := verifyProvisionInputs(ctx, prepared, runtime, true); err != nil {
		return fmt.Errorf("scaffold is preserved; trusted inputs changed after confirmation, bootstrap was not started: %w", err)
	}
	if err := verifyProvisionClusterAbsent(ctx, prepared, runtime); err != nil {
		return fmt.Errorf("scaffold is preserved; management Cluster preflight changed after confirmation, bootstrap was not started: %w", err)
	}
	if err := verifyProvisionChart(runtime); err != nil {
		return fmt.Errorf("scaffold is preserved; Cilium chart changed after confirmation, bootstrap was not started: %w", err)
	}
	if err := verifyWorkloadKubeconfigDestination(runtime.workloadKubeconfig, prepared.name); err != nil {
		return fmt.Errorf("scaffold is preserved; workload kubeconfig destination changed after confirmation: %w", err)
	}
	if err := verifyProvisionArtifactsUnchanged(runtime, prepared, artifacts); err != nil {
		return fmt.Errorf("scaffold changed after review; bootstrap was not started: %w", err)
	}
	if err := runProvisionMake(ctx, runtime, prepared.bootstrapArgs, clusterProvisionBootstrapTimeout, stdout, stderr); err != nil {
		return fmt.Errorf("make bootstrap failed or was interrupted; partial Kubernetes changes and local files may exist; no retry, rollback or cleanup was performed: %w", err)
	}
	if err := verifyProducedWorkloadKubeconfig(runtime.workloadKubeconfig); err != nil {
		return fmt.Errorf("make bootstrap returned success but requested workload kubeconfig is not safely present; partial state is preserved and readiness is not verified: %w", err)
	}
	fmt.Fprintf(stdout, "\nMake bootstrap completed for %s; workload kubeconfig present at %s.\n", prepared.name, runtime.workloadKubeconfig)
	fmt.Fprintln(stdout, "Command completion is not independent verification of cluster readiness; use established read-only verification procedures.")
	return nil
}

func verifyProvisionScaffoldAbsent(runtime clusterProvisionRuntime, clusterName string) error {
	path := filepath.Join(runtime.makeRoot, clusterName)
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("a local scaffold already exists or cannot be safely checked; refusing to overwrite it")
	}
	return nil
}

func verifyProvisionArtifactsUnchanged(runtime clusterProvisionRuntime, prepared clusterProvisionPrepared, expected []clusterProvisionArtifact) error {
	actual, _, err := inspectProvisionScaffold(runtime, prepared)
	if err != nil {
		return errors.New("reviewed scaffold is no longer safely inspectable")
	}
	if !reflectProvisionArtifactsEqual(actual, expected) {
		return errors.New("reviewed scaffold artifact set or SHA-256 changed")
	}
	return nil
}

func reflectProvisionArtifactsEqual(a, b []clusterProvisionArtifact) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func prepareClusterProvision(request clusterRequest, runtime clusterProvisionRuntime) (clusterProvisionPrepared, error) {
	values := clusterPlanValuesForRequest(request)
	prepared := clusterProvisionPrepared{
		name: values.Name, kubernetesVersion: values.Kubernetes, talosVersion: values.Talos, workers: values.Workers,
		managementKubeconfig: runtime.managementKubeconfig, workloadKubeconfig: runtime.workloadKubeconfig,
		chartPath: filepath.Join(runtime.makeRoot, ".tools", "cilium-1.19.6.tgz"),
	}
	if !clusterProvisionRevisionPattern.MatchString(runtime.makeRevision) || !clusterProvisionRevisionPattern.MatchString(runtime.okLinuxRevision) {
		return clusterProvisionPrepared{}, errors.New("trusted Make and ok-linux revisions must be full lowercase Git commit IDs")
	}
	if runtime.reviewedMakeSource == "" || runtime.expectedChartHash == "" || runtime.command == nil {
		return clusterProvisionPrepared{}, errors.New("trusted provisioning runtime is incomplete")
	}
	managementTarget, err := inspectProvisionManagementKubeconfig(runtime.managementKubeconfig)
	if err != nil {
		return clusterProvisionPrepared{}, err
	}
	managementHash, err := hashRegularPrivateFile(runtime.managementKubeconfig, 4*1024*1024)
	if err != nil {
		return clusterProvisionPrepared{}, errors.New("management kubeconfig cannot be fingerprinted safely")
	}
	prepared.managementKubeconfigSHA256 = managementHash
	prepared.managementContext = managementTarget.context
	prepared.managementAPIServer = managementTarget.server
	if err := verifyWorkloadKubeconfigDestination(runtime.workloadKubeconfig, prepared.name); err != nil {
		return clusterProvisionPrepared{}, err
	}
	for _, path := range []string{runtime.makeRoot, runtime.okLinuxRoot, runtime.managementKubeconfig, runtime.workloadKubeconfig} {
		if !clusterProvisionSafePathPattern.MatchString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return clusterProvisionPrepared{}, errors.New("checkout and kubeconfig paths must be absolute and contain only shell-safe path characters")
		}
	}
	prepared.newArgs = append([]string{"--no-print-directory", "new"}, clusterProvisionMakeAssignments(prepared, runtime, false)...)
	prepared.bootstrapArgs = append([]string{"--no-print-directory", "bootstrap"}, clusterProvisionMakeAssignments(prepared, runtime, true)...)
	return prepared, nil
}

func clusterProvisionMakeAssignments(prepared clusterProvisionPrepared, runtime clusterProvisionRuntime, bootstrap bool) []string {
	assignments := []string{
		"CLUSTER=" + prepared.name, "TYPE=talos", "PROVIDER=kubevirt", "HA=false", "WORKERS=" + fmt.Sprint(prepared.workers),
		"K8S_VERSION=" + prepared.kubernetesVersion, "TALOS_VERSION=" + prepared.talosVersion, "ARCHITECTURE=amd64",
		"SCHEDULING_PROFILE=ok-infra", "NODE_SELECTOR=ok-infra", "CP_CORES=2", "CP_MEMORY=4Gi", "CP_DISK=20Gi",
		"WORKER_CORES=2", "WORKER_MEMORY=4Gi", "WORKER_DISK=15Gi", "REGISTRY_TRUST=false", "START_IP=",
		"OK76_REQUIRE_LIVE_METALLB_INVENTORY=true", "TALOS_INFRA_KUBECONFIG=" + prepared.managementKubeconfig,
		"OK_LINUX_PATH=" + runtime.okLinuxRoot,
	}
	if bootstrap {
		assignments = append(assignments,
			"GUEST_KUBECONFIG_DIR="+filepath.Dir(prepared.workloadKubeconfig),
			"TALOS_WORKLOAD_KUBECONFIG="+prepared.workloadKubeconfig,
			"CILIUM_CHART="+prepared.chartPath,
		)
	}
	return assignments
}

func inspectProvisionScaffold(runtime clusterProvisionRuntime, prepared clusterProvisionPrepared) ([]clusterProvisionArtifact, clusterProvisionNetwork, error) {
	dir := filepath.Join(runtime.makeRoot, prepared.name)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, clusterProvisionNetwork{}, errors.New("published cluster directory is absent or unsafe")
	}
	configPath := filepath.Join(dir, "cluster-config.yaml")
	configInfo, err := os.Lstat(configPath)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Size() > 256*1024 {
		return nil, clusterProvisionNetwork{}, errors.New("cluster-config.yaml is absent, non-regular or oversized")
	}
	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, clusterProvisionNetwork{}, errors.New("cluster-config.yaml cannot be read")
	}
	var config clusterProvisionConfig
	decoder := yaml.NewDecoder(bytes.NewReader(configRaw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, clusterProvisionNetwork{}, errors.New("cluster-config.yaml is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, clusterProvisionNetwork{}, errors.New("cluster-config.yaml must contain exactly one YAML document")
	}
	if config.Name != prepared.name || config.Type != "talos" ||
		config.ControlPlane.Replicas != 1 || config.ControlPlane.Cores != 2 || config.ControlPlane.Memory != "4Gi" || config.ControlPlane.Disk != "20Gi" ||
		config.Workers.Replicas != prepared.workers || config.Workers.Cores != 2 || config.Workers.Memory != "4Gi" || config.Workers.Disk != "15Gi" ||
		config.Versions.Kubernetes != prepared.kubernetesVersion || config.Versions.Talos != prepared.talosVersion ||
		config.OS.Distribution != "ok-linux" || config.OS.Profile != "kubevirt" || config.OS.SchematicID != clusterRequestSchematic || config.OS.Architecture != "amd64" ||
		!provisionSHA256Pattern.MatchString(config.OS.ImageDigest) || !provisionSHA256Pattern.MatchString(config.OS.Identity) ||
		config.OS.GoldenImage.Namespace != "ok-images" || config.OS.GoldenImage.Claim == "" || !config.OS.GoldenImage.Published || config.OS.GoldenImage.StorageClass != "ok-storage-block" ||
		config.ProviderProfile.Name != "ok-infra" || config.ProviderProfile.Identity != expectedProvisionProviderIdentity() || config.ProviderProfile.NodeSelector != "ok-infra" ||
		config.ProviderProfile.CloneTargetStorageClass != "ok-storage-block" || config.ProviderProfile.ReplicaCount != 2 || config.ProviderProfile.SnapshotClass != "ok-storage-block-snapshot" ||
		config.NodeSelector != "ok-infra" || config.Upgrade.Strategy != "blue-green" || config.Upgrade.WorkloadMigration.Stateless != "gitops" || config.Upgrade.WorkloadMigration.Stateful != "app-native" {
		return nil, clusterProvisionNetwork{}, errors.New("cluster-config.yaml differs from the validated request or fixed reference profile")
	}
	if err := validateProvisionNetwork(config.Network); err != nil {
		return nil, clusterProvisionNetwork{}, err
	}
	var artifacts []clusterProvisionArtifact
	var total int64
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || (!entry.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("scaffold contains a symlink or non-regular artifact")
		}
		if entry.IsDir() {
			return nil
		}
		if info.Size() > 32*1024*1024 || total+info.Size() > 128*1024*1024 {
			return errors.New("scaffold exceeds bounded artifact inspection limits")
		}
		total += info.Size()
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(raw)
		relative, relErr := filepath.Rel(dir, path)
		if relErr != nil || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("artifact path escapes scaffold")
		}
		artifacts = append(artifacts, clusterProvisionArtifact{name: relative, digest: hex.EncodeToString(digest[:])})
		return nil
	})
	if err != nil {
		return nil, clusterProvisionNetwork{}, errors.New("scaffold artifacts are not safely inspectable")
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].name < artifacts[j].name })
	if len(artifacts) < 2 || !containsProvisionArtifact(artifacts, "cluster-config.yaml") || !containsProvisionArtifact(artifacts, "cluster-base.yaml") {
		return nil, clusterProvisionNetwork{}, errors.New("scaffold is missing required configuration or Cluster manifest")
	}
	return artifacts, config.Network, nil
}

var provisionSHA256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func expectedProvisionProviderIdentity() string {
	digest := sha256.Sum256([]byte("talos-kubevirt-provider|ok-infra|ok-infra|ok-storage-block|2|ok-storage-block-snapshot"))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateProvisionNetwork(network clusterProvisionNetwork) error {
	endpoint, err := netip.ParseAddr(network.Endpoint)
	if err != nil || !endpoint.Is4() || !endpoint.IsGlobalUnicast() {
		return errors.New("resolved network.endpoint is missing or invalid")
	}
	pod, podErr := netip.ParsePrefix(network.PodCIDR)
	service, serviceErr := netip.ParsePrefix(network.ServiceCIDR)
	if podErr != nil || serviceErr != nil || !pod.Addr().Is4() || !service.Addr().Is4() || pod != pod.Masked() || service != service.Masked() ||
		pod.Overlaps(service) || pod.Contains(endpoint) || service.Contains(endpoint) {
		return errors.New("resolved Pod/Service CIDRs are missing, invalid, overlapping or conflict with endpoint")
	}
	return nil
}

func containsProvisionArtifact(artifacts []clusterProvisionArtifact, name string) bool {
	for _, artifact := range artifacts {
		if artifact.name == name {
			return true
		}
	}
	return false
}

func verifyProvisionInputs(ctx context.Context, prepared clusterProvisionPrepared, runtime clusterProvisionRuntime, allowScaffold bool) error {
	managementTarget, err := inspectProvisionManagementKubeconfig(prepared.managementKubeconfig)
	if err != nil {
		return err
	}
	if managementTarget.context != prepared.managementContext || managementTarget.server != prepared.managementAPIServer {
		return errors.New("management kubeconfig target changed after the request was prepared")
	}
	managementHash, err := hashRegularPrivateFile(prepared.managementKubeconfig, 4*1024*1024)
	if err != nil || managementHash != prepared.managementKubeconfigSHA256 {
		return errors.New("management kubeconfig changed after the request was prepared")
	}
	if err := verifyWorkloadKubeconfigDestination(prepared.workloadKubeconfig, prepared.name); err != nil {
		return err
	}
	if err := verifyProvisionChart(runtime); err != nil {
		return err
	}
	if err := verifyProvisionTools(runtime); err != nil {
		return err
	}
	if err := verifyProvisionCheckout(ctx, runtime, runtime.makeRoot, runtime.makeRevision, allowScaffold, prepared.name, true); err != nil {
		return fmt.Errorf("Make checkout is not the reviewed source: %w", err)
	}
	if err := verifyProvisionCheckout(ctx, runtime, runtime.okLinuxRoot, runtime.okLinuxRevision, false, "", false); err != nil {
		return fmt.Errorf("ok-linux checkout is not the reviewed source: %w", err)
	}
	return nil
}

func hashRegularPrivateFile(path string, maxBytes int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		return "", errors.New("file is not a bounded private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", errors.New("file changed while opening")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", err
	}
	if count > maxBytes {
		return "", errors.New("file grew beyond the bounded size")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyProvisionCheckout(ctx context.Context, runtime clusterProvisionRuntime, path, expectedRevision string, allowScaffold bool, clusterName string, makeCheckout bool) error {
	if !clusterProvisionSafePathPattern.MatchString(path) {
		return errors.New("checkout path contains unsupported characters")
	}
	if makeCheckout {
		info, err := os.Lstat(filepath.Join(path, "Makefile"))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Makefile is absent")
		}
	} else {
		info, err := os.Lstat(filepath.Join(path, "profiles", "kubevirt", "profile.yaml"))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 1024*1024 {
			return errors.New("pinned ok-linux KubeVirt profile is absent or unsafe")
		}
	}
	stdout := new(bytes.Buffer)
	gitPrefix := []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", path}
	if err := runProvisionCheck(ctx, runtime, runtime.toolPaths["git"], append(append([]string{}, gitPrefix...), "rev-parse", "HEAD"), path, stdout); err != nil || strings.TrimSpace(stdout.String()) != expectedRevision {
		return errors.New("checkout revision does not match its required full commit")
	}
	makefileChangeAllowed := false
	if makeCheckout {
		args := append(append([]string{}, gitPrefix...), "diff", "--quiet", "--no-ext-diff", "--no-textconv", runtime.reviewedMakeSource, "--", ".", ":(exclude)cmd/ok/**", ":(exclude)Makefile")
		if err := runProvisionCheck(ctx, runtime, runtime.toolPaths["git"], args, path, io.Discard); err != nil {
			return errors.New("Make source outside cmd/ok and the exact offline-smoke selector differs from the reviewed M2a baseline")
		}
		baseline := new(bytes.Buffer)
		showArgs := append(append([]string{}, gitPrefix...), "show", runtime.reviewedMakeSource+":Makefile")
		if err := runProvisionCheck(ctx, runtime, runtime.toolPaths["git"], showArgs, path, baseline); err != nil {
			return errors.New("reviewed Makefile baseline could not be verified")
		}
		current, err := os.ReadFile(filepath.Join(path, "Makefile"))
		if err != nil {
			return errors.New("Makefile could not be read safely")
		}
		makefileChangeAllowed = provisionMakefileHasOnlyOfflineSmokeSelectorChange(baseline.Bytes(), current)
		if !makefileChangeAllowed {
			return errors.New("Makefile differs from the reviewed baseline beyond the exact offline-smoke selector")
		}
	}
	status := new(bytes.Buffer)
	if err := runProvisionCheck(ctx, runtime, runtime.toolPaths["git"], append(append([]string{}, gitPrefix...), "status", "--porcelain", "--untracked-files=all"), path, status); err != nil {
		return errors.New("checkout status could not be verified")
	}
	if !allowScaffold && status.Len() != 0 && !(makeCheckout && makefileChangeAllowed && status.String() == " M Makefile\n") {
		return errors.New("checkout has local changes or untracked files")
	}
	if allowScaffold && !provisionStatusContainsOnlyScaffold(status.String(), clusterName) && !(makeCheckout && makefileChangeAllowed && provisionStatusContainsOnlyScaffoldAndMakefile(status.String(), clusterName)) {
		return errors.New("Make checkout has changes outside the newly generated scaffold")
	}
	return nil
}

func provisionMakefileHasOnlyOfflineSmokeSelectorChange(baseline, current []byte) bool {
	const before = "TestClusterPlan|TestClusterCreateManifestTemplateIsMachineReadableAndNonAuthorizing"
	const after = "TestClusterPlan|TestClusterProvision|TestClusterCreateManifestTemplateIsMachineReadableAndNonAuthorizing"
	if bytes.Count(baseline, []byte(before)) != 1 {
		return false
	}
	expected := bytes.Replace(baseline, []byte(before), []byte(after), 1)
	return bytes.Equal(expected, current)
}

func runProvisionCheck(parent context.Context, runtime clusterProvisionRuntime, executable string, args []string, directory string, stdout io.Writer) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, clusterProvisionCheckTimeout)
	defer cancel()
	return runtime.command(ctx, executable, args, directory, provisionEnvironment(runtime), stdout, io.Discard)
}

func provisionStatusContainsOnlyScaffold(status, clusterName string) bool {
	if status == "" {
		return true
	}
	for _, line := range strings.Split(strings.TrimSuffix(status, "\n"), "\n") {
		if len(line) < 4 || line[:3] != "?? " {
			return false
		}
		name := filepath.Clean(line[3:])
		if name != clusterName && !strings.HasPrefix(name, clusterName+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

func provisionStatusContainsOnlyScaffoldAndMakefile(status, clusterName string) bool {
	if status == "" {
		return true
	}
	makefileSeen := false
	for _, line := range strings.Split(strings.TrimSuffix(status, "\n"), "\n") {
		if line == " M Makefile" && !makefileSeen {
			makefileSeen = true
			continue
		}
		if len(line) < 4 || line[:3] != "?? " {
			return false
		}
		name := filepath.Clean(line[3:])
		if name != clusterName && !strings.HasPrefix(name, clusterName+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

func verifyProvisionTools(runtime clusterProvisionRuntime) error {
	for _, tool := range clusterProvisionRequiredTools {
		path := runtime.toolPaths[tool]
		if path == "" {
			return fmt.Errorf("required provisioning tool is not pinned: %s", tool)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			return fmt.Errorf("required provisioning tool is unavailable: %s", tool)
		}
	}
	if err := runProvisionCheck(context.Background(), runtime, runtime.toolPaths["python3"], []string{"-c", "import yaml"}, runtime.makeRoot, io.Discard); err != nil {
		return errors.New("python3 with PyYAML is required by the Make renderer")
	}
	return nil
}

func verifyProvisionChart(runtime clusterProvisionRuntime) error {
	path := filepath.Join(runtime.makeRoot, ".tools", "cilium-1.19.6.tgz")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("pinned Cilium chart is absent or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("pinned Cilium chart cannot be read")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return errors.New("pinned Cilium chart cannot be hashed")
	}
	if hex.EncodeToString(hash.Sum(nil)) != runtime.expectedChartHash {
		return errors.New("pinned Cilium chart SHA-256 does not match the reviewed Cilium 1.19.6 digest")
	}
	return nil
}

type provisionManagementTarget struct{ context, server string }

func inspectProvisionManagementKubeconfig(path string) (provisionManagementTarget, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !clusterProvisionSafePathPattern.MatchString(path) {
		return provisionManagementTarget{}, errors.New("TALOS_INFRA_KUBECONFIG must be an explicit absolute path with shell-safe characters")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return provisionManagementTarget{}, errors.New("management kubeconfig must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return provisionManagementTarget{}, errors.New("management kubeconfig permissions must be private (no group/other access)")
	}
	if info.Size() == 0 || info.Size() > 4*1024*1024 {
		return provisionManagementTarget{}, errors.New("management kubeconfig is empty or exceeds the bounded size")
	}
	file, err := os.Open(path)
	if err != nil {
		return provisionManagementTarget{}, errors.New("management kubeconfig cannot be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return provisionManagementTarget{}, errors.New("management kubeconfig changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 4*1024*1024+1))
	if err != nil || len(contents) > 4*1024*1024 {
		return provisionManagementTarget{}, errors.New("management kubeconfig exceeds the bounded size")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var config clusterProvisionKubeconfig
	if err := decoder.Decode(&config); err != nil {
		return provisionManagementTarget{}, errors.New("management kubeconfig is not valid Kubernetes YAML")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return provisionManagementTarget{}, errors.New("management kubeconfig must contain exactly one YAML document")
	}
	if config.APIVersion != "v1" || config.Kind != "Config" || config.CurrentContext == "" {
		return provisionManagementTarget{}, errors.New("management kubeconfig must identify one explicit current context")
	}
	var selectedContext *struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	}
	for i := range config.Contexts {
		if config.Contexts[i].Name == config.CurrentContext {
			if selectedContext != nil {
				return provisionManagementTarget{}, errors.New("management kubeconfig has duplicate current-context entries")
			}
			selectedContext = &config.Contexts[i]
		}
	}
	if selectedContext == nil || selectedContext.Context.Cluster == "" || selectedContext.Context.User == "" {
		return provisionManagementTarget{}, errors.New("management current-context has no complete cluster/user binding")
	}
	var server string
	clusterMatches := 0
	for _, cluster := range config.Clusters {
		if cluster.Name == selectedContext.Context.Cluster {
			clusterMatches++
			if cluster.Cluster.InsecureSkipTLSVerify || cluster.Cluster.ProxyURL != "" {
				return provisionManagementTarget{}, errors.New("management API TLS verification and direct endpoint routing are required")
			}
			server = cluster.Cluster.Server
		}
	}
	if clusterMatches != 1 {
		return provisionManagementTarget{}, errors.New("management current-context cluster reference is missing or ambiguous")
	}
	parsedServer, err := url.Parse(server)
	if err != nil || parsedServer.Scheme != "https" || parsedServer.Hostname() == "" || parsedServer.User != nil || parsedServer.RawQuery != "" || parsedServer.Fragment != "" {
		return provisionManagementTarget{}, errors.New("management API server must be an explicit HTTPS endpoint without embedded credentials")
	}
	userMatches := 0
	for _, user := range config.Users {
		if user.Name == selectedContext.Context.User {
			userMatches++
			if user.User.Exec != nil || user.User.AuthProvider != nil {
				return provisionManagementTarget{}, errors.New("external kubeconfig credential plugins are not allowed in the restricted operator execution environment")
			}
			if user.User.As != "" || user.User.AsUID != "" || len(user.User.AsGroups) != 0 {
				return provisionManagementTarget{}, errors.New("kubeconfig impersonation is not allowed for operator provisioning")
			}
		}
	}
	if userMatches != 1 {
		return provisionManagementTarget{}, errors.New("management current-context user reference is missing or ambiguous")
	}
	return provisionManagementTarget{context: config.CurrentContext, server: server}, nil
}

func verifyWorkloadKubeconfigDestination(path, clusterName string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != clusterName+".yaml" || !clusterProvisionSafePathPattern.MatchString(path) {
		return errors.New("--workload-kubeconfig must be an absolute shell-safe private path named <cluster>.yaml")
	}
	parent := filepath.Dir(path)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("workload kubeconfig parent must be an existing non-symlink directory")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o300 != 0o300 {
		return errors.New("workload kubeconfig parent must be private and owner-writable/traversable (normally mode 0700)")
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("workload kubeconfig destination already exists or cannot be safely checked")
	}
	return nil
}

func verifyProvisionClusterAbsent(ctx context.Context, prepared clusterProvisionPrepared, runtime clusterProvisionRuntime) error {
	stdout := new(bytes.Buffer)
	args := []string{"--kubeconfig", prepared.managementKubeconfig, "--request-timeout=15s", "get", "clusters.cluster.x-k8s.io", prepared.name, "-n", prepared.name, "--ignore-not-found", "-o", "name"}
	if err := runProvisionCheck(ctx, runtime, runtime.toolPaths["kubectl"], args, runtime.makeRoot, stdout); err != nil {
		return errors.New("management API access or Cluster absence could not be verified")
	}
	if strings.TrimSpace(stdout.String()) != "" {
		return errors.New("a Cluster with the requested name already exists or discovery returned ambiguous output")
	}
	return nil
}

func verifyProducedWorkloadKubeconfig(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("requested kubeconfig is missing, unsafe, empty or not private")
	}
	return nil
}

func provisionEnvironment(runtime clusterProvisionRuntime) []string {
	values := map[string]string{
		"PATH": runtime.environmentPath, "HOME": os.Getenv("HOME"),
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "PYTHONNOUSERSITE": "1",
		"PYTHONDONTWRITEBYTECODE": "1", "LANG": "C", "LC_ALL": "C",
		"OK_LINUX_PATH": runtime.okLinuxRoot, "TALOS_INFRA_KUBECONFIG": runtime.managementKubeconfig,
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if values[key] != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment
}

func runProvisionMake(ctx context.Context, runtime clusterProvisionRuntime, args []string, timeout time.Duration, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("invalid internal Make invocation")
	}
	if args[1] == "new" && runtime.newTimeout > 0 {
		timeout = runtime.newTimeout
	} else if args[1] == "bootstrap" && runtime.bootstrapTimeout > 0 {
		timeout = runtime.bootstrapTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stepContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stepContext, stopSignals := clusterProvisionSignalContext(stepContext)
	defer stopSignals()
	if err := runtime.command(stepContext, runtime.makeExecutable, args, runtime.makeRoot, provisionEnvironment(runtime), stdout, stderr); err != nil {
		if errors.Is(stepContext.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		if errors.Is(stepContext.Err(), context.Canceled) {
			return errors.New("cancelled")
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("exit status %d", exitError.ExitCode())
		}
		return errors.New("could not start or complete the Make process")
	}
	return nil
}

func printClusterProvisionPlan(output io.Writer, prepared clusterProvisionPrepared, runtime clusterProvisionRuntime) {
	fmt.Fprintf(output, "OK-76 operator provisioning plan\nRequest: %s (%s)\n", prepared.name, clusterRequestProfile)
	fmt.Fprintf(output, "Trusted Make checkout: %s @ %s (clean; provision sources match reviewed base %s)\n", runtime.makeRoot, runtime.makeRevision, runtime.reviewedMakeSource)
	fmt.Fprintf(output, "ok-linux checkout: %s @ %s (clean)\n", runtime.okLinuxRoot, runtime.okLinuxRevision)
	fmt.Fprintf(output, "Management kubeconfig: %s (explicit; contents are not displayed)\n", prepared.managementKubeconfig)
	fmt.Fprintf(output, "Management target: context=%s apiServer=%s (TLS verification enabled)\n", prepared.managementContext, prepared.managementAPIServer)
	fmt.Fprintf(output, "Cilium chart: %s sha256:%s\n", prepared.chartPath, runtime.expectedChartHash)
	fmt.Fprintln(output, "Child environment: explicit variable allowlist; PATH contains only isolated links to the resolved required tools. Ambient KUBECONFIG, Make flags, Docker context/host and credential overrides are omitted.")
	toolNames := make([]string, 0, len(runtime.toolPaths))
	for name := range runtime.toolPaths {
		toolNames = append(toolNames, name)
	}
	sort.Strings(toolNames)
	for _, name := range toolNames {
		fmt.Fprintf(output, "  tool %s: %s\n", name, runtime.toolPaths[name])
	}
	fmt.Fprintln(output, "Execution order (no other Make targets):")
	fmt.Fprintf(output, "  1. make %s\n", quotedProvisionArgs(prepared.newArgs))
	fmt.Fprintln(output, "     Creates local scaffold and performs explicit management Cluster/network inventory checks.")
	fmt.Fprintf(output, "  2. make %s\n", quotedProvisionArgs(prepared.bootstrapArgs))
	fmt.Fprintln(output, "     Applies CAPI resources, annotates management PVCs, obtains a workload kubeconfig and installs pinned Cilium.")
	fmt.Fprintf(output, "Local writes: %s and, during bootstrap, %s; kubectl/Helm may update standard caches under HOME. Temporary tool links are removed on exit.\n", filepath.Join(runtime.makeRoot, prepared.name), prepared.workloadKubeconfig)
	fmt.Fprintln(output, "Management access: reads Cluster and Service allocation inventory; bootstrap mutates management CAPI/PVC resources and workload Cilium resources.")
	fmt.Fprintln(output, "Network endpoint, Pod CIDR and Service CIDR remain auto until the scaffold is reviewed after make new.")
	fmt.Fprintln(output, "Interactive confirmation is an operator UX boundary, not protection from other locally privileged processes.")
	fmt.Fprintln(output, "No Runner grants, Stage Authority, independent evidence or readiness attestation are used.")
	fmt.Fprintf(output, "To authorize step 1, type exactly: provision %s\n", prepared.name)
}

func quotedProvisionArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = fmt.Sprintf("%q", arg)
	}
	return strings.Join(quoted, " ")
}

func requireProvisionConfirmation(input *bufio.Reader, output io.Writer, expected string) error {
	fmt.Fprintf(output, "Confirmation required; type exactly %q: ", expected)
	line, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("confirmation input failed")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line != expected {
		return errors.New("confirmation did not match")
	}
	return nil
}

func runClusterProvisionCommand(ctx context.Context, executable string, args []string, dir string, environment []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir, command.Env, command.Stdout, command.Stderr = dir, environment, stdout, stderr
	configureClusterProvisionProcess(command)
	return command.Run()
}
