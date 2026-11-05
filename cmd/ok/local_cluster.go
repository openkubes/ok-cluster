package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	localClusterStateFormat = "ok-cli-local-cluster/v2"
	localClusterDefaultName = "ok-local"
	localConsoleDefaultPort = 18787
	localOwnerLabel         = "cli.openkubes.io/local-owner"
)

var localOwnerIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var localClusterNamePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,28}[a-z0-9])?$`)

type localNodeIdentity struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type localContainerIdentity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type localProviderIdentity struct {
	Kind     string `json:"kind"`
	Context  string `json:"context"`
	Endpoint string `json:"endpoint"`
	DaemonID string `json:"daemonID"`
}

// localClusterState is an ownership receipt, not an authority by itself. Every
// destructive operation also checks OwnerID and the recorded Kubernetes
// identities against the live kind cluster through its private kubeconfig.
type localClusterState struct {
	Format        string                   `json:"format"`
	Name          string                   `json:"name"`
	OwnerID       string                   `json:"ownerID"`
	KindName      string                   `json:"kindName"`
	Provider      localProviderIdentity    `json:"provider"`
	Kubeconfig    string                   `json:"kubeconfig"`
	KubeSystemUID string                   `json:"kubeSystemUID"`
	Nodes         []localNodeIdentity      `json:"nodes"`
	Containers    []localContainerIdentity `json:"containers"`
	Forward       *localForwardIdentity    `json:"forward,omitempty"`
}

// A future managed forward is only stoppable after matching this whole process
// identity; PID is retained for lookup, never used as the authorization check.
type localForwardIdentity struct {
	PID             int    `json:"pid"`
	OwnerID         string `json:"ownerID"`
	StartedAt       string `json:"startedAt"`
	Executable      string `json:"executable"`
	ArgumentsSHA256 string `json:"argumentsSHA256"`
}

type localCommandRunner func(context.Context, string, ...string) ([]byte, error)

type localRuntime struct {
	stateRoot   string
	input       io.Reader
	interactive bool
	run         localCommandRunner
	runPinned   func(context.Context, localProviderIdentity, string, ...string) ([]byte, error)
}

func defaultLocalRuntime() localRuntime {
	root, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(root) {
		root = ""
	}
	stateRoot := ""
	if root != "" {
		stateRoot = filepath.Join(root, "ok", "local")
	}
	return localRuntime{
		stateRoot:   stateRoot,
		input:       os.Stdin,
		interactive: term.IsTerminal(int(os.Stdin.Fd())),
		run:         runLocalCommand,
		runPinned:   runLocalCommandPinned,
	}
}

func runLocalCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		if name == "kind" && len(arguments) >= 2 && arguments[0] == "get" && arguments[1] == "kubeconfig" {
			return nil, fmt.Errorf("%s %s failed: %w", name, strings.Join(arguments, " "), err)
		}
		return output, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func runLocalCommandPinned(ctx context.Context, provider localProviderIdentity, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "DOCKER_CONTEXT=") || strings.HasPrefix(item, "DOCKER_HOST=") || strings.HasPrefix(item, "DOCKER_TLS_VERIFY=") || strings.HasPrefix(item, "DOCKER_CERT_PATH=") || strings.HasPrefix(item, "KIND_EXPERIMENTAL_PROVIDER=") {
			continue
		}
		env = append(env, item)
	}
	command.Env = append(env, "DOCKER_HOST="+provider.Endpoint, "KIND_EXPERIMENTAL_PROVIDER=docker")
	output, err := command.CombinedOutput()
	if err != nil {
		if name == "kind" && len(arguments) >= 2 && arguments[0] == "get" && arguments[1] == "kubeconfig" {
			return nil, fmt.Errorf("%s %s failed: %w", name, strings.Join(arguments, " "), err)
		}
		return output, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func runLocalPinned(ctx context.Context, runtime localRuntime, provider localProviderIdentity, name string, arguments ...string) ([]byte, error) {
	if runtime.runPinned != nil {
		return runtime.runPinned(ctx, provider, name, arguments...)
	}
	return runtime.run(ctx, name, arguments...)
}

func runLocal(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runLocalWithRuntime(ctx, arguments, stdout, stderr, defaultLocalRuntime())
}

func runLocalWithRuntime(ctx context.Context, arguments []string, stdout, stderr io.Writer, runtime localRuntime) error {
	if len(arguments) == 0 || isHelpArgument(arguments[0]) {
		writeLocalHelp(stdout)
		return nil
	}
	if runtime.run == nil || runtime.stateRoot == "" {
		return errors.New("cannot locate the private local state directory")
	}
	switch arguments[0] {
	case "up":
		return runLocalUp(arguments[1:], stdout, stderr)
	case "status":
		return runLocalStatus(ctx, arguments[1:], runtime, stdout)
	case "down":
		return runLocalDown(ctx, arguments[1:], runtime, stdout, stderr)
	default:
		return errors.New("use ok local up, ok local status, or ok local down; see ok local --help")
	}
}

func runLocalUp(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok local up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", localClusterDefaultName, "Dedicated local kind cluster name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local up accepts no positional arguments and requires a valid --name")
	}
	return errors.New("ok local up is not enabled until the separately reviewed Console integration is available; no cluster was contacted or changed")
}

func runLocalStatus(ctx context.Context, arguments []string, runtime localRuntime, stdout io.Writer) error {
	flags := flag.NewFlagSet("ok local status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", localClusterDefaultName, "Managed local kind cluster name")
	jsonOutput := flags.Bool("json", false, "Print machine-readable status")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local status accepts no positional arguments and requires a valid --name")
	}
	state, err := readLocalClusterState(runtime.stateRoot, *name)
	if errors.Is(err, os.ErrNotExist) {
		return writeLocalStatus(stdout, *jsonOutput, localStatus{Format: "ok-cli-local-status/v1", State: "NOT_INSTALLED", Name: *name, ClusterContacted: false, ConsoleChecked: false})
	}
	if err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing cluster access: %w", err)
	}
	if err := validateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing cluster access: %w", err)
	}
	owned, present, err := observeLocalOwnership(ctx, runtime, state)
	if err != nil {
		return fmt.Errorf("could not verify local cluster ownership; no mutation allowed: %w", err)
	}
	status := localStatus{Format: "ok-cli-local-status/v1", Name: *name, ClusterContacted: true, ConsoleChecked: false}
	if !present {
		status.State = "CLUSTER_MISSING"
	} else if !owned {
		status.State = "OWNERSHIP_UNVERIFIED"
	} else {
		status.State = "OWNED_CLUSTER_PRESENT"
	}
	if err := writeLocalStatus(stdout, *jsonOutput, status); err != nil {
		return err
	}
	if present && !owned {
		return errors.New("live cluster identity does not match the local ownership receipt; no action was taken")
	}
	return nil
}

func runLocalDown(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok local down", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", localClusterDefaultName, "Managed local kind cluster name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local down accepts no positional arguments and requires a valid --name")
	}
	if !runtime.interactive || runtime.input == nil {
		return errors.New("ok local down requires a terminal and explicit ok/no confirmation")
	}
	state, err := readLocalClusterState(runtime.stateRoot, *name)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no local ownership receipt exists; refusing to inspect or delete a cluster by name")
	}
	if err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing deletion: %w", err)
	}
	if err := validateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing deletion: %w", err)
	}
	owned, present, err := observeLocalOwnership(ctx, runtime, state)
	if err != nil {
		return fmt.Errorf("could not verify local cluster ownership; refusing deletion: %w", err)
	}
	if !present || !owned {
		return errors.New("live cluster identity does not match the ownership receipt; refusing deletion")
	}
	if _, err := fmt.Fprintf(stdout, "Delete the verified ok-managed local cluster %q and its private kubeconfig? Type ok or no: ", *name); err != nil {
		return err
	}
	answer, err := bufio.NewReader(runtime.input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(answer) != "ok" {
		_, _ = fmt.Fprintln(stdout, "Cancelled; cluster and local state were not changed.")
		return nil
	}
	// Recheck after the confirmation prompt, which may have taken arbitrary time.
	owned, present, err = observeLocalOwnership(ctx, runtime, state)
	if err != nil || !present || !owned {
		if err != nil {
			return fmt.Errorf("ownership changed or could not be verified after confirmation; refusing deletion: %w", err)
		}
		return errors.New("ownership changed after confirmation; refusing deletion")
	}
	// Last pre-delete checks reduce the check-to-delete window and ensure all
	// external commands remain pinned to the inspected provider context.
	clusters, err := runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "clusters")
	if err != nil {
		return fmt.Errorf("recheck pinned kind provider immediately before deletion: %w", err)
	}
	if !containsExactLine(string(clusters), state.KindName) {
		return errors.New("verified Kind cluster disappeared after confirmation; refusing name-based deletion")
	}
	containersBeforeDelete, err := observeLocalKindContainers(ctx, runtime, state.Provider, state.KindName)
	if err != nil || !sameLocalContainers(containersBeforeDelete, state.Containers) {
		if err != nil {
			return fmt.Errorf("recheck exact container identities immediately before deletion: %w", err)
		}
		return errors.New("Kind node container identity changed immediately before deletion")
	}
	providerBeforeDelete, err := observeLocalDockerProvider(ctx, runtime)
	if err != nil || providerBeforeDelete != state.Provider {
		if err != nil {
			return fmt.Errorf("recheck Docker provider immediately before deletion: %w", err)
		}
		return errors.New("Docker provider identity changed immediately before deletion")
	}
	if _, err := runLocalPinned(ctx, runtime, state.Provider, "kind", "delete", "cluster", "--name", state.KindName, "--kubeconfig", state.Kubeconfig); err != nil {
		return fmt.Errorf("delete verified local kind cluster; ownership state retained for recovery: %w", err)
	}
	clusters, err = runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "clusters")
	if err != nil {
		return fmt.Errorf("verify local kind cluster deletion; ownership state retained: %w", err)
	}
	if containsExactLine(string(clusters), state.KindName) {
		return errors.New("kind still reports the cluster after deletion; ownership state retained")
	}
	containers, err := observeLocalKindContainers(ctx, runtime, state.Provider, state.KindName)
	if err != nil {
		return fmt.Errorf("verify local kind containers were removed; ownership state retained: %w", err)
	}
	if len(containers) != 0 {
		return errors.New("kind cluster name is gone but owner-labeled containers remain; ownership state retained")
	}
	if err := removeLocalClusterState(runtime.stateRoot, *name); err != nil {
		return fmt.Errorf("cluster is deleted but private local state cleanup is incomplete: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Deleted verified local cluster %q.\n", *name)
	return err
}

type localStatus struct {
	Format           string `json:"format"`
	State            string `json:"state"`
	Name             string `json:"name"`
	ClusterContacted bool   `json:"clusterContacted"`
	ConsoleChecked   bool   `json:"consoleChecked"`
}

func writeLocalStatus(output io.Writer, jsonOutput bool, status localStatus) error {
	if jsonOutput {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(status)
	}
	_, err := fmt.Fprintf(output, "Local cluster %s: %s (Console status not available until integration is enabled).\n", status.Name, status.State)
	return err
}

func localStateFilePath(root, name string) string {
	return filepath.Join(root, "clusters", name, "state.json")
}

func readLocalClusterState(root, name string) (localClusterState, error) {
	var state localClusterState
	path := localStateFilePath(root, name)
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 64*1024 {
		return state, errors.New("state must be a private regular file (0600 or stricter), not a symlink, at most 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return state, errors.New("state changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return state, errors.New("cannot read bounded local state")
	}
	if err := jsonstrict.Decode(raw, &state); err != nil {
		return state, errors.New("invalid local state: reject unknown/duplicate fields, wrong types or trailing data")
	}
	return state, nil
}

func validateLocalClusterState(root, name string, state localClusterState) error {
	parentInfo, parentErr := os.Lstat(filepath.Dir(root))
	if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("parent of local state root must be a private directory, not a symlink")
	}
	for _, directory := range []string{root, filepath.Join(root, "clusters")} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("local state directories must be private (0700 or stricter), not symlinks")
		}
	}
	clusterDir := filepath.Join(root, "clusters", name)
	dirInfo, err := os.Lstat(clusterDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("cluster state directory must be private (0700 or stricter), not a symlink")
	}
	if state.Format != localClusterStateFormat || state.Name != name || !localClusterNamePattern.MatchString(name) || !localOwnerIDPattern.MatchString(state.OwnerID) || state.KindName != localKindClusterName(name, state.OwnerID) {
		return errors.New("unsupported local state format, cluster name or owner identifier")
	}
	if state.Provider.Kind != "docker" || state.Provider.Context == "" || !strings.HasPrefix(state.Provider.Endpoint, "unix://") || state.Provider.DaemonID == "" {
		return errors.New("local Docker provider identity is incomplete or unsupported")
	}
	expectedKubeconfig := filepath.Join(clusterDir, "kubeconfig")
	if state.Kubeconfig != expectedKubeconfig || !filepath.IsAbs(state.Kubeconfig) || filepath.Clean(state.Kubeconfig) != state.Kubeconfig {
		return errors.New("kubeconfig path is not the isolated path bound to this local cluster")
	}
	if state.KubeSystemUID == "" || strings.ContainsAny(state.KubeSystemUID, " \t\r\n") || len(state.Nodes) == 0 {
		return errors.New("cluster identity receipt is incomplete")
	}
	if len(state.Nodes) > 32 {
		return errors.New("cluster identity receipt exceeds the node limit")
	}
	seen := map[string]bool{}
	for _, node := range state.Nodes {
		if node.Name == "" || node.UID == "" || strings.ContainsAny(node.Name+node.UID, " \t\r\n") || seen[node.Name] {
			return errors.New("cluster node identity receipt is invalid")
		}
		seen[node.Name] = true
	}
	if len(state.Containers) == 0 || len(state.Containers) > 32 {
		return errors.New("Docker container identity receipt is incomplete")
	}
	containerIDs := map[string]bool{}
	for _, container := range state.Containers {
		if container.ID == "" || container.Name == "" || (container.Role != "control-plane" && container.Role != "worker") || containerIDs[container.ID] {
			return errors.New("Docker container identity receipt is invalid")
		}
		containerIDs[container.ID] = true
	}
	if state.Forward != nil {
		if state.Forward.PID <= 0 || state.Forward.OwnerID != state.OwnerID || state.Forward.StartedAt == "" ||
			!filepath.IsAbs(state.Forward.Executable) || !sha256DigestPattern.MatchString(state.Forward.ArgumentsSHA256) {
			return errors.New("managed port-forward process identity is invalid")
		}
	}
	kubeconfigInfo, err := os.Lstat(state.Kubeconfig)
	if err != nil || !kubeconfigInfo.Mode().IsRegular() || kubeconfigInfo.Mode()&os.ModeSymlink != 0 || kubeconfigInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("isolated kubeconfig must be a private regular file (0600 or stricter), not a symlink")
	}
	return nil
}

type localNodeList struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	} `json:"items"`
}

type localNamespace struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
}

func observeLocalOwnership(ctx context.Context, runtime localRuntime, state localClusterState) (owned, present bool, err error) {
	provider, err := observeLocalDockerProvider(ctx, runtime)
	if err != nil {
		return false, false, err
	}
	if provider != state.Provider {
		return false, false, errors.New("active Docker provider identity differs from the recorded provider")
	}
	clusterList, err := runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "clusters")
	if err != nil {
		return false, false, err
	}
	if !containsExactLine(string(clusterList), state.KindName) {
		containers, containerErr := observeLocalKindContainers(ctx, runtime, state.Provider, state.KindName)
		if containerErr != nil {
			return false, false, containerErr
		}
		if len(containers) != 0 {
			return false, true, errors.New("Kind cluster is absent but owner-labeled containers remain")
		}
		return false, false, nil
	}
	containers, err := observeLocalKindContainers(ctx, runtime, state.Provider, state.KindName)
	if err != nil {
		return false, true, err
	}
	if !sameLocalContainers(containers, state.Containers) {
		return false, len(containers) > 0, errors.New("live kind container IDs/names/roles differ from the ownership receipt")
	}
	kindConfig, err := runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "kubeconfig", "--name", state.KindName)
	if err != nil {
		return false, true, err
	}
	privateConfig, err := readBoundedLocalFile(state.Kubeconfig, 4*1024*1024)
	if err != nil {
		return false, true, fmt.Errorf("read isolated kubeconfig: %w", err)
	}
	if err := compareKindKubeconfig(kindConfig, privateConfig, "kind-"+state.KindName); err != nil {
		return false, true, err
	}
	contextName := "kind-" + state.KindName
	nodeJSON, err := runtime.run(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", contextName, "get", "nodes", "-o", "json")
	if err != nil {
		return false, true, err
	}
	var nodes localNodeList
	if err := json.Unmarshal(nodeJSON, &nodes); err != nil || len(nodes.Items) == 0 || len(nodes.Items) > 32 {
		return false, true, errors.New("could not parse bounded node identity from the isolated kind context")
	}
	namespaceJSON, err := runtime.run(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", contextName, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return false, true, err
	}
	var namespace localNamespace
	if err := json.Unmarshal(namespaceJSON, &namespace); err != nil || namespace.Metadata.UID == "" {
		return false, true, errors.New("could not parse kube-system namespace identity")
	}
	observed := make([]localNodeIdentity, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		if node.Metadata.Labels[localOwnerLabel] != state.OwnerID {
			return false, true, nil
		}
		observed = append(observed, localNodeIdentity{Name: node.Metadata.Name, UID: node.Metadata.UID})
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].Name < observed[j].Name })
	expected := append([]localNodeIdentity(nil), state.Nodes...)
	sort.Slice(expected, func(i, j int) bool { return expected[i].Name < expected[j].Name })
	if namespace.Metadata.UID != state.KubeSystemUID || len(observed) != len(expected) {
		return false, true, nil
	}
	for i := range observed {
		if observed[i] != expected[i] {
			return false, true, nil
		}
	}
	return true, true, nil
}

func observeLocalDockerProvider(ctx context.Context, runtime localRuntime) (localProviderIdentity, error) {
	contextOutput, err := runtime.run(ctx, "docker", "context", "show")
	if err != nil {
		return localProviderIdentity{}, err
	}
	contextName := strings.TrimSpace(string(contextOutput))
	if contextName == "" || strings.ContainsAny(contextName, "\r\n") {
		return localProviderIdentity{}, errors.New("cannot determine active Docker context")
	}
	endpointOutput, err := runtime.run(ctx, "docker", "context", "inspect", contextName, "--format", "{{.Endpoints.docker.Host}}")
	if err != nil {
		return localProviderIdentity{}, err
	}
	endpoint := strings.TrimSpace(string(endpointOutput))
	if !strings.HasPrefix(endpoint, "unix://") {
		return localProviderIdentity{}, errors.New("local workflow requires a local unix-socket Docker endpoint")
	}
	daemonOutput, err := runtime.run(ctx, "docker", "--context", contextName, "info", "--format", "{{.ID}}")
	if err != nil {
		return localProviderIdentity{}, err
	}
	daemonID := strings.TrimSpace(string(daemonOutput))
	if daemonID == "" || strings.ContainsAny(daemonID, "\r\n") {
		return localProviderIdentity{}, errors.New("cannot determine Docker daemon identity")
	}
	return localProviderIdentity{Kind: "docker", Context: contextName, Endpoint: endpoint, DaemonID: daemonID}, nil
}

func observeLocalKindContainers(ctx context.Context, runtime localRuntime, provider localProviderIdentity, kindName string) ([]localContainerIdentity, error) {
	format := `{{.ID}}|{{.Names}}|{{.Label "io.x-k8s.kind.role"}}`
	output, err := runLocalPinned(ctx, runtime, provider, "docker", "ps", "-a", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster="+kindName, "--format", format)
	if err != nil {
		return nil, err
	}
	var result []localContainerIdentity
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || (parts[2] != "control-plane" && parts[2] != "worker") {
			return nil, errors.New("Docker returned malformed kind container identity")
		}
		result = append(result, localContainerIdentity{ID: parts[0], Name: parts[1], Role: parts[2]})
		if len(result) > 32 {
			return nil, errors.New("kind container identity exceeds node limit")
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func sameLocalContainers(a, b []localContainerIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]localContainerIdentity(nil), a...)
	right := append([]localContainerIdentity(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func localKindClusterName(name, ownerID string) string {
	// The full random owner ID makes accidental same-name replacement extremely unlikely.
	// The logical name is bounded so the resulting DNS label remains <= 63 characters.
	return name + "-" + ownerID
}

func compareKindKubeconfig(kindRaw, privateRaw []byte, expectedContext string) error {
	var kindConfig, privateConfig localKubeconfig
	if err := yaml.Unmarshal(kindRaw, &kindConfig); err != nil {
		return errors.New("kind did not return a valid kubeconfig for its named cluster")
	}
	if err := yaml.Unmarshal(privateRaw, &privateConfig); err != nil {
		return errors.New("isolated kubeconfig is invalid")
	}
	if kindConfig.CurrentContext != expectedContext || privateConfig.CurrentContext != expectedContext ||
		len(kindConfig.Contexts) != 1 || len(kindConfig.Clusters) != 1 || len(kindConfig.Users) != 1 ||
		len(privateConfig.Contexts) != 1 || len(privateConfig.Clusters) != 1 || len(privateConfig.Users) != 1 {
		return errors.New("kubeconfig must contain only the exact named kind context, cluster and user")
	}
	kindContext := kindConfig.Contexts[0]
	privateContext := privateConfig.Contexts[0]
	kindCluster := kindConfig.Clusters[0]
	privateCluster := privateConfig.Clusters[0]
	kindUser := kindConfig.Users[0]
	privateUser := privateConfig.Users[0]
	if kindContext.Name != expectedContext || privateContext.Name != expectedContext ||
		kindCluster.Name != expectedContext || privateCluster.Name != expectedContext ||
		kindUser.Name != expectedContext || privateUser.Name != expectedContext ||
		kindContext.Context.Cluster != expectedContext || kindContext.Context.User != expectedContext ||
		privateContext.Context.Cluster != expectedContext || privateContext.Context.User != expectedContext ||
		kindCluster.Cluster.Server == "" || kindCluster.Cluster.Server != privateCluster.Cluster.Server ||
		kindCluster.Cluster.CertificateAuthorityData == "" || kindCluster.Cluster.CertificateAuthorityData != privateCluster.Cluster.CertificateAuthorityData ||
		privateCluster.Cluster.CertificateAuthority != "" || privateCluster.Cluster.InsecureSkipTLSVerify ||
		privateCluster.Cluster.TLSServerName != kindCluster.Cluster.TLSServerName || privateCluster.Cluster.ProxyURL != kindCluster.Cluster.ProxyURL ||
		kindUser.User.ClientCertificateData == "" || kindUser.User.ClientKeyData == "" ||
		kindUser.User.ClientCertificateData != privateUser.User.ClientCertificateData ||
		kindUser.User.ClientKeyData != privateUser.User.ClientKeyData ||
		privateUser.User.Token != "" || privateUser.User.TokenFile != "" || privateUser.User.Username != "" || privateUser.User.Password != "" ||
		privateUser.User.ClientCertificate != "" || privateUser.User.ClientKey != "" ||
		privateUser.User.Exec != nil || privateUser.User.AuthProvider != nil {
		return errors.New("isolated kubeconfig does not match the live kind cluster identity")
	}
	return nil
}

type localKubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			TLSServerName            string `yaml:"tls-server-name"`
			ProxyURL                 string `yaml:"proxy-url"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string     `yaml:"client-certificate-data"`
			ClientKeyData         string     `yaml:"client-key-data"`
			ClientCertificate     string     `yaml:"client-certificate"`
			ClientKey             string     `yaml:"client-key"`
			Token                 string     `yaml:"token"`
			TokenFile             string     `yaml:"tokenFile"`
			Username              string     `yaml:"username"`
			Password              string     `yaml:"password"`
			Exec                  *yaml.Node `yaml:"exec"`
			AuthProvider          *yaml.Node `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func containsExactLine(text, wanted string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

func newLocalOwnerID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate local cluster owner identifier: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func renderKindOwnershipConfig(name, ownerID string) ([]byte, error) {
	if !localClusterNamePattern.MatchString(name) || !localOwnerIDPattern.MatchString(ownerID) {
		return nil, errors.New("invalid kind cluster name or owner identifier")
	}
	config := fmt.Sprintf(`kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
	name: %s
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: %s=%s
`, localKindClusterName(name, ownerID), localOwnerLabel, ownerID)
	return []byte(config), nil
}

func writeLocalClusterState(root, name string, state localClusterState) error {
	clusterDir, err := initLocalStateDirectory(root, name)
	if err != nil {
		return err
	}
	if err := validateLocalClusterState(root, name, state); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := filepath.Join(clusterDir, "state.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(clusterDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}

func removeLocalClusterState(root, name string) error {
	clusterDir := filepath.Join(root, "clusters", name)
	paths := []string{filepath.Join(clusterDir, "state.json"), filepath.Join(clusterDir, "kubeconfig")}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to remove unexpected local state path")
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if err := os.Remove(clusterDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("local cluster directory is not empty or could not be removed: %w", err)
	}
	return nil
}

func writeLocalHelp(output io.Writer) {
	fmt.Fprint(output, `Manage the dedicated local kind + Console demo environment

Usage:
  ok local <command> [flags]

Commands:
  up       Create the local kind cluster and deploy the Console demo (integration pending)
  status   Inspect an ok-owned local cluster using its isolated kubeconfig
  down     Confirm and delete only a cluster whose live identity matches its receipt

The local workflow is independent of OK-147 CreateCluster. It never selects the
global/current Kubernetes context. The first MVP uses the Console local-kind
fixture profile; no production identity or database is installed.
`)
}

func writeLocalCommandHelp(command string, output io.Writer) {
	switch command {
	case "up":
		fmt.Fprint(output, "Usage: ok local up [--name ok-local]\n\nCreates one managed local kind cluster and deploys the Console demo. This command remains disabled until the separately reviewed Console integration is available.\n")
	case "status":
		fmt.Fprint(output, "Usage: ok local status [--name ok-local] [--json]\n\nRead-only ownership inspection through the isolated kubeconfig; Console health reporting is added with the Console integration.\n")
	case "down":
		fmt.Fprint(output, "Usage: ok local down [--name ok-local]\n\nRequires an interactive ok/no confirmation and a live ownership match. No state file or cluster name alone authorizes deletion.\n")
	default:
		writeLocalHelp(output)
	}
}

func initLocalStateDirectory(root, name string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || !localClusterNamePattern.MatchString(name) {
		return "", errors.New("local state root must be absolute and cluster name valid")
	}
	if runtime.GOOS == "windows" {
		return "", errors.New("local kind state permissions are not supported on this platform yet")
	}
	parent := filepath.Dir(root)
	grandparentInfo, err := os.Lstat(filepath.Dir(parent))
	if err != nil || !grandparentInfo.IsDir() || grandparentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("parent of local state root must be beneath an existing non-symlink directory")
	}
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("parent of local state root must be a private directory, not a symlink")
	}
	clusters := filepath.Join(root, "clusters")
	clusterDir := filepath.Join(clusters, name)
	for _, directory := range []string{root, clusters, clusterDir} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("local state directories must be private (0700 or stricter), not symlinks")
		}
	}
	return clusterDir, nil
}
