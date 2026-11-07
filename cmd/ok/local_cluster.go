package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	localClusterStateFormat        = "ok-cli-local-cluster/v3"
	localBootstrapStateFormat      = "ok-cli-local-bootstrap-cluster/v1"
	localClusterDefaultName        = "ok-local"
	localConsoleDefaultPort        = 18787
	localOwnerLabel                = "cli.openkubes.io/local-owner"
	localKindMinimumVersion        = "0.33.0"
	localKindMaxNameLength         = 49
	localKindPreviousMaxNameLength = 50
	localKindControlPlaneSuffix    = "-control-plane"
	localKindDiagnosticOutputLimit = 1 << 20
)

var localOwnerIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var localClusterNamePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,28}[a-z0-9])?$`)
var localKindClusterNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var localBashVersionPattern = regexp.MustCompile(`version ([0-9]+)\.([0-9]+)`)
var localKindVersionPattern = regexp.MustCompile(`kind v([0-9]+)\.([0-9]+)\.([0-9]+)`)

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
	Phase         string                   `json:"phase"`
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

type localBootstrapDiagnosticReceipt struct {
	Format         string                   `json:"format"`
	Name           string                   `json:"name"`
	OwnerID        string                   `json:"ownerID"`
	KindName       string                   `json:"kindName"`
	Provider       localProviderIdentity    `json:"provider"`
	ConfigSHA256   string                   `json:"configSHA256"`
	State          string                   `json:"state"`
	FailureCode    string                   `json:"failureCode,omitempty"`
	ResourceState  string                   `json:"resourceState"`
	Containers     []localContainerIdentity `json:"containers,omitempty"`
	KubeconfigSeen bool                     `json:"kubeconfigSeen"`
}

type localKindCreateRunner func(context.Context, localProviderIdentity, string, ...string) ([]byte, bool, error)

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
	stateRoot      string
	consoleRoot    string
	input          io.Reader
	interactive    bool
	run            localCommandRunner
	newOwnerID     func() (string, error)
	runPinned      func(context.Context, localProviderIdentity, string, ...string) ([]byte, error)
	runKindCreate  localKindCreateRunner
	runVerifier    func(context.Context, string, map[string]string) error
	inspectForward func(localForwardIdentity) (localForwardProcessState, error)
	stopForward    func(localForwardIdentity) error
	checkLocalPort func(int) error
	startForward   func(context.Context, localClusterState) (localForwardIdentity, error)
	waitConsole    func(context.Context, int) error
	lookPath       func(string) (string, error)
	runCAPI        localCAPICommandRunner
}

type localVerifierFailure struct {
	stage    string
	code     string
	exitCode string
}

func (failure localVerifierFailure) Error() string { return formatLocalVerifierFailure(failure) }

type localForwardProcessState string

const (
	localForwardAbsent    localForwardProcessState = "ABSENT"
	localForwardMatches   localForwardProcessState = "MATCHES"
	localForwardPIDReused localForwardProcessState = "PID_REUSED"
)

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
		stateRoot:      stateRoot,
		consoleRoot:    findLocalConsoleRoot(),
		input:          os.Stdin,
		interactive:    term.IsTerminal(int(os.Stdin.Fd())),
		run:            runLocalCommand,
		runPinned:      runLocalCommandPinned,
		runKindCreate:  runLocalKindCreatePinned,
		runVerifier:    runLocalConsoleVerifier,
		checkLocalPort: ensureLocalPortAvailable,
		startForward:   startLocalForward,
		stopForward:    stopLocalForward,
		waitConsole:    waitLocalConsole,
		lookPath:       exec.LookPath,
		runCAPI:        runLocalCAPICommand,
	}
}

func runLocalCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	if isLocalKindKubeconfigCommand(name, arguments) {
		return runLocalStdoutOnly(command, name, arguments...)
	}
	if isLocalKubectlStructuredCommand(name, arguments) {
		return runLocalStructuredStdout(command)
	}
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
	if isLocalKindKubeconfigCommand(name, arguments) {
		return runLocalStdoutOnly(command, name, arguments...)
	}
	if isLocalKubectlStructuredCommand(name, arguments) {
		return runLocalStructuredStdout(command)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		if name == "kind" && len(arguments) >= 2 && arguments[0] == "get" && arguments[1] == "kubeconfig" {
			return nil, fmt.Errorf("%s %s failed: %w", name, strings.Join(arguments, " "), err)
		}
		return output, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func isLocalKubectlStructuredCommand(name string, arguments []string) bool {
	if name != "kubectl" {
		return false
	}
	for i, argument := range arguments {
		if argument == "-o" || argument == "--output" {
			return i+1 < len(arguments) && arguments[i+1] == "json"
		}
		if argument == "-o=json" || argument == "--output=json" {
			return true
		}
	}
	return false
}

// runLocalStructuredStdout keeps machine-readable stdout separate from
// potentially sensitive kubectl warnings on stderr. Stderr is bounded and
// intentionally discarded; command failures expose only a generic message and
// an exit code, never either stream.
func runLocalStructuredStdout(command *exec.Cmd) ([]byte, error) {
	var stderr boundedDiagnosticOutput
	stderr.limit = 64 * 1024
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("kubectl structured command failed (exit %d)", exit.ExitCode())
		}
		return nil, errors.New("kubectl structured command failed")
	}
	return output, nil
}

func isLocalKindKubeconfigCommand(name string, arguments []string) bool {
	return name == "kind" && len(arguments) >= 2 && arguments[0] == "get" && arguments[1] == "kubeconfig"
}

func runLocalStdoutOnly(command *exec.Cmd, name string, arguments ...string) ([]byte, error) {
	// Kind may write provider-selection notices to stderr. Keep that stream
	// separate so only kubeconfig YAML on stdout reaches the parser.
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s failed: %w", name, strings.Join(arguments, " "), err)
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
		return runLocalUp(ctx, arguments[1:], runtime, stdout, stderr)
	case "resume":
		return runLocalResume(ctx, arguments[1:], runtime, stdout, stderr)
	case "reconnect":
		return runLocalReconnect(ctx, arguments[1:], runtime, stdout, stderr)
	case "status":
		return runLocalStatus(ctx, arguments[1:], runtime, stdout)
	case "down":
		return runLocalDown(ctx, arguments[1:], runtime, stdout, stderr)
	case "diagnose":
		if len(arguments) < 2 || arguments[1] != "bootstrap" {
			return errors.New("use ok local diagnose bootstrap --name <fresh-logical-name>; see ok local diagnose --help")
		}
		return runLocalDiagnoseBootstrap(ctx, arguments[2:], runtime, stdout, stderr)
	default:
		return errors.New("use ok local up, ok local resume, ok local reconnect, ok local status, or ok local down; see ok local --help")
	}
}

func runLocalKindCreatePinned(ctx context.Context, provider localProviderIdentity, kubeconfig string, arguments ...string) ([]byte, bool, error) {
	command := exec.CommandContext(ctx, "kind", arguments...)
	env := make([]string, 0, len(os.Environ())+3)
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		if key == "DOCKER_CONTEXT" || key == "DOCKER_HOST" || key == "DOCKER_TLS_VERIFY" || key == "DOCKER_CERT_PATH" || key == "KIND_EXPERIMENTAL_PROVIDER" || key == "KUBECONFIG" {
			continue
		}
		env = append(env, item)
	}
	command.Env = append(env, "DOCKER_HOST="+provider.Endpoint, "KIND_EXPERIMENTAL_PROVIDER=docker", "KUBECONFIG="+kubeconfig)
	output := &boundedDiagnosticOutput{limit: localKindDiagnosticOutputLimit}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	return output.Bytes(), output.truncated, err
}

type boundedDiagnosticOutput struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (output *boundedDiagnosticOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	original := len(data)
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.truncated = true
		return original, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		output.truncated = true
	}
	_, err := output.buffer.Write(data)
	return original, err
}

func (output *boundedDiagnosticOutput) Bytes() []byte {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.buffer.Bytes()...)
}

func runLocalUp(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) (result error) {
	flags := flag.NewFlagSet("ok local up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", localClusterDefaultName, "Dedicated local kind cluster name")
	bootstrap := flags.String("bootstrap", "", "Experimental bootstrap mode (currently: capi)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local up accepts no positional arguments and requires a valid --name")
	}
	bootstrapSet := false
	flags.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "bootstrap" {
			bootstrapSet = true
		}
	})
	if bootstrapSet {
		if *bootstrap != "capi" {
			return errors.New("unsupported --bootstrap mode; the only recognized experimental value is capi")
		}
		if err := runLocalCAPIUpContext(ctx, *name, runtime); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stdout, "Temporary CAPI bootstrap %q is ready; lifecycle phase CAPI_READY. No workload cluster was provisioned or moved.\n", *name)
		return err
	}
	if _, err := os.Lstat(localCAPIStateDirectory(runtime.stateRoot, *name)); err == nil {
		return errors.New("CAPI lifecycle ownership exists for this name; the Console workflow will not adopt or overwrite it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot safely inspect CAPI lifecycle ownership; the Console workflow stopped")
	}
	if runtime.consoleRoot == "" || runtime.runVerifier == nil {
		return errors.New("cannot find the ok-console checkout and local-kind verifier; set OK_CONSOLE_DIR; no cluster was contacted")
	}
	if err := ensureLocalPortAvailable(localConsoleDefaultPort); err != nil {
		return err
	}
	if _, err := os.Stat(localStateFilePath(runtime.stateRoot, *name)); err == nil {
		return errors.New("local ownership state already exists; inspect with ok local status; automatic retries are disabled")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect existing local state: %w", err)
	}
	if _, err := os.Lstat(localBootstrapDiagnosticPath(runtime.stateRoot, *name)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("local bootstrap diagnostic receipt already exists; normal up will not adopt or retry it")
	}
	revision, err := runtime.run(ctx, "git", "-C", runtime.consoleRoot, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(revision)) == "" {
		return errors.New("cannot identify the Console source revision; no local state or cluster change was made")
	}
	dirty, err := runtime.run(ctx, "git", "-C", runtime.consoleRoot, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return fmt.Errorf("cannot verify the Console source tree before preparation: %w", err)
	}
	if strings.TrimSpace(string(dirty)) != "" {
		return errors.New("Console checkout is dirty; the existing local-image source cleanliness check requires a clean tree, including untracked files; no local state or cluster change was made")
	}
	bashVersion, err := runtime.run(ctx, "bash", "--version")
	if err != nil {
		return fmt.Errorf("Bash 4.4 or newer is required before local preparation: %w", err)
	}
	versionMatch := localBashVersionPattern.FindStringSubmatch(string(bashVersion))
	if len(versionMatch) != 3 {
		return errors.New("cannot establish Bash version; require Bash 4.4 or newer before local preparation")
	}
	major, _ := strconv.Atoi(versionMatch[1])
	minor, _ := strconv.Atoi(versionMatch[2])
	if major < 4 || (major == 4 && minor < 4) {
		return errors.New("Bash 4.4 or newer is required; no local state or cluster change was made")
	}
	kindVersion, err := runtime.run(ctx, "kind", "version")
	if err != nil || !localKindVersionSupported(string(kindVersion), localKindMinimumVersion) {
		return fmt.Errorf("kind %s or newer is required for isolated kubeconfig creation; no local state or cluster change was made", localKindMinimumVersion)
	}
	releaseOperation, err := acquireLocalLifecycleOperationLock(runtime.stateRoot, *name)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseOperation(); err != nil {
			result = errors.Join(result, errors.New("local lifecycle lock could not be safely released; inspect it before another up"))
		}
	}()
	if _, err := os.Lstat(localCAPIStateDirectory(runtime.stateRoot, *name)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("CAPI lifecycle ownership exists or cannot be inspected; the Console workflow will not adopt it")
	}
	if _, err := os.Lstat(localStateFilePath(runtime.stateRoot, *name)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("local ownership state appeared during preparation; automatic retries are disabled")
	}
	provider, err := observeLocalDockerProvider(ctx, runtime)
	if err != nil {
		return fmt.Errorf("identify local Docker provider before creating durable intent: %w", err)
	}
	ownerID, err := newLocalOwnerID()
	if err != nil {
		return err
	}
	clusterDir, err := initLocalStateDirectory(runtime.stateRoot, *name)
	if err != nil {
		return err
	}
	kubeconfigPath := filepath.Join(clusterDir, "kubeconfig")
	if _, err := os.Lstat(kubeconfigPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("private kubeconfig path already exists or cannot be checked; refusing to overwrite it")
	}
	state := localClusterState{Format: localClusterStateFormat, Phase: "CREATING", Name: *name, OwnerID: ownerID,
		KindName: localKindClusterName(*name, ownerID), Provider: provider, Kubeconfig: kubeconfigPath}
	config, err := renderKindOwnershipConfig(*name, ownerID)
	if err != nil {
		return err
	}
	configPath := filepath.Join(clusterDir, "kind.yaml")
	if err := writePrivateNewFile(configPath, config); err != nil {
		return err
	}
	if err := writeLocalClusterIntent(runtime.stateRoot, *name, state); err != nil {
		return err
	}
	env := map[string]string{
		"OK_CONSOLE_KIND_CLUSTER":     state.KindName,
		"OK_CONSOLE_KEEP_CLUSTER":     "true",
		"OK_CONSOLE_KIND_CONFIG":      configPath,
		"OK_CONSOLE_KUBECONFIG":       state.Kubeconfig,
		"OK_CONSOLE_LOCAL_PORT":       fmt.Sprint(localConsoleDefaultPort),
		"DOCKER_HOST":                 provider.Endpoint,
		"KIND_EXPERIMENTAL_PROVIDER":  "docker",
		"KUBECONFIG":                  state.Kubeconfig,
		"OK_CONSOLE_MIN_KIND_VERSION": localKindMinimumVersion,
	}
	if err := runtime.runVerifier(ctx, filepath.Join(runtime.consoleRoot, "deploy/kubernetes/verify-local-kind.sh"), env); err != nil {
		state.Phase = "INCOMPLETE"
		if persistErr := updateLocalClusterState(runtime.stateRoot, *name, state); persistErr != nil {
			return fmt.Errorf("verifier failed (%v) and INCOMPLETE state update failed (%w); original CREATING intent remains", err, persistErr)
		}
		return fmt.Errorf("Console local-kind workflow stopped; durable INCOMPLETE state retained, no retry performed: %s", safeLocalVerifierFailure(err))
	}
	if err := captureLocalClusterIdentity(ctx, &runtime, &state); err != nil {
		state.Phase = "INCOMPLETE"
		if persistErr := updateLocalClusterState(runtime.stateRoot, *name, state); persistErr != nil {
			return fmt.Errorf("identity capture failed (%v) and INCOMPLETE state update failed (%w); original CREATING intent remains", err, persistErr)
		}
		return fmt.Errorf("Console deployment returned success but ownership evidence is incomplete; no success claimed: %w", err)
	}
	state.Phase = "CLUSTER_READY"
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("persist verified cluster receipt: %w", err)
	}
	fwd, err := startLocalForward(ctx, state)
	if err != nil {
		return fmt.Errorf("cluster is deployed but Console forwarding failed; state retained for inspection: %w", err)
	}
	state.Forward = &fwd
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("forward started but receipt update failed; inspect process and state: %w", err)
	}
	if err := waitLocalConsole(ctx, localConsoleDefaultPort); err != nil {
		return fmt.Errorf("cluster is deployed but Console health is not verified; no success claimed: %w", err)
	}
	state.Phase = "READY"
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "OpenKubes Console is ready: http://127.0.0.1:%d\n", localConsoleDefaultPort)
	return err
}

// runLocalResume continues only an installation whose durable intent and live
// ownership can be independently matched. It never creates Kubernetes
// resources, deploys Console, or replaces the private kubeconfig.
func runLocalResume(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok local resume", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", localClusterDefaultName, "Managed local kind cluster name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local resume accepts no positional arguments and requires a valid --name")
	}
	state, err := readLocalClusterState(runtime.stateRoot, *name)
	if err != nil {
		return fmt.Errorf("cannot read existing local recovery state: %w", err)
	}
	if state.Format != localClusterStateFormat || state.Phase != "INCOMPLETE" {
		return errors.New("ok local resume accepts only an existing v3 INCOMPLETE installation")
	}
	if err := validateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("local recovery state is invalid; refusing resume: %w", err)
	}
	if _, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, *name); err == nil {
		return errors.New("bootstrap diagnostic receipt exists; refusing normal local resume")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("bootstrap diagnostic receipt is invalid; refusing local resume")
	}
	if len(state.Containers) == 0 || state.Forward != nil {
		return errors.New("recovery state lacks prior container identity or contains an ambiguous port-forward receipt")
	}
	checkPort := runtime.checkLocalPort
	if checkPort == nil {
		checkPort = ensureLocalPortAvailable
	}
	if err := checkPort(localConsoleDefaultPort); err != nil {
		return fmt.Errorf("local Console port is not safely available: %w", err)
	}

	// Capture rechecks provider, Kind name, exact Docker IDs, the existing
	// isolated kubeconfig, Kubernetes owner labels/UIDs, and kube-system UID.
	// The read-only mode deliberately does not chmod or rewrite user data.
	if err := captureLocalClusterIdentityReadOnly(ctx, &runtime, &state); err != nil {
		return errors.New("live ownership or kubeconfig verification failed; INCOMPLETE state preserved")
	}
	if err := verifyLocalConsoleWorkload(ctx, runtime, state); err != nil {
		return fmt.Errorf("existing Console workload is not verified healthy; INCOMPLETE state preserved: %w", err)
	}

	state.Phase = "CLUSTER_READY"
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("persist verified cluster identity before forwarding: %w", err)
	}
	startForward := runtime.startForward
	if startForward == nil {
		startForward = startLocalForward
	}
	forward, err := startForward(ctx, state)
	if err != nil {
		return fmt.Errorf("verified cluster and Console remain CLUSTER_READY; port-forward was not established: %w", err)
	}
	if forward.OwnerID != state.OwnerID || forward.PID <= 0 || forward.StartedAt == "" || !filepath.IsAbs(forward.Executable) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(forward.ArgumentsSHA256) {
		stop := runtime.stopForward
		if stop == nil {
			stop = stopLocalForward
		}
		stopErr := stop(forward)
		if stopErr != nil {
			return fmt.Errorf("port-forward identity is invalid and safe stop failed; state remains CLUSTER_READY: %w", stopErr)
		}
		return errors.New("port-forward returned an invalid process identity; state remains CLUSTER_READY")
	}
	state.Forward = &forward
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		stop := runtime.stopForward
		if stop == nil {
			stop = stopLocalForward
		}
		if stopErr := stop(forward); stopErr != nil {
			return fmt.Errorf("forward receipt update failed and verified forward could not be stopped; state remains CLUSTER_READY: %w", stopErr)
		}
		return fmt.Errorf("forward receipt update failed; verified forward stopped and state remains CLUSTER_READY: %w", err)
	}
	waitConsole := runtime.waitConsole
	if waitConsole == nil {
		waitConsole = waitLocalConsole
	}
	if err := waitConsole(ctx, localConsoleDefaultPort); err != nil {
		return fmt.Errorf("Console loopback health is not verified; durable CLUSTER_READY state retained: %w", err)
	}
	state.Phase = "READY"
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("Console health passed but READY receipt could not be persisted: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "OpenKubes Console is ready: http://127.0.0.1:%d\n", localConsoleDefaultPort)
	return err
}

func runLocalReconnect(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok local reconnect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", localClusterDefaultName, "Managed local kind cluster name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local reconnect accepts no positional arguments and requires a valid --name")
	}
	state, err := readLocalClusterState(runtime.stateRoot, *name)
	if err != nil {
		return fmt.Errorf("cannot read existing local ownership state: %w", err)
	}
	if state.Format != localClusterStateFormat || state.Phase != "READY" || state.Forward == nil {
		return errors.New("ok local reconnect requires an existing v3 READY receipt with a managed forward identity")
	}
	if err := validateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing reconnect: %w", err)
	}
	if _, err := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, *name); err == nil {
		return errors.New("bootstrap diagnostic receipt exists; refusing local reconnect")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("bootstrap diagnostic receipt is invalid; refusing local reconnect")
	}
	inspect := runtime.inspectForward
	if inspect == nil {
		inspect = inspectLocalForwardProcess
	}
	oldForwardState, err := inspect(*state.Forward)
	if err != nil {
		return errors.New("could not safely classify the recorded port-forward; refusing reconnect")
	}
	switch oldForwardState {
	case localForwardMatches:
		return errors.New("recorded port-forward is still active; refusing to start a second forward")
	case localForwardAbsent, localForwardPIDReused:
		// Never signal an absent or identity-mismatched PID.
	default:
		return errors.New("recorded port-forward state is ambiguous; refusing reconnect")
	}

	// Persist that the old process is no longer managed before any later check
	// can fail. This keeps the receipt from claiming a live forward on failure.
	state.Phase = "CLUSTER_READY"
	state.Forward = nil
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("could not persist the missing-forward recovery boundary: %w", err)
	}

	owned, present, err := observeLocalOwnership(ctx, runtime, state)
	if err != nil {
		return errors.New("could not verify the pinned provider, Kind containers, kubeconfig and Kubernetes ownership; reconnect stopped")
	}
	if !present || !owned {
		return errors.New("live cluster identity does not match the READY receipt; reconnect stopped")
	}
	if err := verifyLocalConsoleWorkload(ctx, runtime, state); err != nil {
		return errors.New("existing Console Deployment or Service is not healthy; reconnect stopped")
	}
	checkPort := runtime.checkLocalPort
	if checkPort == nil {
		checkPort = ensureLocalPortAvailable
	}
	if err := checkPort(localConsoleDefaultPort); err != nil {
		return errors.New("loopback port 127.0.0.1:18787 is not available; no forward was started")
	}
	startForward := runtime.startForward
	if startForward == nil {
		startForward = startLocalForward
	}
	forward, err := startForward(ctx, state)
	if err != nil {
		return errors.New("could not start one detached local Console forward; receipt remains CLUSTER_READY")
	}
	if forward.OwnerID != state.OwnerID || forward.PID <= 0 || forward.StartedAt == "" || !filepath.IsAbs(forward.Executable) || !sha256DigestPattern.MatchString(forward.ArgumentsSHA256) {
		return errors.New("new port-forward did not return a valid managed process identity; receipt remains CLUSTER_READY")
	}
	processState, inspectErr := inspect(forward)
	if inspectErr != nil || processState != localForwardMatches {
		return errors.New("new port-forward process identity could not be verified; receipt remains CLUSTER_READY")
	}
	state.Forward = &forward
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		stop := runtime.stopForward
		if stop == nil {
			stop = stopLocalForward
		}
		if stopErr := stop(forward); stopErr != nil {
			return errors.New("could not persist or safely stop the new port-forward; inspect the CLUSTER_READY receipt and process")
		}
		return errors.New("could not persist the new port-forward identity; verified process was stopped and receipt remains CLUSTER_READY")
	}
	checkHTTP := runtime.waitConsole
	if checkHTTP == nil {
		checkHTTP = waitLocalConsole
	}
	if err := checkHTTP(ctx, localConsoleDefaultPort); err != nil {
		return errors.New("Console HTTP health is unavailable; verified process identity is retained in CLUSTER_READY state")
	}
	state.Phase = "READY"
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return errors.New("Console HTTP health passed but READY state could not be persisted; verified forward remains recorded")
	}
	_, err = fmt.Fprintf(stdout, "OpenKubes Console is ready: http://127.0.0.1:%d\n", localConsoleDefaultPort)
	return err
}

const localBootstrapDiagnosticFormat = "ok-cli-local-bootstrap-diagnostic/v1"

var localBootstrapDiagnosticCodes = map[string]bool{
	"KIND_CONFIG_REJECTED":    true,
	"DOCKER_PROVISION_FAILED": true,
	"NODE_BOOTSTRAP_FAILED":   true,
	"KIND_READINESS_TIMEOUT":  true,
	"UNKNOWN":                 true,
}

func runLocalDiagnoseBootstrap(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok local diagnose bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "Fresh logical name for one diagnostic Kind bootstrap attempt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) {
		return errors.New("ok local diagnose bootstrap requires a fresh valid --name and accepts no positional arguments")
	}
	if runtime.run == nil || runtime.runPinned == nil || runtime.runKindCreate == nil {
		return errors.New("diagnostic bootstrap requires pinned Docker/Kind command runners; no cluster was contacted")
	}
	if _, err := os.Lstat(localStateFilePath(runtime.stateRoot, *name)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("local state already exists or cannot be checked; diagnostic bootstrap will not retry or adopt")
	}
	if _, err := os.Lstat(localBootstrapDiagnosticPath(runtime.stateRoot, *name)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("local diagnostic receipt already exists or cannot be checked; diagnostic bootstrap will not retry or adopt")
	}
	clusterDir := filepath.Join(runtime.stateRoot, "clusters", *name)
	if _, err := os.Lstat(clusterDir); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("local state directory already exists or cannot be checked; diagnostic bootstrap requires a fresh name")
	}
	kindVersion, err := runtime.run(ctx, "kind", "version")
	if err != nil || !localKindVersionSupported(string(kindVersion), localKindMinimumVersion) {
		return fmt.Errorf("kind %s or newer is required; no local state or cluster change was made", localKindMinimumVersion)
	}
	provider, err := observeLocalDockerProvider(ctx, runtime)
	if err != nil {
		return errors.New("could not verify Docker endpoint and daemon identity; no local state or cluster change was made")
	}
	if provider.Kind != "docker" || !strings.HasPrefix(provider.Endpoint, "unix://") || provider.DaemonID == "" {
		return errors.New("diagnostic bootstrap requires a verified local Docker socket and daemon identity")
	}
	// Verify the active provider one more time immediately before writing intent.
	verifiedProvider, err := observeLocalDockerProvider(ctx, runtime)
	if err != nil || verifiedProvider != provider {
		return errors.New("Docker provider identity changed during preflight; no diagnostic create was attempted")
	}
	newOwnerID := runtime.newOwnerID
	if newOwnerID == nil {
		newOwnerID = newLocalOwnerID
	}
	ownerID, err := newOwnerID()
	if err != nil {
		return err
	}
	kindName := localKindClusterName(*name, ownerID)
	if !validLocalKindClusterName(kindName) {
		return errors.New("generated Kind name must be at most 49 characters and its control-plane hostname at most 63 characters")
	}
	// The final random name must itself be checked against both inventories.
	clusters, err := runLocalPinned(ctx, runtime, provider, "kind", "get", "clusters")
	if err != nil {
		return errors.New("could not prove the generated Kind name is unused; no diagnostic create was attempted")
	}
	if containsExactLine(string(clusters), kindName) {
		return errors.New("generated Kind name already exists; refusing to adopt or modify it")
	}
	containers, err := observeLocalKindContainers(ctx, runtime, provider, kindName)
	if err != nil || len(containers) != 0 {
		return errors.New("could not prove the generated Kind container identity is unused; no diagnostic create was attempted")
	}
	clusterDir, err = initLocalStateDirectory(runtime.stateRoot, *name)
	if err != nil {
		return err
	}
	kubeconfigPath := filepath.Join(clusterDir, "kubeconfig")
	configPath := filepath.Join(clusterDir, "kind.yaml")
	receiptPath := localBootstrapDiagnosticPath(runtime.stateRoot, *name)
	for _, path := range []string{kubeconfigPath, configPath, receiptPath} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("diagnostic output path already exists or cannot be checked; refusing to overwrite it")
		}
	}
	config, err := renderKindOwnershipConfig(*name, ownerID)
	if err != nil {
		return err
	}
	if err := writePrivateNewFile(configPath, config); err != nil {
		return fmt.Errorf("prepare private Kind config: %w", err)
	}
	state := localClusterState{Format: localBootstrapStateFormat, Phase: "CREATING", Name: *name, OwnerID: ownerID,
		KindName: kindName, Provider: provider, Kubeconfig: kubeconfigPath}
	if err := writeLocalClusterIntent(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("persist diagnostic intent before Kind create: %w", err)
	}
	receipt := localBootstrapDiagnosticReceipt{Format: localBootstrapDiagnosticFormat, Name: *name, OwnerID: ownerID,
		KindName: kindName, Provider: provider, ConfigSHA256: sha256Hex(config), State: "PREPARED", ResourceState: "UNKNOWN"}
	if err := writeLocalBootstrapDiagnosticReceipt(runtime.stateRoot, receipt, false); err != nil {
		state.Phase = "INCOMPLETE"
		_ = updateLocalClusterState(runtime.stateRoot, *name, state)
		return errors.New("could not persist private diagnostic receipt; Kind create was not attempted")
	}
	argumentsForKind := localKindDiagnosticCreateArguments(configPath, kindName, kubeconfigPath)
	output, truncated, createErr := runtime.runKindCreate(ctx, provider, kubeconfigPath, argumentsForKind...)
	if createErr != nil {
		receipt.FailureCode = classifyLocalKindCreateFailure(output, truncated)
		state.Phase = "INCOMPLETE"
		resourceState, observedContainers, kubeconfigSeen := observeLocalBootstrapResources(ctx, runtime, state)
		receipt.State = "FAILED"
		receipt.ResourceState = resourceState
		receipt.Containers = observedContainers
		receipt.KubeconfigSeen = kubeconfigSeen
		state.Containers = observedContainers
		if err := writeLocalBootstrapDiagnosticReceipt(runtime.stateRoot, receipt, true); err != nil {
			return fmt.Errorf("Kind diagnostic failed [code=%s]; CREATING intent retained and diagnostic receipt update failed; no retry was performed", receipt.FailureCode)
		}
		if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
			return fmt.Errorf("Kind diagnostic failed [code=%s]; diagnostic outcome retained but state remains CREATING; no retry was performed", receipt.FailureCode)
		}
		return fmt.Errorf("Kind bootstrap diagnostic stopped [code=%s resources=%s]; INCOMPLETE state retained, no retry or cleanup performed", receipt.FailureCode, receipt.ResourceState)
	}
	// A successful Kind command is not enough: verify provider, Kind name,
	// exact containers, isolated kubeconfig, owner-labeled node and API identity.
	if err := captureLocalClusterIdentity(ctx, &runtime, &state); err != nil {
		state.Phase = "INCOMPLETE"
		resourceState, observedContainers, kubeconfigSeen := observeLocalBootstrapResources(ctx, runtime, state)
		state.Containers = observedContainers
		receipt.State = "FAILED"
		receipt.FailureCode = "UNKNOWN"
		receipt.ResourceState = resourceState
		receipt.Containers = observedContainers
		receipt.KubeconfigSeen = kubeconfigSeen
		if err := writeLocalBootstrapDiagnosticReceipt(runtime.stateRoot, receipt, true); err != nil {
			return errors.New("Kind returned success but ownership evidence is incomplete; CREATING intent retained and diagnostic receipt update failed")
		}
		if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
			return errors.New("Kind returned success but identity evidence is incomplete; CREATING intent and diagnostic receipt retained, no retry or cleanup performed")
		}
		return errors.New("Kind returned success but exact cluster ownership evidence is incomplete; INCOMPLETE state retained, no retry or cleanup performed")
	}
	state.Phase = "CLUSTER_READY"
	receipt.State = "SUCCEEDED_RETAINED"
	receipt.ResourceState = "VERIFIED_RETAINED"
	receipt.Containers = append([]localContainerIdentity(nil), state.Containers...)
	receipt.KubeconfigSeen = true
	if err := writeLocalBootstrapDiagnosticReceipt(runtime.stateRoot, receipt, true); err != nil {
		return fmt.Errorf("Kind bootstrap succeeded and identity was verified, but diagnostic receipt update failed; CREATING intent retained and no cleanup performed: %w", err)
	}
	if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
		return fmt.Errorf("Kind bootstrap succeeded and diagnostic receipt records verified retained resources, but state remains CREATING; no cleanup or retry performed: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Kind bootstrap verified and retained as %s; no Console was built or deployed. Separate owner approval is required for diagnostic export or cleanup.\n", state.KindName)
	return err
}

func localKindDiagnosticCreateArguments(configPath, kindName, kubeconfig string) []string {
	return []string{"create", "cluster", "--retain", "--config", configPath, "--name", kindName, "--kubeconfig", kubeconfig, "--wait", "90s"}
}

func classifyLocalKindCreateFailure(output []byte, truncated bool) string {
	if truncated {
		return "UNKNOWN"
	}
	const failurePrefix = "error: failed to create cluster: "
	patterns := map[string][]string{
		"KIND_CONFIG_REJECTED":    {"failed to load config:", "failed to read config:", "failed to parse config:", "invalid kind config:", "invalid configuration:"},
		"DOCKER_PROVISION_FAILED": {"failed to create container", "failed to create network", "failed to get docker info:", "cannot connect to the docker daemon", "error during connect"},
		"NODE_BOOTSTRAP_FAILED":   {"failed to init node with kubeadm:", "failed to run kubeadm init:"},
		"KIND_READINESS_TIMEOUT":  {"timed out waiting for control plane", "timed out waiting for control-plane", "timeout waiting for control plane", "timed out waiting for kubernetes", "failed to wait for control-plane", "could not find a log line that matches"},
	}
	matched := ""
	for _, line := range strings.Split(strings.ToLower(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, failurePrefix) {
			continue
		}
		detail := strings.TrimPrefix(line, failurePrefix)
		lineMatch := ""
		for code, needles := range patterns {
			for _, needle := range needles {
				if strings.Contains(detail, needle) {
					if lineMatch != "" && lineMatch != code {
						return "UNKNOWN"
					}
					lineMatch = code
				}
			}
		}
		if lineMatch == "" || matched != "" && matched != lineMatch {
			return "UNKNOWN"
		}
		matched = lineMatch
	}
	if localBootstrapDiagnosticCodes[matched] {
		return matched
	}
	return "UNKNOWN"
}

func observeLocalBootstrapResources(ctx context.Context, runtime localRuntime, state localClusterState) (string, []localContainerIdentity, bool) {
	provider, providerErr := observeLocalDockerProvider(ctx, runtime)
	if providerErr != nil || provider != state.Provider {
		seen, _ := diagnosticKubeconfigState(state.Kubeconfig)
		return "AMBIGUOUS", nil, seen
	}
	clusters, clusterErr := runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "clusters")
	containers, containerErr := observeLocalKindContainers(ctx, runtime, state.Provider, state.KindName)
	kubeconfigSeen, kubeconfigValid := diagnosticKubeconfigState(state.Kubeconfig)
	if !kubeconfigValid {
		return "AMBIGUOUS", containers, kubeconfigSeen
	}
	if clusterErr != nil || containerErr != nil {
		return "AMBIGUOUS", containers, kubeconfigSeen
	}
	clusterPresent := containsExactLine(string(clusters), state.KindName)
	if !clusterPresent && len(containers) == 0 && !kubeconfigSeen {
		return "ABSENT", nil, false
	}
	if clusterPresent && len(containers) == 1 && containers[0].Name == state.KindName+"-control-plane" && containers[0].Role == "control-plane" && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(containers[0].ID) {
		return "VERIFIED_RETAINED", containers, kubeconfigSeen
	}
	return "AMBIGUOUS", containers, kubeconfigSeen
}

func diagnosticKubeconfigState(path string) (seen, valid bool) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	if err != nil {
		return true, false
	}
	return true, info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func localKindVersionSupported(output, minimum string) bool {
	current := localKindVersionPattern.FindStringSubmatch(output)
	wanted := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`).FindStringSubmatch(minimum)
	if len(current) != 4 || len(wanted) != 4 {
		return false
	}
	for index := 1; index <= 3; index++ {
		actual, errA := strconv.Atoi(current[index])
		required, errR := strconv.Atoi(wanted[index])
		if errA != nil || errR != nil {
			return false
		}
		if actual > required {
			return true
		}
		if actual < required {
			return false
		}
	}
	return true
}

func ensureLocalPortAvailable(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("loopback port %d is unavailable; no local cluster will be created: %w", port, err)
	}
	return listener.Close()
}

func findLocalConsoleRoot() string {
	if configured := os.Getenv("OK_CONSOLE_DIR"); configured != "" {
		if validLocalConsoleRoot(configured) {
			return configured
		}
		return ""
	}
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		for _, candidate := range []string{filepath.Join(dir, "ok-console"), dir} {
			if validLocalConsoleRoot(candidate) {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return ""
}

func validLocalConsoleRoot(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	for _, relative := range []string{"deploy/kubernetes/verify-local-kind.sh", "deploy/kubernetes/overlays/local-kind/kustomization.yaml"} {
		info, err := os.Lstat(filepath.Join(path, relative))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

func runLocalConsoleVerifier(ctx context.Context, script string, env map[string]string) error {
	command := exec.CommandContext(ctx, "bash", script)
	command.Dir = filepath.Dir(filepath.Dir(filepath.Dir(script)))
	childEnv := make([]string, 0, len(os.Environ())+len(env))
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		if _, replaced := env[key]; !replaced && key != "DOCKER_CONTEXT" && key != "DOCKER_TLS_VERIFY" && key != "DOCKER_CERT_PATH" {
			childEnv = append(childEnv, entry)
		}
	}
	for key, value := range env {
		childEnv = append(childEnv, key+"="+value)
	}
	command.Env = childEnv
	output, err := command.CombinedOutput()
	if err != nil {
		return classifyLocalVerifierFailure(output, err)
	}
	return nil
}

func safeLocalVerifierFailure(err error) string {
	var failure localVerifierFailure
	if errors.As(err, &failure) {
		return formatLocalVerifierFailure(failure)
	}
	return "local verifier failed [stage=unknown code=UNKNOWN]; raw output suppressed"
}

func localVerifierDiagnostic(output []byte, err error) string {
	return formatLocalVerifierFailure(classifyLocalVerifierFailure(output, err))
}

var localVerifierDiagnosticCodes = map[string]string{
	"KIND_NAME_TOO_LONG":           "preflight",
	"KIND_LIST_FAILED":             "kind_inventory",
	"KIND_CONFIG_OR_CREATE_FAILED": "kind_create",
	"IMAGE_OR_DEPLOY_FAILED":       "image_deploy",
	"TEMP_FILE_PREPARATION_FAILED": "temp_file",
	"UNKNOWN":                      "unknown",
}

var localVerifierDiagnosticPattern = regexp.MustCompile(`^OK_LOCAL_DIAGNOSTIC stage=([a-z_]+) code=([A-Z_]+)$`)

func classifyLocalVerifierFailure(output []byte, err error) localVerifierFailure {
	status := "unknown"
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		status = strconv.Itoa(exitError.ExitCode())
	}
	failure := localVerifierFailure{stage: "unknown", code: "UNKNOWN", exitCode: status}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return failure
	}
	lastLine := strings.TrimSpace(lines[len(lines)-1])
	matches := localVerifierDiagnosticPattern.FindStringSubmatch(lastLine)
	if len(matches) != 3 {
		return failure
	}
	wantStage, allowed := localVerifierDiagnosticCodes[matches[2]]
	if !allowed || matches[1] != wantStage {
		return failure
	}
	failure.stage = matches[1]
	failure.code = matches[2]
	return failure
}

func formatLocalVerifierFailure(failure localVerifierFailure) string {
	wantStage, allowed := localVerifierDiagnosticCodes[failure.code]
	if !allowed || failure.stage != wantStage {
		failure.stage, failure.code = "unknown", "UNKNOWN"
	}
	if failure.exitCode != "" && regexp.MustCompile(`^[0-9]+$`).MatchString(failure.exitCode) {
		return fmt.Sprintf("local verifier failed [stage=%s code=%s] (exit %s); raw output suppressed", failure.stage, failure.code, failure.exitCode)
	}
	return fmt.Sprintf("local verifier failed [stage=%s code=%s]; raw output suppressed", failure.stage, failure.code)
}

func writePrivateNewFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func captureLocalClusterIdentity(ctx context.Context, runtime *localRuntime, state *localClusterState) error {
	return captureLocalClusterIdentityWithKubeconfigMode(ctx, runtime, state, true)
}

func captureLocalClusterIdentityReadOnly(ctx context.Context, runtime *localRuntime, state *localClusterState) error {
	return captureLocalClusterIdentityWithKubeconfigMode(ctx, runtime, state, false)
}

func captureLocalClusterIdentityWithKubeconfigMode(ctx context.Context, runtime *localRuntime, state *localClusterState, normalizeKubeconfigMode bool) error {
	provider, err := observeLocalDockerProvider(ctx, *runtime)
	if err != nil {
		return err
	}
	if provider != state.Provider {
		return errors.New("Docker provider changed during Console installation")
	}
	clusters, err := runLocalPinned(ctx, *runtime, state.Provider, "kind", "get", "clusters")
	if err != nil {
		return err
	}
	if !containsExactLine(string(clusters), state.KindName) {
		return errors.New("expected owner-specific kind cluster is absent")
	}
	containers, err := observeLocalKindContainers(ctx, *runtime, state.Provider, state.KindName)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return errors.New("owner-specific Kind node containers are absent")
	}
	previousContainers := append([]localContainerIdentity(nil), state.Containers...)
	if len(previousContainers) > 0 && !sameLocalContainers(containers, previousContainers) {
		return errors.New("live Kind container identities differ from the existing incomplete receipt")
	}
	state.Containers = containers
	if normalizeKubeconfigMode {
		if err := os.Chmod(state.Kubeconfig, 0o600); err != nil {
			return err
		}
	}
	info, err := os.Lstat(state.Kubeconfig)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Kind did not produce a private isolated kubeconfig")
	}
	kindConfig, err := runLocalPinned(ctx, *runtime, state.Provider, "kind", "get", "kubeconfig", "--name", state.KindName)
	if err != nil {
		return err
	}
	privateConfig, err := readBoundedLocalFile(state.Kubeconfig, 4*1024*1024)
	if err != nil {
		return err
	}
	if err := compareKindKubeconfig(kindConfig, privateConfig, "kind-"+state.KindName); err != nil {
		return err
	}
	ctxName := "kind-" + state.KindName
	nodeJSON, err := runtime.run(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", ctxName, "get", "nodes", "-o", "json")
	if err != nil {
		return err
	}
	var nodes localNodeList
	if err := json.Unmarshal(nodeJSON, &nodes); err != nil || len(nodes.Items) != len(containers) || len(nodes.Items) == 0 {
		return errors.New("Kubernetes node set does not match owner-labeled Kind containers")
	}
	previousNodes := append([]localNodeIdentity(nil), state.Nodes...)
	state.Nodes = nil
	for _, node := range nodes.Items {
		if node.Metadata.Labels[localOwnerLabel] != state.OwnerID || node.Metadata.UID == "" || !containsLocalContainerName(containers, node.Metadata.Name) {
			return errors.New("Kubernetes node owner label or UID does not match durable intent")
		}
		state.Nodes = append(state.Nodes, localNodeIdentity{Name: node.Metadata.Name, UID: node.Metadata.UID})
	}
	if len(previousNodes) > 0 && !sameLocalNodes(state.Nodes, previousNodes) {
		return errors.New("live Kubernetes node names or UIDs differ from the existing incomplete receipt")
	}
	namespaceJSON, err := runtime.run(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", ctxName, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return err
	}
	var ns localNamespace
	if err := json.Unmarshal(namespaceJSON, &ns); err != nil || ns.Metadata.UID == "" {
		return errors.New("missing kube-system identity")
	}
	if state.KubeSystemUID != "" && state.KubeSystemUID != ns.Metadata.UID {
		return errors.New("live kube-system UID differs from the existing incomplete receipt")
	}
	state.KubeSystemUID = ns.Metadata.UID
	return nil
}

func containsLocalContainerName(containers []localContainerIdentity, name string) bool {
	for _, container := range containers {
		if container.Name == name {
			return true
		}
	}
	return false
}

func sameLocalNodes(a, b []localNodeIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]localNodeIdentity(nil), a...)
	right := append([]localNodeIdentity(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].Name < left[j].Name })
	sort.Slice(right, func(i, j int) bool { return right[i].Name < right[j].Name })
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

type localConsoleDeploymentObservation struct {
	Metadata struct {
		Name       string `json:"name"`
		Namespace  string `json:"namespace"`
		Generation int64  `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		UpdatedReplicas    int32 `json:"updatedReplicas"`
		ReadyReplicas      int32 `json:"readyReplicas"`
		AvailableReplicas  int32 `json:"availableReplicas"`
	} `json:"status"`
}

type localConsoleServiceObservation struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Type      string            `json:"type"`
		ClusterIP string            `json:"clusterIP"`
		Selector  map[string]string `json:"selector"`
		Ports     []struct {
			Port     int32  `json:"port"`
			Protocol string `json:"protocol"`
			NodePort int32  `json:"nodePort"`
		} `json:"ports"`
	} `json:"spec"`
}

type localConsoleEndpointsObservation struct {
	Subsets []struct {
		Addresses []struct {
			IP string `json:"ip"`
		} `json:"addresses"`
		Ports []struct {
			Port     int32  `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
	} `json:"subsets"`
}

func verifyLocalConsoleWorkload(ctx context.Context, runtime localRuntime, state localClusterState) error {
	contextName := "kind-" + state.KindName
	base := []string{"--kubeconfig", state.Kubeconfig, "--context", contextName, "--request-timeout=10s", "-n", "openkubes-console"}
	deploymentJSON, err := runtime.run(ctx, "kubectl", append(append([]string(nil), base...), "get", "deployment", "ok-console", "-o", "json")...)
	if err != nil {
		return errors.New("could not read the existing Console deployment through the isolated kubeconfig")
	}
	var deployment localConsoleDeploymentObservation
	if err := json.Unmarshal(deploymentJSON, &deployment); err != nil {
		return errors.New("existing Console deployment response is invalid")
	}
	desired := int32(1)
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != desired ||
		deployment.Metadata.Name != "ok-console" || deployment.Metadata.Namespace != "openkubes-console" ||
		deployment.Status.ObservedGeneration < deployment.Metadata.Generation ||
		deployment.Status.UpdatedReplicas != desired || deployment.Status.ReadyReplicas != desired || deployment.Status.AvailableReplicas != desired {
		return errors.New("existing Console deployment is not fully observed and Ready")
	}
	serviceJSON, err := runtime.run(ctx, "kubectl", append(append([]string(nil), base...), "get", "service", "ok-console", "-o", "json")...)
	if err != nil {
		return errors.New("could not read the existing Console service through the isolated kubeconfig")
	}
	var service localConsoleServiceObservation
	if err := json.Unmarshal(serviceJSON, &service); err != nil {
		return errors.New("existing Console service response is invalid")
	}
	portReady := false
	for _, port := range service.Spec.Ports {
		if port.Port == 8787 && (port.Protocol == "" || port.Protocol == "TCP") && port.NodePort == 0 {
			portReady = true
		}
	}
	if service.Metadata.Name != "ok-console" || service.Metadata.Namespace != "openkubes-console" ||
		service.Spec.Type != "ClusterIP" || service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" || len(service.Spec.Selector) == 0 || !portReady {
		return errors.New("existing Console service is not the expected internal 8787/TCP service")
	}
	endpointsJSON, err := runtime.run(ctx, "kubectl", append(append([]string(nil), base...), "get", "endpoints", "ok-console", "-o", "json")...)
	if err != nil {
		return errors.New("could not read the existing Console service endpoints through the isolated kubeconfig")
	}
	var endpoints localConsoleEndpointsObservation
	if err := json.Unmarshal(endpointsJSON, &endpoints); err != nil {
		return errors.New("existing Console service endpoints response is invalid")
	}
	for _, subset := range endpoints.Subsets {
		addressReady := false
		for _, address := range subset.Addresses {
			if net.ParseIP(address.IP) != nil {
				addressReady = true
			}
		}
		endpointPortReady := false
		for _, port := range subset.Ports {
			if port.Port == 8787 && (port.Protocol == "" || port.Protocol == "TCP") {
				endpointPortReady = true
			}
		}
		if addressReady && endpointPortReady {
			return nil
		}
	}
	return errors.New("existing Console service has no Ready endpoint on 8787/TCP")
}

func startLocalForward(_ context.Context, state localClusterState) (localForwardIdentity, error) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return localForwardIdentity{}, err
	}
	kubectl, err = filepath.Abs(kubectl)
	if err != nil {
		return localForwardIdentity{}, err
	}
	args := []string{"--kubeconfig", state.Kubeconfig, "--context", "kind-" + state.KindName, "-n", "openkubes-console", "port-forward", "--address", "127.0.0.1", "service/ok-console", fmt.Sprintf("%d:8787", localConsoleDefaultPort)}
	logPath := filepath.Join(filepath.Dir(state.Kubeconfig), "port-forward.log")
	return startDetachedLocalProcess(kubectl, args, logPath, state.OwnerID)
}

func startDetachedLocalProcess(executable string, arguments []string, logPath, ownerID string) (localForwardIdentity, error) {
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return localForwardIdentity{}, err
	}
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		_ = log.Close()
		return localForwardIdentity{}, err
	}
	command := exec.Command(executable, arguments...)
	command.Stdin = stdin
	command.Stdout = log
	command.Stderr = log
	// A dedicated session prevents terminal hangup and foreground process-group
	// signals from taking down the managed local forward when the CLI exits.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = log.Close()
		return localForwardIdentity{}, err
	}
	_ = stdin.Close()
	_ = log.Close()
	started, err := localProcessField(command.Process.Pid, "lstart")
	if err != nil {
		_ = command.Process.Kill()
		return localForwardIdentity{}, err
	}
	commandLine, err := localProcessField(command.Process.Pid, "command")
	if err != nil {
		_ = command.Process.Kill()
		return localForwardIdentity{}, err
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(commandLine)))
	identity := localForwardIdentity{PID: command.Process.Pid, OwnerID: ownerID, StartedAt: strings.TrimSpace(started), Executable: executable, ArgumentsSHA256: "sha256:" + hex.EncodeToString(digest[:])}
	if err := verifyLocalForward(identity); err != nil {
		_ = command.Process.Kill()
		return localForwardIdentity{}, err
	}
	if err := command.Process.Release(); err != nil {
		_ = stopLocalForward(identity)
		return localForwardIdentity{}, errors.New("could not release verified managed port-forward process handle")
	}
	return identity, nil
}

func localProcessField(pid int, field string) (string, error) {
	if pid <= 0 || (field != "lstart" && field != "command") {
		return "", errors.New("invalid process identity query")
	}
	output, err := exec.Command("ps", "-p", fmt.Sprint(pid), "-o", field+"=").Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if value == "" {
		return "", errors.New("managed process is not observable")
	}
	return value, nil
}

func stopLocalForward(identity localForwardIdentity) error {
	state, err := inspectLocalForwardProcess(identity)
	if err != nil {
		return err
	}
	if state == localForwardAbsent || state == localForwardPIDReused {
		return nil
	}
	if state != localForwardMatches {
		return errors.New("port-forward process state is ambiguous")
	}
	// Repeat the identity check immediately before the signal. This narrows the
	// unavoidable PID check-to-signal race on platforms without pidfd support.
	state, err = inspectLocalForwardProcess(identity)
	if err != nil {
		return err
	}
	if state == localForwardAbsent || state == localForwardPIDReused {
		return nil
	}
	if state != localForwardMatches {
		return errors.New("port-forward process state changed before signal")
	}
	process, err := os.FindProcess(identity.PID)
	if err != nil {
		return err
	}
	if err := process.Signal(os.Interrupt); err != nil {
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := inspectLocalForwardProcess(identity)
		if err == nil && (state == localForwardAbsent || state == localForwardPIDReused) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("verified port-forward did not stop after interrupt; refusing cluster deletion")
}

func inspectLocalForwardProcess(identity localForwardIdentity) (localForwardProcessState, error) {
	if identity.PID <= 0 {
		return "", errors.New("recorded port-forward PID is invalid")
	}
	output, err := exec.Command("ps", "-p", fmt.Sprint(identity.PID), "-o", "pid=").Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("ps is unavailable; cannot classify recorded port-forward PID")
		}
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 && strings.TrimSpace(string(output)) == "" {
			return localForwardAbsent, nil
		}
		return "", fmt.Errorf("inspect recorded port-forward PID: %w", err)
	}
	if strings.TrimSpace(string(output)) == "" {
		return localForwardAbsent, nil
	}
	started, startErr := localProcessField(identity.PID, "lstart")
	command, commandErr := localProcessField(identity.PID, "command")
	if startErr != nil || commandErr != nil {
		return "", errors.New("PID exists but its full process identity cannot be read")
	}
	if validateLocalForwardObservation(identity, strings.TrimSpace(started), strings.TrimSpace(command)) != nil {
		return localForwardPIDReused, nil
	}
	return localForwardMatches, nil
}

func verifyLocalForward(identity localForwardIdentity) error {
	started, err := localProcessField(identity.PID, "lstart")
	if err != nil {
		return err
	}
	command, err := localProcessField(identity.PID, "command")
	if err != nil {
		return err
	}
	if err := validateLocalForwardObservation(identity, strings.TrimSpace(started), strings.TrimSpace(command)); err != nil {
		return err
	}
	return nil
}

func validateLocalForwardObservation(identity localForwardIdentity, started, command string) error {
	hash := sha256.Sum256([]byte(strings.TrimSpace(command)))
	if identity.PID <= 0 || !localOwnerIDPattern.MatchString(identity.OwnerID) || !filepath.IsAbs(identity.Executable) || started != identity.StartedAt || !strings.HasPrefix(command, identity.Executable+" ") || identity.ArgumentsSHA256 != "sha256:"+hex.EncodeToString(hash[:]) {
		return errors.New("PID does not match recorded executable, command and start time")
	}
	return nil
}

func waitLocalConsole(ctx context.Context, port int) error {
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(90 * time.Second)
	endpoints := []string{"/health/live", "/health/ready", "/"}
	for time.Now().Before(deadline) {
		all := true
		for _, endpoint := range endpoints {
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, endpoint), nil)
			response, err := client.Do(request)
			if err != nil {
				all = false
				break
			}
			_ = response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				all = false
				break
			}
		}
		if all {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("Console did not pass loopback health checks within 90 seconds")
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
		if _, diagnosticErr := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, *name); diagnosticErr == nil {
			return errors.New("bootstrap diagnostic receipt exists without its state; refusing NOT_INSTALLED claim")
		} else if !errors.Is(diagnosticErr, os.ErrNotExist) {
			return errors.New("bootstrap diagnostic receipt is invalid; refusing cluster access")
		}
		return writeLocalStatus(stdout, *jsonOutput, localStatus{Format: "ok-cli-local-status/v1", State: "NOT_INSTALLED", Name: *name, ClusterContacted: false, ConsoleChecked: false})
	}
	if err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing cluster access: %w", err)
	}
	if state.Phase == "CREATING" || state.Phase == "INCOMPLETE" {
		if err := validateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
			return fmt.Errorf("local recovery state is invalid: %w", err)
		}
		statusName := state.Phase
		if receipt, receiptErr := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, *name); receiptErr == nil {
			if receipt.OwnerID != state.OwnerID || receipt.Provider != state.Provider || receipt.KindName != state.KindName || !sameLocalContainers(receipt.Containers, state.Containers) {
				return errors.New("bootstrap diagnostic receipt identity differs from durable local intent")
			}
			statusName = "DIAGNOSTIC_" + receipt.State
		} else if !errors.Is(receiptErr, os.ErrNotExist) {
			return errors.New("bootstrap diagnostic receipt is invalid; refusing cluster access")
		} else if state.Format == localBootstrapStateFormat {
			return errors.New("diagnostic state exists without its required receipt; refusing cluster access")
		}
		return writeLocalStatus(stdout, *jsonOutput, localStatus{Format: "ok-cli-local-status/v1", State: statusName, Name: *name, ClusterContacted: false, ConsoleChecked: false})
	}
	if receipt, receiptErr := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, *name); receiptErr == nil {
		if receipt.OwnerID != state.OwnerID || receipt.Provider != state.Provider || receipt.KindName != state.KindName || receipt.State != "SUCCEEDED_RETAINED" || !sameLocalContainers(receipt.Containers, state.Containers) {
			return errors.New("bootstrap diagnostic receipt differs from the retained cluster receipt; refusing cluster access")
		}
	} else if !errors.Is(receiptErr, os.ErrNotExist) {
		return errors.New("bootstrap diagnostic receipt is invalid; refusing cluster access")
	} else if state.Format == localBootstrapStateFormat {
		return errors.New("diagnostic state exists without its required receipt; refusing cluster access")
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
		if state.Phase == "READY" && state.Forward != nil {
			inspect := runtime.inspectForward
			if inspect == nil {
				inspect = inspectLocalForwardProcess
			}
			processState, inspectErr := inspect(*state.Forward)
			if inspectErr != nil {
				return errors.New("could not safely inspect the recorded port-forward process identity")
			}
			switch processState {
			case localForwardAbsent:
				status.State = "FORWARD_PROCESS_MISSING"
			case localForwardPIDReused:
				status.State = "FORWARD_IDENTITY_MISMATCH"
			case localForwardMatches:
				checkHTTP := runtime.waitConsole
				if checkHTTP == nil {
					checkHTTP = waitLocalConsole
				}
				if err := checkHTTP(ctx, localConsoleDefaultPort); err == nil {
					status.State = "READY"
					status.ConsoleChecked = true
					status.URL = fmt.Sprintf("http://127.0.0.1:%d", localConsoleDefaultPort)
				} else {
					status.State = "CONSOLE_HTTP_UNAVAILABLE"
				}
			default:
				return errors.New("could not safely classify the recorded port-forward process")
			}
		}
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
	state, err := readLocalClusterState(runtime.stateRoot, *name)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no local ownership receipt exists; refusing to inspect or delete a cluster by name")
	}
	if err != nil {
		return fmt.Errorf("local ownership state is invalid; refusing deletion: %w", err)
	}
	if receipt, receiptErr := readLocalBootstrapDiagnosticReceipt(runtime.stateRoot, *name); receiptErr == nil {
		if receipt.OwnerID != state.OwnerID || receipt.Provider != state.Provider || receipt.KindName != state.KindName || !sameLocalContainers(receipt.Containers, state.Containers) {
			return errors.New("bootstrap diagnostic identity is inconsistent; refusing deletion")
		}
		return errors.New("bootstrap diagnostic resources require separately authorized, identity-bound cleanup; ok local down will not delete them")
	} else if !errors.Is(receiptErr, os.ErrNotExist) {
		return errors.New("bootstrap diagnostic receipt is invalid; refusing deletion")
	} else if state.Format == localBootstrapStateFormat {
		return errors.New("diagnostic state exists without its required receipt; refusing deletion")
	}
	if !runtime.interactive || runtime.input == nil {
		return errors.New("ok local down requires a terminal and explicit ok/no confirmation")
	}
	if state.Phase == "CREATING" || state.Phase == "INCOMPLETE" {
		return errors.New("local installation is incomplete; automatic cleanup is disabled because ownership evidence is not complete")
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
	if state.Forward != nil {
		inspect := runtime.inspectForward
		if inspect == nil {
			inspect = inspectLocalForwardProcess
		}
		processState, inspectErr := inspect(*state.Forward)
		if inspectErr != nil {
			return fmt.Errorf("cannot inspect recorded port-forward safely; refusing cluster deletion: %w", inspectErr)
		}
		switch processState {
		case localForwardMatches:
			stop := runtime.stopForward
			if stop == nil {
				stop = stopLocalForward
			}
			if err := stop(*state.Forward); err != nil {
				return fmt.Errorf("cannot stop verified port-forward; refusing cluster deletion: %w", err)
			}
		case localForwardAbsent:
			// A reboot or unexpected process exit leaves only stale local metadata.
		case localForwardPIDReused:
			// The PID now belongs to another process. Drop only our stale receipt;
			// never signal a process whose identity differs.
		default:
			return errors.New("port-forward process state is ambiguous; refusing cluster deletion")
		}
		state.Forward = nil
		if err := updateLocalClusterState(runtime.stateRoot, *name, state); err != nil {
			return fmt.Errorf("forward stopped but state update failed; refusing cluster deletion: %w", err)
		}
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
	URL              string `json:"url,omitempty"`
}

func writeLocalStatus(output io.Writer, jsonOutput bool, status localStatus) error {
	if jsonOutput {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(status)
	}
	if status.URL != "" {
		_, err := fmt.Fprintf(output, "Local %s: %s — %s\n", status.Name, status.State, status.URL)
		return err
	}
	_, err := fmt.Fprintf(output, "Local cluster %s: %s.\n", status.Name, status.State)
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
	bootstrapState := state.Format == localBootstrapStateFormat
	if (state.Format != localClusterStateFormat && state.Format != localBootstrapStateFormat && state.Format != "ok-cli-local-cluster/v2") || state.Name != name || !localClusterNamePattern.MatchString(name) || !localOwnerIDPattern.MatchString(state.OwnerID) || !localKindClusterNameMatchesReceipt(name, state.OwnerID, state.KindName) {
		return errors.New("unsupported local state format, cluster name or owner identifier")
	}
	if bootstrapState && state.Phase != "CREATING" && state.Phase != "INCOMPLETE" && state.Phase != "CLUSTER_READY" {
		return errors.New("unsupported diagnostic cluster state phase")
	}
	if (state.Format == localClusterStateFormat || bootstrapState) && (state.Phase == "CREATING" || state.Phase == "INCOMPLETE") {
		if state.Provider.Kind != "docker" || state.Provider.Context == "" || !strings.HasPrefix(state.Provider.Endpoint, "unix://") || state.Provider.DaemonID == "" || state.Kubeconfig != filepath.Join(clusterDir, "kubeconfig") {
			return errors.New("partial local intent is not bound to a valid private Docker provider and kubeconfig path")
		}
		return nil
	}
	if bootstrapState && state.Phase != "CLUSTER_READY" {
		return errors.New("diagnostic local state is not a verified retained cluster")
	}
	if state.Format == localClusterStateFormat && state.Phase != "READY" && state.Phase != "CLUSTER_READY" {
		return errors.New("local state phase is not a complete installation receipt")
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
	return localKindClusterNameWithLimit(name, ownerID, localKindMaxNameLength)
}

func localKindClusterNameWithLimit(name, ownerID string, maxLength int) string {
	// Keep the full random owner ID as the collision-resistant suffix and shorten
	// only the readable prefix to fit the Kind and derived-hostname contracts.
	prefixLimit := maxLength - len(ownerID) - 1
	if prefixLimit < 1 {
		return ""
	}
	prefix := name
	if len(prefix) > prefixLimit {
		prefix = prefix[:prefixLimit]
	}
	prefix = strings.TrimRight(prefix, "-")
	if prefix == "" {
		return ""
	}
	return prefix + "-" + ownerID
}

func validLocalKindClusterName(name string) bool {
	hostname := name + localKindControlPlaneSuffix
	return len(name) <= localKindMaxNameLength && localKindClusterNamePattern.MatchString(name) &&
		len(hostname) <= 63 && localKindClusterNamePattern.MatchString(hostname)
}

func localKindClusterNameMatchesReceipt(name, ownerID, kindName string) bool {
	if kindName == localKindClusterName(name, ownerID) {
		return true
	}
	// Receipts from the previous 50-character Kind-name contract remain valid.
	previousName := localKindClusterNameWithLimit(name, ownerID, localKindPreviousMaxNameLength)
	if kindName == previousName && len(previousName) <= localKindPreviousMaxNameLength && localKindClusterNamePattern.MatchString(previousName) {
		return true
	}
	// Existing v3 receipts used the full logical name before the verifier's
	// bounded-name contract. Continue to read those owner-bound receipts so a
	// prior installation can still be inspected or cleaned up safely.
	legacyName := name + "-" + ownerID
	return len(legacyName) <= 63 && localKindClusterNamePattern.MatchString(legacyName) && kindName == legacyName
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
	kindName := localKindClusterName(name, ownerID)
	if !validLocalKindClusterName(kindName) {
		return nil, errors.New("generated Kind name must be at most 49 characters and its control-plane hostname at most 63 characters")
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
`, kindName, localOwnerLabel, ownerID)
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

func writeLocalClusterIntent(root, name string, state localClusterState) error {
	clusterDir := filepath.Join(root, "clusters", name)
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
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	dir, err := os.Open(clusterDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func localBootstrapDiagnosticPath(root, name string) string {
	return filepath.Join(root, "clusters", name, "bootstrap-diagnostic.json")
}

func validateLocalBootstrapDiagnosticReceipt(receipt localBootstrapDiagnosticReceipt) error {
	if receipt.Format != localBootstrapDiagnosticFormat || !localClusterNamePattern.MatchString(receipt.Name) ||
		!localOwnerIDPattern.MatchString(receipt.OwnerID) || !localKindClusterNameMatchesReceipt(receipt.Name, receipt.OwnerID, receipt.KindName) ||
		receipt.Provider.Kind != "docker" || receipt.Provider.Context == "" || !strings.HasPrefix(receipt.Provider.Endpoint, "unix://") || receipt.Provider.DaemonID == "" ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(receipt.ConfigSHA256) {
		return errors.New("invalid local bootstrap diagnostic identity receipt")
	}
	if receipt.State != "PREPARED" && receipt.State != "FAILED" && receipt.State != "SUCCEEDED_RETAINED" {
		return errors.New("unsupported local bootstrap diagnostic state")
	}
	if receipt.ResourceState != "UNKNOWN" && receipt.ResourceState != "ABSENT" && receipt.ResourceState != "VERIFIED_RETAINED" && receipt.ResourceState != "AMBIGUOUS" {
		return errors.New("unsupported local bootstrap diagnostic resource state")
	}
	if receipt.State == "PREPARED" && (receipt.FailureCode != "" || receipt.ResourceState != "UNKNOWN" || len(receipt.Containers) != 0 || receipt.KubeconfigSeen) {
		return errors.New("prepared diagnostic receipt contains outcome data")
	}
	if receipt.State == "FAILED" && !localBootstrapDiagnosticCodes[receipt.FailureCode] {
		return errors.New("failed diagnostic receipt has an unapproved failure code")
	}
	if receipt.State == "SUCCEEDED_RETAINED" && (receipt.FailureCode != "" || receipt.ResourceState != "VERIFIED_RETAINED" || len(receipt.Containers) != 1 || !receipt.KubeconfigSeen) {
		return errors.New("successful diagnostic receipt lacks exact retained-resource evidence")
	}
	if receipt.ResourceState == "ABSENT" && (len(receipt.Containers) != 0 || receipt.KubeconfigSeen) {
		return errors.New("absent diagnostic resource receipt contains resource evidence")
	}
	if receipt.ResourceState == "VERIFIED_RETAINED" && len(receipt.Containers) != 1 {
		return errors.New("retained diagnostic resource receipt must contain exactly one node")
	}
	if len(receipt.Containers) > 32 {
		return errors.New("diagnostic container inventory exceeds the node limit")
	}
	seen := map[string]bool{}
	for _, container := range receipt.Containers {
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(container.ID) || container.Name == "" || strings.ContainsAny(container.Name, " \t\r\n") ||
			(container.Role != "control-plane" && container.Role != "worker") || seen[container.ID] {
			return errors.New("diagnostic container identity is invalid or duplicated")
		}
		seen[container.ID] = true
	}
	if receipt.ResourceState == "VERIFIED_RETAINED" {
		container := receipt.Containers[0]
		if container.Name != receipt.KindName+"-control-plane" || container.Role != "control-plane" {
			return errors.New("retained diagnostic container does not match the owner-specific control plane")
		}
	}
	return nil
}

func writeLocalBootstrapDiagnosticReceipt(root string, receipt localBootstrapDiagnosticReceipt, replace bool) error {
	if err := validateLocalBootstrapDiagnosticReceipt(receipt); err != nil {
		return err
	}
	path := localBootstrapDiagnosticPath(root, receipt.Name)
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return errors.New("could not encode local bootstrap diagnostic receipt")
	}
	raw = append(raw, '\n')
	if !replace {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := file.Write(raw); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return err
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(path)
			return err
		}
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("existing bootstrap diagnostic receipt is not a private regular file")
	}
	previous, err := readLocalBootstrapDiagnosticReceipt(root, receipt.Name)
	if err != nil || previous.State != "PREPARED" || previous.OwnerID != receipt.OwnerID || previous.Provider != receipt.Provider || previous.KindName != receipt.KindName {
		return errors.New("bootstrap diagnostic receipt identity changed; refusing replacement")
	}
	temporary := path + ".tmp-" + receipt.OwnerID
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readLocalBootstrapDiagnosticReceipt(root, name string) (localBootstrapDiagnosticReceipt, error) {
	var receipt localBootstrapDiagnosticReceipt
	path := localBootstrapDiagnosticPath(root, name)
	info, err := os.Lstat(path)
	if err != nil {
		return receipt, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 64*1024 {
		return receipt, errors.New("bootstrap diagnostic receipt must be a private regular file at most 64 KiB")
	}
	raw, err := readBoundedLocalFile(path, 64*1024)
	if err != nil {
		return receipt, err
	}
	if err := jsonstrict.Decode(raw, &receipt); err != nil {
		return receipt, errors.New("invalid bootstrap diagnostic receipt")
	}
	if err := validateLocalBootstrapDiagnosticReceipt(receipt); err != nil || receipt.Name != name {
		return receipt, errors.New("bootstrap diagnostic receipt does not match its state path")
	}
	configPath := filepath.Join(filepath.Dir(path), "kind.yaml")
	configInfo, err := os.Lstat(configPath)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Mode()&os.ModeSymlink != 0 || configInfo.Mode().Perm()&0o077 != 0 {
		return receipt, errors.New("bootstrap diagnostic Kind config is not private and regular")
	}
	config, err := readBoundedLocalFile(configPath, 64*1024)
	if err != nil || sha256Hex(config) != receipt.ConfigSHA256 {
		return receipt, errors.New("bootstrap diagnostic config digest does not match its private config")
	}
	return receipt, nil
}

func updateLocalClusterState(root, name string, state localClusterState) error {
	if err := validateLocalClusterState(root, name, state); err != nil {
		return err
	}
	path := localStateFilePath(root, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("existing local state is not a private regular file")
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	temporary := path + ".tmp-" + state.OwnerID
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removeLocalClusterState(root, name string) error {
	clusterDir := filepath.Join(root, "clusters", name)
	paths := []string{filepath.Join(clusterDir, "state.json"), filepath.Join(clusterDir, "kubeconfig"), filepath.Join(clusterDir, "kind.yaml"), filepath.Join(clusterDir, "port-forward.log")}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
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
  up       Create a dedicated kind cluster and deploy the local Console demo, or explicitly select temporary CAPI bootstrap
  resume   Verify and resume an existing owner-bound INCOMPLETE installation
  reconnect Restore a missing owner-bound Console port-forward without redeploying
  status   Verify local cluster ownership and Console health
  down     Confirm and delete only a cluster whose live identity matches its receipt
  diagnose Run one explicit Kind bootstrap diagnostic without deploying Console

The local workflow is independent of OK-147 CreateCluster. It never selects the
global/current Kubernetes context. The first MVP uses the Console local-kind
fixture profile; no production identity or database is installed.
`)
}

func writeLocalCommandHelp(command string, output io.Writer) {
	switch command {
	case "up":
		fmt.Fprint(output, "Usage: ok local up [--name ok-local]\n       ok local up [--name ok-local] --bootstrap capi\n\nWithout --bootstrap, creates one owner-labeled local Kind cluster and deploys the Console local-kind fixture profile.\n--bootstrap capi creates a temporary owner-bound Colima/Kind management cluster, installs pinned CAPI/CAPD providers and stops at CAPI_READY. It does not create ok-mgmt-local, move cluster ownership, or deploy Console.\nRequires Docker, Kind, kubectl, clusterctl v1.14.4 and Colima. Failures after durable intent remain INCOMPLETE; no automatic retry or cleanup.\n")
	case "resume":
		fmt.Fprint(output, "Usage: ok local resume [--name ok-local]\n\nResumes only an existing owner-bound INCOMPLETE installation. Rechecks Docker, Kind, Kubernetes identities, the isolated kubeconfig and the existing Console workload before starting the managed loopback port-forward. It never creates or redeploys resources or replaces kubeconfig.\n")
	case "reconnect":
		fmt.Fprint(output, "Usage: ok local reconnect [--name ok-local]\n\nRestores one missing managed Console port-forward from a valid READY receipt after rechecking provider, cluster ownership, kubeconfig, Console health and port availability. Refuses an active or ambiguous prior process. It never creates or redeploys Kubernetes resources.\n")
	case "status":
		fmt.Fprint(output, "Usage: ok local status [--name ok-local] [--json]\n\nRead-only ownership and Console health inspection through the isolated kubeconfig. Reports forward-process loss, identity mismatch, HTTP unavailability, or READY separately.\n")
	case "down":
		fmt.Fprint(output, "Usage: ok local down [--name ok-local]\n\nRequires an interactive ok/no confirmation and a live ownership match. No state file or cluster name alone authorizes deletion.\n")
	case "diagnose":
		fmt.Fprint(output, "Usage: ok local diagnose bootstrap --name <fresh-logical-name>\n\nExplicit E2E diagnostic only. Uses Kind --retain, never builds or deploys Console, and leaves every result for owner-controlled inspection. No automatic retry or cleanup.\n")
	case "diagnose bootstrap":
		fmt.Fprint(output, "Usage: ok local diagnose bootstrap --name <fresh-logical-name>\n\nCreates one owner-bound Kind cluster with --retain for failure forensics. It does not deploy Console, export logs, retry, adopt or delete resources. A retained result blocks ok local up/down until separately authorized cleanup is implemented.\n")
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
