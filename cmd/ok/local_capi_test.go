package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func validLocalCAPIState(root string) localCAPIState {
	name, ownerID := "ok-local", "0123456789abcdef0123456789abcdef"
	dir := localCAPIStateDirectory(root, name)
	return localCAPIState{
		Format: localCAPIStateFormat, Phase: localCAPIPhaseCreating, Name: name, OwnerID: ownerID,
		Provider:          localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: testColimaEndpoint(), DaemonID: "daemon-123"},
		BootstrapKindName: localKindClusterName(name, ownerID), BootstrapKubeconfig: filepath.Join(dir, "bootstrap.kubeconfig"),
		KindConfigPath: filepath.Join(dir, "kind.yaml"), KindConfigSHA256: strings.Repeat("a", 64),
		ClusterctlConfigPath: filepath.Join(dir, "clusterctl.yaml"), ClusterctlConfigSHA256: strings.Repeat("b", 64),
		KubernetesVersion: localCAPIKubernetesVersion, NodeImage: localCAPINodeImage, ProviderVersions: localCAPIVersions(), BootstrapResourceState: localCAPIResourceUnknown,
	}
}

func testColimaEndpoint() string {
	home, _ := os.UserHomeDir()
	return "unix://" + filepath.Join(home, ".colima", "default", "docker.sock")
}

func TestLocalCAPIStateValidationAndIsolation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state := validLocalCAPIState(root)
	if state.Format == localClusterStateFormat || localCAPIStateFilePath(root, state.Name) == localStateFilePath(root, state.Name) {
		t.Fatal("CAPI receipt is not isolated from the existing Kind/Console lifecycle")
	}
	for _, phase := range []localCAPIPhase{localCAPIPhaseCreating, localCAPIPhaseIncomplete} {
		t.Run(string(phase), func(t *testing.T) {
			candidate := state
			candidate.Phase = phase
			if phase == localCAPIPhaseIncomplete {
				candidate.FailureStage, candidate.FailureCode = "kind-create", "KIND_CREATE_FAILED"
			}
			if err := validateLocalCAPIState(root, candidate); err != nil {
				t.Fatalf("valid %s rejected: %v", phase, err)
			}
		})
	}
	for _, mutate := range []func(*localCAPIState){
		func(s *localCAPIState) { s.Format = localClusterStateFormat },
		func(s *localCAPIState) { s.Phase = "READY" },
		func(s *localCAPIState) { s.Name = "Not-valid" },
		func(s *localCAPIState) { s.OwnerID = "owner" },
		func(s *localCAPIState) { s.BootstrapKindName = "other" },
		func(s *localCAPIState) { s.BootstrapKubeconfig = "/tmp/other" },
		func(s *localCAPIState) { s.Provider.Kind = "kubernetes" },
		func(s *localCAPIState) { s.Provider.Context = "default" },
		func(s *localCAPIState) { s.Provider.DaemonID = "" },
		func(s *localCAPIState) { s.Provider.Endpoint = "tcp://example" },
		func(s *localCAPIState) { s.FailureCode = "raw secret" },
	} {
		candidate := state
		mutate(&candidate)
		if err := validateLocalCAPIState(root, candidate); err == nil {
			t.Fatalf("invalid state accepted: %+v", candidate)
		}
	}
	if err := validateLocalCAPIState("relative", state); err == nil {
		t.Fatal("relative root accepted")
	}
}

func TestLocalCAPIClusterctlVersionPinIsExact(t *testing.T) {
	for _, test := range []struct {
		output string
		want   bool
	}{
		{"clusterctl version: v1.14.4\n", true},
		{"clusterctl version: v1.14.40\n", false},
		{"clusterctl version: v1.14.3\n", false},
		{"diagnostic v1.14.4, clusterctl version: v1.14.5\n", false},
		{"clusterctl version: v1.14.4\nclusterctl version: v1.14.4\n", false},
	} {
		if got := validateLocalCAPIClusterctlVersion([]byte(test.output)); got != test.want {
			t.Errorf("validateLocalCAPIClusterctlVersion(%q)=%v, want %v", test.output, got, test.want)
		}
	}
}

func TestLocalCAPIKindConfigIsOwnerBoundAndMountsColimaSocket(t *testing.T) {
	owner := "0123456789abcdef0123456789abcdef"
	raw, err := renderLocalCAPIKindConfig("ok-local", owner)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Kind       string `yaml:"kind"`
		APIVersion string `yaml:"apiVersion"`
		Name       string `yaml:"name"`
		Networking struct {
			APIServerAddress string `yaml:"apiServerAddress"`
		} `yaml:"networking"`
		Nodes []struct {
			Role        string `yaml:"role"`
			ExtraMounts []struct {
				HostPath      string `yaml:"hostPath"`
				ContainerPath string `yaml:"containerPath"`
			} `yaml:"extraMounts"`
			Patches []string `yaml:"kubeadmConfigPatches"`
		} `yaml:"nodes"`
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config.Kind != "Cluster" || config.APIVersion != "kind.x-k8s.io/v1alpha4" || config.Name != localKindClusterName("ok-local", owner) || config.Networking.APIServerAddress != "127.0.0.1" || len(config.Nodes) != 1 || config.Nodes[0].Role != "control-plane" {
		t.Fatalf("unexpected Kind config: %+v", config)
	}
	if len(config.Nodes[0].ExtraMounts) != 1 || config.Nodes[0].ExtraMounts[0].HostPath != "/var/run/docker.sock" || config.Nodes[0].ExtraMounts[0].ContainerPath != "/var/run/docker.sock" {
		t.Fatalf("CAPD socket mount missing: %+v", config.Nodes[0].ExtraMounts)
	}
	if len(config.Nodes[0].Patches) != 1 || !strings.Contains(config.Nodes[0].Patches[0], localOwnerLabel+"="+owner) {
		t.Fatal("owner label not in node bootstrap patch")
	}
	if len(config.Name+localKindControlPlaneSuffix) > 63 {
		t.Fatal("derived hostname exceeds DNS label limit")
	}
}

func TestLocalUpCAPIArgumentsAndStateConflictAreFailClosed(t *testing.T) {
	for _, args := range [][]string{{"up", "--bootstrap", "kubeadm"}, {"up", "--bootstrap="}, {"up", "--bootstrap", "capi", "extra"}, {"up", "--name", "BAD", "--bootstrap", "capi"}} {
		calls := 0
		runtime := localRuntime{stateRoot: t.TempDir(), run: func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }}
		if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil || calls != 0 {
			t.Fatalf("bad args reached execution: %v calls=%d", err, calls)
		}
	}
	for _, path := range []string{filepath.Join("clusters", "ok-local"), filepath.Join("capi", "clusters", "ok-local")} {
		root := t.TempDir()
		conflict := filepath.Join(root, path)
		if err := os.MkdirAll(conflict, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(conflict, "state.json")
		const original = `{"format":"existing-owner-receipt"}`
		if err := os.WriteFile(marker, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		calls := 0
		runtime := localRuntime{stateRoot: root, run: func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }}
		err := runLocalWithRuntime(context.Background(), []string{"up", "--name", "ok-local", "--bootstrap", "capi"}, io.Discard, io.Discard, runtime)
		if err == nil || !strings.Contains(err.Error(), "will not overwrite") || calls != 0 {
			t.Fatalf("ownership conflict not rejected: %v calls=%d", err, calls)
		}
		got, _ := os.ReadFile(marker)
		if string(got) != original {
			t.Fatal("conflicting receipt changed")
		}
	}
}

func capiMockRuntime(t *testing.T, createErr error) localRuntime {
	t.Helper()
	root := filepath.Join(t.TempDir(), "local-state")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "unix://" + filepath.Join(home, ".colima", "default", "docker.sock")
	provider := localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: endpoint, DaemonID: "daemon-id"}
	kubeconfig := strings.ReplaceAll(localKubeconfigFixture, "kind-ok-local", "kind-"+localKindClusterName("ok-local", "0123456789abcdef0123456789abcdef"))
	owner := "0123456789abcdef0123456789abcdef"
	kindName := localKindClusterName("ok-local", owner)
	created := false
	runtime := localRuntime{stateRoot: root, run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		switch command {
		case "kind":
			return []byte("kind v0.33.0 go1.25.0 darwin/arm64\n"), nil
		case "clusterctl":
			return []byte("clusterctl version: v1.14.4\n"), nil
		case "kubectl":
			return []byte(`{"clientVersion":{"gitVersion":"v1.35.8"}}`), nil
		case "docker":
			joined := strings.Join(args, " ")
			if joined == "context show" {
				return []byte("colima\n"), nil
			}
			if strings.Contains(joined, "context inspect") {
				return []byte(endpoint + "\n"), nil
			}
			if strings.Contains(joined, "info --format {{.ID}}") {
				return []byte(provider.DaemonID + "\n"), nil
			}
			return []byte(`{"cpus":8,"memory":12500000000,"root":"/var/lib/docker"}`), nil
		case "colima":
			if strings.Contains(strings.Join(args, " "), "docker info") {
				return []byte(provider.DaemonID + "\n"), nil
			}
			if strings.Contains(strings.Join(args, " "), "df -Pk") {
				return []byte("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000000 1000000 99000000 1% /var/lib/docker\n"), nil
			}
			if strings.Contains(strings.Join(args, " "), "sysctl") {
				return []byte("8192\n"), nil
			}
			return nil, nil
		}
		return nil, errors.New("unexpected mock command")
	}, runPinned: func(_ context.Context, _ localProviderIdentity, command string, args ...string) ([]byte, error) {
		if command == "kind" && strings.Join(args, " ") == "get clusters" {
			return nil, nil
		}
		if command == "kind" && len(args) > 1 && args[0] == "get" && args[1] == "kubeconfig" {
			return []byte(kubeconfig), nil
		}
		if command == "docker" && strings.Contains(strings.Join(args, " "), "ps -a") {
			if created {
				return []byte(strings.Repeat("a", 64) + "|" + kindName + "-control-plane|control-plane\n"), nil
			}
			return nil, nil
		}
		if command == "docker" && strings.Contains(strings.Join(args, " "), "info --format") {
			return []byte(`{"cpus":8,"memory":12500000000,"root":"/var/lib/docker"}`), nil
		}
		return nil, errors.New("unexpected pinned command")
	}, lookPath: func(string) (string, error) { return "/mock/tool", nil },
		runKindCreate: func(_ context.Context, _ localProviderIdentity, _ string, args ...string) ([]byte, bool, error) {
			if createErr != nil {
				return []byte("secret-bearing raw output"), false, createErr
			}
			created = true
			for i, arg := range args {
				if arg == "--kubeconfig" {
					if err := os.WriteFile(args[i+1], []byte(kubeconfig), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			return nil, false, nil
		},
		runCAPI: func(_ context.Context, _ localProviderIdentity, private string, env map[string]string, command string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if command == "kubectl" && strings.Contains(joined, " wait ") {
				return nil, nil
			}
			switch {
			case command == "kubectl" && strings.Contains(joined, "get nodes"):
				return []byte(`{"items":[{"metadata":{"name":"` + kindName + `-control-plane","uid":"node-uid","labels":{"` + localOwnerLabel + `":"` + owner + `"}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`), nil
			case command == "kubectl" && strings.Contains(joined, "get namespace kube-system"):
				return []byte(`{"metadata":{"uid":"kube-system-uid"}}`), nil
			case command == "kubectl" && strings.Contains(joined, "get deployments"):
				return capiDeploymentFixture(), nil
			case command == "kubectl" && strings.Contains(joined, "get crds"):
				return []byte(`{"items":[{"metadata":{"name":"clusters.cluster.x-k8s.io"}},{"metadata":{"name":"kubeadmconfigs.bootstrap.cluster.x-k8s.io"}},{"metadata":{"name":"kubeadmcontrolplanes.controlplane.cluster.x-k8s.io"}},{"metadata":{"name":"dockerclusters.infrastructure.cluster.x-k8s.io"}}]}`), nil
			case command == "clusterctl" && strings.Contains(joined, "get providers"):
				return []byte(`{"providers":[{"name":"cluster-api","type":"CoreProvider","version":"v1.14.4"},{"name":"kubeadm","type":"BootstrapProvider","version":"v1.14.4"},{"name":"kubeadm","type":"ControlPlaneProvider","version":"v1.14.4"},{"name":"docker","type":"InfrastructureProvider","version":"v1.14.4"}]}`), nil
			case command == "clusterctl" && len(args) > 0 && args[0] == "init":
				if env["CLUSTER_TOPOLOGY"] != "true" || private == "" {
					t.Fatal("clusterctl init missing isolated bootstrap settings")
				}
				return nil, nil
			}
			return nil, errors.New("unexpected CAPI command")
		},
		newOwnerID: func() (string, error) { return owner, nil },
	}
	return runtime
}

func capiDeploymentFixture() []byte {
	type item struct {
		Metadata map[string]any `json:"metadata"`
		Spec     map[string]any `json:"spec"`
		Status   map[string]any `json:"status"`
		Template map[string]any `json:"template"`
	}
	names := [][2]string{{"capi-system", "capi-controller-manager"}, {"capi-kubeadm-bootstrap-system", "capi-kubeadm-bootstrap-controller-manager"}, {"capi-kubeadm-control-plane-system", "capi-kubeadm-control-plane-controller-manager"}, {"capd-system", "capd-controller-manager"}, {"cert-manager", "cert-manager"}, {"cert-manager", "cert-manager-cainjector"}, {"cert-manager", "cert-manager-webhook"}}
	items := make([]item, 0, len(names))
	for i, pair := range names {
		args := []string{}
		image := "controller:v1.14.4"
		if i < 4 {
			args = []string{"--feature-gates=ClusterTopology=true"}
		}
		if i >= 4 {
			image = "controller:" + localCAPICertManagerVersion
		}
		container := map[string]any{"name": "manager", "image": image, "args": args}
		templateSpec := map[string]any{"containers": []map[string]any{container}}
		if i == 3 {
			container["volumeMounts"] = []map[string]any{{"name": "dockersock", "mountPath": "/var/run/docker.sock"}}
			templateSpec["volumes"] = []map[string]any{{"name": "dockersock", "hostPath": map[string]any{"path": "/var/run/docker.sock"}}}
		}
		items = append(items, item{Metadata: map[string]any{"name": pair[1], "namespace": pair[0], "uid": "uid-" + pair[1], "generation": 1}, Spec: map[string]any{"replicas": 1}, Status: map[string]any{"observedGeneration": 1, "availableReplicas": 1}, Template: map[string]any{"spec": templateSpec}})
	}
	data, _ := json.Marshal(map[string]any{"items": items})
	return data
}

func TestLocalCAPIBootstrapSuccessIsMockedOwnerBoundAndCAPIReady(t *testing.T) {
	runtime := capiMockRuntime(t, nil)
	baseRunner := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		if kubeconfig != filepath.Join(runtime.stateRoot, "capi", "clusters", "ok-local", "bootstrap.kubeconfig") {
			t.Fatalf("non-private kubeconfig passed to %s", command)
		}
		if command == "kubectl" || command == "clusterctl" {
			found := false
			for i := 0; i+1 < len(args); i++ {
				if args[i] == "--kubeconfig" && args[i+1] == kubeconfig {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s command lacks an explicit isolated kubeconfig: %q", command, args)
			}
		}
		if command == "clusterctl" && len(args) > 0 && args[0] == "init" {
			state, err := readLocalCAPIState(runtime.stateRoot, "ok-local")
			if err != nil || state.Phase != localCAPIPhaseInitializing {
				t.Fatalf("CAPI init mutation began without durable initializing phase: state=%+v err=%v", state, err)
			}
		}
		return baseRunner(ctx, provider, kubeconfig, env, command, args...)
	}
	if err := runLocalWithRuntime(context.Background(), []string{"up", "--bootstrap", "capi"}, io.Discard, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	state, err := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != localCAPIPhaseCAPIReady || state.Node == nil || state.Node.UID != "node-uid" || state.KubeSystemUID != "kube-system-uid" || len(state.Containers) != 1 || len(state.Deployments) != 7 || len(state.CRDs) != 4 {
		t.Fatalf("CAPI_READY evidence incomplete: %+v", state)
	}
	if _, err := os.Stat(localStateFilePath(runtime.stateRoot, "ok-local")); !os.IsNotExist(err) {
		t.Fatalf("CAPI mode wrote v3 local receipt: %v", err)
	}
}

func TestLocalCAPIFailurePersistsIncompleteAndDoesNotRetryOrLeakOutput(t *testing.T) {
	runtime := capiMockRuntime(t, errors.New("mock secret token failure"))
	err := runLocalWithRuntime(context.Background(), []string{"up", "--bootstrap", "capi"}, io.Discard, io.Discard, runtime)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "raw output") {
		t.Fatalf("unsafe or missing failure: %v", err)
	}
	state, readErr := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if state.Phase != localCAPIPhaseIncomplete || state.FailureCode != "KIND_CREATE_FAILED" {
		t.Fatalf("failure state not durable: %+v", state)
	}
	calls := 0
	runtime.run = func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	if err := runLocalCAPIUpContext(context.Background(), "ok-local", runtime); err == nil || calls != 0 {
		t.Fatalf("existing CAPI intent was retried: err=%v calls=%d", err, calls)
	}
}

func TestLocalCAPIClusterctlFailureLeavesVerifiedBootstrapAndNoCAPIReady(t *testing.T) {
	runtime := capiMockRuntime(t, nil)
	base := runtime.runCAPI
	initFailed := false
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		if command == "clusterctl" && len(args) > 0 && args[0] == "init" {
			initFailed = true
			return []byte("secret-token must not be shown"), errors.New("failed after partial install")
		}
		if initFailed && command == "clusterctl" && strings.Contains(strings.Join(args, " "), "get providers") {
			return []byte(`{"providers":[{"name":"cluster-api","type":"CoreProvider","version":"v1.14.4"}]}`), nil
		}
		if initFailed && command == "kubectl" && strings.Contains(strings.Join(args, " "), "get deployments") {
			return []byte(`{"items":[{"metadata":{"name":"capi-controller-manager","namespace":"capi-system","uid":"partial-deploy-uid","generation":2},"spec":{"replicas":1,"template":{"spec":{"containers":[{"env":[{"name":"TOKEN","value":"do-not-persist"}]}]}}},"status":{"observedGeneration":1,"availableReplicas":0}}]}`), nil
		}
		if initFailed && command == "kubectl" && strings.Contains(strings.Join(args, " "), "get crds") {
			return []byte(`{"items":[{"metadata":{"name":"clusters.cluster.x-k8s.io"}}]}`), nil
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	err := runLocalCAPIUpContext(context.Background(), "ok-local", runtime)
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unsafe or missing failure: %v", err)
	}
	state, readErr := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if state.Phase != localCAPIPhaseIncomplete || state.FailureCode != "CAPI_INIT_FAILED" || state.BootstrapResourceState != localCAPIResourceVerified || state.Node == nil || state.Node.UID == "" {
		t.Fatalf("verified bootstrap evidence was not retained: %+v", state)
	}
	if state.InitEvidence == nil || !state.InitEvidence.ProvidersObserved || len(state.InitEvidence.Providers) != 1 || !state.InitEvidence.DeploymentsObserved || len(state.InitEvidence.Deployments) != 1 || state.InitEvidence.Deployments[0].AvailableReplicas != 0 || !state.InitEvidence.CRDsObserved || len(state.InitEvidence.CRDs) != 1 {
		t.Fatalf("partial CAPI install inventory was not retained: %+v", state.InitEvidence)
	}
	receipt, readErr := os.ReadFile(localCAPIStateFilePath(runtime.stateRoot, "ok-local"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(receipt), "do-not-persist") || strings.Contains(string(receipt), "secret-token") {
		t.Fatal("partial CAPI receipt leaked command or environment secrets")
	}
}

func TestLocalCAPIReadinessTimeoutNeverClaimsCAPIReady(t *testing.T) {
	runtime := capiMockRuntime(t, nil)
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		if command == "kubectl" && strings.Contains(strings.Join(args, " "), "wait --for=condition=Available deployment/capi-controller-manager") {
			return nil, errors.New("timed out")
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	err := runLocalCAPIUpContext(context.Background(), "ok-local", runtime)
	if err == nil {
		t.Fatal("controller timeout was reported as success")
	}
	state, readErr := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if state.Phase != localCAPIPhaseIncomplete || state.FailureCode != "CAPI_VERIFY_FAILED" {
		t.Fatalf("timeout falsely claimed readiness: %+v", state)
	}
}

func TestLocalCAPIReadyRequiresCAPDDockerSocketMount(t *testing.T) {
	runtime := capiMockRuntime(t, nil)
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		if command == "kubectl" && strings.Contains(strings.Join(args, " "), "get deployments") {
			var inventory map[string]any
			if err := json.Unmarshal(capiDeploymentFixture(), &inventory); err != nil {
				t.Fatal(err)
			}
			items := inventory["items"].([]any)
			capd := items[3].(map[string]any)
			templateSpec := capd["template"].(map[string]any)["spec"].(map[string]any)
			delete(templateSpec, "volumes")
			containers := templateSpec["containers"].([]any)
			delete(containers[0].(map[string]any), "volumeMounts")
			return json.Marshal(inventory)
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	if err := runLocalCAPIUpContext(context.Background(), "ok-local", runtime); err == nil {
		t.Fatal("CAPI_READY accepted a CAPD deployment without the Docker socket mount")
	}
	state, err := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != localCAPIPhaseIncomplete || state.FailureCode != "CAPI_VERIFY_FAILED" {
		t.Fatalf("missing CAPD socket did not fail closed: %+v", state)
	}
}

func TestLocalLifecycleOperationLockSerializesNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	release, err := acquireLocalLifecycleOperationLock(root, "ok-local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLocalLifecycleOperationLock(root, "ok-local"); err == nil {
		t.Fatal("second lifecycle operation acquired the same logical name")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	releaseAgain, err := acquireLocalLifecycleOperationLock(root, "ok-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseAgain(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalCAPIPreflightDriftAndCollisionDoNotCreateIntent(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*testing.T, *localRuntime)
	}{
		{"wrong Docker context", func(_ *testing.T, rt *localRuntime) {
			base := rt.run
			rt.run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "docker" && strings.Join(args, " ") == "context show" {
					return []byte("default"), nil
				}
				return base(ctx, cmd, args...)
			}
		}},
		{"wrong VM daemon", func(_ *testing.T, rt *localRuntime) {
			base := rt.run
			rt.run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "colima" && strings.Contains(strings.Join(args, " "), "docker info") {
					return []byte("different-daemon"), nil
				}
				return base(ctx, cmd, args...)
			}
		}},
		{"missing Colima Docker socket", func(_ *testing.T, rt *localRuntime) {
			base := rt.run
			rt.run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "colima" && strings.Contains(strings.Join(args, " "), "test -S") {
					return nil, errors.New("missing")
				}
				return base(ctx, cmd, args...)
			}
		}},
		{"low inotify limit", func(_ *testing.T, rt *localRuntime) {
			base := rt.run
			rt.run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "colima" && strings.Contains(strings.Join(args, " "), "sysctl") {
					return []byte("4096"), nil
				}
				return base(ctx, cmd, args...)
			}
		}},
		{"unsafe socket endpoint", func(_ *testing.T, rt *localRuntime) {
			base := rt.run
			rt.run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "docker" && strings.Contains(strings.Join(args, " "), "context inspect") {
					return []byte("tcp://127.0.0.1:2376"), nil
				}
				return base(ctx, cmd, args...)
			}
		}},
		{"existing generated kind name", func(_ *testing.T, rt *localRuntime) {
			owner := "0123456789abcdef0123456789abcdef"
			kindName := localKindClusterName("ok-local", owner)
			base := rt.runPinned
			rt.runPinned = func(ctx context.Context, p localProviderIdentity, cmd string, args ...string) ([]byte, error) {
				if cmd == "kind" && strings.Join(args, " ") == "get clusters" {
					return []byte(kindName + "\n"), nil
				}
				return base(ctx, p, cmd, args...)
			}
		}},
		{"existing owner-labeled Docker resource", func(_ *testing.T, rt *localRuntime) {
			base := rt.runPinned
			rt.runPinned = func(ctx context.Context, p localProviderIdentity, cmd string, args ...string) ([]byte, error) {
				if cmd == "docker" && strings.Contains(strings.Join(args, " "), "label="+localOwnerLabel+"=0123456789abcdef0123456789abcdef") {
					return []byte(strings.Repeat("a", 64)), nil
				}
				return base(ctx, p, cmd, args...)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := capiMockRuntime(t, nil)
			test.alter(t, &rt)
			if err := runLocalCAPIUpContext(context.Background(), "ok-local", rt); err == nil {
				t.Fatal("preflight discrepancy accepted")
			}
			if _, err := os.Lstat(rt.stateRoot); !os.IsNotExist(err) {
				t.Fatalf("preflight created lifecycle state: %v", err)
			}
		})
	}
}

func TestLocalCAPICommandRunnerUsesOnlyPrivateKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/global/kubeconfig-must-not-be-used")
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell unavailable for environment isolation check")
	}
	private := filepath.Join(t.TempDir(), "bootstrap.kubeconfig")
	provider := localProviderIdentity{Kind: "docker", Context: "colima", Endpoint: testColimaEndpoint(), DaemonID: "daemon-123"}
	output, err := runLocalCAPICommand(context.Background(), provider, private, nil, "sh", "-c", "printf %s \"$KUBECONFIG\"")
	if err != nil || string(output) != private {
		t.Fatalf("isolated KUBECONFIG not enforced: output=%q err=%v", output, err)
	}
}

func TestLocalCAPIPreflightFailureHasNoStateOrKindMutation(t *testing.T) {
	runtime := capiMockRuntime(t, nil)
	calls := 0
	runtime.lookPath = func(name string) (string, error) {
		calls++
		if name == "clusterctl" {
			return "", errors.New("not found")
		}
		return "/mock/" + name, nil
	}
	err := runLocalCAPIUpContext(context.Background(), "ok-local", runtime)
	if err == nil || !strings.Contains(err.Error(), "clusterctl") {
		t.Fatalf("missing tool not rejected: %v", err)
	}
	if calls != 4 {
		t.Fatalf("unexpected preflight tool probes: %d", calls)
	}
	if _, err := os.Lstat(runtime.stateRoot); !os.IsNotExist(err) {
		t.Fatalf("preflight created state: %v", err)
	}
}

func TestLocalCAPIStateFileIsPrivateAndStrict(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validLocalCAPIState(root)
	if err := createLocalCAPILifecycleDirectory(root, state.Name); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalCAPIState(root, state, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(localCAPIStateFilePath(root, state.Name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o", info.Mode().Perm())
	}
	if _, err := readLocalCAPIState(root, state.Name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localCAPIStateFilePath(root, state.Name), []byte(`{"format":"x","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalCAPIState(root, state.Name); err == nil {
		t.Fatal("unknown receipt fields accepted")
	}
}

func TestLocalCAPIStateTransitionsAreOneWayAndBoundToIntent(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := validLocalCAPIState(root)
	if err := createLocalCAPILifecycleDirectory(root, state.Name); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalCAPIState(root, state, false); err != nil {
		t.Fatal(err)
	}
	bootstrap := state
	bootstrap.Phase = localCAPIPhaseBootstrapReady
	bootstrap.BootstrapResourceState = localCAPIResourceVerified
	bootstrap.BootstrapKubeconfigSeen = true
	bootstrap.Containers = []localCAPIContainerEvidence{{ID: strings.Repeat("a", 64), Name: bootstrap.BootstrapKindName + "-control-plane", Role: "control-plane", KindClusterName: bootstrap.BootstrapKindName}}
	bootstrap.Node = &localNodeIdentity{Name: bootstrap.Containers[0].Name, UID: "node-uid"}
	bootstrap.NodeOwnerID = bootstrap.OwnerID
	bootstrap.KubeSystemUID = "namespace-uid"
	if err := writeLocalCAPIState(root, bootstrap, true); err != nil {
		t.Fatal(err)
	}
	wrongOwner := bootstrap
	wrongOwner.OwnerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := writeLocalCAPIState(root, wrongOwner, true); err == nil {
		t.Fatal("changed owner overwrote durable intent")
	}
	incomplete := bootstrap
	incomplete.Phase = localCAPIPhaseIncomplete
	incomplete.FailureStage = "capi-init"
	incomplete.FailureCode = "CAPI_INIT_FAILED"
	if err := writeLocalCAPIState(root, incomplete, true); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalCAPIState(root, bootstrap, true); err == nil {
		t.Fatal("INCOMPLETE state was replayed")
	}
}

func TestLocalCAPIFailureClassificationIsAllowlisted(t *testing.T) {
	if !localCAPIFailureCodes["KIND_CREATE_FAILED"] || localCAPIFailureCodes["SECRET_TOKEN"] {
		t.Fatal("failure code allowlist is not closed")
	}
}
