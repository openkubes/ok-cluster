package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const localCAPIWorkloadCalicoTestFixture = `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: calico-node
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - name: calico-node
        env:
            # - name: CALICO_IPV4POOL_CIDR
            #   value: "192.168.0.0/16"
`

func localCAPIWorkloadTestRuntimeWithCalico(runtime localRuntime) localRuntime {
	source := []byte(localCAPIWorkloadCalicoTestFixture)
	digest := sha256.Sum256(source)
	runtime.calicoManifestSHA256 = hex.EncodeToString(digest[:])
	runtime.fetchCalicoManifest = func(context.Context) ([]byte, error) { return append([]byte(nil), source...), nil }
	return runtime
}

func localCAPIWorkloadKubeconfigFixture(name string) []byte {
	contextName := "kind-" + name
	return []byte("apiVersion: v1\nkind: Config\ncurrent-context: " + contextName + "\nclusters:\n- name: " + contextName + "\n  cluster:\n    server: https://127.0.0.1:65432\n    certificate-authority-data: Y2E=\ncontexts:\n- name: " + contextName + "\n  context:\n    cluster: " + contextName + "\n    user: " + contextName + "\nusers:\n- name: " + contextName + "\n  user:\n    client-certificate-data: Y2VydA==\n    client-key-data: a2V5\n")
}

func localCAPIWorkloadNodesFixture(ready bool) []byte {
	status := "False"
	if ready {
		status = "True"
	}
	return []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"ok-worker-01-control-plane","uid":"node-cp"},"spec":{"providerID":"docker:////ok-worker-01-control-plane"},"status":{"conditions":[{"type":"Ready","status":"` + status + `"}]}},{"apiVersion":"v1","kind":"Node","metadata":{"name":"ok-worker-01-worker","uid":"node-worker"},"spec":{"providerID":"docker:////ok-worker-01-worker"},"status":{"conditions":[{"type":"Ready","status":"` + status + `"}]}}]}`)
}

// This is the workload-only Cluster projection from the full development
// flavor. Management owns and installs the supporting ClusterClass objects.
//
//go:embed testdata/capd-v1.14.4-development-cluster-only.yaml
var localCAPIDevelopmentClusterOnlyFixture string

func TestBindLocalCAPIWorkloadManifestMatchesDevelopmentFlavorAndOwner(t *testing.T) {
	owner := "fedcba9876543210fedcba9876543210"
	manifest, err := bindLocalCAPIWorkloadManifest([]byte(localCAPIDevelopmentManifestFixture), "ok-worker-01", owner, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	var objects []map[string]any
	for decoder := yamlNewDecoder(bytes.NewReader(manifest)); ; {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if len(object) != 0 {
			objects = append(objects, object)
		}
	}
	if len(objects) != 1 {
		t.Fatalf("workload create output contains %d objects; want only the workload Cluster", len(objects))
	}
	gotInventory := map[string]int{}
	for _, object := range objects {
		metadata, _ := object["metadata"].(map[string]any)
		gotInventory[object["apiVersion"].(string)+"/"+object["kind"].(string)+"/"+metadata["name"].(string)]++
	}
	if len(gotInventory) != 1 || gotInventory[localCAPIWorkloadAPIVersion+"/Cluster/ok-worker-01"] != 1 {
		t.Fatalf("workload create output was not a single requested Cluster: %#v", gotInventory)
	}
	var projected, clusterOnly map[string]any
	if err := yaml.Unmarshal(manifest, &projected); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(localCAPIDevelopmentClusterOnlyFixture), &clusterOnly); err != nil {
		t.Fatal(err)
	}
	metadata := projected["metadata"].(map[string]any)
	labels := metadata["labels"].(map[string]any)
	if labels[localOwnerLabel] != owner {
		t.Fatalf("owner label = %v, want %s", labels[localOwnerLabel], owner)
	}
	delete(labels, localOwnerLabel)
	if len(labels) == 0 {
		delete(metadata, "labels")
	}
	if !reflect.DeepEqual(projected, clusterOnly) {
		t.Fatal("workload output differs from the checked-in Cluster-only projection")
	}
	var rawInventory []map[string]any
	for decoder := yaml.NewDecoder(strings.NewReader(localCAPIDevelopmentManifestFixture)); ; {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if len(object) > 0 {
			rawInventory = append(rawInventory, object)
		}
	}
	if len(rawInventory) != len(localCAPIWorkloadExpectedManifestObjects("ok-worker-01")) {
		t.Fatalf("raw clusterctl development flavor has %d objects, want the complete pinned inventory", len(rawInventory))
	}
	for _, bad := range []struct {
		name string
		raw  string
	}{
		{"wrong cluster name", strings.Replace(localCAPIDevelopmentManifestFixture, "ok-worker-01", "someone-elses-cluster", 1)},
		{"wrong namespace", strings.Replace(localCAPIDevelopmentManifestFixture, "namespace: default", "namespace: other", 1)},
		{"wrong control-plane count", strings.Replace(localCAPIDevelopmentManifestFixture, "    controlPlane:\n      replicas: 1", "    controlPlane:\n      replicas: 3", 1)},
		{"wrong worker count", strings.Replace(localCAPIDevelopmentManifestFixture, "        name: md-0\n        replicas: 1", "        name: md-0\n        replicas: 2", 1)},
		{"wrong Pod CIDR", strings.Replace(localCAPIDevelopmentManifestFixture, "192.168.0.0/16", "10.0.0.0/16", 1)},
		{"wrong Service CIDR", strings.Replace(localCAPIDevelopmentManifestFixture, "10.128.0.0/12", "10.96.0.0/12", 1)},
		{"missing Pod CIDR", strings.Replace(localCAPIDevelopmentManifestFixture, "    pods:\n      cidrBlocks:\n      - 192.168.0.0/16\n", "", 1)},
		{"missing Service CIDR", strings.Replace(localCAPIDevelopmentManifestFixture, "    services:\n      cidrBlocks:\n      - 10.128.0.0/12\n", "", 1)},
		{"wrong Kubernetes version", strings.Replace(localCAPIDevelopmentManifestFixture, "version: v1.35.8", "version: v1.35.7", 1)},
		{"missing Kubernetes version", strings.Replace(localCAPIDevelopmentManifestFixture, "    version: v1.35.8\n", "", 1)},
		{"missing topology class", strings.Replace(localCAPIDevelopmentManifestFixture, "    classRef:\n      name: quick-start\n", "    classRef: {}\n", 1)},
		{"wrong topology class", strings.Replace(localCAPIDevelopmentManifestFixture, "classRef:\n      name: quick-start", "classRef:\n      name: other-class", 1)},
		{"missing control-plane replicas", strings.Replace(localCAPIDevelopmentManifestFixture, "      replicas: 1", "      replicas: null", 1)},
		{"malformed YAML", strings.Replace(localCAPIDevelopmentManifestFixture, "      replicas: 1", "      replicas: [", 1)},
		{"duplicate Cluster", localCAPIDevelopmentManifestFixture + "\n---\n" + localCAPIDevelopmentManifestFixture},
		{"unapproved object", localCAPIDevelopmentManifestFixture + "\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: unexpected\n  namespace: default\ndata: {}\n"},
		{"wrong API version", strings.Replace(localCAPIDevelopmentManifestFixture, "cluster.x-k8s.io/v1beta2", "cluster.x-k8s.io/v1beta1", 1)},
		{"modified support template", strings.Replace(localCAPIDevelopmentManifestFixture, "hostPath: /var/run/docker.sock", "hostPath: /tmp/docker.sock", 1)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, err := bindLocalCAPIWorkloadManifest([]byte(bad.raw), "ok-worker-01", owner, 1, 1); err == nil {
				t.Fatal("invalid generated workload manifest was accepted")
			}
		})
	}
}

func TestCAPDWorkerReplacementEvidenceIsSupplementalAndImmutable(t *testing.T) {
	state := validLocalCAPIWorkloadTestState(t.TempDir())
	state.Phase, state.ClusterUID, state.RecoveryFromFailureCode = "WAITING_FOR_WORKLOAD_ACCESS", "cluster-uid", "CNI_ALREADY_PRESENT"
	state.WorkloadContainers = []localContainerIdentity{
		{ID: "cp-id", Name: "ok-worker-01-control-plane", Role: "control-plane"},
		{ID: "old-worker-id", Name: "ok-worker-01-worker-old", Role: "worker"},
		{ID: "lb-id", Name: "ok-worker-01-lb", Role: "external-load-balancer"},
	}
	state.WorkloadNodes = []localNodeIdentity{{Name: "ok-worker-01-control-plane", UID: "cp-node-uid"}, {Name: "ok-worker-01-worker-old", UID: "old-node-uid"}}
	state.WorkloadKubeconfig = localCAPIWorkloadKubeconfigPath(localCAPIWorkloadRoot(t.TempDir()), state.Name)
	state.WorkloadKubeconfigSHA256 = strings.Repeat("a", 64)
	state.PodCIDR, state.ServiceCIDR, state.WorkloadKindName = localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR, state.Name
	state.CalicoSourceSHA256 = strings.Repeat("b", 64)
	state.CalicoManifestSHA256 = strings.Repeat("c", 64)
	evidence := localCAPIWorkloadWorkerReplacement{ClusterUID: "cluster-uid", MachineDeploymentName: "ok-worker-01-md-0", MachineDeploymentUID: "md-uid", MachineSetName: "ok-worker-01-md-0-abc", MachineSetUID: "ms-uid", MachineName: "ok-worker-01-md-0-new", MachineUID: "machine-uid", DevMachineName: "ok-worker-01-worker-dev", DevMachineUID: "devmachine-uid", ProviderID: "docker:////ok-worker-01-worker-new", Container: localContainerIdentity{ID: "new-worker-id", Name: "ok-worker-01-worker-new", Role: "worker"}, Node: localNodeIdentity{Name: "ok-worker-01-worker-new", UID: "new-node-uid"}}
	state.WorkerReplacement = &evidence
	if !validLocalCAPIWorkloadWorkerReplacement(state, evidence) {
		t.Fatal("complete replacement evidence was rejected")
	}
	if err := validateLocalCAPIWorkloadState(state); err != nil {
		t.Fatalf("valid receipt with supplemental replacement evidence was rejected: %v", err)
	}
	previous := state
	previous.WorkerReplacement = nil
	previous.Phase, previous.FailureCode, previous.RecoveryFromFailureCode = "INCOMPLETE", "CNI_ALREADY_PRESENT", ""
	next := state
	next.Phase, next.FailureCode = "WAITING_FOR_WORKLOAD_ACCESS", ""
	if !validLocalCAPIWorkloadTransition(previous, next) || !sameLocalCAPIWorkloadProgress(previous, next) {
		t.Fatal("one explicit pre-Calico transition with verified replacement evidence was rejected")
	}
	mutatedHistory := next
	mutatedHistory.WorkloadContainers = append([]localContainerIdentity(nil), next.WorkloadContainers...)
	mutatedHistory.WorkloadContainers[1].ID = "rewritten-old-worker"
	if sameLocalCAPIWorkloadProgress(previous, mutatedHistory) {
		t.Fatal("recovery accepted rewriting the originally recorded worker identity")
	}
	changedEvidence := next
	changedEvidence.WorkerReplacement = &localCAPIWorkloadWorkerReplacement{}
	if sameLocalCAPIWorkloadProgress(next, changedEvidence) {
		t.Fatal("recovery accepted changing already persisted replacement evidence")
	}
	originalContainers := append([]localContainerIdentity(nil), state.WorkloadContainers...)
	originalNodes := append([]localNodeIdentity(nil), state.WorkloadNodes...)
	effectiveContainers, effectiveNodes := localCAPIWorkloadEffectiveIdentity(state)
	if !sameLocalContainers(state.WorkloadContainers, originalContainers) || !sameLocalNodeIdentities(state.WorkloadNodes, originalNodes) {
		t.Fatal("effective identities rewrote the original historical receipt identities")
	}
	if !sameLocalContainers(effectiveContainers, []localContainerIdentity{originalContainers[0], evidence.Container, originalContainers[2]}) ||
		!sameLocalNodeIdentities(effectiveNodes, []localNodeIdentity{originalNodes[0], evidence.Node}) {
		t.Fatalf("effective identities did not project exactly the proven replacement: containers=%+v nodes=%+v", effectiveContainers, effectiveNodes)
	}
	for _, mutate := range []struct {
		name string
		fn   func(*localCAPIWorkloadWorkerReplacement)
	}{
		{"different Cluster UID", func(e *localCAPIWorkloadWorkerReplacement) { e.ClusterUID = "other-cluster" }},
		{"missing MachineDeployment UID", func(e *localCAPIWorkloadWorkerReplacement) { e.MachineDeploymentUID = "" }},
		{"same Docker identity", func(e *localCAPIWorkloadWorkerReplacement) { e.Container = state.WorkloadContainers[1] }},
		{"non-worker role", func(e *localCAPIWorkloadWorkerReplacement) { e.Container.Role = "control-plane" }},
		{"same Node identity", func(e *localCAPIWorkloadWorkerReplacement) { e.Node = state.WorkloadNodes[1] }},
		{"unbound provider ID", func(e *localCAPIWorkloadWorkerReplacement) { e.ProviderID = "docker://unrelated" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			bad := evidence
			mutate.fn(&bad)
			if validLocalCAPIWorkloadWorkerReplacement(state, bad) {
				t.Fatal("ambiguous or mismatched replacement evidence was accepted")
			}
		})
	}
}

func TestCAPDWorkerReplacementInputFailuresArePreciseAndOffline(t *testing.T) {
	base := validLocalCAPIWorkloadTestState(t.TempDir())
	base.ClusterUID = "cluster-uid"
	base.WorkloadContainers = []localContainerIdentity{
		{ID: "cp-id", Name: "cp-control-plane", Role: "control-plane"},
		{ID: "old-worker-id", Name: "old-worker", Role: "worker"},
		{ID: "lb-id", Name: "lb", Role: "external-load-balancer"},
	}
	base.WorkloadNodes = []localNodeIdentity{{Name: "cp-control-plane", UID: "cp-node"}, {Name: "old-worker", UID: "old-node"}}
	containers := []localContainerIdentity{
		{ID: "cp-id", Name: "cp-control-plane", Role: "control-plane"},
		{ID: "new-worker-id", Name: "new-worker", Role: "worker"},
		{ID: "lb-id", Name: "lb", Role: "external-load-balancer"},
	}
	nodes := []localNodeIdentity{{Name: "cp-control-plane", UID: "cp-node"}, {Name: "new-worker", UID: "new-node"}}
	tests := []struct {
		name   string
		mutate func(*localCAPIWorkloadState, *[]localContainerIdentity, *[]localNodeIdentity)
		want   string
	}{
		{"missing Cluster UID", func(state *localCAPIWorkloadState, _ *[]localContainerIdentity, _ *[]localNodeIdentity) {
			state.ClusterUID = ""
		}, "receipt.cluster_uid_missing"},
		{"invalid current container inventory", func(_ *localCAPIWorkloadState, containers *[]localContainerIdentity, _ *[]localNodeIdentity) {
			*containers = (*containers)[:2]
		}, "observed.container_inventory_invalid"},
		{"invalid current Node identities", func(_ *localCAPIWorkloadState, _ *[]localContainerIdentity, nodes *[]localNodeIdentity) {
			(*nodes)[1].UID = (*nodes)[0].UID
		}, "observed.node_identity_inventory_invalid"},
		{"invalid historical container count", func(state *localCAPIWorkloadState, _ *[]localContainerIdentity, _ *[]localNodeIdentity) {
			state.WorkloadContainers = state.WorkloadContainers[:2]
		}, "receipt.historical_container_count_invalid"},
		{"invalid historical container roles", func(state *localCAPIWorkloadState, _ *[]localContainerIdentity, _ *[]localNodeIdentity) {
			state.WorkloadContainers[0].Role = "worker"
		}, "receipt.historical_container_roles_invalid"},
		{"invalid historical Node count", func(state *localCAPIWorkloadState, _ *[]localContainerIdentity, _ *[]localNodeIdentity) {
			state.WorkloadNodes = state.WorkloadNodes[:1]
		}, "receipt.historical_node_count_invalid"},
		{"invalid historical Node roles", func(state *localCAPIWorkloadState, _ *[]localContainerIdentity, _ *[]localNodeIdentity) {
			state.WorkloadNodes[0].Name = "node-without-role-marker"
		}, "receipt.historical_node_roles_invalid"},
		{"control-plane container changed", func(_ *localCAPIWorkloadState, containers *[]localContainerIdentity, _ *[]localNodeIdentity) {
			(*containers)[0].ID = "other-cp-id"
		}, "identity.control_plane_container_changed"},
		{"load-balancer container changed", func(_ *localCAPIWorkloadState, containers *[]localContainerIdentity, _ *[]localNodeIdentity) {
			(*containers)[2].ID = "other-lb-id"
		}, "identity.load_balancer_container_changed"},
		{"worker was not replaced", func(_ *localCAPIWorkloadState, containers *[]localContainerIdentity, _ *[]localNodeIdentity) {
			(*containers)[1] = localContainerIdentity{ID: "old-worker-id", Name: "old-worker", Role: "worker"}
		}, "identity.worker_not_replaced"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base
			state.WorkloadContainers = append([]localContainerIdentity(nil), base.WorkloadContainers...)
			state.WorkloadNodes = append([]localNodeIdentity(nil), base.WorkloadNodes...)
			observedContainers := append([]localContainerIdentity(nil), containers...)
			observedNodes := append([]localNodeIdentity(nil), nodes...)
			test.mutate(&state, &observedContainers, &observedNodes)
			if got := capdWorkerReplacementInputFailure(state, observedContainers, observedNodes); got != "" && got != test.want {
				t.Fatalf("input failure=%q, want %q or a later identity-stage diagnostic", got, test.want)
			}
			called := false
			runtime := localRuntime{
				runPinned: func(context.Context, localProviderIdentity, string, ...string) ([]byte, error) {
					called = true
					return nil, nil
				},
				runCAPI: func(context.Context, localProviderIdentity, string, map[string]string, string, ...string) ([]byte, error) {
					called = true
					return nil, nil
				},
			}
			_, err := verifyCAPDWorkerReplacement(context.Background(), runtime, validLocalCAPIState(t.TempDir()), state, observedContainers, observedNodes)
			if err == nil || !strings.Contains(err.Error(), "["+test.want+"]") {
				t.Fatalf("diagnostic=%v, want bounded reason %q", err, test.want)
			}
			if called {
				t.Fatal("invalid local input reached an external inventory command")
			}
		})
	}
}

func TestInitialCNIIdentityDoesNotRequireWorkerContainerStability(t *testing.T) {
	root := t.TempDir()
	management := validLocalCAPIState(root)
	state := validLocalCAPIWorkloadTestState(root)
	state.Phase, state.FailureCode, state.RecoveryFromFailureCode = "INCOMPLETE", "CNI_ALREADY_PRESENT", ""
	state.ClusterUID = "workload-cluster-uid"
	state.WorkloadKindName = state.Name
	state.PodCIDR, state.ServiceCIDR = localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR
	state.WorkloadContainers = []localContainerIdentity{
		{ID: strings.Repeat("1", 64), Name: "ok-worker-4gl9v-qc2jp", Role: "control-plane"},
		{ID: "historical-worker-id", Name: "old-worker", Role: "worker"},
		{ID: strings.Repeat("3", 64), Name: "ok-worker-lb", Role: "external-load-balancer"},
	}
	state.WorkloadNodes = []localNodeIdentity{{Name: "ok-worker-4gl9v-qc2jp", UID: "cp-node-uid"}, {Name: "old-worker", UID: "old-worker-node-uid"}}
	state.WorkloadKubeconfig = localCAPIWorkloadKubeconfigPath(root, state.Name)
	if err := os.MkdirAll(filepath.Dir(state.WorkloadKubeconfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(state.WorkloadKubeconfig), 0o700); err != nil {
		t.Fatal(err)
	}
	kubeconfig := localCAPIWorkloadKubeconfigFixture(state.WorkloadKindName)
	if err := os.WriteFile(state.WorkloadKubeconfig, kubeconfig, 0o600); err != nil {
		t.Fatal(err)
	}
	state.WorkloadKubeconfigSHA256 = localCAPIBytesSHA256(kubeconfig)
	provider := management.Provider
	dockerInventory := strings.Join([]string{
		strings.Repeat("1", 64) + "|ok-worker-4gl9v-qc2jp|control-plane",
		strings.Repeat("3", 64) + "|ok-worker-lb|external-load-balancer",
	}, "\n") + "\n"
	workloadNodeInventory := `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"ok-worker-4gl9v-qc2jp","uid":"cp-node-uid"},"spec":{"providerID":"docker:////ok-worker-4gl9v-qc2jp"}},{"apiVersion":"v1","kind":"Node","metadata":{"name":"new-worker","uid":"new-worker-node-uid"},"spec":{"providerID":"docker:////new-worker"}}]}`
	runtime := localRuntime{
		stateRoot: root,
		runPinned: func(_ context.Context, gotProvider localProviderIdentity, command string, args ...string) ([]byte, error) {
			if gotProvider != provider {
				t.Fatalf("external command used an unpinned provider: %+v", gotProvider)
			}
			switch {
			case command == "kind" && reflect.DeepEqual(args, []string{"get", "clusters"}):
				return []byte(state.WorkloadKindName + "\n"), nil
			case command == "docker" && len(args) > 0 && args[0] == "ps":
				// The old worker is gone; only the independently checked control
				// plane and load balancer must remain stable before first CNI.
				return []byte(dockerInventory), nil
			case command == "kind" && len(args) > 0 && args[0] == "get" && len(args) > 1 && args[1] == "kubeconfig":
				return kubeconfig, nil
			default:
				t.Fatalf("unexpected pinned read-only command: %s %q", command, args)
				return nil, nil
			}
		},
		runCAPI: func(_ context.Context, gotProvider localProviderIdentity, kubeconfigPath string, _ map[string]string, command string, args ...string) ([]byte, error) {
			if gotProvider != provider || kubeconfigPath != state.WorkloadKubeconfig || command != "kubectl" || !hasExactLocalCAPIWorkloadFlag(args, "--context", "kind-"+state.WorkloadKindName) {
				t.Fatalf("workload API query was not identity-bound: provider=%+v kubeconfig=%q command=%q args=%q", gotProvider, kubeconfigPath, command, args)
			}
			if !strings.Contains(strings.Join(args, " "), "get nodes -o json") {
				t.Fatalf("unexpected workload API query: %q", args)
			}
			return []byte(workloadNodeInventory), nil
		},
	}
	original := state
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(context.Background(), runtime, management, state, state.WorkloadContainers); err != nil {
		t.Fatalf("safe initial CNI target rejected a changed worker while preserving control-plane identity: %v", err)
	}
	if !reflect.DeepEqual(original, state) {
		t.Fatal("read-only CNI target verification modified historical receipt state")
	}
	// The continuation phase after its durable, explicit recovery transition
	// must use the same narrow target identity rule.
	state.Phase, state.FailureCode, state.RecoveryFromFailureCode = "WAITING_FOR_WORKLOAD_ACCESS", "", "CNI_ALREADY_PRESENT"
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(context.Background(), runtime, management, state, state.WorkloadContainers); err != nil {
		t.Fatalf("explicit unattempted continuation failed target identity verification: %v", err)
	}
	dockerInventory = strings.Replace(dockerInventory, strings.Repeat("1", 64), strings.Repeat("9", 64), 1)
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(context.Background(), runtime, management, state, state.WorkloadContainers); err == nil {
		t.Fatal("target-level CNI verification accepted a changed control-plane container")
	}
	dockerInventory = strings.Replace(dockerInventory, strings.Repeat("9", 64), strings.Repeat("1", 64), 1)
	workloadNodeInventory = strings.Replace(workloadNodeInventory, `"uid":"cp-node-uid"`, `"uid":"different-cp-node-uid"`, 1)
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(context.Background(), runtime, management, state, state.WorkloadContainers); err == nil {
		t.Fatal("target-level CNI verification accepted a different control-plane Node UID")
	}
	state.CalicoCreateAttempted = true
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(context.Background(), runtime, management, state, state.WorkloadContainers); err == nil {
		t.Fatal("target-level pre-CNI identity path accepted a receipt after the one-shot Calico marker")
	}
}

func TestCAPDWorkerReplacementProviderIDMustIdentifyExactContainer(t *testing.T) {
	for _, test := range []struct {
		providerID string
		container  localContainerIdentity
		want       bool
	}{
		{"docker:////worker-name", localContainerIdentity{Name: "worker-name", ID: "container-id", Role: "worker"}, true},
		{"docker://container-id", localContainerIdentity{Name: "worker-name", ID: "container-id", Role: "worker"}, true},
		{"docker:////other-name", localContainerIdentity{Name: "worker-name", ID: "container-id", Role: "worker"}, false},
		{"other://worker-name", localContainerIdentity{Name: "worker-name", ID: "container-id", Role: "worker"}, false},
	} {
		if got := replacementProviderMatches(test.providerID, test.container); got != test.want {
			t.Errorf("provider ID %q match=%t, want %t", test.providerID, got, test.want)
		}
	}
}

func TestVerifyCAPDWorkerReplacementFollowsUIDBoundCAPIChain(t *testing.T) {
	state := validLocalCAPIWorkloadTestState(t.TempDir())
	state.ClusterUID = "cluster-uid"
	state.WorkloadContainers = []localContainerIdentity{{ID: "cp-id", Name: "ok-worker-01-control-plane", Role: "control-plane"}, {ID: "old-id", Name: "old-node", Role: "worker"}, {ID: "lb-id", Name: "lb", Role: "external-load-balancer"}}
	state.WorkloadNodes = []localNodeIdentity{{Name: "ok-worker-01-control-plane", UID: "cp-node-old"}, {Name: "old-node", UID: "old-node-uid"}}
	currentContainers := []localContainerIdentity{{ID: "cp-id", Name: "ok-worker-01-control-plane", Role: "control-plane"}, {ID: "new-id", Name: "new-worker", Role: "worker"}, {ID: "lb-id", Name: "lb", Role: "external-load-balancer"}}
	currentNodes := []localNodeIdentity{{Name: "ok-worker-01-control-plane", UID: "cp-node-old"}, {Name: "new-node", UID: "new-node-uid"}}
	fixtures := map[string][]byte{
		"machinedeployments.cluster.x-k8s.io":         []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"MachineDeployment","metadata":{"name":"ok-worker-01-md-0","namespace":"default","uid":"md-uid","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01"},"ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","name":"ok-worker-01","uid":"cluster-uid"}]},"spec":{"clusterName":"ok-worker-01","replicas":1}}]}`),
		"machinesets.cluster.x-k8s.io":                []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"MachineSet","metadata":{"name":"ok-worker-01-md-0-abc","namespace":"default","uid":"ms-uid","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01"},"ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"MachineDeployment","name":"ok-worker-01-md-0","uid":"md-uid","controller":true}]},"spec":{"clusterName":"ok-worker-01","replicas":1}}]}`),
		"machines.cluster.x-k8s.io":                   []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Machine","metadata":{"name":"ok-worker-01-control-plane","namespace":"default","uid":"cp-machine-uid","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01","cluster.x-k8s.io/control-plane":""}},"spec":{"infrastructureRef":{"apiGroup":"infrastructure.cluster.x-k8s.io","kind":"DevMachine","name":"cp-dev"}},"status":{"nodeRef":{"name":"ok-worker-01-control-plane"}}},{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Machine","metadata":{"name":"ok-worker-01-md-0-new","namespace":"default","uid":"machine-uid","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01"},"ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"MachineSet","name":"ok-worker-01-md-0-abc","uid":"ms-uid","controller":true}]},"spec":{"clusterName":"ok-worker-01","infrastructureRef":{"apiGroup":"infrastructure.cluster.x-k8s.io","kind":"DevMachine","name":"worker-dev"}},"status":{"nodeRef":{"name":"new-node"}}}]}`),
		"devmachines.infrastructure.cluster.x-k8s.io": []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"infrastructure.cluster.x-k8s.io/v1beta2","kind":"DevMachine","metadata":{"name":"cp-dev","namespace":"default","uid":"cp-dev-uid","ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Machine","name":"ok-worker-01-control-plane","uid":"cp-machine-uid","controller":true}]},"spec":{"providerID":"docker:////ok-worker-01-control-plane"},"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"ContainerProvisioned","status":"True"}]}},{"apiVersion":"infrastructure.cluster.x-k8s.io/v1beta2","kind":"DevMachine","metadata":{"name":"worker-dev","namespace":"default","uid":"devmachine-uid","ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Machine","name":"ok-worker-01-md-0-new","uid":"machine-uid","controller":true}]},"spec":{"providerID":"docker:////new-worker"},"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"ContainerProvisioned","status":"True"}]}}]}`),
	}
	nodeFixture := []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"ok-worker-01-control-plane","uid":"cp-node-old"},"spec":{"providerID":"docker:////ok-worker-01-control-plane"}},{"apiVersion":"v1","kind":"Node","metadata":{"name":"new-node","uid":"new-node-uid"},"spec":{"providerID":"docker:////new-worker"}}]}`)
	for _, bad := range []struct {
		name, resource string
		edit           func([]byte) []byte
		nodeEdit       func([]byte) []byte
		containerEdit  func([]localContainerIdentity) []localContainerIdentity
	}{
		{"wrong MachineSet owner UID", "machines.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"uid":"ms-uid","controller":true`, `"uid":"other-ms","controller":true`, 1))
		}, nil, nil},
		{"wrong MachineDeployment Cluster owner UID", "machinedeployments.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"uid":"cluster-uid"`, `"uid":"other-cluster"`, 1))
		}, nil, nil},
		{"wrong DevMachine owner UID", "devmachines.infrastructure.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"uid":"machine-uid","controller":true`, `"uid":"other-machine","controller":true`, 1))
		}, nil, nil},
		{"wrong infrastructureRef API group", "machines.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"apiGroup":"infrastructure.cluster.x-k8s.io"`, `"apiGroup":"other.example.io"`, 1))
		}, nil, nil},
		{"contradictory Machine providerID", "machines.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"status":{"nodeRef":{"name":"new-node"}}`, `"status":{"providerID":"docker://wrong","nodeRef":{"name":"new-node"}}`, 1))
		}, nil, nil},
		{"contradictory DevMachine providerID", "devmachines.infrastructure.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"spec":{"providerID":"docker:////new-worker"},"status":{"conditions"`, `"spec":{"providerID":"docker:////new-worker"},"status":{"providerID":"docker://wrong","conditions"`, 1))
		}, nil, nil},
		{"contradictory DevMachine spec providerID", "devmachines.infrastructure.cluster.x-k8s.io", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"spec":{"providerID":"docker:////new-worker"}`, `"spec":{"providerID":"docker://wrong"}`, 1))
		}, nil, nil},
		{"wrong Node providerID", "", nil, func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"providerID":"docker:////new-worker"`, `"providerID":"docker:////other-worker"`, 1))
		}, nil},
		{"wrong Docker container identity", "", nil, nil, func(containers []localContainerIdentity) []localContainerIdentity {
			changed := append([]localContainerIdentity(nil), containers...)
			for i := range changed {
				if changed[i].Role == "worker" {
					changed[i].Name, changed[i].ID = "unrelated-worker", "unrelated-container-id"
				}
			}
			return changed
		}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			localFixtures := map[string][]byte{}
			for key, value := range fixtures {
				localFixtures[key] = append([]byte(nil), value...)
			}
			if bad.resource != "" {
				original := localFixtures[bad.resource]
				localFixtures[bad.resource] = bad.edit(original)
				if bytes.Equal(original, localFixtures[bad.resource]) {
					t.Fatal("negative fixture mutation did not change the source object")
				}
			}
			localNodeFixture := append([]byte(nil), nodeFixture...)
			if bad.nodeEdit != nil {
				localNodeFixture = bad.nodeEdit(localNodeFixture)
				if bytes.Equal(nodeFixture, localNodeFixture) {
					t.Fatal("negative Node fixture mutation did not change the source object")
				}
			}
			localContainers := append([]localContainerIdentity(nil), currentContainers...)
			if bad.containerEdit != nil {
				localContainers = bad.containerEdit(localContainers)
			}
			runtime := localRuntime{runCAPI: func(_ context.Context, _ localProviderIdentity, kubeconfig string, _ map[string]string, command string, args ...string) ([]byte, error) {
				if command != "kubectl" {
					t.Fatalf("unexpected executable %s", command)
				}
				joined := strings.Join(args, " ")
				for resource, raw := range localFixtures {
					if strings.Contains(joined, "get "+resource+" ") {
						return raw, nil
					}
				}
				if strings.Contains(joined, "get nodes") && kubeconfig == state.WorkloadKubeconfig {
					return localNodeFixture, nil
				}
				t.Fatalf("unexpected read-only query: %s", joined)
				return nil, nil
			}}
			if _, err := verifyCAPDWorkerReplacement(context.Background(), runtime, validLocalCAPIState(t.TempDir()), state, localContainers, currentNodes); err == nil {
				t.Fatal("ambiguous CAPI ownership chain was accepted")
			} else if bad.name == "wrong infrastructureRef API group" && !strings.Contains(err.Error(), "infrastructureRef.apiGroup") {
				t.Fatalf("diagnostic did not identify the failing contract field: %v", err)
			} else if bad.name == "wrong MachineDeployment Cluster owner UID" && !strings.Contains(err.Error(), "MachineDeployment.ownerReferences Cluster UID") {
				t.Fatalf("diagnostic did not identify the failing Cluster owner UID: %v", err)
			}
		})
	}
	runtime := localRuntime{runCAPI: func(_ context.Context, _ localProviderIdentity, kubeconfig string, _ map[string]string, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		for resource, raw := range fixtures {
			if strings.Contains(joined, "get "+resource+" ") {
				return raw, nil
			}
		}
		if strings.Contains(joined, "get nodes") && kubeconfig == state.WorkloadKubeconfig {
			return nodeFixture, nil
		}
		t.Fatalf("unexpected read-only query: %s", joined)
		return nil, nil
	}}
	evidence, err := verifyCAPDWorkerReplacement(context.Background(), runtime, validLocalCAPIState(t.TempDir()), state, currentContainers, currentNodes)
	if err != nil || evidence.MachineUID != "machine-uid" || evidence.DevMachineUID != "devmachine-uid" || evidence.Container.ID != "new-id" || evidence.Node.UID != "new-node-uid" {
		t.Fatalf("valid CAPI ownership chain did not prove replacement: evidence=%+v err=%v", evidence, err)
	}
}

func TestBindLocalCAPIWorkloadManifestReportsInventoryContractField(t *testing.T) {
	owner := "fedcba9876543210fedcba9876543210"
	decoder := yaml.NewDecoder(strings.NewReader(localCAPIDevelopmentManifestFixture))
	var clusterOnly bytes.Buffer
	encoder := yaml.NewEncoder(&clusterOnly)
	for {
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if len(node.Content) == 0 {
			continue
		}
		kind, err := yamlMappingScalar(node.Content[0], "kind")
		if err != nil {
			t.Fatal(err)
		}
		if kind == "Cluster" {
			if err := encoder.Encode(&node); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	// With management-owned ClusterClass/templates already installed,
	// clusterctl v1.14.4 emits only this workload-specific Cluster. The
	// management receipt separately verifies ownership of the shared objects.
	clusterOnlyManifest, err := bindLocalCAPIWorkloadManifest(clusterOnly.Bytes(), "ok-worker-01", owner, 1, 1)
	if err != nil {
		t.Fatalf("cluster-only output for preinstalled management templates was rejected: %v", err)
	}
	var clusterOnlyObject map[string]any
	if err := yaml.Unmarshal(clusterOnlyManifest, &clusterOnlyObject); err != nil {
		t.Fatal(err)
	}
	if clusterOnlyObject["kind"] != "Cluster" || clusterOnlyObject["apiVersion"] != localCAPIWorkloadAPIVersion {
		t.Fatalf("cluster-only workload output has unexpected identity: %#v", clusterOnlyObject)
	}
	clusterOnlyWrongName := strings.Replace(clusterOnly.String(), "name: ok-worker-01", "name: another-cluster", 1)
	if _, err := bindLocalCAPIWorkloadManifest([]byte(clusterOnlyWrongName), "ok-worker-01", owner, 1, 1); err == nil {
		t.Fatal("cluster-only manifest with a different workload identity was accepted")
	}
	wrongCIDR := strings.Replace(localCAPIDevelopmentManifestFixture, "10.128.0.0/12", "10.96.0.0/12", 1)
	if _, err := bindLocalCAPIWorkloadManifest([]byte(wrongCIDR), "ok-worker-01", owner, 1, 1); err == nil || !strings.Contains(err.Error(), "manifest.Cluster.spec.clusterNetwork") {
		t.Fatalf("CIDR mismatch should identify the failing Cluster field, got %v", err)
	}
}

func TestObserveLocalCAPIWorkloadIncludesExpectedExternalLoadBalancer(t *testing.T) {
	provider := localProviderIdentity{Kind: "docker", Context: "colima-ok-capi", Endpoint: "unix:///private/tmp/ok-capi/docker.sock", DaemonID: "daemon-id"}
	var gotProvider localProviderIdentity
	var gotCommand string
	var gotArgs []string
	runtime := localRuntime{runPinned: func(_ context.Context, observed localProviderIdentity, command string, args ...string) ([]byte, error) {
		gotProvider, gotCommand, gotArgs = observed, command, append([]string(nil), args...)
		return []byte(strings.Join([]string{
			strings.Repeat("1", 64) + "|ok-worker-03-md-0-5mtgg-p99tp|worker",
			strings.Repeat("2", 64) + "|ok-worker-03-control-plane|control-plane",
			strings.Repeat("3", 64) + "|ok-worker-03-lb|external-load-balancer",
		}, "\n") + "\n"), nil
	}}
	containers, err := observeLocalCAPIWorkloadContainers(context.Background(), runtime, provider, "ok-worker-03")
	if err != nil || !validLocalCAPIWorkloadContainerInventory(containers) {
		t.Fatalf("actual CAPD control-plane, worker and external-load-balancer inventory was rejected: containers=%+v err=%v", containers, err)
	}
	if gotProvider != provider || gotCommand != "docker" || !reflect.DeepEqual(gotArgs, []string{"ps", "-a", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster=ok-worker-03", "--format", `{{.ID}}|{{.Names}}|{{.Label "io.x-k8s.kind.role"}}`}) {
		t.Fatalf("CAPD inventory was not queried through the pinned provider: provider=%+v command=%q args=%q", gotProvider, gotCommand, gotArgs)
	}
	if !validLocalCAPIWorkloadContainerSubset(containers[:2]) {
		t.Fatal("known partial CAPD inventory should remain a nonterminal provisioning observation")
	}
	if validLocalCAPIWorkloadContainerInventory(containers[:2]) {
		t.Fatal("partial CAPD inventory was treated as complete")
	}
	for _, bad := range []string{
		strings.Repeat("1", 64) + "|cp|control-plane\n" + strings.Repeat("2", 64) + "|worker|worker\n" + strings.Repeat("3", 64) + "|lb|unknown-role\n",
		strings.Repeat("1", 64) + "|cp|control-plane\n" + strings.Repeat("2", 64) + "|cp-duplicate|control-plane\n" + strings.Repeat("3", 64) + "|lb|external-load-balancer\n",
	} {
		runtime.runPinned = func(context.Context, localProviderIdentity, string, ...string) ([]byte, error) {
			return []byte(bad), nil
		}
		if _, err := observeLocalCAPIWorkloadContainers(context.Background(), runtime, provider, "ok-worker-03"); err == nil {
			t.Fatal("unknown or duplicate CAPD role was accepted")
		}
	}
}

func TestLocalCAPIWorkloadContractFailurePrecedesReceiptAndKubernetesMutation(t *testing.T) {
	runtime, management := localCAPIVerificationFixture(t)
	runtime = localCAPIWorkloadTestRuntimeWithCalico(runtime)
	management.Phase = localCAPIPhaseIncomplete
	management.FailureStage, management.FailureCode = "capi-verify", "CAPI_VERIFY_FAILED"
	raw, err := json.MarshalIndent(management, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localCAPIStateFilePath(runtime.stateRoot, management.Name), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	mutatedManifest := strings.Replace(localCAPIDevelopmentManifestFixture, "ok-worker-01", "ok-worker-03", 1)
	mutatedManifest = strings.Replace(mutatedManifest, "10.128.0.0/12", "10.96.0.0/12", 1)
	createCalls := 0
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		if command == "clusterctl" && strings.HasPrefix(strings.Join(args, " "), "generate cluster ok-worker-03 ") {
			return []byte(mutatedManifest), nil
		}
		if command == "kubectl" && strings.Contains(strings.Join(args, " "), " create") {
			createCalls++
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	args := []string{"cluster", "create", "--name", "ok-worker-03", "--management", management.Name}
	if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil {
		t.Fatal("wrong Service CIDR passed the generated manifest contract")
	}
	if _, err := os.Lstat(localCAPIWorkloadDirectory(runtime.stateRoot, "ok-worker-03")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("contract rejection created durable workload state: %v", err)
	}
	if createCalls != 0 {
		t.Fatalf("contract rejection reached Kubernetes create: %d calls", createCalls)
	}
}

func TestPinnedCalicoManifestIsChecksumAndPodCIDRBound(t *testing.T) {
	if localCAPIWorkloadCalicoURL != "https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml" || localCAPIWorkloadCalicoSourceSHA256 != "2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5" {
		t.Fatal("Calico source is not bound to the reviewed v3.33.0 artifact")
	}
	source := []byte(localCAPIWorkloadCalicoTestFixture)
	digest := sha256.Sum256(source)
	manifest, err := renderLocalCAPIWorkloadCalico(source, hex.EncodeToString(digest[:]), localCAPIWorkloadPodCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalCAPIWorkloadCalicoManifest(manifest, localCAPIWorkloadPodCIDR); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifest, []byte("value: \"192.168.0.0/16\"")) {
		t.Fatal("rendered Calico manifest does not set the expected Pod CIDR")
	}
	if _, err := renderLocalCAPIWorkloadCalico(source, strings.Repeat("0", 64), localCAPIWorkloadPodCIDR); err == nil {
		t.Fatal("wrong source checksum was accepted")
	}
	if _, err := renderLocalCAPIWorkloadCalico(source, hex.EncodeToString(digest[:]), "10.0.0.0/16"); err == nil {
		t.Fatal("unapproved Pod CIDR was accepted")
	}
	duplicate := append(append([]byte(nil), source...), []byte("\n"+localCAPIWorkloadCalicoTestFixture)...)
	duplicateHash := sha256.Sum256(duplicate)
	if _, err := renderLocalCAPIWorkloadCalico(duplicate, hex.EncodeToString(duplicateHash[:]), localCAPIWorkloadPodCIDR); err == nil {
		t.Fatal("ambiguous duplicate CIDR setting was accepted")
	}
}

func TestLocalCAPIWorkloadDurablyRecordsIdentityBeforeCNIAndKeepsFailureOneShot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validLocalCAPIWorkloadTestState(root)
	state.PodCIDR, state.ServiceCIDR, state.WorkloadKindName = localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR, state.Name
	state.WorkloadKubeconfig = localCAPIWorkloadKubeconfigPath(root, state.Name)
	state.CalicoSourceSHA256, state.CalicoManifestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := writeNewLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	state.ClusterUID = "verified-capi-cluster-uid"
	state.WorkloadKubeconfigSHA256 = strings.Repeat("c", 64)
	state.WorkloadContainers = []localContainerIdentity{{ID: strings.Repeat("1", 64), Name: "ok-worker-01-control-plane", Role: "control-plane"}, {ID: strings.Repeat("2", 64), Name: "ok-worker-01-worker", Role: "worker"}}
	state.WorkloadNodes = []localNodeIdentity{{Name: "worker-control-plane", UID: "node-cp"}, {Name: "worker-md-0", UID: "node-worker"}}
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatalf("pre-CNI identity intent was not durably persisted: %v", err)
	}
	persisted, err := readLocalCAPIWorkloadState(root, state.Name)
	if err != nil || persisted.Phase != "APPLYING" || persisted.ClusterUID != state.ClusterUID || len(persisted.WorkloadContainers) != 2 {
		t.Fatalf("pre-CNI evidence missing: %+v err=%v", persisted, err)
	}
	state.Phase, state.FailureCode = "INCOMPLETE", "CALICO_CREATE_FAILED"
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	persisted, err = readLocalCAPIWorkloadState(root, state.Name)
	if err != nil || persisted.Phase != "INCOMPLETE" || persisted.ClusterUID != state.ClusterUID || persisted.FailureCode != "CALICO_CREATE_FAILED" {
		t.Fatalf("partial CNI failure evidence was not retained: %+v err=%v", persisted, err)
	}
	if err := updateLocalCAPIWorkloadState(root, state); err == nil {
		t.Fatal("terminal INCOMPLETE receipt was replayed")
	}
}

func TestCAPIWorkloadClusterCIDRMustMatchTheCalicoPool(t *testing.T) {
	owner := "fedcba9876543210fedcba9876543210"
	var cluster localCAPIWorkloadClusterObservation
	if err := json.Unmarshal(localCAPIWorkloadClusterFixture(owner, true), &cluster); err != nil {
		t.Fatal(err)
	}
	if !localCAPIWorkloadClusterNetworkMatches(cluster, localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR) {
		t.Fatal("expected CAPI network CIDRs were not recognized")
	}
	cluster.Spec.ClusterNetwork.Pods.CIDRBlocks[0] = "10.0.0.0/16"
	if localCAPIWorkloadClusterNetworkMatches(cluster, localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR) {
		t.Fatal("Calico install could proceed with a mismatched live Pod CIDR")
	}
}

func TestCNIInventoryFailsClosedOnExistingOrMalformedResources(t *testing.T) {
	root := t.TempDir()
	management := validLocalCAPIState(root)
	state := validLocalCAPIWorkloadTestState(root)
	state.WorkloadKindName = state.Name
	state.WorkloadKubeconfig = localCAPIWorkloadKubeconfigPath(root, state.Name)
	for _, test := range []struct {
		name, daemonSets string
		wantErr          bool
	}{
		{"only kube-proxy", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"kube-proxy","namespace":"kube-system"}}]}`, false},
		{"existing CNI daemonset", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"calico-node","namespace":"kube-system"}}]}`, true},
		{"malformed inventory", `not-json`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := localRuntime{stateRoot: root, runCAPI: func(_ context.Context, _ localProviderIdentity, _ string, _ map[string]string, command string, args ...string) ([]byte, error) {
				if command != "kubectl" || !hasExactLocalCAPIWorkloadFlag(args, "--context", "kind-"+state.Name) {
					t.Fatalf("CNI inspection was not isolated: %q", args)
				}
				if strings.Contains(strings.Join(args, " "), "get daemonsets") {
					return []byte(test.daemonSets), nil
				}
				if strings.Contains(strings.Join(args, " "), "get crds") {
					return []byte(`{"apiVersion":"v1","kind":"List","items":[]}`), nil
				}
				return []byte(`{"apiVersion":"v1","kind":"List","items":[]}`), nil
			}}
			err := verifyLocalCAPIWorkloadCNIAbsent(context.Background(), runtime, management, state)
			if (err != nil) != test.wantErr {
				t.Fatalf("CNI preflight err=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestLocalCAPIWorkloadGenerateArgumentsArePinned(t *testing.T) {
	state := validLocalCAPIState("/private/state")
	got := buildLocalCAPIWorkloadGenerateArgs(state, "ok-worker-01")
	want := []string{"generate", "cluster", "ok-worker-01", "--infrastructure", "docker:v1.14.4",
		"--kubernetes-version", "v1.35.8", "--control-plane-machine-count", "1", "--worker-machine-count", "1",
		"--flavor", "development", "--target-namespace", "default", "--kubeconfig", state.BootstrapKubeconfig,
		"--kubeconfig-context", "kind-" + state.BootstrapKindName, "--config", state.ClusterctlConfigPath}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clusterctl generate args = %#v, want %#v", got, want)
	}
}

func TestLocalCAPIWorkloadCreateRejectsUnsupportedArgumentsBeforeExternalCommands(t *testing.T) {
	runtime := localRuntime{
		stateRoot: filepath.Join(t.TempDir(), "local"),
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("invalid arguments must be rejected before external commands")
			return nil, nil
		},
	}
	for _, args := range [][]string{
		{"cluster", "create", "ok-worker-01", "--management", "ok-capi-test2"},
		{"cluster", "create", "--name", "ok-worker-01", "--management", "ok-capi-test2", "--control-plane", "2"},
		{"cluster", "create", "--name", "ok-worker-01", "--management", "ok-capi-test2", "--workers", "0"},
	} {
		if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil {
			t.Fatalf("unsupported invocation was accepted: %q", args)
		}
	}
}

func TestLocalCAPIWorkloadNameAvailabilityRequiresExactPinnedInventory(t *testing.T) {
	management := validLocalCAPIState(t.TempDir())
	for _, test := range []struct {
		name string
		raw  string
		want bool
	}{
		{"empty Kubernetes List", `{"apiVersion":"v1","kind":"List","items":[]}`, false},
		{"valid nonmatching Cluster item", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","metadata":{"name":"other","namespace":"default"}}]}`, false},
		{"existing name in another namespace", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","metadata":{"name":"ok-worker-01","namespace":"other"}}]}`, true},
		{"duplicate identity", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","metadata":{"name":"other","namespace":"default"}},{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","metadata":{"name":"other","namespace":"default"}}]}`, true},
		{"invalid item version", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta1","kind":"Cluster","metadata":{"name":"other","namespace":"default"}}]}`, true},
		{"invalid item kind", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Namespace","metadata":{"name":"other","namespace":"default"}}]}`, true},
		{"incomplete item identity", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","metadata":{"name":"different"}}]}`, true},
		{"null items", `{"apiVersion":"v1","kind":"List","items":null}`, true},
		{"unexpected envelope", `{"apiVersion":"other/v1","kind":"List","items":[]}`, true},
		{"unexpected list kind", `{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"UnexpectedList","items":[]}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := localRuntime{runCAPI: func(_ context.Context, provider localProviderIdentity, kubeconfig string, _ map[string]string, command string, args ...string) ([]byte, error) {
				if provider != management.Provider || kubeconfig != management.BootstrapKubeconfig || command != "kubectl" || !hasExactLocalCAPIWorkloadFlag(args, "--kubeconfig", management.BootstrapKubeconfig) || !hasExactLocalCAPIWorkloadFlag(args, "--context", "kind-"+management.BootstrapKindName) {
					t.Fatalf("inventory query was not pinned to the receipt: provider=%+v kubeconfig=%q args=%q", provider, kubeconfig, args)
				}
				return []byte(test.raw), nil
			}}
			err := verifyLocalCAPIWorkloadNameAbsent(context.Background(), runtime, management, "ok-worker-01")
			if (err != nil) != test.want {
				t.Fatalf("availability error = %v, wantErr %v", err, test.want)
			}
		})
	}
}

func TestLocalCAPIWorkloadStatusUsesCAPIv1beta2AvailabilityConditions(t *testing.T) {
	const owner = "fedcba9876543210fedcba9876543210"
	readyConditions := []localCAPIWorkloadCondition{
		{Type: "Available", Status: "True"},
		{Type: "ControlPlaneAvailable", Status: "True"},
		{Type: "WorkersAvailable", Status: "True"},
	}
	cases := []struct {
		name       string
		conditions []localCAPIWorkloadCondition
		result     string
		reason     string
	}{
		{"observed healthy v1beta2 conditions awaits workload evidence", readyConditions, "PROVISIONING", "WORKLOAD_ACCESS_EVIDENCE_NOT_RECORDED"},
		{"missing Available", readyConditions[1:], "PROVISIONING", "CLUSTER_AVAILABLE_NOT_CONFIRMED"},
		{"missing ControlPlaneAvailable", []localCAPIWorkloadCondition{readyConditions[0], readyConditions[2]}, "PROVISIONING", "CONTROL_PLANE_AVAILABLE_NOT_CONFIRMED"},
		{"missing WorkersAvailable", readyConditions[:2], "PROVISIONING", "WORKERS_AVAILABLE_NOT_CONFIRMED"},
		{"Unknown Available", []localCAPIWorkloadCondition{{Type: "Available", Status: "Unknown"}, readyConditions[1], readyConditions[2]}, "PROVISIONING", "CLUSTER_AVAILABLE_NOT_CONFIRMED"},
		{"False ControlPlaneAvailable", []localCAPIWorkloadCondition{readyConditions[0], {Type: "ControlPlaneAvailable", Status: "False"}, readyConditions[2]}, "PROVISIONING", "CONTROL_PLANE_AVAILABLE_NOT_CONFIRMED"},
		{"contradictory duplicate Available", []localCAPIWorkloadCondition{readyConditions[0], {Type: "Available", Status: "False"}, readyConditions[1], readyConditions[2]}, "UNVERIFIABLE", "CLUSTER_CONDITIONS_AMBIGUOUS"},
		{"invalid condition status", []localCAPIWorkloadCondition{readyConditions[0], {Type: "ControlPlaneAvailable", Status: "Maybe"}, readyConditions[2]}, "UNVERIFIABLE", "CLUSTER_CONDITIONS_AMBIGUOUS"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var cluster localCAPIWorkloadClusterObservation
			if err := json.Unmarshal(localCAPIWorkloadClusterFixtureWithConditions(owner, test.conditions), &cluster); err != nil {
				t.Fatal(err)
			}
			management := validLocalCAPIState(t.TempDir())
			state := validLocalCAPIWorkloadTestState(t.TempDir())
			state.Phase, state.ClusterUID = "APPLIED", "workload-cluster-uid"
			runtime := localRuntime{runCAPI: func(_ context.Context, _ localProviderIdentity, _ string, _ map[string]string, _ string, _ ...string) ([]byte, error) {
				return localCAPIWorkloadMachinesFixture(), nil
			}}
			report := observeLocalCAPIWorkloadStatus(context.Background(), runtime, management, state, cluster)
			if report.Result != test.result || report.ReasonCode != test.reason {
				t.Fatalf("status result=%s reason=%s, want %s / %s", report.Result, report.ReasonCode, test.result, test.reason)
			}
			if test.result == "READY" && (!report.ClusterReady || !report.ControlPlaneReady || !report.WorkersReady || report.ReadyMachineCount != 2) {
				t.Fatalf("healthy CAPI v1beta2 status lacks required readiness evidence: %+v", report)
			}
		})
	}
}

func TestLocalCAPIWorkloadReceiptIsPrivateOneShotAndTransitionsOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validLocalCAPIWorkloadTestState(root)
	if err := writeNewLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(localCAPIWorkloadStatePath(root, state.Name))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("workload receipt is not private: info=%v err=%v", info, err)
	}
	got, err := readLocalCAPIWorkloadState(root, state.Name)
	if err != nil || !sameLocalCAPIWorkloadIntent(state, got) {
		t.Fatalf("cannot read exact one-shot intent: state=%+v err=%v", got, err)
	}
	state.ClusterUID = "cluster-uid"
	state.Phase = "WAITING_FOR_WORKLOAD_ACCESS"
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	state.Phase, state.FailureCode = "INCOMPLETE", "WORKLOAD_KUBECONFIG_FAILED"
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	if err := updateLocalCAPIWorkloadState(root, state); err == nil {
		t.Fatal("terminal INCOMPLETE receipt was transitioned or replayed")
	}
}

func TestLocalCAPIWorkloadCalicoAttemptMarkerMakesContinuationTerminal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validLocalCAPIWorkloadTestState(root)
	state.PodCIDR, state.ServiceCIDR, state.WorkloadKindName = localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR, state.Name
	state.WorkloadKubeconfig = localCAPIWorkloadKubeconfigPath(root, state.Name)
	state.CalicoSourceSHA256, state.CalicoManifestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := writeNewLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	state.Phase, state.ClusterUID = "WAITING_FOR_WORKLOAD_ACCESS", "cluster-uid"
	state.WorkloadKubeconfigSHA256 = strings.Repeat("c", 64)
	state.WorkloadContainers = []localContainerIdentity{{ID: strings.Repeat("1", 64), Name: "ok-worker-01-control-plane", Role: "control-plane"}, {ID: strings.Repeat("2", 64), Name: "ok-worker-01-worker", Role: "worker"}}
	state.WorkloadNodes = []localNodeIdentity{{Name: "worker-control-plane", UID: "node-cp"}, {Name: "worker-md-0", UID: "node-worker"}}
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	state.Phase, state.CalicoCreateAttempted = "CALICO_CREATE_ATTEMPTED", true
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatalf("durable pre-mutation marker rejected: %v", err)
	}
	markerBytes, err := os.ReadFile(localCAPIWorkloadStatePath(root, state.Name))
	if err != nil {
		t.Fatal(err)
	}
	mutations := 0
	runtime := localRuntime{stateRoot: root,
		run: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		runPinned: func(context.Context, localProviderIdentity, string, ...string) ([]byte, error) {
			mutations++
			return nil, nil
		},
		runCAPI: func(context.Context, localProviderIdentity, string, map[string]string, string, ...string) ([]byte, error) {
			mutations++
			return nil, nil
		},
	}
	if err := runLocalCAPIWorkloadContinue(context.Background(), []string{"--name", state.Name, "--management", state.ManagementName}, runtime, io.Discard, io.Discard); err == nil {
		t.Fatal("continuation accepted a receipt after Calico create was marked attempted")
	}
	if mutations != 0 {
		t.Fatalf("terminal attempted receipt caused external operations: %d", mutations)
	}
	after, err := os.ReadFile(localCAPIWorkloadStatePath(root, state.Name))
	if err != nil || !bytes.Equal(markerBytes, after) {
		t.Fatalf("ambiguous Calico attempt receipt changed: err=%v", err)
	}
	state.Phase, state.FailureCode = "INCOMPLETE", "CALICO_CREATE_OUTCOME_UNCERTAIN"
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatalf("ambiguous Calico create result did not persist terminal state: %v", err)
	}
	persisted, err := readLocalCAPIWorkloadState(root, state.Name)
	if err != nil || persisted.Phase != "INCOMPLETE" || persisted.FailureCode != "CALICO_CREATE_OUTCOME_UNCERTAIN" || !persisted.CalicoCreateAttempted {
		t.Fatalf("ambiguous Calico result was not terminal: state=%+v err=%v", persisted, err)
	}
}

func TestLocalCAPIWorkloadCNIRecoveryIsExplicitNarrowAndOneShot(t *testing.T) {
	state := validLocalCAPIWorkloadTestState(t.TempDir())
	state.Phase, state.FailureCode, state.ClusterUID = "INCOMPLETE", "CNI_ALREADY_PRESENT", "cluster-uid"
	state.WorkloadKubeconfigSHA256 = strings.Repeat("a", 64)
	state.WorkloadContainers = []localContainerIdentity{
		{ID: strings.Repeat("1", 64), Name: "ok-worker-01-control-plane", Role: "control-plane"},
		{ID: strings.Repeat("2", 64), Name: "ok-worker-01-worker", Role: "worker"},
		{ID: strings.Repeat("3", 64), Name: "ok-worker-01-lb", Role: "external-load-balancer"},
	}
	state.WorkloadNodes = []localNodeIdentity{{Name: "cp", UID: "node-cp"}, {Name: "worker", UID: "node-worker"}}
	if !localCAPIWorkloadCNIRecoveryCandidate(state) {
		t.Fatal("exact pre-Calico CNI false-positive receipt was not recognized as an explicit recovery candidate")
	}
	next := state
	next.Phase, next.FailureCode, next.RecoveryFromFailureCode = "WAITING_FOR_WORKLOAD_ACCESS", "", "CNI_ALREADY_PRESENT"
	if !validLocalCAPIWorkloadTransition(state, next) {
		t.Fatal("explicit CNI-only continuation was not permitted from the exact failure")
	}
	for _, mutate := range []func(*localCAPIWorkloadState){
		func(s *localCAPIWorkloadState) { s.FailureCode = "WORKLOAD_CREATE_FAILED" },
		func(s *localCAPIWorkloadState) { s.CalicoCreateAttempted = true },
		func(s *localCAPIWorkloadState) { s.RecoveryFromFailureCode = "CNI_ALREADY_PRESENT" },
		func(s *localCAPIWorkloadState) { s.WorkloadNodes = nil },
	} {
		bad := state
		mutate(&bad)
		if localCAPIWorkloadCNIRecoveryCandidate(bad) {
			t.Fatalf("unsafe or previously recovered receipt was eligible: %+v", bad)
		}
		if validLocalCAPIWorkloadTransition(bad, next) {
			t.Fatalf("unsafe receipt transition was allowed: %+v", bad)
		}
	}
}

func TestLocalCAPIWorkloadCancellationBeforeCalicoMutationKeepsWaitingPhase(t *testing.T) {
	root := filepath.Join(t.TempDir(), "local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validLocalCAPIWorkloadTestState(root)
	source := []byte(localCAPIWorkloadCalicoTestFixture)
	sourceDigest := localCAPIBytesSHA256(source)
	manifest, err := renderLocalCAPIWorkloadCalico(source, sourceDigest, localCAPIWorkloadPodCIDR)
	if err != nil {
		t.Fatal(err)
	}
	state.PodCIDR, state.ServiceCIDR, state.WorkloadKindName = localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR, state.Name
	state.WorkloadKubeconfig = localCAPIWorkloadKubeconfigPath(root, state.Name)
	state.CalicoSourceSHA256, state.CalicoManifestSHA256 = sourceDigest, localCAPIBytesSHA256(manifest)
	if err := writeNewLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	state.Phase, state.ClusterUID = "WAITING_FOR_WORKLOAD_ACCESS", "cluster-uid"
	state.WorkloadKubeconfigSHA256 = localCAPIBytesSHA256(localCAPIWorkloadKubeconfigFixture(state.Name))
	state.WorkloadContainers = []localContainerIdentity{{ID: strings.Repeat("1", 64), Name: "ok-worker-01-control-plane", Role: "control-plane"}, {ID: strings.Repeat("2", 64), Name: "ok-worker-01-worker", Role: "worker"}}
	state.WorkloadNodes = []localNodeIdentity{{Name: "worker-control-plane", UID: "node-cp"}, {Name: "worker-md-0", UID: "node-worker"}}
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateNewFile(state.WorkloadKubeconfig, localCAPIWorkloadKubeconfigFixture(state.Name)); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateNewFile(localCAPIWorkloadCalicoPath(root, state.Name), manifest); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runtime := localRuntime{stateRoot: root, calicoManifestSHA256: sourceDigest, runCAPI: func(ctx context.Context, _ localProviderIdentity, _ string, _ map[string]string, _ string, _ ...string) ([]byte, error) {
		return nil, ctx.Err()
	}}
	_, err = installLocalCAPIWorkloadCalico(ctx, runtime, validLocalCAPIState(root), state)
	if err != nil {
		t.Fatalf("ordinary cancellation before Calico mutation became terminal: %v", err)
	}
	persisted, err := readLocalCAPIWorkloadState(root, state.Name)
	if err != nil || persisted.Phase != "WAITING_FOR_WORKLOAD_ACCESS" || persisted.CalicoCreateAttempted {
		t.Fatalf("cancelled pre-mutation check lost its resumable state: state=%+v err=%v", persisted, err)
	}
}

func TestLocalCAPIWorkloadLegacyReceiptIsReadWithoutUpgrade(t *testing.T) {
	root := filepath.Join(t.TempDir(), "local")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validLocalCAPIWorkloadTestState(root)
	state.Phase, state.ClusterUID = "APPLIED", "legacy-cluster-uid"
	if err := writeNewLocalCAPIWorkloadState(root, state); err != nil {
		t.Fatal(err)
	}
	path := localCAPIWorkloadStatePath(root, state.Name)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("calicoCreateAttempted")) {
		t.Fatal("legacy receipt unexpectedly contains the new mutation marker")
	}
	got, err := readLocalCAPIWorkloadState(root, state.Name)
	if err != nil || got.CalicoCreateAttempted {
		t.Fatalf("legacy receipt was rejected or silently upgraded: marker=%t err=%v", got.CalicoCreateAttempted, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("reading legacy receipt modified it: err=%v", err)
	}
}

func TestLocalCAPIWorkloadContinuationRejectsIdentityCIDRAndTopologyDrift(t *testing.T) {
	baselineRaw := localCAPIWorkloadClusterFixture("fedcba9876543210fedcba9876543210", true)
	state := validLocalCAPIWorkloadTestState(t.TempDir())
	state.Phase, state.ClusterUID = "WAITING_FOR_WORKLOAD_ACCESS", "workload-cluster-uid"
	state.PodCIDR, state.ServiceCIDR = localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR
	state.WorkloadKindName = state.Name
	tests := []struct {
		name   string
		mutate func(*localCAPIWorkloadClusterObservation)
	}{
		{"owner mismatch", func(cluster *localCAPIWorkloadClusterObservation) {
			cluster.Metadata.Labels[localOwnerLabel] = "other-owner"
		}},
		{"UID mismatch", func(cluster *localCAPIWorkloadClusterObservation) { cluster.Metadata.UID = "other-uid" }},
		{"Pod CIDR mismatch", func(cluster *localCAPIWorkloadClusterObservation) {
			cluster.Spec.ClusterNetwork.Pods.CIDRBlocks[0] = "10.0.0.0/16"
		}},
		{"Service CIDR mismatch", func(cluster *localCAPIWorkloadClusterObservation) {
			cluster.Spec.ClusterNetwork.Services.CIDRBlocks[0] = "10.96.0.0/12"
		}},
		{"topology mismatch", func(cluster *localCAPIWorkloadClusterObservation) { *cluster.Spec.Topology.ControlPlane.Replicas = 2 }},
		{"class mismatch", func(cluster *localCAPIWorkloadClusterObservation) { cluster.Spec.Topology.ClassRef.Name = "other" }},
		{"Kubernetes version mismatch", func(cluster *localCAPIWorkloadClusterObservation) { cluster.Spec.Topology.Version = "v1.35.7" }},
		{"worker class mismatch", func(cluster *localCAPIWorkloadClusterObservation) {
			cluster.Spec.Topology.Workers.MachineDeployments[0].Class = "other"
		}},
		{"worker deployment name mismatch", func(cluster *localCAPIWorkloadClusterObservation) {
			cluster.Spec.Topology.Workers.MachineDeployments[0].Name = "other"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var candidate localCAPIWorkloadClusterObservation
			if err := json.Unmarshal(baselineRaw, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(&candidate)
			if localCAPIWorkloadClusterIdentityMatches(state, candidate) {
				t.Fatal("continuation accepted workload identity drift")
			}
		})
	}
}

func TestLocalCAPIWorkloadCreateAndStatusUseVerifiedManagementAndDoNotEditItsReceipt(t *testing.T) {
	runtime, management := localCAPIVerificationFixture(t)
	runtime = localCAPIWorkloadTestRuntimeWithCalico(runtime)
	management.Phase = localCAPIPhaseIncomplete
	management.FailureStage, management.FailureCode = "capi-verify", "CAPI_VERIFY_FAILED"
	managementBytes, err := json.MarshalIndent(management, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	managementBytes = append(managementBytes, '\n')
	managementPath := localCAPIStateFilePath(runtime.stateRoot, management.Name)
	if err := os.WriteFile(managementPath, managementBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	managementBefore, err := os.ReadFile(managementPath)
	if err != nil {
		t.Fatal(err)
	}
	const workloadOwner = "fedcba9876543210fedcba9876543210"
	runtime.newOwnerID = func() (string, error) { return workloadOwner, nil }
	createCalls, dryRunCalls, calicoCreateCalls, capiCreateCalls := 0, 0, 0, 0
	nodesReady, calicoReady, cniAlreadyPresent := true, true, false
	calicoImageMismatch := false
	capiCreated, workloadKindLists, waitCalls := false, 0, 0
	workloadKubeconfig := localCAPIWorkloadKubeconfigFixture("ok-worker-01")
	basePinned := runtime.runPinned
	runtime.runPinned = func(ctx context.Context, provider localProviderIdentity, command string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case command == "kind" && joined == "get clusters":
			if capiCreated {
				workloadKindLists++
				if workloadKindLists == 1 {
					return []byte(management.BootstrapKindName + "\n"), nil
				}
			}
			return []byte(management.BootstrapKindName + "\nok-worker-01\n"), nil
		case command == "kind" && strings.HasPrefix(joined, "get kubeconfig --name ok-worker-01"):
			return workloadKubeconfig, nil
		case command == "docker" && strings.Contains(joined, "ok-worker-01"):
			return []byte("container-cp|ok-worker-01-control-plane|control-plane\ncontainer-worker|ok-worker-01-worker|worker\ncontainer-lb|ok-worker-01-lb|external-load-balancer\n"), nil
		default:
			return basePinned(ctx, provider, command, args...)
		}
	}
	machineOutput := localCAPIWorkloadMachinesFixture()
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if command == "kubectl" {
			if provider != management.Provider {
				t.Fatalf("kubectl provider was not pinned: %+v", provider)
			}
			if kubeconfig == management.BootstrapKubeconfig {
				if !hasExactLocalCAPIWorkloadFlag(args, "--kubeconfig", management.BootstrapKubeconfig) || !hasExactLocalCAPIWorkloadFlag(args, "--context", "kind-"+management.BootstrapKindName) {
					t.Fatalf("management kubectl call not explicitly pinned: %q", joined)
				}
			} else if kubeconfig != localCAPIWorkloadKubeconfigPath(runtime.stateRoot, "ok-worker-01") || !hasExactLocalCAPIWorkloadFlag(args, "--kubeconfig", kubeconfig) || !hasExactLocalCAPIWorkloadFlag(args, "--context", "kind-ok-worker-01") {
				t.Fatalf("workload kubectl call not explicitly pinned: kubeconfig=%q args=%q", kubeconfig, joined)
			}
		}
		switch {
		case command == "clusterctl" && strings.HasPrefix(joined, "generate cluster ok-worker-01 "):
			if provider != management.Provider || kubeconfig != management.BootstrapKubeconfig || env != nil {
				t.Fatalf("clusterctl generation was not pinned: provider=%+v kubeconfig=%q env=%v", provider, kubeconfig, env)
			}
			return []byte(localCAPIDevelopmentManifestFixture), nil
		case command == "kubectl" && strings.Contains(joined, "get clusters.cluster.x-k8s.io -A -o json"):
			return []byte(`{"apiVersion":"v1","kind":"List","items":[]}`), nil
		case command == "kubectl" && strings.Contains(joined, "create --dry-run=server -f"):
			dryRunCalls++
			if kubeconfig == management.BootstrapKubeconfig {
				assertWorkloadClusterOnlyManifestFile(t, args)
			}
			return nil, nil
		case command == "kubectl" && strings.Contains(joined, "create -f"):
			createCalls++
			if kubeconfig == management.BootstrapKubeconfig {
				assertWorkloadClusterOnlyManifestFile(t, args)
				capiCreateCalls++
				capiCreated = true
			} else {
				calicoCreateCalls++
				persisted, readErr := readLocalCAPIWorkloadState(runtime.stateRoot, "ok-worker-01")
				if readErr != nil || persisted.Phase != "CALICO_CREATE_ATTEMPTED" || !persisted.CalicoCreateAttempted {
					t.Fatalf("Calico mutation began before durable attempt marker: state=%+v err=%v", persisted, readErr)
				}
			}
			return nil, nil
		case command == "kubectl" && strings.Contains(joined, "get cluster.cluster.x-k8s.io ok-worker-01"):
			return localCAPIWorkloadClusterFixture(workloadOwner, true), nil
		case command == "kubectl" && strings.Contains(joined, "get machines.cluster.x-k8s.io"):
			return machineOutput, nil
		case command == "kubectl" && kubeconfig == localCAPIWorkloadKubeconfigPath(runtime.stateRoot, "ok-worker-01") && strings.Contains(joined, "get nodes -o json"):
			return localCAPIWorkloadNodesFixture(nodesReady), nil
		case command == "kubectl" && kubeconfig == localCAPIWorkloadKubeconfigPath(runtime.stateRoot, "ok-worker-01") && strings.Contains(joined, "get daemonsets -A -o json"):
			if cniAlreadyPresent {
				return []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"calico-node","namespace":"kube-system"}}]}`), nil
			}
			return []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"kube-proxy","namespace":"kube-system"}}]}`), nil
		case command == "kubectl" && kubeconfig == localCAPIWorkloadKubeconfigPath(runtime.stateRoot, "ok-worker-01") && strings.Contains(joined, "get crds -o json"):
			return []byte(`{"apiVersion":"v1","kind":"List","items":[]}`), nil
		case command == "kubectl" && kubeconfig == localCAPIWorkloadKubeconfigPath(runtime.stateRoot, "ok-worker-01") && strings.Contains(joined, "get pods -A -o json"):
			return []byte(`{"apiVersion":"v1","kind":"List","items":[]}`), nil
		case command == "kubectl" && strings.Contains(joined, "get daemonset calico-node"):
			if !calicoReady {
				return []byte(`{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"calico-node","namespace":"kube-system"},"spec":{"template":{"spec":{"containers":[{"image":"quay.io/calico/node:v3.33.0"}]}}},"status":{"desiredNumberScheduled":2,"numberReady":1,"updatedNumberScheduled":1}}`), nil
			}
			if calicoImageMismatch {
				return []byte(`{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"calico-node","namespace":"kube-system"},"spec":{"template":{"spec":{"containers":[{"image":"quay.io/calico/node:v3.32.0"}]}}},"status":{"desiredNumberScheduled":2,"numberReady":2,"updatedNumberScheduled":2}}`), nil
			}
			return []byte(`{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"calico-node","namespace":"kube-system"},"spec":{"template":{"spec":{"containers":[{"image":"quay.io/calico/node:v3.33.0"}],"initContainers":[{"image":"quay.io/calico/calico:v3.33.0"}]}}},"status":{"desiredNumberScheduled":2,"numberReady":2,"updatedNumberScheduled":2}}`), nil
		case command == "kubectl" && strings.Contains(joined, "get deployment calico-kube-controllers"):
			return []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"calico-kube-controllers","namespace":"kube-system"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"image":"quay.io/calico/calico:v3.33.0"}]}}},"status":{"availableReplicas":1,"readyReplicas":1}}`), nil
		default:
			return base(ctx, provider, kubeconfig, env, command, args...)
		}
	}
	runtime.wait = func(_ context.Context, delay time.Duration) error {
		if delay != 5*time.Second {
			t.Fatalf("unexpected workload access polling interval: %s", delay)
		}
		waitCalls++
		return context.DeadlineExceeded
	}
	var created bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "create", "--name", "ok-worker-01", "--management", management.Name, "--control-plane", "1", "--workers", "1"}, &created, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var report localCAPIWorkloadReport
	if err := json.Unmarshal(created.Bytes(), &report); err != nil {
		t.Fatalf("invalid create report: %v output=%s", err, created.String())
	}
	if report.Result != "PROVISIONING" || report.Operation != "CREATE" || report.ReasonCode != "WORKLOAD_ACCESS_PENDING" || report.HistoricalOperationPhase != "WAITING_FOR_WORKLOAD_ACCESS" || report.ClusterUID != "workload-cluster-uid" || createCalls != 1 || dryRunCalls != 1 || waitCalls != 1 || calicoCreateCalls != 0 {
		t.Fatalf("unexpected create result: %+v creates=%d dryruns=%d waits=%d", report, createCalls, dryRunCalls, waitCalls)
	}
	workload, err := readLocalCAPIWorkloadState(runtime.stateRoot, "ok-worker-01")
	if err != nil || workload.Phase != "WAITING_FOR_WORKLOAD_ACCESS" || workload.ClusterUID != "workload-cluster-uid" || workload.CalicoCreateAttempted {
		t.Fatalf("workload did not remain in its durable waiting phase: %+v err=%v", workload, err)
	}
	waitingReceipt, err := os.ReadFile(localCAPIWorkloadStatePath(runtime.stateRoot, "ok-worker-01"))
	if err != nil {
		t.Fatal(err)
	}
	var waitingStatus bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &waitingStatus, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var waitingReport localCAPIWorkloadReport
	if err := json.Unmarshal(waitingStatus.Bytes(), &waitingReport); err != nil || waitingReport.Result != "PROVISIONING" || waitingReport.ReasonCode != "WORKLOAD_ACCESS_PENDING" || waitingReport.HistoricalOperationPhase != "WAITING_FOR_WORKLOAD_ACCESS" {
		t.Fatalf("waiting status was not read-only PROVISIONING: report=%+v err=%v", waitingReport, err)
	}
	waitingReceiptAfter, err := os.ReadFile(localCAPIWorkloadStatePath(runtime.stateRoot, "ok-worker-01"))
	if err != nil || !bytes.Equal(waitingReceipt, waitingReceiptAfter) || createCalls != 1 || calicoCreateCalls != 0 {
		t.Fatalf("status changed waiting state or caused mutation: readErr=%v createCalls=%d calicoCalls=%d", err, createCalls, calicoCreateCalls)
	}
	// Model the confirmed pre-Calico false-positive failure. The attempt has a
	// stable Cluster UID and access evidence, but no Calico create marker.
	workload.WorkloadContainers = []localContainerIdentity{
		{ID: "container-cp", Name: "ok-worker-01-control-plane", Role: "control-plane"},
		{ID: "container-worker", Name: "ok-worker-01-worker", Role: "worker"},
		{ID: "container-lb", Name: "ok-worker-01-lb", Role: "external-load-balancer"},
	}
	workload.WorkloadNodes = []localNodeIdentity{{Name: "ok-worker-01-control-plane", UID: "node-cp"}, {Name: "ok-worker-01-worker", UID: "node-worker"}}
	workloadConfig := localCAPIWorkloadKubeconfigFixture("ok-worker-01")
	workload.WorkloadKubeconfigSHA256 = localCAPIBytesSHA256(workloadConfig)
	if err := writePrivateNewFile(workload.WorkloadKubeconfig, workloadConfig); err != nil {
		t.Fatal(err)
	}
	workload.Phase, workload.FailureCode = "INCOMPLETE", "CNI_ALREADY_PRESENT"
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, workload); err != nil {
		t.Fatalf("could not persist synthetic pre-Calico false-positive receipt: %v", err)
	}
	recoveryReceipt, err := os.ReadFile(localCAPIWorkloadStatePath(runtime.stateRoot, "ok-worker-01"))
	if err != nil {
		t.Fatal(err)
	}
	var cniFailureStatus bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &cniFailureStatus, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var cniFailureReport localCAPIWorkloadReport
	if err := json.Unmarshal(cniFailureStatus.Bytes(), &cniFailureReport); err != nil || cniFailureReport.Result != "INCOMPLETE" || cniFailureReport.ReasonCode != "EXPLICIT_CNI_CONTINUATION_REQUIRED" {
		t.Fatalf("read-only status did not report the narrow explicit recovery boundary: report=%+v err=%v", cniFailureReport, err)
	}
	recoveryReceiptAfterStatus, err := os.ReadFile(localCAPIWorkloadStatePath(runtime.stateRoot, "ok-worker-01"))
	if err != nil || !bytes.Equal(recoveryReceipt, recoveryReceiptAfterStatus) || capiCreateCalls != 1 || calicoCreateCalls != 0 {
		t.Fatalf("status changed the terminal receipt or caused a mutation: err=%v capi=%d calico=%d", err, capiCreateCalls, calicoCreateCalls)
	}
	cniAlreadyPresent = true
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "continue", "--name", "ok-worker-01", "--management", management.Name}, io.Discard, io.Discard, runtime); err == nil {
		t.Fatal("explicit recovery proceeded while a CNI daemonset was present")
	}
	recoveryReceiptAfter, err := os.ReadFile(localCAPIWorkloadStatePath(runtime.stateRoot, "ok-worker-01"))
	if err != nil || !bytes.Equal(recoveryReceipt, recoveryReceiptAfter) || calicoCreateCalls != 0 || capiCreateCalls != 1 {
		t.Fatalf("rejected CNI recovery changed the receipt or invoked mutations: err=%v calico=%d capi=%d", err, calicoCreateCalls, capiCreateCalls)
	}
	cniAlreadyPresent = false
	var continued bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "continue", "--name", "ok-worker-01", "--management", management.Name}, &continued, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(continued.Bytes(), &report); err != nil || report.Result != "READY" || report.Operation != "CONTINUE" || report.HistoricalOperationPhase != "APPLIED" || createCalls != 2 || dryRunCalls != 2 || calicoCreateCalls != 1 || capiCreateCalls != 1 {
		t.Fatalf("explicit continuation failed or replayed a mutation: report=%+v err=%v creates=%d dryruns=%d calico=%d capi=%d", report, err, createCalls, dryRunCalls, calicoCreateCalls, capiCreateCalls)
	}
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "continue", "--name", "ok-worker-01", "--management", management.Name}, io.Discard, io.Discard, runtime); err == nil || capiCreateCalls != 1 || calicoCreateCalls != 1 {
		t.Fatalf("continuation replayed a completed mutation: err=%v capi=%d calico=%d", err, capiCreateCalls, calicoCreateCalls)
	}
	workload, err = readLocalCAPIWorkloadState(runtime.stateRoot, "ok-worker-01")
	if err != nil || workload.Phase != "APPLIED" || !workload.CalicoCreateAttempted || workload.RecoveryFromFailureCode != "CNI_ALREADY_PRESENT" || workload.FailureCode != "" || workload.ClusterUID != "workload-cluster-uid" || workload.WorkloadKubeconfigSHA256 == "" || len(workload.WorkloadNodes) != 2 || workload.CalicoManifestSHA256 == "" {
		t.Fatalf("workload receipt not applied with one-shot Calico marker: %+v err=%v", workload, err)
	}
	kubeconfigPath := localCAPIWorkloadKubeconfigPath(runtime.stateRoot, "ok-worker-01")
	kubeconfigInfo, err := os.Stat(kubeconfigPath)
	kubeconfigBytes, readErr := os.ReadFile(kubeconfigPath)
	if err != nil || readErr != nil || kubeconfigInfo.Mode().Perm() != 0o600 || localCAPIBytesSHA256(kubeconfigBytes) != workload.WorkloadKubeconfigSHA256 {
		t.Fatalf("host workload kubeconfig is not privately and durably bound: statErr=%v readErr=%v", err, readErr)
	}
	var status bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &status, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var statusReport localCAPIWorkloadReport
	if err := json.Unmarshal(status.Bytes(), &statusReport); err != nil || statusReport.Result != "READY" || statusReport.Operation != "STATUS" {
		t.Fatalf("unexpected read-only status: report=%+v err=%v output=%s", statusReport, err, status.String())
	}
	nodesReady = false
	var nodesNotReady bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &nodesNotReady, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var nodesNotReadyReport localCAPIWorkloadReport
	if err := json.Unmarshal(nodesNotReady.Bytes(), &nodesNotReadyReport); err != nil || nodesNotReadyReport.Result != "PROVISIONING" || nodesNotReadyReport.ReasonCode != "WORKLOAD_NODES_NOT_READY" {
		t.Fatalf("not-ready Nodes were reported healthy: %+v err=%v", nodesNotReadyReport, err)
	}
	nodesReady, calicoReady = true, false
	var calicoNotReady bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &calicoNotReady, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var calicoNotReadyReport localCAPIWorkloadReport
	if err := json.Unmarshal(calicoNotReady.Bytes(), &calicoNotReadyReport); err != nil || calicoNotReadyReport.Result != "PROVISIONING" || calicoNotReadyReport.ReasonCode != "CALICO_NOT_READY" {
		t.Fatalf("not-ready Calico was reported healthy: %+v err=%v", calicoNotReadyReport, err)
	}
	calicoReady = true
	calicoImageMismatch = true
	var calicoWrongVersion bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &calicoWrongVersion, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var calicoWrongVersionReport localCAPIWorkloadReport
	if err := json.Unmarshal(calicoWrongVersion.Bytes(), &calicoWrongVersionReport); err != nil || calicoWrongVersionReport.Result != "PROVISIONING" || calicoWrongVersionReport.ReasonCode != "CALICO_NOT_READY" {
		t.Fatalf("Calico image version mismatch was reported healthy: %+v err=%v", calicoWrongVersionReport, err)
	}
	calicoImageMismatch = false
	machineOutput = []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta1","kind":"Machine","metadata":{"name":"wrong-version","namespace":"default","uid":"machine-uid","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01"}}}]}`)
	var malformedStatus bytes.Buffer
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "status", "--name", "ok-worker-01", "--management", management.Name}, &malformedStatus, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	var malformedReport localCAPIWorkloadReport
	if err := json.Unmarshal(malformedStatus.Bytes(), &malformedReport); err != nil || malformedReport.Result != "UNVERIFIABLE" || malformedReport.ReasonCode != "MACHINE_IDENTITY_MISSING" {
		t.Fatalf("malformed Machine item was accepted: report=%+v err=%v", malformedReport, err)
	}
	managementAfter, err := os.ReadFile(managementPath)
	if err != nil || !bytes.Equal(managementBefore, managementAfter) {
		t.Fatalf("management receipt changed during workload operation: err=%v", err)
	}
	if err := runLocalWithRuntime(context.Background(), []string{"cluster", "create", "--name", "ok-worker-01", "--management", management.Name}, io.Discard, io.Discard, runtime); err == nil || createCalls != 2 {
		t.Fatalf("duplicate workload command was adopted or reapplied: err=%v createCalls=%d", err, createCalls)
	}
}

func assertWorkloadClusterOnlyManifestFile(t *testing.T, args []string) {
	t.Helper()
	path := ""
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-f" {
			path = args[i+1]
			break
		}
	}
	if path == "" {
		t.Fatal("management workload create did not use a manifest file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read workload manifest: %v", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	count := 0
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("cannot parse workload manifest: %v", err)
		}
		if len(object) == 0 {
			continue
		}
		count++
		if object["apiVersion"] != localCAPIWorkloadAPIVersion || object["kind"] != "Cluster" {
			t.Fatalf("workload create attempted to apply shared or unexpected object %v/%v", object["apiVersion"], object["kind"])
		}
	}
	if count != 1 {
		t.Fatalf("workload create manifest contained %d objects; want exactly one Cluster", count)
	}
}

func TestLocalCAPIWorkloadRejectsLegacyManagementReceiptWithoutTemplateOwnership(t *testing.T) {
	runtime, management := localCAPIVerificationFixture(t)
	runtime = localCAPIWorkloadTestRuntimeWithCalico(runtime)
	management.DevelopmentTemplatesAttempted = false
	management.DevelopmentTemplatesSHA256 = ""
	management.DevelopmentTemplatesComplete = false
	management.DevelopmentTemplates = nil
	raw, err := json.MarshalIndent(management, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	managementPath := localCAPIStateFilePath(runtime.stateRoot, management.Name)
	if err := os.WriteFile(managementPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(managementPath)
	if err != nil {
		t.Fatal(err)
	}
	createCalls := 0
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if command == "kubectl" && strings.Contains(joined, " create") {
			createCalls++
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	args := []string{"cluster", "create", "--name", "ok-worker-03", "--management", management.Name, "--control-plane", "1", "--workers", "1"}
	if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil || !strings.Contains(err.Error(), "template ownership evidence") {
		t.Fatalf("legacy management receipt without template ownership was adopted: %v", err)
	}
	if _, err := os.Lstat(localCAPIWorkloadDirectory(runtime.stateRoot, "ok-worker-03")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected legacy management receipt created workload state: %v", err)
	}
	after, err := os.ReadFile(managementPath)
	if err != nil || !bytes.Equal(before, after) || createCalls != 0 {
		t.Fatalf("legacy receipt changed or Kubernetes create ran: readErr=%v createCalls=%d", err, createCalls)
	}
}

func TestLocalCAPITemplateInventoryClassifiesEveryExpectedResource(t *testing.T) {
	runtime, state, expected, _ := localCAPITemplateObservationFixture(t)
	baseline := observeLocalCAPIDevelopmentTemplateResources(context.Background(), runtime, state, expected)
	if !localCAPITemplateInventoryComplete(baseline) {
		t.Fatalf("complete seven-object inventory was not verified: %+v", baseline)
	}
	for _, item := range baseline {
		if item.Status != localCAPITemplateVerified || item.UID == "" || !localCAPISHA256Pattern.MatchString(item.SpecSHA256) {
			t.Fatalf("verified template lacks identity evidence: %+v", item)
		}
	}

	firstKey := "cluster.x-k8s.io/v1beta2/ClusterClass/quick-start"
	cases := []struct {
		name       string
		behavior   func(*localCAPITemplateObservationBehavior)
		wantStatus string
		wantReason string
	}{
		{"missing resource", func(b *localCAPITemplateObservationBehavior) { b.missing = firstKey }, localCAPITemplateMissing, "NOT_FOUND"},
		{"unreadable resource", func(b *localCAPITemplateObservationBehavior) { b.readError = firstKey }, localCAPITemplateUnverifiable, "READ_FAILED"},
		{"owner mismatch", func(b *localCAPITemplateObservationBehavior) { b.ownerMismatch = firstKey }, localCAPITemplateMismatch, "OWNER_MISMATCH"},
		{"spec mismatch", func(b *localCAPITemplateObservationBehavior) { b.specMismatch = firstKey }, localCAPITemplateMismatch, "SPEC_MISMATCH"},
		{"missing UID", func(b *localCAPITemplateObservationBehavior) { b.uidMissing = firstKey }, localCAPITemplateMismatch, "UID_MISSING"},
		{"identity mismatch", func(b *localCAPITemplateObservationBehavior) { b.identityMismatch = firstKey }, localCAPITemplateMismatch, "IDENTITY_MISMATCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			behavior := &localCAPITemplateObservationBehavior{}
			tc.behavior(behavior)
			items := observeLocalCAPIDevelopmentTemplateResources(context.Background(), localCAPITemplateObservationRuntime(runtime, expected, behavior), state, expected)
			var got localCAPITemplateEvidence
			for _, item := range items {
				if item.APIVersion+"/"+item.Kind+"/"+item.Name == firstKey {
					got = item
				}
			}
			if got.Status != tc.wantStatus || got.ReasonCode != tc.wantReason || localCAPITemplateInventoryComplete(items) {
				t.Fatalf("inventory did not safely classify %s: %+v", tc.name, got)
			}
		})
	}
}

func TestLocalCAPITemplateReceiptRejectsChangedUID(t *testing.T) {
	runtime, state, expected, _ := localCAPITemplateObservationFixture(t)
	state.DevelopmentTemplatesAttempted = true
	state.DevelopmentTemplatesComplete = true
	manifest, err := renderLocalCAPIDevelopmentTemplateManifest(state.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	state.DevelopmentTemplatesSHA256 = localCAPIBytesSHA256(manifest)
	if err := os.WriteFile(filepath.Join(localCAPIStateDirectory(runtime.stateRoot, state.Name), "development-templates.yaml"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	state.DevelopmentTemplates = observeLocalCAPIDevelopmentTemplateResources(context.Background(), runtime, state, expected)
	if !localCAPITemplateInventoryComplete(state.DevelopmentTemplates) {
		t.Fatal("test receipt did not start with complete verified template identities")
	}
	behavior := &localCAPITemplateObservationBehavior{uidMismatch: "cluster.x-k8s.io/v1beta2/ClusterClass/quick-start"}
	if err := verifyLocalCAPITemplateReceipt(context.Background(), localCAPITemplateObservationRuntime(runtime, expected, behavior), state); err == nil {
		t.Fatal("changed live UID was accepted against the persisted management receipt")
	}
}

func TestLocalCAPITemplatePartialCreateIsDurableTerminalAndNotRetried(t *testing.T) {
	runtime := capiMockRuntimeWithTemplateOptions(t, capiMockTemplateOptions{
		templateCreateErr:   errors.New("mock partial kubectl create error"),
		templateCreateLimit: 2,
	})
	templateCreates, calls := 0, 0
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		calls++
		joined := strings.Join(args, " ")
		if command == "kubectl" && strings.Contains(joined, "create -f ") && strings.HasSuffix(args[len(args)-1], "development-templates.yaml") {
			templateCreates++
		}
		if command == "kubectl" && (strings.Contains(joined, " delete ") || strings.Contains(joined, " apply ") || strings.Contains(joined, " patch ")) {
			t.Fatalf("partial template failure triggered forbidden repair/cleanup: %q", joined)
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	args := []string{"up", "--bootstrap", "capi", "--colima-profile", "ok-capi"}
	if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil || strings.Contains(err.Error(), "mock partial") {
		t.Fatalf("partial template failure was not safely classified: %v", err)
	}
	state, err := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if err != nil || state.Phase != localCAPIPhaseIncomplete || state.FailureCode != "CAPI_TEMPLATES_INSTALL_FAILED" || !state.DevelopmentTemplatesAttempted || state.DevelopmentTemplatesComplete || len(state.DevelopmentTemplates) != 7 {
		t.Fatalf("partial create evidence was not durably retained as terminal INCOMPLETE: state=%+v err=%v", state, err)
	}
	verified, missing := 0, 0
	for _, item := range state.DevelopmentTemplates {
		switch item.Status {
		case localCAPITemplateVerified:
			verified++
		case localCAPITemplateMissing:
			missing++
		default:
			t.Fatalf("unexpected partial-create status: %+v", item)
		}
	}
	if verified != 2 || missing != 5 || templateCreates != 1 {
		t.Fatalf("partial create inventory = verified %d, missing %d, creates %d", verified, missing, templateCreates)
	}
	priorCalls := calls
	if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil {
		t.Fatal("subsequent bootstrap adopted the incomplete template installation")
	}
	if calls != priorCalls || templateCreates != 1 {
		t.Fatalf("subsequent bootstrap performed external operations: calls %d->%d creates=%d", priorCalls, calls, templateCreates)
	}
}

func TestLocalCAPITemplateExistingResourceStopsBeforeCreate(t *testing.T) {
	key := "cluster.x-k8s.io/v1beta2/ClusterClass/quick-start"
	runtime := capiMockRuntimeWithTemplateOptions(t, capiMockTemplateOptions{
		templateCreateLimit: len(localCAPIWorkloadExpectedManifestObjects("")) - 1,
		existingTemplate:    key,
	})
	templateCreates := 0
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if command == "kubectl" && strings.Contains(joined, "create -f ") && strings.HasSuffix(args[len(args)-1], "development-templates.yaml") {
			templateCreates++
		}
		if command == "kubectl" && (strings.Contains(joined, " delete ") || strings.Contains(joined, " apply ") || strings.Contains(joined, " patch ")) {
			t.Fatalf("preexisting template triggered repair/cleanup: %q", joined)
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	if err := runLocalWithRuntime(context.Background(), []string{"up", "--bootstrap", "capi", "--colima-profile", "ok-capi"}, io.Discard, io.Discard, runtime); err == nil {
		t.Fatal("preexisting shared template was adopted")
	}
	state, err := readLocalCAPIState(runtime.stateRoot, "ok-local")
	if err != nil || state.Phase != localCAPIPhaseIncomplete || templateCreates != 0 {
		t.Fatalf("preexisting template did not stop before create: state=%+v err=%v creates=%d", state, err, templateCreates)
	}
}

func TestLocalCAPIDevClusterTemplateReadbackDefaultsAreExplicitAndStrict(t *testing.T) {
	runtime, state, expected, _ := localCAPITemplateObservationFixture(t)
	key := "infrastructure.cluster.x-k8s.io/v1beta2/DevClusterTemplate/quick-start-cluster"
	object, ok := expected[key]
	if !ok {
		t.Fatalf("expected CAPD DevClusterTemplate %q is missing", key)
	}
	spec := object["spec"].(map[string]any)
	templateSpec := spec["template"].(map[string]any)["spec"].(map[string]any)
	endpoint := templateSpec["controlPlaneEndpoint"].(map[string]any)
	if endpoint["port"] != 6443 {
		t.Fatalf("CAPD controlPlaneEndpoint default is not explicit: %#v", endpoint)
	}
	docker := templateSpec["backend"].(map[string]any)["docker"].(map[string]any)
	loadBalancer := docker["loadBalancer"].(map[string]any)
	if len(loadBalancer) != 0 {
		t.Fatalf("CAPD loadBalancer default is not the observed empty object: %#v", loadBalancer)
	}

	observed := observeLocalCAPIDevelopmentTemplateResources(context.Background(), runtime, state, expected)
	var got localCAPITemplateEvidence
	for _, item := range observed {
		if item.APIVersion+"/"+item.Kind+"/"+item.Name == key {
			got = item
		}
	}
	if got.Status != localCAPITemplateVerified {
		t.Fatalf("CAPD API-defaulted template did not verify: %+v", got)
	}

	// The explicit values are still part of the strict spec identity: a
	// different port or additional load-balancer configuration must fail.
	wrongObserved := map[string]map[string]any{}
	for id, value := range expected {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var clone map[string]any
		if err := json.Unmarshal(raw, &clone); err != nil {
			t.Fatal(err)
		}
		wrongObserved[id] = clone
	}
	wrongSpec := wrongObserved[key]["spec"].(map[string]any)
	wrongTemplateSpec := wrongSpec["template"].(map[string]any)["spec"].(map[string]any)
	wrongTemplateSpec["controlPlaneEndpoint"].(map[string]any)["port"] = float64(6444)
	wrongBehavior := &localCAPITemplateObservationBehavior{}
	wrongRuntime := localCAPITemplateObservationRuntime(runtime, wrongObserved, wrongBehavior)
	wrongInventory := observeLocalCAPIDevelopmentTemplateResources(context.Background(), wrongRuntime, state, expected)
	for _, item := range wrongInventory {
		if item.APIVersion+"/"+item.Kind+"/"+item.Name == key {
			if item.Status != localCAPITemplateMismatch || item.ReasonCode != "SPEC_MISMATCH" {
				t.Fatalf("unexpected CAPD spec change was accepted: %+v", item)
			}
			return
		}
	}
	t.Fatal("CAPD DevClusterTemplate was absent from mismatch inventory")
}

type localCAPITemplateObservationBehavior struct {
	missing, readError, ownerMismatch, specMismatch, uidMissing, identityMismatch, uidMismatch string
}

func localCAPITemplateObservationFixture(t *testing.T) (localRuntime, localCAPIState, map[string]map[string]any, *localCAPITemplateObservationBehavior) {
	t.Helper()
	runtime, state := localCAPIVerificationFixture(t)
	expected, err := localCAPITemplateExpectedObjects(state.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	behavior := &localCAPITemplateObservationBehavior{}
	return localCAPITemplateObservationRuntime(runtime, expected, behavior), state, expected, behavior
}

func localCAPITemplateObservationRuntime(runtime localRuntime, expected map[string]map[string]any, behavior *localCAPITemplateObservationBehavior) localRuntime {
	runtime.runCAPI = func(_ context.Context, _ localProviderIdentity, _ string, _ map[string]string, command string, args ...string) ([]byte, error) {
		if command != "kubectl" {
			return nil, errors.New("unexpected command")
		}
		resourceIndex := -1
		for i := range args {
			if args[i] == "get" && i+2 < len(args) {
				resourceIndex = i + 1
				break
			}
		}
		if resourceIndex < 0 {
			return nil, errors.New("unexpected inventory command")
		}
		var key string
		for _, identity := range localCAPIWorkloadExpectedManifestObjects("") {
			if identity.kind != "Cluster" && args[resourceIndex] == identity.resource && args[resourceIndex+1] == identity.name {
				key = identity.apiVersion + "/" + identity.kind + "/" + identity.name
			}
		}
		if key == "" {
			return nil, errors.New("unexpected resource")
		}
		switch key {
		case behavior.readError:
			return nil, errors.New("mock read failure")
		case behavior.missing:
			return nil, nil
		}
		object, ok := expected[key]
		if !ok {
			return nil, errors.New("missing expected fixture")
		}
		raw, _ := json.Marshal(object)
		var observed map[string]any
		if json.Unmarshal(raw, &observed) != nil {
			return nil, errors.New("cannot clone fixture")
		}
		metadata := observed["metadata"].(map[string]any)
		labels := metadata["labels"].(map[string]any)
		metadata["uid"] = "uid-" + metadata["name"].(string)
		if key == behavior.ownerMismatch {
			labels[localOwnerLabel] = "foreign-owner"
		}
		if key == behavior.specMismatch {
			spec := observed["spec"].(map[string]any)
			spec["unexpected"] = true
		}
		if key == behavior.uidMissing || key == behavior.uidMismatch {
			metadata["uid"] = ""
			if key == behavior.uidMismatch {
				metadata["uid"] = "replaced-uid"
			}
		}
		if key == behavior.identityMismatch {
			metadata["namespace"] = "foreign-namespace"
		}
		return json.Marshal(observed)
	}
	return runtime
}

func hasExactLocalCAPIWorkloadFlag(args []string, flagName, expected string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flagName && args[i+1] == expected {
			return true
		}
	}
	return false
}

func TestLocalCAPIWorkloadPartialCreateRemainsIncompleteAndCannotRetry(t *testing.T) {
	runtime, management := localCAPIVerificationFixture(t)
	runtime = localCAPIWorkloadTestRuntimeWithCalico(runtime)
	management.Phase = localCAPIPhaseIncomplete
	management.FailureStage, management.FailureCode = "capi-verify", "CAPI_VERIFY_FAILED"
	raw, _ := json.MarshalIndent(management, "", "  ")
	if err := os.WriteFile(localCAPIStateFilePath(runtime.stateRoot, management.Name), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.newOwnerID = func() (string, error) { return "fedcba9876543210fedcba9876543210", nil }
	createCalls := 0
	base := runtime.runCAPI
	runtime.runCAPI = func(ctx context.Context, provider localProviderIdentity, kubeconfig string, env map[string]string, command string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if command == "clusterctl" && strings.HasPrefix(joined, "generate cluster ok-worker-01 ") {
			return []byte(localCAPIDevelopmentManifestFixture), nil
		}
		if command == "kubectl" && strings.Contains(joined, "get clusters.cluster.x-k8s.io -A -o json") {
			return []byte(`{"apiVersion":"v1","kind":"List","items":[]}`), nil
		}
		if command == "kubectl" && strings.Contains(joined, "create --dry-run=server -f") {
			return nil, nil
		}
		if command == "kubectl" && strings.Contains(joined, "create -f") {
			createCalls++
			return nil, errors.New("secret raw provider error")
		}
		return base(ctx, provider, kubeconfig, env, command, args...)
	}
	args := []string{"cluster", "create", "--name", "ok-worker-01", "--management", management.Name}
	if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("partial failure was not safely classified: %v", err)
	}
	state, err := readLocalCAPIWorkloadState(runtime.stateRoot, "ok-worker-01")
	if err != nil || state.Phase != "INCOMPLETE" || state.FailureCode != "WORKLOAD_CREATE_FAILED" || createCalls != 1 {
		t.Fatalf("partial create was not durably stopped: state=%+v err=%v createCalls=%d", state, err, createCalls)
	}
	if err := runLocalWithRuntime(context.Background(), args, io.Discard, io.Discard, runtime); err == nil || createCalls != 1 {
		t.Fatalf("partial operation was retried: err=%v createCalls=%d", err, createCalls)
	}
}

func validLocalCAPIWorkloadTestState(root string) localCAPIWorkloadState {
	owner := "0123456789abcdef0123456789abcdef"
	management := validLocalCAPIState(root)
	return localCAPIWorkloadState{Format: localCAPIWorkloadStateFormat, Phase: "APPLYING", Name: "ok-worker-01", Namespace: "default",
		ManagementName: management.Name, ManagementOwnerID: owner, ManagementKindName: management.BootstrapKindName,
		ManagementNodeUID: "node-uid", ManagementKubeSystemID: "kube-system-uid", ColimaProfile: "ok-capi",
		WorkloadOwnerID: "fedcba9876543210fedcba9876543210", Provider: management.Provider, ManifestSHA256: strings.Repeat("c", 64),
		ControlPlaneReplicas: 1, WorkerReplicas: 1}
}

func localCAPIWorkloadClusterFixture(owner string, ready bool) []byte {
	conditions := []localCAPIWorkloadCondition{
		{Type: "Available", Status: "False"},
		{Type: "ControlPlaneAvailable", Status: "False"},
		{Type: "WorkersAvailable", Status: "False"},
	}
	if ready {
		conditions[0].Status, conditions[1].Status, conditions[2].Status = "True", "True", "True"
	}
	return localCAPIWorkloadClusterFixtureWithConditions(owner, conditions)
}

func localCAPIWorkloadClusterFixtureWithConditions(owner string, conditions []localCAPIWorkloadCondition) []byte {
	encodedConditions, err := json.Marshal(conditions)
	if err != nil {
		panic(err)
	}
	return []byte(`{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Cluster","metadata":{"name":"ok-worker-01","namespace":"default","uid":"workload-cluster-uid","labels":{"` + localOwnerLabel + `":"` + owner + `"}},"spec":{"clusterNetwork":{"pods":{"cidrBlocks":["192.168.0.0/16"]},"services":{"cidrBlocks":["10.128.0.0/12"]}},"topology":{"classRef":{"name":"quick-start"},"version":"v1.35.8","controlPlane":{"replicas":1},"workers":{"machineDeployments":[{"class":"default-worker","name":"md-0","replicas":1}]}}},"status":{"conditions":` + string(encodedConditions) + `}}`)
}

func localCAPIWorkloadMachinesFixture() []byte {
	return []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Machine","metadata":{"name":"ok-worker-01-control-plane","namespace":"default","uid":"machine-cp","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01","cluster.x-k8s.io/control-plane":""}},"status":{"nodeRef":{"name":"ok-worker-01-control-plane"},"conditions":[{"type":"Ready","status":"True"}]}},{"apiVersion":"cluster.x-k8s.io/v1beta2","kind":"Machine","metadata":{"name":"ok-worker-01-worker","namespace":"default","uid":"machine-worker","labels":{"cluster.x-k8s.io/cluster-name":"ok-worker-01"}},"status":{"nodeRef":{"name":"ok-worker-01-worker"},"conditions":[{"type":"Ready","status":"True"}]}}]}`)
}

// yamlNewDecoder keeps YAML decoder use local to this test's multi-document input.
func yamlNewDecoder(reader io.Reader) *yaml.Decoder { return yaml.NewDecoder(reader) }
