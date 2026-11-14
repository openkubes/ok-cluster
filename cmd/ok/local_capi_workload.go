package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"gopkg.in/yaml.v3"
)

const (
	localCAPIWorkloadStateFormat        = "ok-cli-capi-workload/v1"
	localCAPIWorkloadNamespace          = "default"
	localCAPIWorkloadAPIVersion         = "cluster.x-k8s.io/v1beta2"
	localCAPIWorkloadPodCIDR            = "192.168.0.0/16"
	localCAPIWorkloadServiceCIDR        = "10.128.0.0/12"
	localCAPIWorkloadClassName          = "quick-start"
	localCAPIWorkloadWorkerClass        = "default-worker"
	localCAPIWorkloadWorkerName         = "md-0"
	localCAPIWorkloadCalicoURL          = "https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml"
	localCAPIWorkloadCalicoSourceSHA256 = "2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5"
	localCAPITemplateVerified           = "VERIFIED"
	localCAPITemplateMissing            = "MISSING"
	localCAPITemplateMismatch           = "MISMATCH"
	localCAPITemplateUnverifiable       = "UNVERIFIABLE"
)

// This fixture is the complete eight-document stdout from clusterctl v1.14.4
// `generate cluster --flavor development`. The first seven documents are
// management-owned templates; workload creation projects only its Cluster.
//
//go:embed testdata/capd-v1.14.4-development.yaml
var localCAPIDevelopmentManifestFixture string

var localCAPIWorkloadFailureCodes = map[string]bool{
	"MANIFEST_PERSIST_FAILED": true, "MANAGEMENT_IDENTITY_CHANGED": true,
	"WORKLOAD_NAME_NOT_AVAILABLE": true, "SERVER_DRY_RUN_REJECTED": true,
	"WORKLOAD_CREATE_FAILED": true, "WORKLOAD_IDENTITY_UNVERIFIED": true,
	"POD_CIDR_MISMATCH": true, "KIND_IDENTITY_UNVERIFIED": true,
	"WORKLOAD_KUBECONFIG_FAILED": true, "CNI_ALREADY_PRESENT": true,
	"CALICO_SOURCE_UNVERIFIED": true, "CALICO_MANIFEST_FAILED": true,
	"CALICO_CREATE_FAILED": true, "WORKLOAD_READINESS_UNVERIFIED": true,
	"CALICO_DRY_RUN_REJECTED":         true,
	"CALICO_CREATE_OUTCOME_UNCERTAIN": true,
}

var errLocalCAPIWorkloadAccessPending = errors.New("workload access is not ready yet")

type localCAPIWorkloadState struct {
	Format                   string                              `json:"format"`
	Phase                    string                              `json:"phase"`
	Name                     string                              `json:"name"`
	Namespace                string                              `json:"namespace"`
	ManagementName           string                              `json:"managementName"`
	ManagementOwnerID        string                              `json:"managementOwnerID"`
	ManagementKindName       string                              `json:"managementKindName"`
	ManagementNodeUID        string                              `json:"managementNodeUID"`
	ManagementKubeSystemID   string                              `json:"managementKubeSystemUID"`
	ColimaProfile            string                              `json:"colimaProfile"`
	WorkloadOwnerID          string                              `json:"workloadOwnerID"`
	Provider                 localProviderIdentity               `json:"provider"`
	ManifestSHA256           string                              `json:"manifestSHA256"`
	ControlPlaneReplicas     int                                 `json:"controlPlaneReplicas"`
	WorkerReplicas           int                                 `json:"workerReplicas"`
	ClusterUID               string                              `json:"clusterUID,omitempty"`
	PodCIDR                  string                              `json:"podCIDR,omitempty"`
	ServiceCIDR              string                              `json:"serviceCIDR,omitempty"`
	WorkloadKindName         string                              `json:"workloadKindName,omitempty"`
	WorkloadKubeconfig       string                              `json:"workloadKubeconfig,omitempty"`
	WorkloadKubeconfigSHA256 string                              `json:"workloadKubeconfigSHA256,omitempty"`
	WorkloadContainers       []localContainerIdentity            `json:"workloadContainers,omitempty"`
	WorkloadNodes            []localNodeIdentity                 `json:"workloadNodes,omitempty"`
	WorkerReplacement        *localCAPIWorkloadWorkerReplacement `json:"workerReplacement,omitempty"`
	CalicoSourceSHA256       string                              `json:"calicoSourceSHA256,omitempty"`
	CalicoManifestSHA256     string                              `json:"calicoManifestSHA256,omitempty"`
	CalicoCreateAttempted    bool                                `json:"calicoCreateAttempted,omitempty"`
	RecoveryFromFailureCode  string                              `json:"recoveryFromFailureCode,omitempty"`
	FailureCode              string                              `json:"failureCode,omitempty"`
}

type localCAPIWorkloadReport struct {
	Format                    string `json:"format"`
	Operation                 string `json:"operation"`
	Result                    string `json:"result"`
	Cluster                   string `json:"cluster"`
	Namespace                 string `json:"namespace"`
	Management                string `json:"management"`
	HistoricalOperationPhase  string `json:"historicalOperationPhase,omitempty"`
	HistoricalManagementPhase string `json:"historicalManagementPhase,omitempty"`
	ClusterUID                string `json:"clusterUID,omitempty"`
	ClusterReady              bool   `json:"clusterReady"`
	ControlPlaneReady         bool   `json:"controlPlaneReady"`
	WorkersReady              bool   `json:"workersReady"`
	MachineCount              int    `json:"machineCount"`
	ReadyMachineCount         int    `json:"readyMachineCount"`
	ReadyNodeCount            int    `json:"readyNodeCount"`
	CNIReady                  bool   `json:"cniReady"`
	ReasonCode                string `json:"reasonCode,omitempty"`
	ObservedAt                string `json:"observedAt"`
}

type localCAPIWorkloadManifestCluster struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		ClusterNetwork *struct {
			Pods struct {
				CIDRBlocks []string `yaml:"cidrBlocks"`
			} `yaml:"pods"`
			Services struct {
				CIDRBlocks []string `yaml:"cidrBlocks"`
			} `yaml:"services"`
		} `yaml:"clusterNetwork"`
		Topology *struct {
			Version  string `yaml:"version"`
			ClassRef struct {
				Name string `yaml:"name"`
			} `yaml:"classRef"`
			ControlPlane struct {
				Replicas *int `yaml:"replicas"`
			} `yaml:"controlPlane"`
			Workers struct {
				MachineDeployments []struct {
					Class    string `yaml:"class"`
					Name     string `yaml:"name"`
					Replicas *int   `yaml:"replicas"`
				} `yaml:"machineDeployments"`
			} `yaml:"workers"`
		} `yaml:"topology"`
	} `yaml:"spec"`
}

type localCAPIWorkloadClusterObservation struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		UID       string            `json:"uid"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		ClusterNetwork *struct {
			Pods struct {
				CIDRBlocks []string `json:"cidrBlocks"`
			} `json:"pods"`
			Services struct {
				CIDRBlocks []string `json:"cidrBlocks"`
			} `json:"services"`
		} `json:"clusterNetwork"`
		Topology *struct {
			Version  string `json:"version"`
			ClassRef struct {
				Name string `json:"name"`
			} `json:"classRef"`
			ControlPlane struct {
				Replicas *int32 `json:"replicas"`
			} `json:"controlPlane"`
			Workers struct {
				MachineDeployments []struct {
					Class    string `json:"class"`
					Name     string `json:"name"`
					Replicas *int32 `json:"replicas"`
				} `json:"machineDeployments"`
			} `json:"workers"`
		} `json:"topology"`
	} `json:"spec"`
	Status struct {
		Conditions []localCAPIWorkloadCondition `json:"conditions"`
	} `json:"status"`
}

type localCAPIWorkloadCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type localCAPIWorkloadMachineList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Items      []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			UID       string            `json:"uid"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			NodeRef *struct {
				Name string `json:"name"`
			} `json:"nodeRef"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

func localCAPIWorkloadRoot(root string) string {
	return filepath.Join(root, "capi", "workloads")
}

func rejectLocalCAPIWorkloadNameConflict(root, name string) error {
	for _, path := range []string{localCAPIWorkloadDirectory(root, name), localCAPIStateDirectory(root, name), localStateFilePath(root, name), localBootstrapDiagnosticPath(root, name)} {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("existing local or workload ownership material; refusing to overwrite, adopt, or retry it")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot safely inspect local or workload ownership material")
		}
	}
	return nil
}

func localCAPIWorkloadDirectory(root, name string) string {
	return filepath.Join(localCAPIWorkloadRoot(root), name)
}

func localCAPIWorkloadStatePath(root, name string) string {
	return filepath.Join(localCAPIWorkloadDirectory(root, name), "state.json")
}

func localCAPIWorkloadKubeconfigPath(root, name string) string {
	return filepath.Join(localCAPIWorkloadDirectory(root, name), "kubeconfig")
}

func waitLocalCAPIWorkloadInterval(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func localCAPIWorkloadCalicoPath(root, name string) string {
	return filepath.Join(localCAPIWorkloadDirectory(root, name), "calico-v3.33.0.yaml")
}

func localCAPIBytesSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fetchPinnedLocalCAPIWorkloadCalicoManifest(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, localCAPIWorkloadCalicoURL, nil)
	if err != nil {
		return nil, errors.New("cannot prepare pinned Calico manifest request")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if len(previous) > 0 && (request.URL.Scheme != "https" || request.URL.Host != previous[0].URL.Host || request.URL.Path != previous[0].URL.Path || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "") {
			return errors.New("pinned Calico source redirect is not allowed")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("pinned Calico source is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("pinned Calico source returned an unexpected response")
	}
	if response.Request == nil || response.Request.URL.Scheme != "https" || response.Request.URL.Host != "raw.githubusercontent.com" || response.Request.URL.Path != "/projectcalico/calico/v3.33.0/manifests/calico.yaml" {
		return nil, errors.New("pinned Calico source resolved to an unexpected location")
	}
	manifest, err := io.ReadAll(io.LimitReader(response.Body, 2<<20+1))
	if err != nil || len(manifest) == 0 || len(manifest) > 2<<20 {
		return nil, errors.New("pinned Calico source exceeds its size limit or is unreadable")
	}
	if localCAPIBytesSHA256(manifest) != localCAPIWorkloadCalicoSourceSHA256 {
		return nil, errors.New("pinned Calico source checksum mismatch")
	}
	return manifest, nil
}

func renderLocalCAPIWorkloadCalico(source []byte, expectedSHA256, podCIDR string) ([]byte, error) {
	if expectedSHA256 == "" || localCAPIBytesSHA256(source) != expectedSHA256 || podCIDR != localCAPIWorkloadPodCIDR {
		return nil, errors.New("Calico source or Pod CIDR is not approved")
	}
	const disabled = "            # - name: CALICO_IPV4POOL_CIDR\n            #   value: \"192.168.0.0/16\""
	const enabled = "            - name: CALICO_IPV4POOL_CIDR\n              value: \"192.168.0.0/16\""
	if bytes.Count(source, []byte(disabled)) != 1 || bytes.Contains(source, []byte(enabled)) {
		return nil, errors.New("pinned Calico manifest does not have the expected single default Pod CIDR setting")
	}
	manifest := bytes.Replace(source, []byte(disabled), []byte(enabled), 1)
	if err := validateLocalCAPIWorkloadCalicoManifest(manifest, podCIDR); err != nil {
		return nil, err
	}
	return manifest, nil
}

func validateLocalCAPIWorkloadCalicoManifest(raw []byte, podCIDR string) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	found := 0
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.New("Calico manifest YAML is malformed")
		}
		if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
			continue
		}
		root := document.Content[0]
		kind, _ := yamlMappingScalar(root, "kind")
		if kind != "DaemonSet" {
			continue
		}
		metadata, err := yamlMappingNode(root, "metadata")
		if err != nil {
			return err
		}
		name, _ := yamlMappingScalar(metadata, "name")
		namespace, _ := yamlMappingScalar(metadata, "namespace")
		if name != "calico-node" || namespace != "kube-system" {
			continue
		}
		found++
		spec, err := yamlMappingNode(root, "spec")
		if err != nil {
			return err
		}
		template, err := yamlMappingNode(spec, "template")
		if err != nil {
			return err
		}
		templateSpec, err := yamlMappingNode(template, "spec")
		if err != nil {
			return err
		}
		containers, err := yamlMappingValue(templateSpec, "containers")
		if err != nil || containers.Kind != yaml.SequenceNode {
			return errors.New("Calico node container list is malformed")
		}
		calicoNodeFound := false
		for _, container := range containers.Content {
			containerName, _ := yamlMappingScalar(container, "name")
			if containerName != "calico-node" {
				continue
			}
			calicoNodeFound = true
			env, err := yamlMappingValue(container, "env")
			if err != nil || env.Kind != yaml.SequenceNode {
				return errors.New("Calico node environment is malformed")
			}
			cidrCount := 0
			for _, variable := range env.Content {
				variableName, _ := yamlMappingScalar(variable, "name")
				if variableName == "CALICO_IPV4POOL_CIDR" {
					value, _ := yamlMappingScalar(variable, "value")
					if value != podCIDR {
						return errors.New("Calico manifest Pod CIDR differs from workload intent")
					}
					cidrCount++
				}
			}
			if cidrCount != 1 {
				return errors.New("Calico manifest must set exactly one IPv4 pool CIDR")
			}
		}
		if !calicoNodeFound {
			return errors.New("Calico node container is missing")
		}
	}
	if found != 1 {
		return errors.New("Calico manifest must contain exactly one kube-system calico-node DaemonSet")
	}
	return nil
}

func yamlMappingValue(node *yaml.Node, key string) (*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, errors.New("YAML object is not a mapping")
	}
	var found *yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			if found != nil {
				return nil, errors.New("YAML field is duplicated")
			}
			found = node.Content[i+1]
		}
	}
	if found == nil {
		return nil, errors.New("YAML field is missing")
	}
	return found, nil
}

type localCAPIWorkloadNodeList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Items      []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			Conditions []localCAPIWorkloadCondition `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

func captureLocalCAPIWorkloadAccess(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState) ([]localContainerIdentity, []byte, []localNodeIdentity, error) {
	clusters, err := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "clusters")
	if err != nil {
		return nil, nil, nil, errors.New("cannot enumerate workload Kind clusters")
	}
	clusterCount := countLocalCAPIWorkloadName(string(clusters), state.WorkloadKindName)
	if clusterCount < 0 || clusterCount > 1 {
		return nil, nil, nil, errors.New("workload Kind cluster inventory is ambiguous")
	}
	if clusterCount == 0 {
		return nil, nil, nil, fmt.Errorf("%w: owner-bound Kind cluster not created yet", errLocalCAPIWorkloadAccessPending)
	}
	containers, err := observeLocalCAPIWorkloadContainers(ctx, runtime, management.Provider, state.WorkloadKindName)
	if err != nil {
		return nil, nil, nil, errors.New("workload Kind container ownership is incomplete")
	}
	if !validLocalCAPIWorkloadContainerInventory(containers) {
		if validLocalCAPIWorkloadContainerSubset(containers) {
			return nil, nil, nil, fmt.Errorf("%w: CAPD nodes are still being created", errLocalCAPIWorkloadAccessPending)
		}
		return nil, nil, nil, errors.New("workload Kind container ownership is ambiguous")
	}
	kubeconfig, err := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "kubeconfig", "--name", state.WorkloadKindName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: Kind API credentials are not available yet", errLocalCAPIWorkloadAccessPending)
	}
	if compareKindKubeconfig(kubeconfig, kubeconfig, "kind-"+state.WorkloadKindName) != nil {
		return nil, nil, nil, errors.New("workload Kind kubeconfig identity is invalid")
	}
	path := localCAPIWorkloadKubeconfigPath(runtime.stateRoot, state.Name)
	if path != state.WorkloadKubeconfig || !filepath.IsAbs(path) {
		return nil, nil, nil, errors.New("workload kubeconfig path is not the expected private path")
	}
	if info, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		if err := writePrivateNewFile(path, kubeconfig); err != nil {
			return nil, nil, nil, errors.New("cannot persist private workload kubeconfig")
		}
	} else if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, nil, nil, errors.New("existing private workload kubeconfig is unsafe")
	} else {
		previous, readErr := os.ReadFile(path)
		if readErr != nil || compareKindKubeconfig(kubeconfig, previous, "kind-"+state.WorkloadKindName) != nil {
			return nil, nil, nil, errors.New("existing private workload kubeconfig does not match the live Kind identity")
		}
		kubeconfig = previous
	}
	nodesRaw, err := runLocalCAPIRaw(ctx, runtime, management.Provider, path, nil, "kubectl", "--kubeconfig", path, "--context", "kind-"+state.WorkloadKindName, "get", "nodes", "-o", "json")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: workload API is not reachable yet", errLocalCAPIWorkloadAccessPending)
	}
	nodes, err := parseLocalCAPIWorkloadNodes(nodesRaw)
	if err != nil {
		return nil, nil, nil, errors.New("workload Kubernetes Node inventory is malformed")
	}
	if len(nodes) < 2 {
		return nil, nil, nil, fmt.Errorf("%w: workload Kubernetes Nodes are still registering", errLocalCAPIWorkloadAccessPending)
	}
	if len(nodes) != 2 {
		return nil, nil, nil, errors.New("workload Kubernetes nodes do not match the owned Kind node inventory")
	}
	return containers, kubeconfig, nodes, nil
}

func countLocalCAPIWorkloadName(output, expected string) int {
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == expected {
			count++
		} else if line != "" && !localKindClusterNamePattern.MatchString(line) {
			return -1
		}
	}
	return count
}

func validLocalCAPIWorkloadContainers(containers []localContainerIdentity) bool {
	if len(containers) != 2 && len(containers) != 3 {
		return false
	}
	controlPlane, worker, loadBalancer := 0, 0, 0
	seen := map[string]bool{}
	seenNames := map[string]bool{}
	for _, container := range containers {
		if container.ID == "" || container.Name == "" || seen[container.ID] || seenNames[container.Name] {
			return false
		}
		seen[container.ID] = true
		seenNames[container.Name] = true
		if container.Role == "control-plane" {
			controlPlane++
		} else if container.Role == "worker" {
			worker++
		} else if container.Role == "external-load-balancer" {
			loadBalancer++
		} else {
			return false
		}
	}
	return controlPlane == 1 && worker == 1 && (len(containers) == 2 && loadBalancer == 0 || len(containers) == 3 && loadBalancer == 1)
}

func validLocalCAPIWorkloadContainerInventory(containers []localContainerIdentity) bool {
	return len(containers) == 3 && validLocalCAPIWorkloadContainers(containers)
}

// A subset is nonterminal only while CAPD is still creating its known node roles.
// Unknown roles and duplicate identities remain hard failures.
func validLocalCAPIWorkloadContainerSubset(containers []localContainerIdentity) bool {
	if len(containers) >= 3 {
		return false
	}
	seenIDs, seenNames, seenRoles := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, container := range containers {
		if container.ID == "" || container.Name == "" || seenIDs[container.ID] || seenNames[container.Name] || seenRoles[container.Role] {
			return false
		}
		if container.Role != "control-plane" && container.Role != "worker" && container.Role != "external-load-balancer" {
			return false
		}
		seenIDs[container.ID], seenNames[container.Name], seenRoles[container.Role] = true, true, true
	}
	return true
}

func observeLocalCAPIWorkloadContainers(ctx context.Context, runtime localRuntime, provider localProviderIdentity, kindName string) ([]localContainerIdentity, error) {
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
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || (parts[2] != "control-plane" && parts[2] != "worker" && parts[2] != "external-load-balancer") {
			return nil, errors.New("Docker returned malformed CAPD container identity")
		}
		result = append(result, localContainerIdentity{ID: parts[0], Name: parts[1], Role: parts[2]})
		if len(result) > 3 || (len(result) < 3 && !validLocalCAPIWorkloadContainerSubset(result)) || (len(result) == 3 && !validLocalCAPIWorkloadContainers(result)) {
			return nil, errors.New("Docker returned ambiguous CAPD container identities")
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func parseLocalCAPIWorkloadNodes(raw []byte) ([]localNodeIdentity, error) {
	var list localCAPIWorkloadNodeList
	if json.Unmarshal(raw, &list) != nil || !validLocalCAPIWorkloadListEnvelope(list.APIVersion, list.Kind, "NodeList") || list.Items == nil || len(list.Items) > 2 {
		return nil, errors.New("workload Node list is malformed")
	}
	seen := map[string]bool{}
	result := make([]localNodeIdentity, 0, len(list.Items))
	for _, item := range list.Items {
		if item.APIVersion != "v1" || item.Kind != "Node" || item.Metadata.Name == "" || item.Metadata.UID == "" || seen[item.Metadata.Name] {
			return nil, errors.New("workload Node identity is invalid")
		}
		seen[item.Metadata.Name] = true
		result = append(result, localNodeIdentity{Name: item.Metadata.Name, UID: item.Metadata.UID})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func verifyLocalCAPIWorkloadKindIdentity(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, expected []localContainerIdentity) error {
	clusters, err := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "clusters")
	if err != nil || countLocalCAPIWorkloadName(string(clusters), state.WorkloadKindName) != 1 {
		return errors.New("workload Kind identity changed")
	}
	observed, err := observeLocalCAPIWorkloadContainers(ctx, runtime, management.Provider, state.WorkloadKindName)
	if err != nil || !sameLocalContainers(expected, observed) {
		return errors.New("workload Kind container identity changed")
	}
	configInfo, err := os.Lstat(state.WorkloadKubeconfig)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Mode()&os.ModeSymlink != 0 || configInfo.Mode().Perm() != 0o600 {
		return errors.New("workload private kubeconfig identity is unavailable")
	}
	privateConfig, err := os.ReadFile(state.WorkloadKubeconfig)
	if err != nil || localCAPIBytesSHA256(privateConfig) != state.WorkloadKubeconfigSHA256 {
		return errors.New("workload private kubeconfig identity changed")
	}
	kindConfig, err := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "kubeconfig", "--name", state.WorkloadKindName)
	if err != nil || compareKindKubeconfig(kindConfig, privateConfig, "kind-"+state.WorkloadKindName) != nil {
		return errors.New("workload Kind kubeconfig identity changed")
	}
	return nil
}

// verifyLocalCAPIWorkloadCNIInstallTarget keeps the initial CNI mutation bound
// to the exact workload API, kubeconfig, control-plane node/container and load
// balancer. A CAPD worker may be replaced while CNI is absent, so worker
// container identity is proven once through the CAPI chain before entering
// this path, but is not required to remain unchanged across every pre-create
// check. Historical receipt identities are never rewritten here.
func verifyLocalCAPIWorkloadCNIInstallTarget(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, expected []localContainerIdentity) error {
	unattemptedRecovery := state.Phase == "INCOMPLETE" && state.FailureCode == "CNI_ALREADY_PRESENT" && state.RecoveryFromFailureCode == "" ||
		state.Phase == "WAITING_FOR_WORKLOAD_ACCESS" && state.FailureCode == "" && state.RecoveryFromFailureCode == "CNI_ALREADY_PRESENT"
	if state.CalicoCreateAttempted || !unattemptedRecovery {
		return errors.New("CNI install target is not in the unattempted recovery state")
	}
	expectedCP, expectedLB := roleContainer(expected, "control-plane"), roleContainer(expected, "external-load-balancer")
	if expectedCP == nil || expectedLB == nil {
		return errors.New("workload control-plane or load-balancer receipt identity is unavailable")
	}
	clusters, err := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "clusters")
	if err != nil || countLocalCAPIWorkloadName(string(clusters), state.WorkloadKindName) != 1 {
		return errors.New("workload Kind cluster identity changed")
	}
	observed, err := observeLocalCAPIWorkloadContainers(ctx, runtime, management.Provider, state.WorkloadKindName)
	if err != nil {
		return errors.New("workload Kind container inventory is ambiguous")
	}
	observedCP, observedLB := roleContainer(observed, "control-plane"), roleContainer(observed, "external-load-balancer")
	if observedCP == nil || observedLB == nil || *observedCP != *expectedCP || *observedLB != *expectedLB {
		return errors.New("workload Kind control-plane or load-balancer identity changed")
	}
	configInfo, err := os.Lstat(state.WorkloadKubeconfig)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Mode()&os.ModeSymlink != 0 || configInfo.Mode().Perm() != 0o600 {
		return errors.New("workload private kubeconfig identity is unavailable")
	}
	privateConfig, err := os.ReadFile(state.WorkloadKubeconfig)
	if err != nil || localCAPIBytesSHA256(privateConfig) != state.WorkloadKubeconfigSHA256 {
		return errors.New("workload private kubeconfig identity changed")
	}
	kindConfig, err := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "kubeconfig", "--name", state.WorkloadKindName)
	if err != nil || compareKindKubeconfig(kindConfig, privateConfig, "kind-"+state.WorkloadKindName) != nil {
		return errors.New("workload Kind kubeconfig identity changed")
	}
	nodeRaw, err := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, "get", "nodes", "-o", "json")
	if err != nil {
		return errors.New("workload API is not reachable through the private kubeconfig")
	}
	var nodeList localCAPIWorkloadReplacementNodeList
	if json.Unmarshal(nodeRaw, &nodeList) != nil || !validLocalCAPIWorkloadListEnvelope(nodeList.APIVersion, nodeList.Kind, "NodeList") || len(nodeList.Items) == 0 || len(nodeList.Items) > 1000 {
		return errors.New("workload API Node inventory is malformed")
	}
	cpNode, _ := recordedWorkerNodes(state)
	if cpNode == nil {
		return errors.New("historical control-plane Node identity is unavailable")
	}
	cpMatches := 0
	seenNames, seenUIDs := map[string]bool{}, map[string]bool{}
	for _, node := range nodeList.Items {
		if node.APIVersion != "v1" || node.Kind != "Node" || node.Metadata.Name == "" || node.Metadata.UID == "" || seenNames[node.Metadata.Name] || seenUIDs[node.Metadata.UID] {
			return errors.New("workload API Node inventory is ambiguous")
		}
		seenNames[node.Metadata.Name], seenUIDs[node.Metadata.UID] = true, true
		if node.Metadata.Name == cpNode.Name && node.Metadata.UID == cpNode.UID {
			if !replacementProviderMatches(node.Spec.ProviderID, *expectedCP) {
				return errors.New("workload control-plane Node provider identity changed")
			}
			cpMatches++
		}
	}
	if cpMatches != 1 {
		return errors.New("workload control-plane Node identity is not present in the target API")
	}
	return nil
}

func verifyLocalCAPIWorkloadCNIInstallIdentity(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, expected []localContainerIdentity) error {
	initialRecovery := !state.CalicoCreateAttempted && (state.FailureCode == "CNI_ALREADY_PRESENT" || state.RecoveryFromFailureCode == "CNI_ALREADY_PRESENT")
	if initialRecovery {
		return verifyLocalCAPIWorkloadCNIInstallTarget(ctx, runtime, management, state, expected)
	}
	return verifyLocalCAPIWorkloadKindIdentity(ctx, runtime, management, state, expected)
}

func localCAPIWorkloadNodeNameRecorded(nodes []localNodeIdentity, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}

func localCAPIWorkloadClusterNetworkMatches(cluster localCAPIWorkloadClusterObservation, podCIDR, serviceCIDR string) bool {
	return cluster.Spec.ClusterNetwork != nil && len(cluster.Spec.ClusterNetwork.Pods.CIDRBlocks) == 1 && cluster.Spec.ClusterNetwork.Pods.CIDRBlocks[0] == podCIDR &&
		len(cluster.Spec.ClusterNetwork.Services.CIDRBlocks) == 1 && cluster.Spec.ClusterNetwork.Services.CIDRBlocks[0] == serviceCIDR
}

func runLocalCAPIWorkloadKubeconfig(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, args ...string) ([]byte, error) {
	if state.WorkloadKubeconfig == "" || !filepath.IsAbs(state.WorkloadKubeconfig) || state.WorkloadKubeconfig != localCAPIWorkloadKubeconfigPath(runtime.stateRoot, state.Name) {
		return nil, errors.New("private workload kubeconfig identity is unavailable")
	}
	return runLocalCAPIRaw(ctx, runtime, management.Provider, state.WorkloadKubeconfig, nil, "kubectl", append([]string{"--kubeconfig", state.WorkloadKubeconfig, "--context", "kind-" + state.WorkloadKindName}, args...)...)
}

func verifyLocalCAPIWorkloadCNIAbsent(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState) error {
	for _, query := range [][]string{{"get", "daemonsets", "-A", "-o", "json"}, {"get", "crds", "-o", "json"}, {"get", "pods", "-A", "-o", "json"}} {
		raw, err := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, query...)
		if err != nil || localCAPIWorkloadHasCNIResources(query[1], raw) {
			return errors.New("workload has an existing or unverifiable CNI installation")
		}
	}
	return nil
}

func localCAPIWorkloadHasCNIResources(resource string, raw []byte) bool {
	var list struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Items      []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Name  string `json:"name"`
							Image string `json:"image"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
			Status struct {
				Conditions []localCAPIWorkloadCondition `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil || list.Items == nil || list.APIVersion != "v1" || list.Kind != "List" {
		return true
	}
	for _, item := range list.Items {
		if resource == "daemonsets" && !(item.Metadata.Namespace == "kube-system" && item.Metadata.Name == "kube-proxy") {
			return true
		}
		if resource == "crds" {
			return true
		}
		if resource == "pods" {
			_ = item
		}
	}
	if resource == "pods" {
		text := strings.ToLower(string(raw))
		for _, marker := range []string{"calico", "cilium", "flannel", "weave", "antrea", "canal", "kube-router"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func runLocalCAPIWorkloadCommand(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	if len(arguments) == 0 || isHelpArgument(arguments[0]) {
		writeLocalCommandHelp("cluster", stdout)
		return nil
	}
	switch arguments[0] {
	case "create":
		return runLocalCAPIWorkloadCreate(ctx, arguments[1:], runtime, stdout, stderr)
	case "status":
		return runLocalCAPIWorkloadStatus(ctx, arguments[1:], runtime, stdout, stderr)
	case "continue":
		return runLocalCAPIWorkloadContinue(ctx, arguments[1:], runtime, stdout, stderr)
	default:
		return errors.New("use ok local cluster create, continue, or status; see ok local cluster --help")
	}
}

func runLocalCAPIWorkloadCreate(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	flags := flag.NewFlagSet("ok local cluster create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "New CAPI workload cluster name")
	management := flags.String("management", "", "Existing verified CAPI management receipt name")
	controlPlane := flags.Int("control-plane", 1, "Control-plane replicas (MVP supports 1)")
	workers := flags.Int("workers", 1, "Worker replicas (MVP supports 1)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) || !localClusterNamePattern.MatchString(*management) || *name == *management || *controlPlane != 1 || *workers != 1 {
		return errors.New("usage: ok local cluster create --name <cluster> --management <capi-name> --control-plane 1 --workers 1")
	}
	if runtime.run == nil || runtime.runPinned == nil || runtime.runCAPI == nil || runtime.stateRoot == "" {
		return errors.New("verified CAPI command runners and private state are required")
	}
	if runtime.fetchCalicoManifest == nil || runtime.calicoManifestSHA256 == "" {
		return errors.New("pinned Calico source verification is unavailable")
	}
	if err := verifyLocalCAPIStateRoot(runtime.stateRoot); err != nil {
		return errors.New("private local state root is unavailable or unsafe")
	}
	releaseOperation, err := acquireLocalLifecycleOperationLock(runtime.stateRoot, *name)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseOperation(); err != nil {
			result = errors.Join(result, errors.New("local lifecycle operation lock could not be safely released; inspect it before another operation"))
		}
	}()
	managementState, _, err := verifyLocalCAPIWorkloadManagement(ctx, runtime, *management)
	if err != nil {
		return err
	}
	if err := rejectLocalCAPIWorkloadNameConflict(runtime.stateRoot, *name); err != nil {
		return err
	}
	if err := ensureLocalCAPIWorkloadParent(runtime.stateRoot); err != nil {
		return errors.New("private CAPI workload state directory is unavailable")
	}
	version, err := runtime.run(ctx, "clusterctl", "version")
	if err != nil {
		return errors.New("cannot verify the installed clusterctl version")
	}
	if !validateLocalCAPIClusterctlVersion(version) {
		return errors.New("clusterctl v1.14.4 is required for the pinned CAPI templates")
	}
	args := buildLocalCAPIWorkloadGenerateArgs(managementState, *name)
	generated, err := runLocalCAPIRaw(ctx, runtime, managementState.Provider, managementState.BootstrapKubeconfig, nil, "clusterctl", args...)
	if err != nil {
		return errors.New("clusterctl could not generate the pinned CAPD development manifest")
	}
	newOwner := runtime.newOwnerID
	if newOwner == nil {
		newOwner = newLocalOwnerID
	}
	ownerID, err := newOwner()
	if err != nil {
		return errors.New("could not generate workload ownership identifier")
	}
	manifest, err := bindLocalCAPIWorkloadManifest(generated, *name, ownerID, 1, 1)
	if err != nil {
		return fmt.Errorf("generated CAPD manifest contract failed: %w", err)
	}
	calicoSource, err := runtime.fetchCalicoManifest(ctx)
	if err != nil {
		return errors.New("pinned Calico v3.33.0 source could not be verified")
	}
	calicoManifest, err := renderLocalCAPIWorkloadCalico(calicoSource, runtime.calicoManifestSHA256, localCAPIWorkloadPodCIDR)
	if err != nil {
		return errors.New("pinned Calico manifest does not match the approved source and Pod CIDR")
	}
	manifestHash := sha256.Sum256(manifest)
	state := localCAPIWorkloadState{
		Format: localCAPIWorkloadStateFormat, Phase: "APPLYING", Name: *name, Namespace: localCAPIWorkloadNamespace,
		ManagementName: managementState.Name, ManagementOwnerID: managementState.OwnerID,
		ManagementKindName: managementState.BootstrapKindName, ManagementNodeUID: managementState.Node.UID,
		ManagementKubeSystemID: managementState.KubeSystemUID, ColimaProfile: localCAPIStateProfile(managementState), WorkloadOwnerID: ownerID, Provider: managementState.Provider,
		ManifestSHA256: hex.EncodeToString(manifestHash[:]), ControlPlaneReplicas: 1, WorkerReplicas: 1,
		PodCIDR: localCAPIWorkloadPodCIDR, ServiceCIDR: localCAPIWorkloadServiceCIDR,
		WorkloadKindName: *name, WorkloadKubeconfig: localCAPIWorkloadKubeconfigPath(runtime.stateRoot, *name),
		CalicoSourceSHA256: runtime.calicoManifestSHA256, CalicoManifestSHA256: localCAPIBytesSHA256(calicoManifest),
	}
	if err := writeNewLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return errors.New("could not reserve this workload name durably; no Kubernetes objects were submitted")
	}
	fail := func(code string) error {
		state.Phase, state.FailureCode = "INCOMPLETE", code
		if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
			return errors.New("workload operation stopped; durable INCOMPLETE update failed and original one-shot intent remains")
		}
		return fmt.Errorf("workload creation stopped [%s]; one-shot intent retained; no automatic retry or cleanup", code)
	}
	manifestPath := filepath.Join(localCAPIWorkloadDirectory(runtime.stateRoot, *name), "manifest.yaml")
	if err := writePrivateNewFile(manifestPath, manifest); err != nil {
		return fail("MANIFEST_PERSIST_FAILED")
	}
	if err := writePrivateNewFile(localCAPIWorkloadCalicoPath(runtime.stateRoot, *name), calicoManifest); err != nil {
		return fail("CALICO_MANIFEST_FAILED")
	}
	if err := syncLocalCAPIDirectory(localCAPIWorkloadDirectory(runtime.stateRoot, *name)); err != nil {
		return fail("CALICO_MANIFEST_FAILED")
	}
	if err := verifyLocalCAPIWorkloadManagementStillBound(ctx, runtime, managementState, *management); err != nil {
		return fail("MANAGEMENT_IDENTITY_CHANGED")
	}
	if err := verifyLocalCAPIWorkloadNameAbsent(ctx, runtime, managementState, *name); err != nil {
		return fail("WORKLOAD_NAME_NOT_AVAILABLE")
	}
	// Server-side dry-run validates the complete generated object set without
	// persisting it. The final create is create-only, so existing objects are
	// never silently adopted or updated.
	if _, err := runLocalCAPIRaw(ctx, runtime, managementState.Provider, managementState.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", managementState.BootstrapKubeconfig, "--context", "kind-"+managementState.BootstrapKindName,
		"create", "--dry-run=server", "-f", manifestPath); err != nil {
		return fail("SERVER_DRY_RUN_REJECTED")
	}
	if err := verifyLocalCAPIWorkloadManagementStillBound(ctx, runtime, managementState, *management); err != nil {
		return fail("MANAGEMENT_IDENTITY_CHANGED")
	}
	if err := verifyLocalCAPIWorkloadNameAbsent(ctx, runtime, managementState, *name); err != nil {
		return fail("WORKLOAD_NAME_NOT_AVAILABLE")
	}
	if _, err := runLocalCAPIRaw(ctx, runtime, managementState.Provider, managementState.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", managementState.BootstrapKubeconfig, "--context", "kind-"+managementState.BootstrapKindName,
		"create", "-f", manifestPath); err != nil {
		return fail("WORKLOAD_CREATE_FAILED")
	}
	cluster, err := readLocalCAPIWorkloadCluster(ctx, runtime, managementState, *name)
	if err != nil || cluster.Metadata.UID == "" || cluster.Metadata.Labels[localOwnerLabel] != ownerID {
		return fail("WORKLOAD_IDENTITY_UNVERIFIED")
	}
	if !localCAPIWorkloadClusterNetworkMatches(cluster, state.PodCIDR, state.ServiceCIDR) {
		return fail("POD_CIDR_MISMATCH")
	}
	state.ClusterUID = cluster.Metadata.UID
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return errors.New("verified workload Cluster UID could not be durably recorded; preserve the one-shot intent and do not retry")
	}
	state.Phase = "WAITING_FOR_WORKLOAD_ACCESS"
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return errors.New("verified workload ownership could not be durably advanced to its access-wait phase; do not retry")
	}
	var workloadContainers []localContainerIdentity
	var workloadKubeconfig []byte
	var workloadNodes []localNodeIdentity
	for {
		workloadContainers, workloadKubeconfig, workloadNodes, err = captureLocalCAPIWorkloadAccess(ctx, runtime, managementState, state)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return writeLocalCAPIWorkloadWaitingReport(stdout, "CREATE", state, managementState)
		}
		if !errors.Is(err, errLocalCAPIWorkloadAccessPending) {
			return errors.Join(fail("WORKLOAD_KUBECONFIG_FAILED"), err)
		}
		wait := runtime.wait
		if wait == nil {
			wait = waitLocalCAPIWorkloadInterval
		}
		if waitErr := wait(ctx, 5*time.Second); waitErr != nil {
			return writeLocalCAPIWorkloadWaitingReport(stdout, "CREATE", state, managementState)
		}
	}
	state.WorkloadContainers = workloadContainers
	state.WorkloadKubeconfigSHA256 = localCAPIBytesSHA256(workloadKubeconfig)
	state.WorkloadNodes = workloadNodes
	state.ClusterUID = cluster.Metadata.UID
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return errors.New("workload Kubernetes identities could not be durably recorded before CNI inspection; do not retry")
	}
	status, err := installLocalCAPIWorkloadCalico(ctx, runtime, managementState, state)
	if err != nil {
		return err
	}
	if persisted, readErr := readLocalCAPIWorkloadState(runtime.stateRoot, state.Name); readErr == nil {
		state = persisted
	} else {
		return errors.New("completed workload receipt could not be re-read after Calico installation")
	}
	status.Operation, status.HistoricalOperationPhase, status.HistoricalManagementPhase = "CREATE", state.Phase, string(managementState.Phase)
	return writeLocalCAPIWorkloadReport(stdout, status)
}

func runLocalCAPIWorkloadContinue(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	flags := flag.NewFlagSet("ok local cluster continue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "Existing workload cluster name")
	management := flags.String("management", "", "Existing verified CAPI management receipt name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) || !localClusterNamePattern.MatchString(*management) {
		return errors.New("usage: ok local cluster continue --name <workload> --management <management>")
	}
	if runtime.run == nil || runtime.runPinned == nil || runtime.runCAPI == nil || runtime.stateRoot == "" {
		return errors.New("verified CAPI command runners and private state are required")
	}
	releaseOperation, err := acquireLocalLifecycleOperationLock(runtime.stateRoot, *name)
	if err != nil {
		return err
	}
	defer func() { _ = releaseOperation() }()
	state, err := readLocalCAPIWorkloadState(runtime.stateRoot, *name)
	recoveringCNIInventory := err == nil && localCAPIWorkloadCNIRecoveryCandidate(state)
	waitingForAccess := err == nil && state.Phase == "WAITING_FOR_WORKLOAD_ACCESS" && state.FailureCode == "" && !state.CalicoCreateAttempted && state.ClusterUID != ""
	if err != nil || state.ManagementName != *management || (!waitingForAccess && !recoveringCNIInventory) {
		return errors.New("continuation requires a valid waiting receipt with no Calico create attempt")
	}
	managementState, _, err := verifyLocalCAPIWorkloadManagement(ctx, runtime, *management)
	if err != nil || !sameLocalCAPIWorkloadManagement(state, managementState) {
		return errors.New("management identity is not currently verified for continuation")
	}
	cluster, err := readLocalCAPIWorkloadCluster(ctx, runtime, managementState, state.Name)
	if err != nil {
		if recoveringCNIInventory {
			return errors.New("CNI recovery stopped because the existing Cluster identity is not currently verifiable; INCOMPLETE receipt preserved")
		}
		return writeLocalCAPIWorkloadReport(stdout, localCAPIWorkloadReport{
			Format: localCAPIWorkloadStateFormat, Operation: "CONTINUE", Result: "PROVISIONING", Cluster: state.Name,
			Namespace: state.Namespace, Management: state.ManagementName, HistoricalOperationPhase: state.Phase,
			ClusterUID: state.ClusterUID, ReasonCode: "WORKLOAD_IDENTITY_RECHECK_PENDING", ObservedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	if !localCAPIWorkloadClusterIdentityMatches(state, cluster) {
		if recoveringCNIInventory {
			return errors.New("CNI recovery stopped because the existing Cluster identity differs; INCOMPLETE receipt preserved")
		}
		return markLocalCAPIWorkloadIncomplete(runtime.stateRoot, state, "WORKLOAD_IDENTITY_UNVERIFIED")
	}
	containers, kubeconfig, nodes, err := captureLocalCAPIWorkloadAccess(ctx, runtime, managementState, state)
	if ctx.Err() != nil {
		if recoveringCNIInventory {
			return errors.New("CNI recovery stopped because workload access remains unavailable; INCOMPLETE receipt preserved")
		}
		return writeLocalCAPIWorkloadWaitingReport(stdout, "CONTINUE", state, managementState)
	}
	if errors.Is(err, errLocalCAPIWorkloadAccessPending) {
		if recoveringCNIInventory {
			return errors.New("CNI recovery stopped because workload access remains pending; INCOMPLETE receipt preserved")
		}
		return writeLocalCAPIWorkloadWaitingReport(stdout, "CONTINUE", state, managementState)
	}
	if err != nil {
		if recoveringCNIInventory {
			return errors.New("CNI recovery stopped because workload access could not be reverified; INCOMPLETE receipt preserved")
		}
		return markLocalCAPIWorkloadIncomplete(runtime.stateRoot, state, "WORKLOAD_KUBECONFIG_FAILED")
	}
	state.WorkloadKubeconfigSHA256 = localCAPIBytesSHA256(kubeconfig)
	if recoveringCNIInventory {
		if !sameLocalContainers(state.WorkloadContainers, containers) || !sameLocalNodeIdentities(state.WorkloadNodes, nodes) {
			replacement, verifyErr := verifyCAPDWorkerReplacement(ctx, runtime, managementState, state, containers, nodes)
			if verifyErr != nil {
				return fmt.Errorf("CNI recovery stopped because the changed worker identity is not proven by the live CAPI ownership chain: %w; INCOMPLETE receipt preserved", verifyErr)
			}
			state.WorkerReplacement = &replacement
		}
		if err := verifyLocalCAPIWorkloadCNIAbsent(ctx, runtime, managementState, state); err != nil {
			return errors.New("CNI recovery stopped because an existing or unverifiable CNI remains; INCOMPLETE receipt preserved")
		}
		if err := verifyLocalCAPIWorkloadCNIInstallIdentity(ctx, runtime, managementState, state, containers); err != nil {
			return errors.New("CNI recovery stopped because the workload Kind identity differs; INCOMPLETE receipt preserved")
		}
		if err := verifyLocalCAPIWorkloadManagementStillBound(ctx, runtime, managementState, *management); err != nil {
			return errors.New("CNI recovery stopped because management identity changed; INCOMPLETE receipt preserved")
		}
		cluster, err = readLocalCAPIWorkloadCluster(ctx, runtime, managementState, state.Name)
		if err != nil || !localCAPIWorkloadClusterIdentityMatches(state, cluster) {
			return errors.New("CNI recovery stopped because workload Cluster identity changed; INCOMPLETE receipt preserved")
		}
		state.RecoveryFromFailureCode = state.FailureCode
		state.FailureCode = ""
		state.Phase = "WAITING_FOR_WORKLOAD_ACCESS"
	} else {
		state.WorkloadContainers = containers
		state.WorkloadNodes = nodes
	}
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return errors.New("verified workload access evidence or explicit recovery transition could not be durably recorded; no Calico mutation was attempted")
	}
	effectiveContainers, effectiveNodes := localCAPIWorkloadEffectiveIdentity(state)
	if !sameLocalNodeIdentities(effectiveNodes, nodes) {
		return errors.New("CNI recovery stopped because effective workload Node evidence is inconsistent; INCOMPLETE receipt preserved")
	}
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(ctx, runtime, managementState, state, effectiveContainers); err != nil {
		return markLocalCAPIWorkloadIncomplete(runtime.stateRoot, state, "KIND_IDENTITY_UNVERIFIED")
	}
	status, err := installLocalCAPIWorkloadCalico(ctx, runtime, managementState, state)
	if err != nil {
		return err
	}
	if persisted, readErr := readLocalCAPIWorkloadState(runtime.stateRoot, state.Name); readErr == nil {
		state = persisted
	} else {
		return errors.New("completed workload receipt could not be re-read after Calico installation")
	}
	status.Operation, status.HistoricalOperationPhase, status.HistoricalManagementPhase = "CONTINUE", state.Phase, string(managementState.Phase)
	return writeLocalCAPIWorkloadReport(stdout, status)
}

func installLocalCAPIWorkloadCalico(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState) (localCAPIWorkloadReport, error) {
	fail := func(code string) (localCAPIWorkloadReport, error) {
		return localCAPIWorkloadReport{}, markLocalCAPIWorkloadIncomplete(runtime.stateRoot, state, code)
	}
	pending := func(reason string) (localCAPIWorkloadReport, error) {
		return localCAPIWorkloadReport{
			Format: localCAPIWorkloadStateFormat, Result: "PROVISIONING", Cluster: state.Name,
			Namespace: state.Namespace, Management: state.ManagementName, HistoricalOperationPhase: state.Phase,
			ClusterUID: state.ClusterUID, ReasonCode: reason, ObservedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	containers, nodes := localCAPIWorkloadEffectiveIdentity(state)
	if state.Phase != "WAITING_FOR_WORKLOAD_ACCESS" || state.CalicoCreateAttempted || !validLocalCAPIWorkloadContainers(containers) || !validLocalCAPIWorkloadNodeIdentities(nodes) || state.WorkloadKubeconfigSHA256 == "" {
		return fail("WORKLOAD_READINESS_UNVERIFIED")
	}
	calicoPath := localCAPIWorkloadCalicoPath(runtime.stateRoot, state.Name)
	calicoInfo, statErr := os.Lstat(calicoPath)
	calicoManifest, readErr := os.ReadFile(calicoPath)
	if runtime.calicoManifestSHA256 == "" || state.CalicoSourceSHA256 != runtime.calicoManifestSHA256 || statErr != nil || !calicoInfo.Mode().IsRegular() || calicoInfo.Mode()&os.ModeSymlink != 0 || calicoInfo.Mode().Perm() != 0o600 || readErr != nil || localCAPIBytesSHA256(calicoManifest) != state.CalicoManifestSHA256 || validateLocalCAPIWorkloadCalicoManifest(calicoManifest, state.PodCIDR) != nil {
		return fail("CALICO_MANIFEST_FAILED")
	}
	if err := verifyLocalCAPIWorkloadCNIAbsent(ctx, runtime, management, state); err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return fail("CNI_ALREADY_PRESENT")
	}
	if err := verifyLocalCAPIWorkloadManagementStillBound(ctx, runtime, management, state.ManagementName); err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return fail("MANAGEMENT_IDENTITY_CHANGED")
	}
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(ctx, runtime, management, state, containers); err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return fail("KIND_IDENTITY_UNVERIFIED")
	}
	cluster, err := readLocalCAPIWorkloadCluster(ctx, runtime, management, state.Name)
	if err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return pending("WORKLOAD_IDENTITY_RECHECK_PENDING")
	}
	if !localCAPIWorkloadClusterIdentityMatches(state, cluster) {
		return fail("WORKLOAD_IDENTITY_UNVERIFIED")
	}
	if _, err := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, "create", "--dry-run=server", "-f", calicoPath); err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return fail("CALICO_DRY_RUN_REJECTED")
	}
	if err := verifyLocalCAPIWorkloadManagementStillBound(ctx, runtime, management, state.ManagementName); err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return fail("MANAGEMENT_IDENTITY_CHANGED")
	}
	if err := verifyLocalCAPIWorkloadCNIInstallIdentity(ctx, runtime, management, state, containers); err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return fail("KIND_IDENTITY_UNVERIFIED")
	}
	cluster, err = readLocalCAPIWorkloadCluster(ctx, runtime, management, state.Name)
	if err != nil {
		if ctx.Err() != nil {
			return pending("CALICO_INSTALLATION_PENDING")
		}
		return pending("WORKLOAD_IDENTITY_RECHECK_PENDING")
	}
	if !localCAPIWorkloadClusterIdentityMatches(state, cluster) {
		return fail("WORKLOAD_IDENTITY_UNVERIFIED")
	}
	// Persist this marker before invoking create. If the process stops at any
	// point after this write, continuation cannot repeat an ambiguous mutation.
	state.Phase, state.CalicoCreateAttempted = "CALICO_CREATE_ATTEMPTED", true
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return localCAPIWorkloadReport{}, errors.New("Calico create intent could not be durably recorded; no Calico create was invoked")
	}
	if _, err := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, "create", "-f", calicoPath); err != nil {
		return fail("CALICO_CREATE_OUTCOME_UNCERTAIN")
	}
	state.Phase = "APPLIED"
	if err := updateLocalCAPIWorkloadState(runtime.stateRoot, state); err != nil {
		return localCAPIWorkloadReport{}, errors.New("Calico create returned success but its final state could not be durably recorded; do not repeat it")
	}
	status := observeLocalCAPIWorkloadStatus(ctx, runtime, management, state, cluster)
	return status, nil
}

func markLocalCAPIWorkloadIncomplete(root string, state localCAPIWorkloadState, code string) error {
	state.Phase, state.FailureCode = "INCOMPLETE", code
	if err := updateLocalCAPIWorkloadState(root, state); err != nil {
		return errors.New("workload stopped; durable INCOMPLETE update failed; preserve the receipt and do not retry")
	}
	return fmt.Errorf("workload continuation stopped [%s]; no automatic retry or cleanup", code)
}

func writeLocalCAPIWorkloadWaitingReport(output io.Writer, operation string, state localCAPIWorkloadState, management localCAPIState) error {
	return writeLocalCAPIWorkloadReport(output, localCAPIWorkloadReport{
		Format: localCAPIWorkloadStateFormat, Operation: operation, Result: "PROVISIONING", Cluster: state.Name,
		Namespace: state.Namespace, Management: state.ManagementName, HistoricalOperationPhase: state.Phase,
		HistoricalManagementPhase: string(management.Phase), ClusterUID: state.ClusterUID,
		ReasonCode: "WORKLOAD_ACCESS_PENDING", ObservedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func localCAPIWorkloadClusterIdentityMatches(state localCAPIWorkloadState, cluster localCAPIWorkloadClusterObservation) bool {
	return state.ClusterUID != "" && cluster.Metadata.UID == state.ClusterUID && cluster.Metadata.Name == state.Name &&
		cluster.Metadata.Namespace == state.Namespace && cluster.Metadata.Labels[localOwnerLabel] == state.WorkloadOwnerID &&
		localCAPIWorkloadClusterNetworkMatches(cluster, state.PodCIDR, state.ServiceCIDR) &&
		cluster.Spec.Topology != nil && cluster.Spec.Topology.ClassRef.Name == localCAPIWorkloadClassName && cluster.Spec.Topology.Version == localCAPIKubernetesVersion && cluster.Spec.Topology.ControlPlane.Replicas != nil &&
		*cluster.Spec.Topology.ControlPlane.Replicas == int32(state.ControlPlaneReplicas) &&
		len(cluster.Spec.Topology.Workers.MachineDeployments) == 1 && cluster.Spec.Topology.Workers.MachineDeployments[0].Class == localCAPIWorkloadWorkerClass &&
		cluster.Spec.Topology.Workers.MachineDeployments[0].Name == localCAPIWorkloadWorkerName && cluster.Spec.Topology.Workers.MachineDeployments[0].Replicas != nil &&
		*cluster.Spec.Topology.Workers.MachineDeployments[0].Replicas == int32(state.WorkerReplicas)
}

func localCAPIWorkloadCNIRecoveryCandidate(state localCAPIWorkloadState) bool {
	return state.Phase == "INCOMPLETE" && state.FailureCode == "CNI_ALREADY_PRESENT" && state.RecoveryFromFailureCode == "" &&
		!state.CalicoCreateAttempted && state.ClusterUID != "" && state.WorkloadKubeconfigSHA256 != "" &&
		validLocalCAPIWorkloadContainers(state.WorkloadContainers) && validLocalCAPIWorkloadNodeIdentities(state.WorkloadNodes)
}

func runLocalCAPIWorkloadStatus(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	flags := flag.NewFlagSet("ok local cluster status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "CAPI workload cluster name")
	management := flags.String("management", "", "Existing verified CAPI management receipt name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) || !localClusterNamePattern.MatchString(*management) {
		return errors.New("usage: ok local cluster status --name <cluster> --management <capi-name>")
	}
	state, err := readLocalCAPIWorkloadState(runtime.stateRoot, *name)
	if err != nil {
		return writeLocalCAPIWorkloadReport(stdout, localCAPIWorkloadReport{Format: localCAPIWorkloadStateFormat, Operation: "STATUS", Result: "UNVERIFIABLE", Cluster: *name, Management: *management, ReasonCode: "WORKLOAD_RECEIPT_UNAVAILABLE", ObservedAt: time.Now().UTC().Format(time.RFC3339)})
	}
	report := localCAPIWorkloadReport{Format: localCAPIWorkloadStateFormat, Operation: "STATUS", Cluster: state.Name, Namespace: state.Namespace, Management: state.ManagementName, HistoricalOperationPhase: state.Phase, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	if state.ManagementName != *management {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "MANAGEMENT_RECEIPT_MISMATCH"
		return writeLocalCAPIWorkloadReport(stdout, report)
	}
	if state.Phase == "INCOMPLETE" || state.Phase == "CALICO_CREATE_ATTEMPTED" || state.ClusterUID == "" {
		report.Result, report.ReasonCode = "INCOMPLETE", "NO_AUTOMATIC_RECOVERY"
		if localCAPIWorkloadCNIRecoveryCandidate(state) {
			report.ReasonCode = "EXPLICIT_CNI_CONTINUATION_REQUIRED"
		}
		return writeLocalCAPIWorkloadReport(stdout, report)
	}
	managementState, _, err := verifyLocalCAPIWorkloadManagement(ctx, runtime, *management)
	if err != nil || !sameLocalCAPIWorkloadManagement(state, managementState) {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "MANAGEMENT_IDENTITY_UNAVAILABLE"
		return writeLocalCAPIWorkloadReport(stdout, report)
	}
	cluster, err := readLocalCAPIWorkloadCluster(ctx, runtime, managementState, state.Name)
	if err != nil {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "CLUSTER_OBSERVATION_FAILED"
		return writeLocalCAPIWorkloadReport(stdout, report)
	}
	if !localCAPIWorkloadClusterIdentityMatches(state, cluster) {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "CLUSTER_IDENTITY_CHANGED"
		return writeLocalCAPIWorkloadReport(stdout, report)
	}
	if state.Phase == "WAITING_FOR_WORKLOAD_ACCESS" {
		report.Result, report.ReasonCode = "PROVISIONING", "WORKLOAD_ACCESS_PENDING"
		if state.WorkloadKubeconfigSHA256 != "" && validLocalCAPIWorkloadContainers(state.WorkloadContainers) && validLocalCAPIWorkloadNodeIdentities(state.WorkloadNodes) {
			report.ReasonCode = "CALICO_INSTALLATION_PENDING"
		}
		report.ClusterUID = state.ClusterUID
		return writeLocalCAPIWorkloadReport(stdout, report)
	}
	return writeLocalCAPIWorkloadReport(stdout, observeLocalCAPIWorkloadStatus(ctx, runtime, managementState, state, cluster))
}

func verifyLocalCAPIWorkloadManagement(ctx context.Context, runtime localRuntime, name string) (localCAPIState, localCAPIVerificationReport, error) {
	state, err := readLocalCAPIState(runtime.stateRoot, name)
	if err != nil || (state.Phase != localCAPIPhaseIncomplete && state.Phase != localCAPIPhaseCAPIReady) {
		return localCAPIState{}, localCAPIVerificationReport{}, errors.New("management CAPI ownership receipt is missing, invalid, or not inspectable")
	}
	report := verifyLocalCAPIBootstrap(ctx, runtime, name)
	if report.Result != "VERIFIED" {
		return localCAPIState{}, report, fmt.Errorf("management CAPI bootstrap is not currently verified [%s]", report.ReasonCode)
	}
	if state.Node == nil || state.Node.UID == "" || state.NodeOwnerID != state.OwnerID || state.KubeSystemUID == "" ||
		state.BootstrapResourceState != localCAPIResourceVerified || !state.BootstrapKubeconfigSeen || len(state.Containers) != 1 {
		return localCAPIState{}, report, errors.New("management receipt lacks durable bootstrap ownership evidence")
	}
	if !state.DevelopmentTemplatesAttempted || !state.DevelopmentTemplatesComplete || !localCAPITemplateInventoryComplete(state.DevelopmentTemplates) {
		return localCAPIState{}, report, errors.New("management receipt lacks separately installed development-template ownership evidence")
	}
	return state, report, nil
}

func verifyLocalCAPIWorkloadManagementStillBound(ctx context.Context, runtime localRuntime, expected localCAPIState, name string) error {
	observed, _, err := verifyLocalCAPIWorkloadManagement(ctx, runtime, name)
	if err != nil || observed.OwnerID != expected.OwnerID || observed.Provider != expected.Provider || observed.BootstrapKindName != expected.BootstrapKindName || observed.Node == nil || expected.Node == nil || observed.Node.UID != expected.Node.UID || observed.KubeSystemUID != expected.KubeSystemUID {
		return errors.New("management CAPI identity changed")
	}
	return nil
}

func sameLocalCAPIWorkloadManagement(workload localCAPIWorkloadState, management localCAPIState) bool {
	return workload.ManagementOwnerID == management.OwnerID && workload.Provider == management.Provider &&
		workload.ManagementKindName == management.BootstrapKindName && workload.ColimaProfile == localCAPIStateProfile(management) && management.Node != nil &&
		workload.ManagementNodeUID == management.Node.UID && workload.ManagementKubeSystemID == management.KubeSystemUID
}

func buildLocalCAPIWorkloadGenerateArgs(state localCAPIState, name string) []string {
	return []string{"generate", "cluster", name,
		"--infrastructure", "docker:" + localCAPIVersion,
		"--kubernetes-version", localCAPIKubernetesVersion,
		"--control-plane-machine-count", "1", "--worker-machine-count", "1",
		"--flavor", "development", "--target-namespace", localCAPIWorkloadNamespace,
		"--kubeconfig", state.BootstrapKubeconfig,
		"--kubeconfig-context", "kind-" + state.BootstrapKindName,
		"--config", state.ClusterctlConfigPath}
}

func bindLocalCAPIWorkloadManifest(raw []byte, name, ownerID string, controlPlaneReplicas, workerReplicas int) ([]byte, error) {
	if len(raw) == 0 || len(raw) > localCAPIMaxOutput || !localClusterNamePattern.MatchString(name) || !localOwnerIDPattern.MatchString(ownerID) || controlPlaneReplicas != 1 || workerReplicas != 1 {
		return nil, errors.New("invalid generated CAPI workload manifest input")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	clusterCount := 0
	objectCounts := map[string]int{}
	objectIdentityCounts := map[string]int{}
	for document := 0; ; document++ {
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("generated CAPI manifest contains invalid YAML")
		}
		if document >= 128 {
			return nil, errors.New("generated CAPI manifest contains too many documents")
		}
		if len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		kind, err := yamlMappingScalar(root, "kind")
		if err != nil || kind == "" {
			return nil, errors.New("generated CAPI manifest has an invalid object")
		}
		apiVersion, err := yamlMappingScalar(root, "apiVersion")
		if err != nil || !localCAPIWorkloadAllowedManifestObject(apiVersion, kind) {
			return nil, fmt.Errorf("manifest.objects[%d].apiVersion/kind: object is outside the pinned development-flavor inventory", document)
		}
		objectCounts[apiVersion+"/"+kind]++
		metadata, err := yamlMappingNode(root, "metadata")
		if err != nil {
			return nil, errors.New("development flavor object metadata is invalid")
		}
		objectName, nameErr := yamlMappingScalar(metadata, "name")
		objectNamespace, namespaceErr := yamlMappingScalar(metadata, "namespace")
		if nameErr != nil || objectName == "" {
			return nil, fmt.Errorf("manifest.objects[%d].metadata.name: missing or malformed", document)
		}
		if namespaceErr != nil || objectNamespace != localCAPIWorkloadNamespace {
			return nil, fmt.Errorf("manifest.objects[%d].metadata.namespace: does not match the requested workload namespace", document)
		}
		identity := apiVersion + "/" + kind + "/" + objectName
		if !localCAPIWorkloadManifestIdentityExpected(identity, name) {
			return nil, fmt.Errorf("manifest.objects[%d].metadata.name: does not match the pinned development-flavor inventory", document)
		}
		if kind != "Cluster" && !localCAPIWorkloadManifestObjectMatchesDevelopmentFixture(root, apiVersion, kind, objectName, name) {
			return nil, fmt.Errorf("manifest.objects[%d].spec: differs from the pinned clusterctl v1.14.4 development flavor", document)
		}
		objectIdentityCounts[identity]++
		if objectIdentityCounts[identity] != 1 {
			return nil, fmt.Errorf("manifest.objects[%d].identity: duplicate object in generated inventory", document)
		}
		if kind != "Cluster" {
			continue
		}
		if kind == "Cluster" {
			clusterCount++
			var cluster localCAPIWorkloadManifestCluster
			if err := node.Decode(&cluster); err != nil {
				return nil, errors.New("manifest.Cluster: invalid CAPI Cluster structure")
			}
			if cluster.APIVersion != localCAPIWorkloadAPIVersion {
				return nil, errors.New("manifest.Cluster.apiVersion: does not match CAPI v1beta2")
			}
			if cluster.Metadata.Name != name || cluster.Metadata.Namespace != localCAPIWorkloadNamespace {
				return nil, errors.New("manifest.Cluster.metadata: does not match requested name and namespace")
			}
			if !localCAPIWorkloadManifestNetworkMatches(cluster, localCAPIWorkloadPodCIDR, localCAPIWorkloadServiceCIDR) {
				return nil, errors.New("manifest.Cluster.spec.clusterNetwork: Pod or Service CIDR differs from the local MVP contract")
			}
			if cluster.Spec.Topology == nil {
				return nil, errors.New("manifest.Cluster.spec.topology: required topology is missing")
			}
			if cluster.Spec.Topology.ClassRef.Name != localCAPIWorkloadClassName {
				return nil, errors.New("manifest.Cluster.spec.topology.classRef.name: does not match the pinned development flavor")
			}
			if cluster.Spec.Topology.Version != localCAPIKubernetesVersion {
				return nil, errors.New("manifest.Cluster.spec.topology.version: does not match the pinned Kubernetes version")
			}
			if cluster.Spec.Topology.ControlPlane.Replicas == nil || *cluster.Spec.Topology.ControlPlane.Replicas != controlPlaneReplicas {
				return nil, errors.New("manifest.Cluster.spec.topology.controlPlane.replicas: does not match the requested count")
			}
			if len(cluster.Spec.Topology.Workers.MachineDeployments) != 1 || cluster.Spec.Topology.Workers.MachineDeployments[0].Class != localCAPIWorkloadWorkerClass || cluster.Spec.Topology.Workers.MachineDeployments[0].Name != localCAPIWorkloadWorkerName || cluster.Spec.Topology.Workers.MachineDeployments[0].Replicas == nil || *cluster.Spec.Topology.Workers.MachineDeployments[0].Replicas != workerReplicas {
				return nil, errors.New("manifest.Cluster.spec.topology.workers.machineDeployments: does not match the requested worker contract")
			}
			if !localCAPIWorkloadManifestObjectMatchesDevelopmentFixture(root, apiVersion, kind, objectName, name) {
				return nil, errors.New("manifest.Cluster.spec: differs from the pinned clusterctl v1.14.4 development flavor")
			}
			if err := addLocalCAPIWorkloadOwnerLabel(root, ownerID); err != nil {
				return nil, err
			}
		}
		if err := encoder.Encode(&node); err != nil {
			return nil, errors.New("cannot encode owner-bound CAPI manifest")
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, errors.New("cannot encode owner-bound CAPI manifest")
	}
	if clusterCount != 1 || !localCAPIWorkloadManifestInventoryExact(objectCounts) || !localCAPIWorkloadManifestIdentityInventoryExact(objectIdentityCounts, name) {
		return nil, errors.New("manifest.inventory: does not match the complete pinned clusterctl v1.14.4 development flavor")
	}
	return output.Bytes(), nil
}

func localCAPIWorkloadManifestNetworkMatches(cluster localCAPIWorkloadManifestCluster, podCIDR, serviceCIDR string) bool {
	return cluster.Spec.ClusterNetwork != nil && len(cluster.Spec.ClusterNetwork.Pods.CIDRBlocks) == 1 && cluster.Spec.ClusterNetwork.Pods.CIDRBlocks[0] == podCIDR &&
		len(cluster.Spec.ClusterNetwork.Services.CIDRBlocks) == 1 && cluster.Spec.ClusterNetwork.Services.CIDRBlocks[0] == serviceCIDR
}

func localCAPIWorkloadAllowedManifestObject(apiVersion, kind string) bool {
	for _, object := range localCAPIWorkloadExpectedManifestObjects("") {
		if object.apiVersion == apiVersion && object.kind == kind {
			return true
		}
	}
	return false
}

func localCAPIWorkloadManifestInventoryExact(got map[string]int) bool {
	want := map[string]int{}
	for _, object := range localCAPIWorkloadExpectedManifestObjects("") {
		key := object.apiVersion + "/" + object.kind
		want[key]++
	}
	clusterOnly := map[string]int{localCAPIWorkloadAPIVersion + "/Cluster": 1}
	// clusterctl emits the full development flavor when the management
	// ClusterClass templates are not already installed. Once management owns
	// those shared resources, it correctly emits only the workload Cluster.
	return reflect.DeepEqual(got, want) || reflect.DeepEqual(got, clusterOnly)
}

type localCAPIWorkloadManifestObjectIdentity struct {
	apiVersion string
	kind       string
	resource   string
	name       string
}

func localCAPIWorkloadExpectedManifestObjects(clusterName string) []localCAPIWorkloadManifestObjectIdentity {
	return []localCAPIWorkloadManifestObjectIdentity{
		{apiVersion: "cluster.x-k8s.io/v1beta2", kind: "ClusterClass", resource: "clusterclasses.cluster.x-k8s.io", name: "quick-start"},
		{apiVersion: "infrastructure.cluster.x-k8s.io/v1beta2", kind: "DevClusterTemplate", resource: "devclustertemplates.infrastructure.cluster.x-k8s.io", name: "quick-start-cluster"},
		{apiVersion: "controlplane.cluster.x-k8s.io/v1beta2", kind: "KubeadmControlPlaneTemplate", resource: "kubeadmcontrolplanetemplates.controlplane.cluster.x-k8s.io", name: "quick-start-control-plane"},
		{apiVersion: "infrastructure.cluster.x-k8s.io/v1beta2", kind: "DevMachineTemplate", resource: "devmachinetemplates.infrastructure.cluster.x-k8s.io", name: "quick-start-control-plane"},
		{apiVersion: "infrastructure.cluster.x-k8s.io/v1beta2", kind: "DevMachineTemplate", resource: "devmachinetemplates.infrastructure.cluster.x-k8s.io", name: "quick-start-default-worker-machinetemplate"},
		{apiVersion: "infrastructure.cluster.x-k8s.io/v1beta2", kind: "DevMachinePoolTemplate", resource: "devmachinepooltemplates.infrastructure.cluster.x-k8s.io", name: "quick-start-default-worker-machinepooltemplate"},
		{apiVersion: "bootstrap.cluster.x-k8s.io/v1beta2", kind: "KubeadmConfigTemplate", resource: "kubeadmconfigtemplates.bootstrap.cluster.x-k8s.io", name: "quick-start-default-worker-bootstraptemplate"},
		{apiVersion: localCAPIWorkloadAPIVersion, kind: "Cluster", resource: "clusters.cluster.x-k8s.io", name: clusterName},
	}
}

func localCAPITemplateIdentityExpected(got string) bool {
	for _, object := range localCAPIWorkloadExpectedManifestObjects("") {
		if object.kind != "Cluster" && got == object.apiVersion+"/"+object.kind+"/"+object.name {
			return true
		}
	}
	return false
}

func localCAPIWorkloadManifestIdentityExpected(got, clusterName string) bool {
	for _, object := range localCAPIWorkloadExpectedManifestObjects(clusterName) {
		if got == object.apiVersion+"/"+object.kind+"/"+object.name {
			return true
		}
	}
	return false
}

func localCAPIWorkloadManifestIdentityInventoryExact(got map[string]int, clusterName string) bool {
	want := map[string]int{}
	for _, object := range localCAPIWorkloadExpectedManifestObjects(clusterName) {
		want[object.apiVersion+"/"+object.kind+"/"+object.name]++
	}
	clusterOnly := map[string]int{localCAPIWorkloadAPIVersion + "/Cluster/" + clusterName: 1}
	return reflect.DeepEqual(got, want) || reflect.DeepEqual(got, clusterOnly)
}

func renderLocalCAPIDevelopmentTemplateManifest(ownerID string) ([]byte, error) {
	if !localOwnerIDPattern.MatchString(ownerID) {
		return nil, errors.New("invalid CAPI management owner identifier")
	}
	decoder := yaml.NewDecoder(strings.NewReader(localCAPIDevelopmentManifestFixture))
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	seen := map[string]bool{}
	for {
		var doc yaml.Node
		if err := decoder.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("pinned development template fixture is malformed")
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		apiVersion, apiErr := yamlMappingScalar(root, "apiVersion")
		kind, kindErr := yamlMappingScalar(root, "kind")
		if apiErr != nil || kindErr != nil {
			return nil, errors.New("pinned development template identity is malformed")
		}
		if kind == "Cluster" {
			continue
		}
		metadata, err := yamlMappingNode(root, "metadata")
		if err != nil {
			return nil, errors.New("pinned development template metadata is malformed")
		}
		name, nameErr := yamlMappingScalar(metadata, "name")
		namespace, namespaceErr := yamlMappingScalar(metadata, "namespace")
		identity := apiVersion + "/" + kind + "/" + name
		if nameErr != nil || namespaceErr != nil || namespace != localCAPIWorkloadNamespace || !localCAPITemplateIdentityExpected(identity) || seen[identity] ||
			!localCAPIWorkloadManifestObjectMatchesDevelopmentFixture(root, apiVersion, kind, name, "") {
			return nil, errors.New("pinned development template identity or content is invalid")
		}
		if kind == "DevClusterTemplate" {
			// The CAPD v1beta2 admission path defaults these fields when the
			// development-flavor object is stored. Include those exact defaults in
			// our create-only manifest so strict read-back spec hashing remains
			// deterministic without accepting arbitrary server-side changes.
			if err := addLocalCAPIDevClusterTemplateDefaults(root); err != nil {
				return nil, errors.New("cannot make CAPD template defaults explicit")
			}
		}
		if err := addLocalCAPIWorkloadOwnerLabel(root, ownerID); err != nil {
			return nil, errors.New("cannot bind management ownership to development templates")
		}
		seen[identity] = true
		if err := encoder.Encode(&doc); err != nil {
			return nil, errors.New("cannot encode management-owned development templates")
		}
	}
	if err := encoder.Close(); err != nil || len(seen) != len(localCAPIWorkloadExpectedManifestObjects(""))-1 {
		return nil, errors.New("development template fixture inventory is incomplete")
	}
	return output.Bytes(), nil
}

func addLocalCAPIDevClusterTemplateDefaults(root *yaml.Node) error {
	spec, err := yamlMappingNode(root, "spec")
	if err != nil {
		return err
	}
	template, err := yamlMappingNode(spec, "template")
	if err != nil {
		return err
	}
	templateSpec, err := yamlMappingNode(template, "spec")
	if err != nil {
		return err
	}
	if _, err := yamlMappingValue(templateSpec, "controlPlaneEndpoint"); err == nil {
		return errors.New("development fixture unexpectedly sets controlPlaneEndpoint")
	}
	templateSpec.Content = append(templateSpec.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "controlPlaneEndpoint"},
		&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "port"},
			{Kind: yaml.ScalarNode, Tag: "!!int", Value: "6443"},
		}},
	)
	backend, err := yamlMappingNode(templateSpec, "backend")
	if err != nil {
		return err
	}
	docker, err := yamlMappingNode(backend, "docker")
	if err != nil {
		return err
	}
	if _, err := yamlMappingValue(docker, "loadBalancer"); err == nil {
		return errors.New("development fixture unexpectedly sets backend.docker.loadBalancer")
	}
	docker.Content = append(docker.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "loadBalancer"},
		&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"},
	)
	return nil
}

func localCAPITemplateExpectedObjects(ownerID string) (map[string]map[string]any, error) {
	raw, err := renderLocalCAPIDevelopmentTemplateManifest(ownerID)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	objects := map[string]map[string]any{}
	for {
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("management template manifest cannot be parsed")
		}
		if len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		apiVersion, _ := yamlMappingScalar(root, "apiVersion")
		kind, _ := yamlMappingScalar(root, "kind")
		metadata, err := yamlMappingNode(root, "metadata")
		if err != nil {
			return nil, errors.New("management template metadata cannot be parsed")
		}
		name, _ := yamlMappingScalar(metadata, "name")
		var object map[string]any
		if err := root.Decode(&object); err != nil {
			return nil, errors.New("management template object cannot be decoded")
		}
		objects[apiVersion+"/"+kind+"/"+name] = object
	}
	if len(objects) != len(localCAPIWorkloadExpectedManifestObjects(""))-1 {
		return nil, errors.New("management template inventory is incomplete")
	}
	return objects, nil
}

func localCAPITemplateSpecDigest(object map[string]any) (string, error) {
	spec, ok := object["spec"]
	if !ok {
		return "", errors.New("template spec is missing")
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", errors.New("template spec cannot be encoded")
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func installLocalCAPIDevelopmentTemplates(ctx context.Context, runtime localRuntime, state *localCAPIState) error {
	if state == nil || state.DevelopmentTemplatesAttempted || len(state.DevelopmentTemplates) != 0 {
		return errors.New("development template installation is already attempted or ambiguous")
	}
	expected, err := localCAPITemplateExpectedObjects(state.OwnerID)
	if err != nil {
		return err
	}
	manifest, err := renderLocalCAPIDevelopmentTemplateManifest(state.OwnerID)
	if err != nil {
		return err
	}
	for _, identity := range localCAPIWorkloadExpectedManifestObjects("") {
		if identity.kind == "Cluster" {
			continue
		}
		output, getErr := runLocalCAPIRaw(ctx, runtime, state.Provider, state.BootstrapKubeconfig, nil,
			"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName,
			"get", identity.resource, identity.name, "-n", localCAPIWorkloadNamespace, "-o", "json", "--ignore-not-found")
		if getErr != nil {
			return errors.New("cannot safely inspect existing management templates")
		}
		if len(bytes.TrimSpace(output)) != 0 {
			return errors.New("development template resource already exists; refusing to adopt or overwrite it")
		}
	}
	path := filepath.Join(localCAPIStateDirectory(runtime.stateRoot, state.Name), "development-templates.yaml")
	if err := writePrivateNewFile(path, manifest); err != nil {
		return errors.New("cannot persist the private development template manifest")
	}
	if err := syncLocalCAPIDirectory(localCAPIStateDirectory(runtime.stateRoot, state.Name)); err != nil {
		return errors.New("cannot durably persist the development template manifest")
	}
	state.DevelopmentTemplatesAttempted = true
	digest := sha256.Sum256(manifest)
	state.DevelopmentTemplatesSHA256 = hex.EncodeToString(digest[:])
	if err := writeLocalCAPIState(runtime.stateRoot, *state, true); err != nil {
		return errors.New("cannot persist development template create intent; no template create was invoked")
	}
	if err := verifyLocalCAPIProviderStillPinned(ctx, runtime, *state); err != nil {
		return errors.New("selected management provider changed before template creation")
	}
	_, createErr := runLocalCAPIRaw(ctx, runtime, state.Provider, state.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName,
		"create", "-f", path)
	// A kubectl multi-document create can partially succeed. Always perform the
	// same bounded, read-only inventory after the one attempt, even on error.
	evidence := observeLocalCAPIDevelopmentTemplateResources(ctx, runtime, *state, expected)
	state.DevelopmentTemplates = evidence
	if err := writeLocalCAPIState(runtime.stateRoot, *state, true); err != nil {
		return errors.New("development template observations could not be durably recorded; do not retry")
	}
	if createErr != nil {
		return errors.New("management-owned development template create failed; outcome is one-shot and must not be retried")
	}
	if !localCAPITemplateInventoryComplete(evidence) {
		return errors.New("management development templates are missing, mismatched, or unverifiable; do not retry")
	}
	completed := *state
	completed.DevelopmentTemplatesComplete = true
	if err := writeLocalCAPIState(runtime.stateRoot, completed, true); err != nil {
		return errors.New("complete development template ownership could not be durably recorded; do not retry")
	}
	*state = completed
	return nil
}

func observeLocalCAPIDevelopmentTemplateResources(ctx context.Context, runtime localRuntime, state localCAPIState, expected map[string]map[string]any) []localCAPITemplateEvidence {
	evidence := make([]localCAPITemplateEvidence, 0, len(expected))
	for _, identity := range localCAPIWorkloadExpectedManifestObjects("") {
		if identity.kind == "Cluster" {
			continue
		}
		key := identity.apiVersion + "/" + identity.kind + "/" + identity.name
		item := localCAPITemplateEvidence{APIVersion: identity.apiVersion, Kind: identity.kind, Namespace: localCAPIWorkloadNamespace, Name: identity.name}
		output, err := runLocalCAPIRaw(ctx, runtime, state.Provider, state.BootstrapKubeconfig, nil,
			"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName,
			"get", identity.resource, identity.name, "-n", localCAPIWorkloadNamespace, "-o", "json", "--ignore-not-found")
		if err != nil {
			item.Status, item.ReasonCode = localCAPITemplateUnverifiable, "READ_FAILED"
			evidence = append(evidence, item)
			continue
		}
		if len(bytes.TrimSpace(output)) == 0 {
			item.Status, item.ReasonCode = localCAPITemplateMissing, "NOT_FOUND"
			evidence = append(evidence, item)
			continue
		}
		var actual map[string]any
		if json.Unmarshal(output, &actual) != nil {
			item.Status, item.ReasonCode = localCAPITemplateUnverifiable, "MALFORMED_RESPONSE"
			evidence = append(evidence, item)
			continue
		}
		metadata, _ := actual["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		actualUID, _ := metadata["uid"].(string)
		item.ObservedAPIVersion = localCAPITemplateSafeObservedString(actual["apiVersion"])
		item.ObservedKind = localCAPITemplateSafeObservedString(actual["kind"])
		item.ObservedNamespace = localCAPITemplateSafeObservedString(metadata["namespace"])
		item.ObservedName = localCAPITemplateSafeObservedString(metadata["name"])
		item.ObservedOwnerID = localCAPITemplateSafeObservedString(labels[localOwnerLabel])
		if len(actualUID) <= 256 && !strings.ContainsAny(actualUID, "\r\n\x00") {
			item.UID = actualUID
		}
		if digest, digestErr := localCAPITemplateSpecDigest(actual); digestErr == nil {
			item.SpecSHA256 = digest
		}
		wanted := expected[key]
		wantedMetadata, _ := wanted["metadata"].(map[string]any)
		wantedLabels, _ := wantedMetadata["labels"].(map[string]any)
		wantedOwner, _ := wantedLabels[localOwnerLabel].(string)
		wantedDigest, wantedErr := localCAPITemplateSpecDigest(wanted)
		switch {
		case item.ObservedAPIVersion != identity.apiVersion || item.ObservedKind != identity.kind || item.ObservedName != identity.name || item.ObservedNamespace != localCAPIWorkloadNamespace:
			item.Status, item.ReasonCode = localCAPITemplateMismatch, "IDENTITY_MISMATCH"
		case item.ObservedOwnerID != state.OwnerID || wantedOwner != state.OwnerID:
			item.Status, item.ReasonCode = localCAPITemplateMismatch, "OWNER_MISMATCH"
		case item.UID == "":
			item.Status, item.ReasonCode = localCAPITemplateMismatch, "UID_MISSING"
		case wantedErr != nil || item.SpecSHA256 == "":
			item.Status, item.ReasonCode = localCAPITemplateUnverifiable, "SPEC_UNREADABLE"
		case item.SpecSHA256 != wantedDigest:
			item.Status, item.ReasonCode = localCAPITemplateMismatch, "SPEC_MISMATCH"
		default:
			item.Status = localCAPITemplateVerified
		}
		evidence = append(evidence, item)
	}
	return evidence
}

func validLocalCAPITemplateEvidence(evidence localCAPITemplateEvidence) bool {
	safeObserved := func(value string) bool { return len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00") }
	if !safeObserved(evidence.ObservedAPIVersion) || !safeObserved(evidence.ObservedKind) || !safeObserved(evidence.ObservedNamespace) || !safeObserved(evidence.ObservedName) || !safeObserved(evidence.ObservedOwnerID) || !safeObserved(evidence.UID) {
		return false
	}
	if evidence.SpecSHA256 != "" && !localCAPISHA256Pattern.MatchString(evidence.SpecSHA256) {
		return false
	}
	switch evidence.Status {
	case localCAPITemplateVerified:
		return evidence.ReasonCode == "" && evidence.ObservedAPIVersion == evidence.APIVersion && evidence.ObservedKind == evidence.Kind && evidence.ObservedNamespace == evidence.Namespace && evidence.ObservedName == evidence.Name && evidence.ObservedOwnerID != "" && evidence.UID != "" && strings.TrimSpace(evidence.UID) == evidence.UID && localCAPISHA256Pattern.MatchString(evidence.SpecSHA256)
	case localCAPITemplateMissing:
		return evidence.ReasonCode == "NOT_FOUND" && evidence.ObservedAPIVersion == "" && evidence.ObservedKind == "" && evidence.ObservedNamespace == "" && evidence.ObservedName == "" && evidence.ObservedOwnerID == "" && evidence.UID == "" && evidence.SpecSHA256 == ""
	case localCAPITemplateMismatch, localCAPITemplateUnverifiable:
		switch evidence.ReasonCode {
		case "READ_FAILED", "MALFORMED_RESPONSE", "IDENTITY_MISMATCH", "OWNER_MISMATCH", "UID_MISSING", "SPEC_UNREADABLE", "SPEC_MISMATCH":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func localCAPITemplateSafeObservedString(value any) string {
	text, _ := value.(string)
	if len(text) > 256 || strings.ContainsAny(text, "\r\n\x00") {
		return ""
	}
	return text
}

func localCAPITemplateInventoryComplete(evidence []localCAPITemplateEvidence) bool {
	if len(evidence) != len(localCAPIWorkloadExpectedManifestObjects(""))-1 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range evidence {
		key := item.APIVersion + "/" + item.Kind + "/" + item.Name
		if !localCAPITemplateIdentityExpected(key) || item.Status != localCAPITemplateVerified || !validLocalCAPITemplateEvidence(item) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(localCAPIWorkloadExpectedManifestObjects(""))-1
}

func verifyLocalCAPITemplateReceipt(ctx context.Context, runtime localRuntime, state localCAPIState) error {
	if !state.DevelopmentTemplatesAttempted || !state.DevelopmentTemplatesComplete || !localCAPITemplateInventoryComplete(state.DevelopmentTemplates) || !localCAPISHA256Pattern.MatchString(state.DevelopmentTemplatesSHA256) {
		return errors.New("management receipt lacks complete development template ownership evidence")
	}
	path := filepath.Join(localCAPIStateDirectory(runtime.stateRoot, state.Name), "development-templates.yaml")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !localCAPIConfigMatches(path, state.DevelopmentTemplatesSHA256) {
		return errors.New("private development template manifest differs from its receipt")
	}
	expected, err := localCAPITemplateExpectedObjects(state.OwnerID)
	if err != nil {
		return err
	}
	observed := observeLocalCAPIDevelopmentTemplateResources(ctx, runtime, state, expected)
	if !localCAPITemplateInventoryComplete(observed) || !localCAPITemplateEvidenceEqual(observed, state.DevelopmentTemplates) {
		return errors.New("live development template ownership differs from its receipt")
	}
	return nil
}

func localCAPITemplateEvidenceEqual(left, right []localCAPITemplateEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	leftByIdentity := map[string]localCAPITemplateEvidence{}
	for _, item := range left {
		leftByIdentity[item.APIVersion+"/"+item.Kind+"/"+item.Namespace+"/"+item.Name] = item
	}
	for _, item := range right {
		if leftByIdentity[item.APIVersion+"/"+item.Kind+"/"+item.Namespace+"/"+item.Name] != item {
			return false
		}
	}
	return true
}

func localCAPIWorkloadManifestObjectMatchesDevelopmentFixture(root *yaml.Node, apiVersion, kind, name, clusterName string) bool {
	decoder := yaml.NewDecoder(strings.NewReader(localCAPIDevelopmentManifestFixture))
	for {
		var expected yaml.Node
		if err := decoder.Decode(&expected); err != nil {
			if errors.Is(err, io.EOF) {
				return false
			}
			return false
		}
		if len(expected.Content) == 0 {
			continue
		}
		expectedRoot := expected.Content[0]
		expectedAPIVersion, err := yamlMappingScalar(expectedRoot, "apiVersion")
		if err != nil {
			return false
		}
		expectedKind, err := yamlMappingScalar(expectedRoot, "kind")
		if err != nil || expectedAPIVersion != apiVersion || expectedKind != kind {
			continue
		}
		expectedMetadata, err := yamlMappingNode(expectedRoot, "metadata")
		if err != nil {
			return false
		}
		expectedName, err := yamlMappingScalar(expectedMetadata, "name")
		if err != nil || (kind != "Cluster" && expectedName != name) {
			continue
		}
		var actualObject, expectedObject map[string]any
		if root.Decode(&actualObject) != nil || expectedRoot.Decode(&expectedObject) != nil {
			return false
		}
		if kind == "Cluster" {
			metadata, ok := expectedObject["metadata"].(map[string]any)
			if !ok {
				return false
			}
			metadata["name"] = clusterName
		}
		return reflect.DeepEqual(actualObject, expectedObject)
	}
}

func yamlMappingScalar(node *yaml.Node, key string) (string, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return "", errors.New("YAML object is not a mapping")
	}
	found := ""
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			if found != "" || node.Content[i+1].Kind != yaml.ScalarNode {
				return "", errors.New("YAML field is duplicated or not scalar")
			}
			found = node.Content[i+1].Value
		}
	}
	return found, nil
}

func yamlMappingNode(node *yaml.Node, key string) (*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, errors.New("YAML object is not a mapping")
	}
	var found *yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			if found != nil || node.Content[i+1].Kind != yaml.MappingNode {
				return nil, errors.New("YAML field is duplicated or not a mapping")
			}
			found = node.Content[i+1]
		}
	}
	if found == nil {
		return nil, errors.New("YAML mapping field is missing")
	}
	return found, nil
}

func addLocalCAPIWorkloadOwnerLabel(root *yaml.Node, ownerID string) error {
	var metadata, labels *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "metadata" {
			metadata = root.Content[i+1]
		}
	}
	if metadata == nil || metadata.Kind != yaml.MappingNode {
		return errors.New("generated Cluster metadata is missing")
	}
	for i := 0; i+1 < len(metadata.Content); i += 2 {
		if metadata.Content[i].Value == "labels" {
			labels = metadata.Content[i+1]
		}
	}
	if labels == nil {
		labels = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		metadata.Content = append(metadata.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "labels"}, labels)
	}
	if labels.Kind != yaml.MappingNode {
		return errors.New("generated Cluster labels are malformed")
	}
	for i := 0; i+1 < len(labels.Content); i += 2 {
		if labels.Content[i].Value == localOwnerLabel {
			return errors.New("generated Cluster already contains the local owner label")
		}
	}
	labels.Content = append(labels.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: localOwnerLabel}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ownerID})
	return nil
}

func ensureLocalCAPIWorkloadParent(root string) error {
	if err := verifyLocalCAPIStateRoot(root); err != nil {
		return err
	}
	if err := ensureLocalCAPIDirectory(filepath.Join(root, "capi"), false); err != nil {
		return err
	}
	if err := ensureLocalCAPIDirectory(filepath.Join(root, "capi", "workloads"), false); err != nil {
		return err
	}
	info, err := os.Lstat(localCAPIWorkloadRoot(root))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("workload state root is not private")
	}
	return nil
}

func validateLocalCAPIWorkloadState(state localCAPIWorkloadState) error {
	if state.Format != localCAPIWorkloadStateFormat || (state.Phase != "APPLYING" && state.Phase != "WAITING_FOR_WORKLOAD_ACCESS" && state.Phase != "CALICO_CREATE_ATTEMPTED" && state.Phase != "APPLIED" && state.Phase != "INCOMPLETE") ||
		!localClusterNamePattern.MatchString(state.Name) || !localClusterNamePattern.MatchString(state.ManagementName) || state.Name == state.ManagementName ||
		state.Namespace != localCAPIWorkloadNamespace || !localOwnerIDPattern.MatchString(state.ManagementOwnerID) || !localOwnerIDPattern.MatchString(state.WorkloadOwnerID) ||
		!localKindClusterNamePattern.MatchString(state.ManagementKindName) || state.ManagementNodeUID == "" || state.ManagementKubeSystemID == "" ||
		state.ManagementKindName != localKindClusterName(state.ManagementName, state.ManagementOwnerID) ||
		state.Provider.Kind != "docker" || !validLocalDockerContextName(state.Provider.Context) || len(state.Provider.DaemonID) < 3 || len(state.Provider.DaemonID) > 128 ||
		!regexp.MustCompile(`^[A-Za-z0-9._:-]+$`).MatchString(state.Provider.DaemonID) || (state.ColimaProfile == "default" && state.Provider.Context != "colima") ||
		!validLocalColimaProfileSyntax(state.ColimaProfile) || !localCAPIColimaEndpoint(state.Provider.Endpoint, state.ColimaProfile) ||
		!localCAPISHA256Pattern.MatchString(state.ManifestSHA256) || state.ControlPlaneReplicas != 1 || state.WorkerReplicas != 1 {
		return errors.New("invalid local CAPI workload receipt")
	}
	if state.Phase == "APPLIED" && (state.ClusterUID == "" || state.FailureCode != "") {
		return errors.New("APPLIED workload receipt lacks its live Cluster UID")
	}
	if state.Phase == "WAITING_FOR_WORKLOAD_ACCESS" && (state.ClusterUID == "" || state.CalicoCreateAttempted || state.FailureCode != "") {
		return errors.New("waiting workload receipt has inconsistent ownership or Calico state")
	}
	if state.Phase == "CALICO_CREATE_ATTEMPTED" && (!state.CalicoCreateAttempted || state.ClusterUID == "" || state.FailureCode != "") {
		return errors.New("Calico attempted receipt lacks its durable mutation marker")
	}
	if state.CalicoCreateAttempted && state.Phase != "CALICO_CREATE_ATTEMPTED" && state.Phase != "APPLIED" && state.Phase != "INCOMPLETE" {
		return errors.New("Calico mutation marker is inconsistent with workload phase")
	}
	if state.FailureCode != "" && state.Phase != "INCOMPLETE" {
		return errors.New("workload failure code is inconsistent with phase")
	}
	if state.FailureCode != "" && !localCAPIWorkloadFailureCodes[state.FailureCode] {
		return errors.New("workload receipt contains an unapproved failure code")
	}
	if state.RecoveryFromFailureCode != "" && (state.RecoveryFromFailureCode != "CNI_ALREADY_PRESENT" || state.ClusterUID == "" ||
		(state.Phase != "WAITING_FOR_WORKLOAD_ACCESS" && state.Phase != "CALICO_CREATE_ATTEMPTED" && state.Phase != "APPLIED" && state.Phase != "INCOMPLETE")) {
		return errors.New("workload receipt contains an invalid explicit recovery record")
	}
	if state.WorkerReplacement != nil && !validLocalCAPIWorkloadWorkerReplacement(state, *state.WorkerReplacement) {
		return errors.New("workload receipt contains invalid worker replacement evidence")
	}
	if strings.ContainsAny(state.ClusterUID, "\r\n\x00") {
		return errors.New("workload receipt contains an invalid Cluster UID")
	}
	if state.PodCIDR != "" || state.ServiceCIDR != "" || state.WorkloadKindName != "" || state.WorkloadKubeconfig != "" || state.WorkloadKubeconfigSHA256 != "" || state.WorkloadContainers != nil || state.WorkloadNodes != nil || state.CalicoSourceSHA256 != "" || state.CalicoManifestSHA256 != "" {
		if state.PodCIDR != localCAPIWorkloadPodCIDR || state.ServiceCIDR != localCAPIWorkloadServiceCIDR || state.WorkloadKindName != state.Name ||
			!filepath.IsAbs(state.WorkloadKubeconfig) || state.WorkloadKubeconfig != localCAPIWorkloadKubeconfigPath(localCAPIWorkloadRootFromStatePath(state.WorkloadKubeconfig, state.Name), state.Name) ||
			!localCAPISHA256Pattern.MatchString(state.CalicoSourceSHA256) || (state.CalicoManifestSHA256 != "" && !localCAPISHA256Pattern.MatchString(state.CalicoManifestSHA256)) ||
			(state.WorkloadKubeconfigSHA256 != "" && !localCAPISHA256Pattern.MatchString(state.WorkloadKubeconfigSHA256)) {
			return errors.New("workload receipt contains invalid kubeconfig or CNI intent")
		}
		if (state.Phase == "APPLIED" || state.Phase == "CALICO_CREATE_ATTEMPTED") && (!localCAPISHA256Pattern.MatchString(state.WorkloadKubeconfigSHA256) || !localCAPISHA256Pattern.MatchString(state.CalicoManifestSHA256) || !validLocalCAPIWorkloadContainers(state.WorkloadContainers) || !validLocalCAPIWorkloadNodeIdentities(state.WorkloadNodes)) {
			return errors.New("APPLIED workload receipt lacks host access and CNI evidence")
		}
	}
	return nil
}

func localCAPIWorkloadRootFromStatePath(kubeconfigPath, name string) string {
	if kubeconfigPath == "" || name == "" {
		return ""
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(kubeconfigPath))))
}

func validLocalCAPIWorkloadNodeIdentities(nodes []localNodeIdentity) bool {
	if len(nodes) != 2 {
		return false
	}
	seenNames, seenUIDs := map[string]bool{}, map[string]bool{}
	for _, node := range nodes {
		if node.Name == "" || node.UID == "" || seenNames[node.Name] || seenUIDs[node.UID] {
			return false
		}
		seenNames[node.Name], seenUIDs[node.UID] = true, true
	}
	return true
}

func writeNewLocalCAPIWorkloadState(root string, state localCAPIWorkloadState) error {
	if err := validateLocalCAPIWorkloadState(state); err != nil {
		return err
	}
	if err := ensureLocalCAPIWorkloadParent(root); err != nil {
		return err
	}
	dir := localCAPIWorkloadDirectory(root, state.Name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := syncLocalCAPIDirectory(localCAPIWorkloadRoot(root)); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writePrivateNewFile(localCAPIWorkloadStatePath(root, state.Name), raw); err != nil {
		return err
	}
	return syncLocalCAPIDirectory(dir)
}

func readLocalCAPIWorkloadState(root, name string) (localCAPIWorkloadState, error) {
	if !localClusterNamePattern.MatchString(name) {
		return localCAPIWorkloadState{}, errors.New("invalid workload name")
	}
	if err := verifyLocalCAPIStateRoot(root); err != nil {
		return localCAPIWorkloadState{}, errors.New("workload state root is unavailable or unsafe")
	}
	for _, path := range []string{filepath.Join(root, "capi"), localCAPIWorkloadRoot(root), localCAPIWorkloadDirectory(root, name)} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return localCAPIWorkloadState{}, errors.New("workload state directory is unavailable or unsafe")
		}
	}
	path := localCAPIWorkloadStatePath(root, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return localCAPIWorkloadState{}, errors.New("workload receipt is unavailable or unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return localCAPIWorkloadState{}, err
	}
	var state localCAPIWorkloadState
	if err := jsonstrict.Decode(raw, &state); err != nil || state.Name != name || validateLocalCAPIWorkloadState(state) != nil {
		return localCAPIWorkloadState{}, errors.New("workload receipt is malformed or inconsistent")
	}
	return state, nil
}

func updateLocalCAPIWorkloadState(root string, next localCAPIWorkloadState) error {
	if err := validateLocalCAPIWorkloadState(next); err != nil {
		return err
	}
	previous, err := readLocalCAPIWorkloadState(root, next.Name)
	if err != nil || !sameLocalCAPIWorkloadIntent(previous, next) || !validLocalCAPIWorkloadTransition(previous, next) || !sameLocalCAPIWorkloadProgress(previous, next) {
		return errors.New("workload receipt is invalid or transition is not permitted")
	}
	dir, path := localCAPIWorkloadDirectory(root, next.Name), localCAPIWorkloadStatePath(root, next.Name)
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncLocalCAPIDirectory(dir)
}

func validLocalCAPIWorkloadTransition(previous, next localCAPIWorkloadState) bool {
	switch previous.Phase {
	case "APPLYING":
		return next.Phase == "APPLYING" || next.Phase == "WAITING_FOR_WORKLOAD_ACCESS" || next.Phase == "INCOMPLETE"
	case "WAITING_FOR_WORKLOAD_ACCESS":
		return next.Phase == "WAITING_FOR_WORKLOAD_ACCESS" || next.Phase == "CALICO_CREATE_ATTEMPTED" || next.Phase == "INCOMPLETE"
	case "CALICO_CREATE_ATTEMPTED":
		return next.Phase == "APPLIED" || next.Phase == "INCOMPLETE"
	case "INCOMPLETE":
		return localCAPIWorkloadCNIRecoveryCandidate(previous) && next.Phase == "WAITING_FOR_WORKLOAD_ACCESS" &&
			next.FailureCode == "" && next.RecoveryFromFailureCode == "CNI_ALREADY_PRESENT"
	default:
		return false
	}
}

func sameLocalCAPIWorkloadProgress(previous, next localCAPIWorkloadState) bool {
	if previous.RecoveryFromFailureCode != "" && previous.RecoveryFromFailureCode != next.RecoveryFromFailureCode {
		return false
	}
	if previous.CalicoCreateAttempted && !next.CalicoCreateAttempted {
		return false
	}
	if previous.ClusterUID != "" && previous.ClusterUID != next.ClusterUID {
		return false
	}
	if previous.WorkloadKubeconfigSHA256 != "" && previous.WorkloadKubeconfigSHA256 != next.WorkloadKubeconfigSHA256 {
		return false
	}
	if previous.CalicoManifestSHA256 != "" && previous.CalicoManifestSHA256 != next.CalicoManifestSHA256 {
		return false
	}
	if previous.WorkloadContainers != nil && !sameLocalContainers(previous.WorkloadContainers, next.WorkloadContainers) {
		return false
	}
	if previous.WorkloadNodes != nil && !sameLocalNodeIdentities(previous.WorkloadNodes, next.WorkloadNodes) {
		return false
	}
	if previous.WorkerReplacement != nil && !reflect.DeepEqual(previous.WorkerReplacement, next.WorkerReplacement) {
		return false
	}
	if previous.WorkerReplacement == nil && next.WorkerReplacement != nil &&
		(!localCAPIWorkloadCNIRecoveryCandidate(previous) || !validLocalCAPIWorkloadWorkerReplacement(next, *next.WorkerReplacement)) {
		return false
	}
	return true
}

func sameLocalCAPIWorkloadIntent(a, b localCAPIWorkloadState) bool {
	return a.Format == b.Format && a.Name == b.Name && a.Namespace == b.Namespace && a.ManagementName == b.ManagementName &&
		a.ManagementOwnerID == b.ManagementOwnerID && a.ManagementKindName == b.ManagementKindName && a.ManagementNodeUID == b.ManagementNodeUID &&
		a.ManagementKubeSystemID == b.ManagementKubeSystemID && a.ColimaProfile == b.ColimaProfile && a.WorkloadOwnerID == b.WorkloadOwnerID && a.Provider == b.Provider &&
		a.ManifestSHA256 == b.ManifestSHA256 && a.ControlPlaneReplicas == b.ControlPlaneReplicas && a.WorkerReplicas == b.WorkerReplicas &&
		a.PodCIDR == b.PodCIDR && a.ServiceCIDR == b.ServiceCIDR && a.WorkloadKindName == b.WorkloadKindName && a.WorkloadKubeconfig == b.WorkloadKubeconfig && a.CalicoSourceSHA256 == b.CalicoSourceSHA256 && a.CalicoManifestSHA256 == b.CalicoManifestSHA256
}

func verifyLocalCAPIWorkloadNameAbsent(ctx context.Context, runtime localRuntime, management localCAPIState, name string) error {
	raw, err := runLocalCAPIRaw(ctx, runtime, management.Provider, management.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", management.BootstrapKubeconfig, "--context", "kind-"+management.BootstrapKindName,
		"get", "clusters.cluster.x-k8s.io", "-A", "-o", "json")
	if err != nil {
		return errors.New("cannot verify workload Cluster name availability")
	}
	var list struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Items      []struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil || !validLocalCAPIWorkloadListEnvelope(list.APIVersion, list.Kind, "ClusterList") || list.Items == nil || len(list.Items) > 10000 {
		return errors.New("workload Cluster inventory is malformed")
	}
	seen := make(map[string]struct{}, len(list.Items))
	for _, item := range list.Items {
		if item.APIVersion != localCAPIWorkloadAPIVersion || item.Kind != "Cluster" || item.Metadata.Name == "" || item.Metadata.Namespace == "" {
			return errors.New("workload Cluster inventory contains incomplete identity")
		}
		key := item.Metadata.Namespace + "/" + item.Metadata.Name
		if _, duplicate := seen[key]; duplicate {
			return errors.New("workload Cluster inventory contains duplicate identity")
		}
		seen[key] = struct{}{}
		if item.Metadata.Name == name {
			return errors.New("a Cluster with this name already exists")
		}
	}
	return nil
}

func validLocalCAPIWorkloadListEnvelope(apiVersion, kind, resourceListKind string) bool {
	return (apiVersion == "v1" && kind == "List") || (apiVersion == localCAPIWorkloadAPIVersion && kind == resourceListKind)
}

func readLocalCAPIWorkloadCluster(ctx context.Context, runtime localRuntime, management localCAPIState, name string) (localCAPIWorkloadClusterObservation, error) {
	var cluster localCAPIWorkloadClusterObservation
	raw, err := runLocalCAPIRaw(ctx, runtime, management.Provider, management.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", management.BootstrapKubeconfig, "--context", "kind-"+management.BootstrapKindName,
		"get", "cluster.cluster.x-k8s.io", name, "-n", localCAPIWorkloadNamespace, "-o", "json")
	if err != nil || json.Unmarshal(raw, &cluster) != nil || cluster.APIVersion != localCAPIWorkloadAPIVersion || cluster.Kind != "Cluster" || cluster.Metadata.Name != name || cluster.Metadata.Namespace != localCAPIWorkloadNamespace || cluster.Metadata.UID == "" {
		return localCAPIWorkloadClusterObservation{}, errors.New("cannot verify created workload Cluster identity")
	}
	return cluster, nil
}

func observeLocalCAPIWorkloadStatus(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, cluster localCAPIWorkloadClusterObservation) localCAPIWorkloadReport {
	report := localCAPIWorkloadReport{Format: localCAPIWorkloadStateFormat, Operation: "STATUS", Cluster: state.Name, Namespace: state.Namespace, Management: state.ManagementName,
		HistoricalOperationPhase: state.Phase, HistoricalManagementPhase: string(management.Phase), ClusterUID: cluster.Metadata.UID, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	if cluster.Metadata.UID != state.ClusterUID || cluster.Metadata.Labels[localOwnerLabel] != state.WorkloadOwnerID {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "CLUSTER_IDENTITY_CHANGED"
		return report
	}
	if cluster.Spec.Topology == nil || cluster.Spec.Topology.ControlPlane.Replicas == nil || *cluster.Spec.Topology.ControlPlane.Replicas != int32(state.ControlPlaneReplicas) || len(cluster.Spec.Topology.Workers.MachineDeployments) != 1 || cluster.Spec.Topology.Workers.MachineDeployments[0].Replicas == nil || *cluster.Spec.Topology.Workers.MachineDeployments[0].Replicas != int32(state.WorkerReplicas) {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "CLUSTER_TOPOLOGY_CHANGED"
		return report
	}
	if state.PodCIDR != "" && !localCAPIWorkloadClusterNetworkMatches(cluster, state.PodCIDR, state.ServiceCIDR) {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "POD_CIDR_MISMATCH"
		return report
	}
	var conditionErr error
	report.ClusterReady, conditionErr = localCAPIWorkloadConditionReady(cluster.Status.Conditions, "Available")
	if conditionErr == nil {
		report.ControlPlaneReady, conditionErr = localCAPIWorkloadConditionReady(cluster.Status.Conditions, "ControlPlaneAvailable")
	}
	workersAvailable := false
	if conditionErr == nil {
		workersAvailable, conditionErr = localCAPIWorkloadConditionReady(cluster.Status.Conditions, "WorkersAvailable")
	}
	if conditionErr != nil {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "CLUSTER_CONDITIONS_AMBIGUOUS"
		return report
	}
	raw, err := runLocalCAPIRaw(ctx, runtime, management.Provider, management.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", management.BootstrapKubeconfig, "--context", "kind-"+management.BootstrapKindName,
		"get", "machines.cluster.x-k8s.io", "-n", state.Namespace, "-l", "cluster.x-k8s.io/cluster-name="+state.Name, "-o", "json")
	if err != nil {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "MACHINE_OBSERVATION_FAILED"
		return report
	}
	var machines localCAPIWorkloadMachineList
	if json.Unmarshal(raw, &machines) != nil || !validLocalCAPIWorkloadListEnvelope(machines.APIVersion, machines.Kind, "MachineList") || machines.Items == nil || len(machines.Items) > 1000 {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "MACHINE_INVENTORY_MALFORMED"
		return report
	}
	report.MachineCount = len(machines.Items)
	controlPlaneCount, workerCount, readyControlPlane, readyWorkers := 0, 0, 0, 0
	seenMachineUIDs, seenMachineNames := make(map[string]struct{}, len(machines.Items)), make(map[string]struct{}, len(machines.Items))
	for _, machine := range machines.Items {
		if machine.APIVersion != localCAPIWorkloadAPIVersion || machine.Kind != "Machine" || machine.Metadata.Name == "" || machine.Metadata.Namespace != state.Namespace || machine.Metadata.UID == "" || machine.Metadata.Labels["cluster.x-k8s.io/cluster-name"] != state.Name {
			report.Result, report.ReasonCode = "UNVERIFIABLE", "MACHINE_IDENTITY_MISSING"
			return report
		}
		if _, duplicateUID := seenMachineUIDs[machine.Metadata.UID]; duplicateUID {
			report.Result, report.ReasonCode = "UNVERIFIABLE", "MACHINE_INVENTORY_AMBIGUOUS"
			return report
		}
		if _, duplicateName := seenMachineNames[machine.Metadata.Name]; duplicateName {
			report.Result, report.ReasonCode = "UNVERIFIABLE", "MACHINE_INVENTORY_AMBIGUOUS"
			return report
		}
		seenMachineUIDs[machine.Metadata.UID] = struct{}{}
		seenMachineNames[machine.Metadata.Name] = struct{}{}
		readyCondition := false
		for _, condition := range machine.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				readyCondition = true
			}
		}
		ready := machine.Status.NodeRef != nil && machine.Status.NodeRef.Name != "" && readyCondition
		_, effectiveNodes := localCAPIWorkloadEffectiveIdentity(state)
		if machine.Status.NodeRef != nil && len(effectiveNodes) > 0 && !localCAPIWorkloadNodeNameRecorded(effectiveNodes, machine.Status.NodeRef.Name) {
			report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "MACHINE_NODE_IDENTITY_CHANGED"
			return report
		}
		if _, isControlPlane := machine.Metadata.Labels["cluster.x-k8s.io/control-plane"]; isControlPlane {
			controlPlaneCount++
			if ready {
				readyControlPlane++
			}
		} else {
			workerCount++
			if ready {
				readyWorkers++
			}
		}
		if ready {
			report.ReadyMachineCount++
		}
	}
	report.ControlPlaneReady = report.ControlPlaneReady && controlPlaneCount == state.ControlPlaneReplicas && readyControlPlane == state.ControlPlaneReplicas
	report.WorkersReady = workersAvailable && workerCount == state.WorkerReplicas && readyWorkers == state.WorkerReplicas
	if !report.ClusterReady || !report.ControlPlaneReady || !report.WorkersReady {
		report.Result = "PROVISIONING"
		switch {
		case !report.ClusterReady:
			report.ReasonCode = "CLUSTER_AVAILABLE_NOT_CONFIRMED"
		case !report.ControlPlaneReady:
			report.ReasonCode = "CONTROL_PLANE_AVAILABLE_NOT_CONFIRMED"
		default:
			report.ReasonCode = "WORKERS_AVAILABLE_NOT_CONFIRMED"
		}
		return report
	}
	if state.WorkloadKubeconfig == "" || state.WorkloadKubeconfigSHA256 == "" || len(state.WorkloadContainers) == 0 || len(state.WorkloadNodes) == 0 || state.CalicoManifestSHA256 == "" {
		report.Result, report.ReasonCode = "PROVISIONING", "WORKLOAD_ACCESS_EVIDENCE_NOT_RECORDED"
		return report
	}
	effectiveContainers, effectiveNodes := localCAPIWorkloadEffectiveIdentity(state)
	if err := verifyLocalCAPIWorkloadKindIdentity(ctx, runtime, management, state, effectiveContainers); err != nil {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "WORKLOAD_KIND_IDENTITY_CHANGED"
		return report
	}
	kubeconfigInfo, kubeconfigErr := os.Lstat(state.WorkloadKubeconfig)
	kubeconfig, readErr := os.ReadFile(state.WorkloadKubeconfig)
	if kubeconfigErr != nil || !kubeconfigInfo.Mode().IsRegular() || kubeconfigInfo.Mode()&os.ModeSymlink != 0 || kubeconfigInfo.Mode().Perm() != 0o600 || readErr != nil || localCAPIBytesSHA256(kubeconfig) != state.WorkloadKubeconfigSHA256 {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "WORKLOAD_KUBECONFIG_UNVERIFIABLE"
		return report
	}
	kindKubeconfig, kindErr := runLocalPinned(ctx, runtime, management.Provider, "kind", "get", "kubeconfig", "--name", state.WorkloadKindName)
	if kindErr != nil || compareKindKubeconfig(kindKubeconfig, kubeconfig, "kind-"+state.WorkloadKindName) != nil {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "WORKLOAD_KUBECONFIG_IDENTITY_CHANGED"
		return report
	}
	nodesRaw, nodesErr := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, "get", "nodes", "-o", "json")
	if nodesErr != nil {
		report.Result, report.ReasonCode = "UNVERIFIABLE", "WORKLOAD_NODE_OBSERVATION_FAILED"
		return report
	}
	nodes, nodesErr := parseLocalCAPIWorkloadNodes(nodesRaw)
	if nodesErr != nil || !sameLocalNodeIdentities(nodes, effectiveNodes) {
		report.Result, report.ReasonCode = "IDENTITY_MISMATCH", "WORKLOAD_NODE_IDENTITY_CHANGED"
		return report
	}
	report.ReadyNodeCount = countLocalCAPIWorkloadReadyNodes(nodesRaw)
	if report.ReadyNodeCount != len(effectiveNodes) {
		report.Result, report.ReasonCode = "PROVISIONING", "WORKLOAD_NODES_NOT_READY"
		return report
	}
	if !localCAPIWorkloadCalicoReady(ctx, runtime, management, state, len(effectiveNodes)) {
		report.Result, report.ReasonCode = "PROVISIONING", "CALICO_NOT_READY"
		return report
	}
	report.CNIReady = true
	report.Result = "READY"
	return report
}

func sameLocalNodeIdentities(a, b []localNodeIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]localNodeIdentity(nil), a...), append([]localNodeIdentity(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].Name < left[j].Name })
	sort.Slice(right, func(i, j int) bool { return right[i].Name < right[j].Name })
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func countLocalCAPIWorkloadReadyNodes(raw []byte) int {
	var list localCAPIWorkloadNodeList
	if json.Unmarshal(raw, &list) != nil {
		return -1
	}
	ready := 0
	for _, node := range list.Items {
		count, value := 0, false
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" {
				count++
				value = condition.Status == "True"
			}
		}
		if count != 1 {
			return -1
		}
		if value {
			ready++
		}
	}
	return ready
}

func localCAPIWorkloadCalicoReady(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, expectedNodes int) bool {
	manifestInfo, manifestErr := os.Lstat(localCAPIWorkloadCalicoPath(runtime.stateRoot, state.Name))
	manifestRaw, readManifestErr := os.ReadFile(localCAPIWorkloadCalicoPath(runtime.stateRoot, state.Name))
	if manifestErr != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 || manifestInfo.Mode().Perm() != 0o600 || readManifestErr != nil || localCAPIBytesSHA256(manifestRaw) != state.CalicoManifestSHA256 || validateLocalCAPIWorkloadCalicoManifest(manifestRaw, state.PodCIDR) != nil {
		return false
	}
	dsRaw, err := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, "get", "daemonset", "calico-node", "-n", "kube-system", "--ignore-not-found", "-o", "json")
	if err != nil {
		return false
	}
	var ds struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Desired int32 `json:"desiredNumberScheduled"`
			Ready   int32 `json:"numberReady"`
			Updated int32 `json:"updatedNumberScheduled"`
		} `json:"status"`
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Image string `json:"image"`
					} `json:"containers"`
					InitContainers []struct {
						Image string `json:"image"`
					} `json:"initContainers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if json.Unmarshal(dsRaw, &ds) != nil || ds.APIVersion != "apps/v1" || ds.Kind != "DaemonSet" || ds.Metadata.Name != "calico-node" || ds.Metadata.Namespace != "kube-system" || ds.Status.Desired != int32(expectedNodes) || ds.Status.Ready != int32(expectedNodes) || ds.Status.Updated != int32(expectedNodes) || !localCAPIWorkloadImagesPinned(ds.Spec.Template.Spec.Containers, ds.Spec.Template.Spec.InitContainers) {
		return false
	}
	deploymentRaw, err := runLocalCAPIWorkloadKubeconfig(ctx, runtime, management, state, "get", "deployment", "calico-kube-controllers", "-n", "kube-system", "--ignore-not-found", "-o", "json")
	if err != nil {
		return false
	}
	var deployment struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Replicas *int32 `json:"replicas"`
			Template struct {
				Spec struct {
					Containers []struct {
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
		Status struct {
			Available int32 `json:"availableReplicas"`
			Ready     int32 `json:"readyReplicas"`
		} `json:"status"`
	}
	if json.Unmarshal(deploymentRaw, &deployment) != nil || deployment.APIVersion != "apps/v1" || deployment.Kind != "Deployment" || deployment.Metadata.Name != "calico-kube-controllers" || deployment.Metadata.Namespace != "kube-system" || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Status.Available < 1 || deployment.Status.Ready < 1 || !localCAPIWorkloadImagesPinned(deployment.Spec.Template.Spec.Containers, nil) {
		return false
	}
	return true
}

func localCAPIWorkloadImagesPinned(containers, initContainers []struct {
	Image string `json:"image"`
}) bool {
	if len(containers) == 0 {
		return false
	}
	for _, container := range append(append([]struct {
		Image string `json:"image"`
	}(nil), containers...), initContainers...) {
		if !strings.HasPrefix(container.Image, "quay.io/calico/") || !strings.HasSuffix(container.Image, ":v3.33.0") {
			return false
		}
	}
	return true
}

func localCAPIWorkloadConditionReady(conditions []localCAPIWorkloadCondition, requiredType string) (bool, error) {
	var observed *string
	for i := range conditions {
		if conditions[i].Type != requiredType {
			continue
		}
		if observed != nil {
			return false, errors.New("duplicate required condition")
		}
		status := conditions[i].Status
		observed = &status
	}
	if observed == nil {
		return false, nil
	}
	switch *observed {
	case "True":
		return true, nil
	case "False", "Unknown":
		return false, nil
	default:
		return false, errors.New("required condition has an invalid status")
	}
}

func writeLocalCAPIWorkloadReport(output io.Writer, report localCAPIWorkloadReport) error {
	if report.Format == "" {
		report.Format = localCAPIWorkloadStateFormat
	}
	if report.ObservedAt == "" {
		report.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return errors.New("cannot encode CAPI workload status")
	}
	_, err = fmt.Fprintln(output, string(raw))
	return err
}
