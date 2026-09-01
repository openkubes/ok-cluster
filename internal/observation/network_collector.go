package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const maximumNetworkSourceBytes = 4 * 1024 * 1024

// NetworkRawGetter deliberately exposes only GET. Concrete management and
// workload adapters must each bind their own credential and API endpoint.
type NetworkRawGetter interface {
	Get(context.Context, string) ([]byte, error)
}

// FixedCiliumProbe exposes no command argument. A concrete adapter may execute
// only `cilium-health status --probe --output json` in the selected Pod/UID.
type FixedCiliumProbe interface {
	Probe(context.Context, string, string) ([]byte, error)
}

type NetworkCollectorConfig struct {
	Namespace        string
	Name             string
	HCPName          string
	TargetClusterUID string
	Clock            func() time.Time
}

// NetworkSourceCollector performs one bounded source collection. It has no
// mutation, discovery, watch, retry, repair, arbitrary query, or arbitrary
// command path.
type NetworkSourceCollector struct {
	management NetworkRawGetter
	workload   NetworkRawGetter
	probe      FixedCiliumProbe
	config     NetworkCollectorConfig
}

func NewNetworkSourceCollector(management, workload NetworkRawGetter, probe FixedCiliumProbe, config NetworkCollectorConfig) (*NetworkSourceCollector, error) {
	if management == nil || workload == nil || probe == nil || config.Clock == nil {
		return nil, errors.New("network collector sources and clock are required")
	}
	if !validDNSLabel(config.Namespace) || !validDNSLabel(config.Name) || !validDNSLabel(config.HCPName) {
		return nil, errors.New("network collector object identity is invalid")
	}
	if !validUID(config.TargetClusterUID) {
		return nil, errors.New("network collector target Cluster UID is invalid")
	}
	return &NetworkSourceCollector{management: management, workload: workload, probe: probe, config: config}, nil
}

// Observe collects and immediately evaluates one current normalized snapshot.
func (collector *NetworkSourceCollector) Observe(ctx context.Context, policy Policy, profile NetworkProfile) (Evidence, error) {
	snapshot, err := collector.Collect(ctx, policy)
	if err != nil {
		return Evidence{}, err
	}
	return EvaluateNetworkSnapshot(policy, profile, snapshot)
}

// Collect performs at most two management reads, five workload reads and one
// fixed Cilium probe. Every collection is size-bounded and normalized before
// raw payloads leave the call frame.
func (collector *NetworkSourceCollector) Collect(ctx context.Context, policy Policy) (NetworkSnapshot, error) {
	if err := validatePolicy(policy, true); err != nil {
		return NetworkSnapshot{}, err
	}
	if policy.TargetClusterUID != collector.config.TargetClusterUID {
		return NetworkSnapshot{}, errors.New("network collector authority differs from the runtime-bound target Cluster")
	}
	namespace, name, hcpName := collector.config.Namespace, collector.config.Name, collector.config.HCPName
	hcpPath, hrpPath := managementNetworkPaths(namespace, name, hcpName)

	hcpObject, err := getNetworkObject(ctx, collector.management, hcpPath)
	if err != nil {
		return NetworkSnapshot{}, fmt.Errorf("collect exact HCP: %w", err)
	}
	hrpList, err := getNetworkObject(ctx, collector.management, hrpPath)
	if err != nil {
		return NetworkSnapshot{}, fmt.Errorf("collect bounded HRP set: %w", err)
	}
	hcp, err := normalizeHCP(hcpObject, namespace, hcpName, name, policy)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	hrpCount, hrp, err := normalizeHRPList(hrpList, namespace, name, hcpName, hcp.UID, policy)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	snapshot := NetworkSnapshot{
		Format: NetworkSnapshotFormat, ObservedAt: collector.config.Clock().UTC().Format(time.RFC3339Nano),
		TargetClusterUID: policy.TargetClusterUID, IntentRevision: policy.IntentRevision,
		EnablementRevision: hcp.EnablementRevision, HCP: hcp, HRPCount: hrpCount, HRP: hrp,
	}
	// CAAPH objects are created before their status is initialized and before
	// the workload API is necessarily reachable. Preserve that as a bounded
	// Unknown snapshot instead of turning normal convergence into an
	// operational source failure or attempting the functional probe too early.
	if !networkAddonReadyForWorkloadCollection(hcp, hrpCount, hrp) {
		return snapshot, nil
	}

	nodesObject, err := getNetworkObject(ctx, collector.workload, "/api/v1/nodes")
	if err != nil {
		return NetworkSnapshot{}, fmt.Errorf("collect bounded Node set: %w", err)
	}
	nodes, nodeNames, err := normalizeNodes(nodesObject)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	components := make([]NetworkComponent, 0, 3)
	for _, source := range []struct {
		path          string
		kind          string
		name          string
		id            string
		containerName string
	}{
		{"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium", "DaemonSet", "cilium", "cilium-agent", "cilium-agent"},
		{"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium-envoy", "DaemonSet", "cilium-envoy", "cilium-envoy", "cilium-envoy"},
		{"/apis/apps/v1/namespaces/kube-system/deployments/cilium-operator", "Deployment", "cilium-operator", "cilium-operator", "cilium-operator"},
	} {
		object, getErr := getNetworkObject(ctx, collector.workload, source.path)
		if getErr != nil {
			return NetworkSnapshot{}, fmt.Errorf("collect exact %s: %w", source.id, getErr)
		}
		component, normalizeErr := normalizeComponent(object, source.kind, source.name, source.id, source.containerName)
		if normalizeErr != nil {
			return NetworkSnapshot{}, normalizeErr
		}
		components = append(components, component)
	}
	podsObject, err := getNetworkObject(ctx, collector.workload, "/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium")
	if err != nil {
		return NetworkSnapshot{}, fmt.Errorf("collect bounded Cilium Pod set: %w", err)
	}
	pods, selectedName, selectedUID, err := normalizeAgentPods(podsObject, nodeNames)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	snapshot.Nodes, snapshot.Components, snapshot.AgentPods = nodes, components, pods
	// Pod/container status and Node network Conditions are eventually
	// populated. The evaluator can classify those normalized gaps as Unknown;
	// executing cilium-health before they converge would instead manufacture
	// an operational error that the bounded observer must not retry.
	if !networkRuntimeReadyForProbe(nodes, components, pods) {
		return snapshot, nil
	}
	probeRaw, err := collector.probe.Probe(ctx, selectedName, selectedUID)
	if err != nil {
		return NetworkSnapshot{}, errors.New("fixed Cilium functional probe failed")
	}
	probe, err := normalizeNetworkProbe(probeRaw, nodeNames)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	snapshot.Probe = probe
	return snapshot, nil
}

func networkAddonReadyForWorkloadCollection(hcp NetworkAddonSource, hrpCount int, hrp NetworkAddonSource) bool {
	ready := func(source NetworkAddonSource, required ...string) bool {
		if source.Generation <= 0 || source.StatusObservedGeneration != source.Generation || !source.TargetSelected {
			return false
		}
		conditions := make(map[string]NetworkSourceCondition, len(source.Conditions))
		for _, condition := range source.Conditions {
			conditions[condition.Type] = condition
		}
		for _, name := range required {
			condition, exists := conditions[name]
			if !exists || condition.Status != "True" || condition.ObservedGeneration != source.Generation {
				return false
			}
		}
		return true
	}
	return ready(hcp, "Ready", "HelmReleaseProxySpecsUpToDate", "HelmReleaseProxiesReady") &&
		hrpCount == 1 && ready(hrp, "Ready", "HelmReleaseReady") && hrp.ReleaseStatus == "deployed" && hrp.ReleaseRevision > 0
}

func networkRuntimeReadyForProbe(nodes []NetworkNode, components []NetworkComponent, pods []NetworkAgentPod) bool {
	if len(nodes) == 0 || len(components) != 3 || len(pods) != len(nodes) {
		return false
	}
	for _, node := range nodes {
		if node.ProviderID == "" || node.Ready != "True" || node.NetworkUnavailable != "False" || node.NetworkUnavailableReason != "CiliumIsUp" {
			return false
		}
	}
	for _, component := range components {
		if component.Generation <= 0 || component.ObservedGeneration != component.Generation || component.Desired <= 0 || component.Updated != component.Desired || component.Available != component.Desired || component.Ready != component.Desired {
			return false
		}
	}
	for _, pod := range pods {
		if pod.Phase != "Running" || !pod.Ready {
			return false
		}
	}
	return true
}

func getNetworkObject(ctx context.Context, source NetworkRawGetter, path string) (map[string]any, error) {
	raw, err := source.Get(ctx, path)
	if err != nil {
		return nil, errors.New("bounded network source GET failed")
	}
	if len(raw) == 0 || len(raw) > maximumNetworkSourceBytes {
		return nil, errors.New("network source response size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("network source returned invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("network source returned trailing JSON")
	}
	return value, nil
}

func normalizeHCP(object map[string]any, namespace, hcpName, clusterName string, policy Policy) (NetworkAddonSource, error) {
	if text(object["apiVersion"]) != "addons.cluster.x-k8s.io/v1alpha1" || text(object["kind"]) != "HelmChartProxy" {
		return NetworkAddonSource{}, errors.New("HCP API identity is invalid")
	}
	metadata, err := objectMap(object, "metadata")
	if err != nil || text(metadata["namespace"]) != namespace || text(metadata["name"]) != hcpName {
		return NetworkAddonSource{}, errors.New("HCP object identity differs from exact target")
	}
	spec, err := objectMap(object, "spec")
	if err != nil {
		return NetworkAddonSource{}, errors.New("HCP spec is missing")
	}
	specDigest, err := addonSpecDigest(spec, false)
	if err != nil {
		return NetworkAddonSource{}, err
	}
	status, _ := objectMap(object, "status")
	matching, err := optionalObjectSlice(status, "matchingClusters", 10)
	if err != nil {
		return NetworkAddonSource{}, errors.New("HCP target selection is invalid")
	}
	selected := len(matching) == 1 && textMap(matching[0], "namespace") == namespace && textMap(matching[0], "name") == clusterName
	annotations, _ := objectMap(metadata, "annotations")
	conditions, err := normalizeSourceConditions(status)
	if err != nil {
		return NetworkAddonSource{}, err
	}
	return NetworkAddonSource{
		UID: text(metadata["uid"]), Generation: integer(metadata["generation"]),
		StatusObservedGeneration: integer(status["observedGeneration"]), SpecDigest: specDigest,
		IntentRevision: text(annotations["openkubes.io/intent-revision"]), EnablementRevision: text(annotations["openkubes.io/enablement-revision"]),
		TargetClusterUID: policy.TargetClusterUID, TargetSelected: selected,
		Conditions: conditions,
	}, nil
}

func normalizeHRPList(list map[string]any, namespace, clusterName, hcpName, hcpUID string, policy Policy) (int, NetworkAddonSource, error) {
	if text(list["apiVersion"]) != "addons.cluster.x-k8s.io/v1alpha1" || text(list["kind"]) != "HelmReleaseProxyList" {
		return 0, NetworkAddonSource{}, errors.New("HRP collection identity is invalid")
	}
	items, err := requiredObjectSlice(list, "items", 10)
	if err != nil {
		return 0, NetworkAddonSource{}, errors.New("HRP collection is invalid or exceeds bounded size")
	}
	if len(items) != 1 {
		return len(items), NetworkAddonSource{}, nil
	}
	object := items[0]
	metadata, err := objectMap(object, "metadata")
	if err != nil || text(object["apiVersion"]) != "addons.cluster.x-k8s.io/v1alpha1" || text(object["kind"]) != "HelmReleaseProxy" || text(metadata["namespace"]) != namespace {
		return 0, NetworkAddonSource{}, errors.New("HRP object identity is invalid")
	}
	spec, err := objectMap(object, "spec")
	if err != nil {
		return 0, NetworkAddonSource{}, errors.New("HRP spec is missing")
	}
	clusterRef, _ := objectMap(spec, "clusterRef")
	selected := text(clusterRef["apiVersion"]) == "cluster.x-k8s.io/v1beta2" && text(clusterRef["kind"]) == "Cluster" && text(clusterRef["namespace"]) == namespace && text(clusterRef["name"]) == clusterName
	ownerUID, err := controllerOwnerUID(metadata, "HelmChartProxy", hcpName)
	if err != nil {
		return 0, NetworkAddonSource{}, err
	}
	specDigest, err := addonSpecDigest(spec, true)
	if err != nil {
		return 0, NetworkAddonSource{}, err
	}
	status, _ := objectMap(object, "status")
	conditions, err := normalizeSourceConditions(status)
	if err != nil {
		return 0, NetworkAddonSource{}, err
	}
	return 1, NetworkAddonSource{
		UID: text(metadata["uid"]), Generation: integer(metadata["generation"]),
		StatusObservedGeneration: integer(status["observedGeneration"]), SpecDigest: specDigest,
		IntentRevision: policy.IntentRevision, EnablementRevision: policy.EnablementRevision,
		OwnerUID: ownerUID, TargetClusterUID: policy.TargetClusterUID, TargetSelected: selected && ownerUID == hcpUID,
		ReleaseStatus: text(status["status"]), ReleaseRevision: integer(status["revision"]),
		Conditions: conditions,
	}, nil
}

func addonSpecDigest(spec map[string]any, includeClusterRef bool) (string, error) {
	keys := []string{"chartName", "repoURL", "version", "releaseName", "namespace", "reconcileStrategy", "valuesTemplate", "options"}
	if includeClusterRef {
		keys = []string{"chartName", "repoURL", "version", "releaseName", "namespace", "reconcileStrategy", "values", "clusterRef"}
	}
	semantic := make(map[string]any, len(keys))
	for _, key := range keys {
		value := spec[key]
		// CAAPH defaults an omitted enableClientCache to false when persisting
		// HelmChartProxy objects. The API-defaulted representation and the
		// submitted representation have identical Helm semantics, so their
		// revision identity must not diverge.
		if key == "options" {
			if options, ok := value.(map[string]any); ok {
				normalized := make(map[string]any, len(options))
				for option, optionValue := range options {
					if option == "enableClientCache" && optionValue == false {
						continue
					}
					normalized[option] = optionValue
				}
				value = normalized
			}
		}
		semantic[key] = value
	}
	return canonicalDigest(semantic)
}

func normalizeNodes(list map[string]any) ([]NetworkNode, map[string]string, error) {
	if text(list["apiVersion"]) != "v1" || text(list["kind"]) != "NodeList" {
		return nil, nil, errors.New("Node collection identity is invalid")
	}
	items, err := requiredObjectSlice(list, "items", 100)
	if err != nil {
		return nil, nil, errors.New("Node collection is invalid or exceeds bounded size")
	}
	nodes := make([]NetworkNode, 0, len(items))
	names := make(map[string]string, len(items))
	for _, object := range items {
		metadata, _ := objectMap(object, "metadata")
		spec, _ := objectMap(object, "spec")
		status, _ := objectMap(object, "status")
		name, uid := text(metadata["name"]), text(metadata["uid"])
		if !validDNSLabel(name) || uid == "" {
			return nil, nil, errors.New("Node runtime identity is invalid")
		}
		if _, duplicate := names[name]; duplicate {
			return nil, nil, errors.New("Node name is duplicated")
		}
		ready, network, err := exactNodeConditions(status)
		if err != nil {
			return nil, nil, err
		}
		names[name] = uid
		nodes = append(nodes, NetworkNode{UID: uid, ProviderID: text(spec["providerID"]), Ready: text(ready["status"]), NetworkUnavailable: text(network["status"]), NetworkUnavailableReason: text(network["reason"])})
	}
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].UID < nodes[right].UID })
	return nodes, names, nil
}

func normalizeComponent(object map[string]any, kind, name, id, containerName string) (NetworkComponent, error) {
	if text(object["apiVersion"]) != "apps/v1" || text(object["kind"]) != kind {
		return NetworkComponent{}, fmt.Errorf("%s API identity is invalid", id)
	}
	metadata, _ := objectMap(object, "metadata")
	if text(metadata["namespace"]) != "kube-system" || text(metadata["name"]) != name {
		return NetworkComponent{}, fmt.Errorf("%s object identity differs from exact target", id)
	}
	spec, _ := objectMap(object, "spec")
	template, _ := objectMap(spec, "template")
	podSpec, _ := objectMap(template, "spec")
	containers, err := requiredObjectSlice(podSpec, "containers", 20)
	if err != nil {
		return NetworkComponent{}, fmt.Errorf("%s Pod template containers are invalid", id)
	}
	image := containerImage(containers, containerName)
	status, _ := objectMap(object, "status")
	desired := integer(status["desiredNumberScheduled"])
	updated := integer(status["updatedNumberScheduled"])
	available := integer(status["numberAvailable"])
	ready := integer(status["numberReady"])
	if kind == "Deployment" {
		desired = integer(spec["replicas"])
		if desired == 0 {
			desired = 1
		}
		updated, available, ready = integer(status["updatedReplicas"]), integer(status["availableReplicas"]), integer(status["readyReplicas"])
	}
	return NetworkComponent{ID: id, UID: text(metadata["uid"]), Generation: integer(metadata["generation"]), ObservedGeneration: integer(status["observedGeneration"]), Desired: desired, Updated: updated, Available: available, Ready: ready, Image: image}, nil
}

func normalizeAgentPods(list map[string]any, nodeNames map[string]string) ([]NetworkAgentPod, string, string, error) {
	if text(list["apiVersion"]) != "v1" || text(list["kind"]) != "PodList" {
		return nil, "", "", errors.New("Cilium Pod collection identity is invalid")
	}
	items, err := requiredObjectSlice(list, "items", 100)
	if err != nil {
		return nil, "", "", errors.New("Cilium Pod collection size is invalid")
	}
	if len(items) == 0 {
		return []NetworkAgentPod{}, "", "", nil
	}
	type namedPod struct {
		name string
		pod  NetworkAgentPod
	}
	normalized := make([]namedPod, 0, len(items))
	for _, object := range items {
		metadata, _ := objectMap(object, "metadata")
		spec, _ := objectMap(object, "spec")
		status, _ := objectMap(object, "status")
		name, uid, nodeName := text(metadata["name"]), text(metadata["uid"]), text(spec["nodeName"])
		nodeUID := nodeNames[nodeName]
		if !validDNSLabel(name) || uid == "" || nodeUID == "" {
			return nil, "", "", errors.New("Cilium Pod runtime identity is invalid")
		}
		ready := false
		containerStatuses, statusErr := optionalObjectSlice(status, "containerStatuses", 20)
		if statusErr != nil {
			return nil, "", "", errors.New("Cilium Pod container status is invalid")
		}
		for _, item := range containerStatuses {
			if text(item["name"]) == "cilium-agent" {
				ready, _ = item["ready"].(bool)
			}
		}
		normalized = append(normalized, namedPod{name: name, pod: NetworkAgentPod{UID: uid, NodeUID: nodeUID, Phase: text(status["phase"]), Ready: ready}})
	}
	sort.Slice(normalized, func(left, right int) bool { return normalized[left].name < normalized[right].name })
	pods := make([]NetworkAgentPod, 0, len(normalized))
	for _, item := range normalized {
		pods = append(pods, item.pod)
	}
	return pods, normalized[0].name, normalized[0].pod.UID, nil
}

func normalizeNetworkProbe(raw []byte, nodeNames map[string]string) (NetworkProbe, error) {
	if len(raw) == 0 || len(raw) > maximumNetworkSourceBytes {
		return NetworkProbe{}, errors.New("functional probe response size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return NetworkProbe{}, errors.New("functional probe returned invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return NetworkProbe{}, errors.New("functional probe returned trailing JSON")
	}
	interval, err := time.ParseDuration(text(value["probeInterval"]))
	if err != nil || interval <= 0 {
		return NetworkProbe{}, errors.New("functional probe interval is invalid")
	}
	paths := make([]NetworkProbePath, 0, len(nodeNames)*4)
	probeNodes, err := requiredObjectSlice(value, "nodes", 100)
	if err != nil {
		return NetworkProbe{}, errors.New("functional probe Node collection is invalid")
	}
	for _, node := range probeNodes {
		uid := nodeNames[text(node["name"])]
		if uid == "" {
			return NetworkProbe{}, errors.New("functional probe contains a foreign Node")
		}
		for _, scope := range []string{"host", "health-endpoint"} {
			scopeObject, _ := objectMap(node, scope)
			address, _ := objectMap(scopeObject, "primary-address")
			for _, protocol := range []string{"http", "icmp"} {
				path, ok := address[protocol].(map[string]any)
				if !ok {
					return NetworkProbe{}, errors.New("functional probe path is missing")
				}
				statusRaw, present := path["status"]
				status := ""
				if present {
					var valid bool
					status, valid = statusRaw.(string)
					if !valid {
						return NetworkProbe{}, errors.New("functional probe status representation is invalid")
					}
				}
				paths = append(paths, NetworkProbePath{NodeUID: uid, Scope: scope, Protocol: protocol, StatusPresent: present, Status: status, LastProbed: text(path["lastProbed"])})
			}
		}
	}
	sort.Slice(paths, func(left, right int) bool {
		leftKey := paths[left].NodeUID + paths[left].Scope + paths[left].Protocol
		rightKey := paths[right].NodeUID + paths[right].Scope + paths[right].Protocol
		return leftKey < rightKey
	})
	return NetworkProbe{ResponseTimestamp: text(value["timestamp"]), ProbeIntervalMilliseconds: interval.Milliseconds(), Paths: paths}, nil
}

func normalizeSourceConditions(status map[string]any) ([]NetworkSourceCondition, error) {
	items, err := optionalObjectSlice(status, "conditions", 16)
	if err != nil {
		return nil, errors.New("add-on source Conditions are invalid")
	}
	result := make([]NetworkSourceCondition, 0, len(items))
	for _, item := range items {
		result = append(result, NetworkSourceCondition{Type: text(item["type"]), Status: text(item["status"]), ObservedGeneration: integer(item["observedGeneration"])})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Type < result[right].Type })
	return result, nil
}

func exactNodeConditions(status map[string]any) (map[string]any, map[string]any, error) {
	var ready, network map[string]any
	items, err := requiredObjectSlice(status, "conditions", 64)
	if err != nil {
		return nil, nil, errors.New("Node Conditions are invalid")
	}
	for _, item := range items {
		switch text(item["type"]) {
		case "Ready":
			if ready != nil {
				return nil, nil, errors.New("Node Ready Condition is duplicated")
			}
			ready = item
		case "NetworkUnavailable":
			if network != nil {
				return nil, nil, errors.New("Node NetworkUnavailable Condition is duplicated")
			}
			network = item
		}
	}
	if ready == nil && network == nil {
		return map[string]any{}, map[string]any{}, nil
	}
	if ready == nil || network == nil {
		return nil, nil, errors.New("Node network Conditions are incomplete")
	}
	return ready, network, nil
}

func controllerOwnerUID(metadata map[string]any, kind, name string) (string, error) {
	owners, err := requiredObjectSlice(metadata, "ownerReferences", 16)
	if err != nil {
		return "", errors.New("HRP owner references are invalid")
	}
	var uid string
	for _, owner := range owners {
		controller, _ := owner["controller"].(bool)
		if controller && text(owner["kind"]) == kind && text(owner["name"]) == name {
			if uid != "" {
				return "", errors.New("HRP controller owner is ambiguous")
			}
			uid = text(owner["uid"])
		}
	}
	return uid, nil
}

func containerImage(containers []map[string]any, name string) string {
	var image string
	for _, container := range containers {
		if text(container["name"]) == name {
			if image != "" {
				return ""
			}
			image = text(container["image"])
		}
	}
	return image
}

func objectMap(parent map[string]any, key string) (map[string]any, error) {
	value, ok := parent[key].(map[string]any)
	if !ok {
		return map[string]any{}, fmt.Errorf("%s is not an object", key)
	}
	return value, nil
}

func requiredObjectSlice(parent map[string]any, key string, maximum int) ([]map[string]any, error) {
	raw, ok := parent[key].([]any)
	if !ok || len(raw) > maximum {
		return nil, fmt.Errorf("%s is not a bounded array", key)
	}
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s contains a non-object item", key)
		}
		result = append(result, object)
	}
	return result, nil
}

func optionalObjectSlice(parent map[string]any, key string, maximum int) ([]map[string]any, error) {
	if _, exists := parent[key]; !exists {
		return []map[string]any{}, nil
	}
	return requiredObjectSlice(parent, key, maximum)
}

func textMap(parent map[string]any, key string) string { return text(parent[key]) }

func text(value any) string {
	result, _ := value.(string)
	return result
}

func integer(value any) int64 {
	number, ok := value.(json.Number)
	if !ok {
		return 0
	}
	result, _ := number.Int64()
	return result
}
