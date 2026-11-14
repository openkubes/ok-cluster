package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// A replacement is supplemental evidence. WorkloadContainers and WorkloadNodes
// remain the immutable identities first recorded by the create attempt.
type localCAPIWorkloadWorkerReplacement struct {
	ClusterUID            string                 `json:"clusterUID"`
	MachineDeploymentName string                 `json:"machineDeploymentName"`
	MachineDeploymentUID  string                 `json:"machineDeploymentUID"`
	MachineSetName        string                 `json:"machineSetName"`
	MachineSetUID         string                 `json:"machineSetUID"`
	MachineName           string                 `json:"machineName"`
	MachineUID            string                 `json:"machineUID"`
	DevMachineName        string                 `json:"devMachineName"`
	DevMachineUID         string                 `json:"devMachineUID"`
	ProviderID            string                 `json:"providerID"`
	Container             localContainerIdentity `json:"container"`
	Node                  localNodeIdentity      `json:"node"`
}

type localCAPIWorkloadReplacementObjectList struct {
	APIVersion string                               `json:"apiVersion"`
	Kind       string                               `json:"kind"`
	Items      []localCAPIWorkloadReplacementObject `json:"items"`
}

type localCAPIWorkloadReplacementOwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller"`
}

type localCAPIWorkloadReplacementObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string                                       `json:"name"`
		Namespace       string                                       `json:"namespace"`
		UID             string                                       `json:"uid"`
		Labels          map[string]string                            `json:"labels"`
		OwnerReferences []localCAPIWorkloadReplacementOwnerReference `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		ClusterName       string `json:"clusterName"`
		Replicas          *int32 `json:"replicas"`
		ProviderID        string `json:"providerID"`
		InfrastructureRef struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		} `json:"infrastructureRef"`
	} `json:"spec"`
	Status struct {
		ProviderID string `json:"providerID"`
		NodeRef    *struct {
			Name string `json:"name"`
		} `json:"nodeRef"`
		Conditions []localCAPIWorkloadCondition `json:"conditions"`
	} `json:"status"`
}

type localCAPIWorkloadReplacementNodeList struct {
	APIVersion string                                     `json:"apiVersion"`
	Kind       string                                     `json:"kind"`
	Items      []localCAPIWorkloadReplacementNodeListItem `json:"items"`
}

func replacementList(ctx context.Context, runtime localRuntime, management localCAPIState, clusterName, resource, kind string) (localCAPIWorkloadReplacementObjectList, error) {
	raw, err := runLocalCAPIRaw(ctx, runtime, management.Provider, management.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", management.BootstrapKubeconfig, "--context", "kind-"+management.BootstrapKindName,
		"get", resource, "-n", localCAPIWorkloadNamespace, "-l", "cluster.x-k8s.io/cluster-name="+clusterName, "-o", "json")
	if err != nil {
		return localCAPIWorkloadReplacementObjectList{}, errors.New("replacement ownership inventory is unavailable")
	}
	var list localCAPIWorkloadReplacementObjectList
	if json.Unmarshal(raw, &list) != nil || !validLocalCAPIWorkloadListEnvelope(list.APIVersion, list.Kind, kind) || list.Items == nil {
		return localCAPIWorkloadReplacementObjectList{}, errors.New("replacement ownership inventory is malformed")
	}
	return list, nil
}

func controllerOwner(refs []localCAPIWorkloadReplacementOwnerReference, apiVersion, kind, name, uid string) bool {
	count := 0
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller {
			count++
			if ref.APIVersion != apiVersion || ref.Kind != kind || ref.Name != name || ref.UID != uid {
				return false
			}
		}
	}
	return count == 1
}

// ownerReference verifies the UID-bound ownership relationship without
// requiring the reference to be Kubernetes' controller owner. CAPI's
// topology-created MachineDeployment may be owned by its Cluster with the
// controller bit unset while still having an exact garbage-collection owner.
func ownerReference(refs []localCAPIWorkloadReplacementOwnerReference, apiVersion, kind, name, uid string) bool {
	count := 0
	for _, ref := range refs {
		matches := ref.APIVersion == apiVersion && ref.Kind == kind && ref.Name == name && ref.UID == uid
		if matches {
			count++
		}
		if ref.Controller != nil && *ref.Controller && !matches {
			return false
		}
	}
	return count == 1
}

func oneReplacementItem(list localCAPIWorkloadReplacementObjectList, apiVersion, kind, namespace, name string) (localCAPIWorkloadReplacementObject, bool) {
	if len(list.Items) != 1 {
		return localCAPIWorkloadReplacementObject{}, false
	}
	item := list.Items[0]
	return item, item.APIVersion == apiVersion && item.Kind == kind && item.Metadata.Namespace == namespace && item.Metadata.Name == name && item.Metadata.UID != ""
}

func capdWorkerReplacementInputFailure(state localCAPIWorkloadState, containers []localContainerIdentity, nodes []localNodeIdentity) string {
	switch {
	case state.ClusterUID == "":
		return "receipt.cluster_uid_missing"
	case !validLocalCAPIWorkloadContainerInventory(containers):
		return "observed.container_inventory_invalid"
	case !validLocalCAPIWorkloadNodeIdentities(nodes):
		return "observed.node_identity_inventory_invalid"
	case len(state.WorkloadContainers) != 3:
		return "receipt.historical_container_count_invalid"
	case len(state.WorkloadNodes) != 2:
		return "receipt.historical_node_count_invalid"
	}
	return ""
}

// verifyCAPDWorkerReplacement independently follows Cluster -> MachineDeployment
// -> MachineSet -> Machine -> DevMachine -> Docker container -> Node. It is only
// used for the single explicit pre-Calico continuation; it never changes resources.
func verifyCAPDWorkerReplacement(ctx context.Context, runtime localRuntime, management localCAPIState, state localCAPIWorkloadState, containers []localContainerIdentity, nodes []localNodeIdentity) (localCAPIWorkloadWorkerReplacement, error) {
	stage := "input"
	deny := func() (localCAPIWorkloadWorkerReplacement, error) {
		return localCAPIWorkloadWorkerReplacement{}, fmt.Errorf("CAPI worker replacement evidence failed [%s]", stage)
	}
	if inputFailure := capdWorkerReplacementInputFailure(state, containers, nodes); inputFailure != "" {
		stage = inputFailure
		return deny()
	}
	oldCP, oldWorker, oldLB := roleContainer(state.WorkloadContainers, "control-plane"), roleContainer(state.WorkloadContainers, "worker"), roleContainer(state.WorkloadContainers, "external-load-balancer")
	newCP, newWorker, newLB := roleContainer(containers, "control-plane"), roleContainer(containers, "worker"), roleContainer(containers, "external-load-balancer")
	if oldCP == nil || oldWorker == nil || oldLB == nil {
		stage = "receipt.historical_container_roles_invalid"
		return deny()
	}
	if newCP == nil || newWorker == nil || newLB == nil {
		stage = "observed.container_roles_invalid"
		return deny()
	}
	if *oldCP != *newCP {
		stage = "identity.control_plane_container_changed"
		return deny()
	}
	if *oldLB != *newLB {
		stage = "identity.load_balancer_container_changed"
		return deny()
	}
	if *oldWorker == *newWorker {
		stage = "identity.worker_not_replaced"
		return deny()
	}
	oldCPNode, oldWorkerNode := recordedWorkerNodes(state)
	if oldCPNode == nil || oldWorkerNode == nil {
		stage = "receipt.historical_node_roles_invalid"
		return deny()
	}

	stage = "MachineDeployment"
	mdList, err := replacementList(ctx, runtime, management, state.Name, "machinedeployments.cluster.x-k8s.io", "MachineDeploymentList")
	if err != nil || len(mdList.Items) != 1 {
		return deny()
	}
	md := mdList.Items[0]
	if md.APIVersion != localCAPIWorkloadAPIVersion || md.Kind != "MachineDeployment" || md.Metadata.Namespace != state.Namespace || md.Metadata.UID == "" || md.Metadata.Labels["cluster.x-k8s.io/cluster-name"] != state.Name || md.Spec.ClusterName != state.Name || md.Spec.Replicas == nil || *md.Spec.Replicas != 1 {
		return deny()
	}
	stage = "MachineDeployment.ownerReferences Cluster UID"
	if !ownerReference(md.Metadata.OwnerReferences, localCAPIWorkloadAPIVersion, "Cluster", state.Name, state.ClusterUID) {
		return deny()
	}

	stage = "MachineSet"
	msList, err := replacementList(ctx, runtime, management, state.Name, "machinesets.cluster.x-k8s.io", "MachineSetList")
	if err != nil || len(msList.Items) != 1 {
		return deny()
	}
	ms := msList.Items[0]
	if ms.APIVersion != localCAPIWorkloadAPIVersion || ms.Kind != "MachineSet" || ms.Metadata.Namespace != state.Namespace || ms.Metadata.UID == "" || ms.Metadata.Labels["cluster.x-k8s.io/cluster-name"] != state.Name || ms.Spec.ClusterName != state.Name || ms.Spec.Replicas == nil || *ms.Spec.Replicas != 1 || !controllerOwner(ms.Metadata.OwnerReferences, localCAPIWorkloadAPIVersion, "MachineDeployment", md.Metadata.Name, md.Metadata.UID) {
		return deny()
	}

	stage = "Machine"
	machineList, err := replacementList(ctx, runtime, management, state.Name, "machines.cluster.x-k8s.io", "MachineList")
	if err != nil || len(machineList.Items) != 2 {
		return deny()
	}
	var workerMachine, controlPlaneMachine *localCAPIWorkloadReplacementObject
	for i := range machineList.Items {
		machine := &machineList.Items[i]
		if machine.APIVersion != localCAPIWorkloadAPIVersion || machine.Kind != "Machine" || machine.Metadata.Namespace != state.Namespace || machine.Metadata.UID == "" || machine.Metadata.Labels["cluster.x-k8s.io/cluster-name"] != state.Name {
			return deny()
		}
		if _, cp := machine.Metadata.Labels["cluster.x-k8s.io/control-plane"]; cp {
			if controlPlaneMachine != nil {
				return deny()
			}
			controlPlaneMachine = machine
		} else {
			if workerMachine != nil {
				return deny()
			}
			workerMachine = machine
		}
	}
	stage = "Machine.spec.infrastructureRef.apiGroup/kind/name or MachineSet owner UID"
	if workerMachine == nil || controlPlaneMachine == nil || workerMachine.Status.NodeRef == nil || workerMachine.Status.NodeRef.Name == "" || workerMachine.Spec.InfrastructureRef.APIGroup != "infrastructure.cluster.x-k8s.io" || workerMachine.Spec.InfrastructureRef.Kind != "DevMachine" || workerMachine.Spec.InfrastructureRef.Name == "" || !controllerOwner(workerMachine.Metadata.OwnerReferences, localCAPIWorkloadAPIVersion, "MachineSet", ms.Metadata.Name, ms.Metadata.UID) {
		return deny()
	}
	stage = "control-plane Machine.spec.infrastructureRef.apiGroup/kind/name or NodeRef"
	if controlPlaneMachine.Status.NodeRef == nil || controlPlaneMachine.Status.NodeRef.Name == "" || controlPlaneMachine.Spec.InfrastructureRef.APIGroup != "infrastructure.cluster.x-k8s.io" || controlPlaneMachine.Spec.InfrastructureRef.Kind != "DevMachine" || controlPlaneMachine.Spec.InfrastructureRef.Name == "" {
		return deny()
	}
	if !localCAPIWorkloadNodeNameRecorded([]localNodeIdentity{*oldCPNode}, controlPlaneMachine.Status.NodeRef.Name) {
		return deny()
	}

	stage = "DevMachine"
	devList, err := replacementList(ctx, runtime, management, state.Name, "devmachines.infrastructure.cluster.x-k8s.io", "DevMachineList")
	if err != nil || len(devList.Items) != 2 {
		return deny()
	}
	var workerDev, controlPlaneDev *localCAPIWorkloadReplacementObject
	for i := range devList.Items {
		dev := &devList.Items[i]
		if dev.APIVersion != "infrastructure.cluster.x-k8s.io/v1beta2" || dev.Kind != "DevMachine" || dev.Metadata.Namespace != state.Namespace || dev.Metadata.UID == "" {
			return deny()
		}
		if dev.Metadata.Name == workerMachine.Spec.InfrastructureRef.Name {
			workerDev = dev
		}
		if dev.Metadata.Name == controlPlaneMachine.Spec.InfrastructureRef.Name {
			controlPlaneDev = dev
		}
	}
	stage = "DevMachine exact reference and Machine owner UID"
	if workerDev == nil || controlPlaneDev == nil || !controllerOwner(workerDev.Metadata.OwnerReferences, "cluster.x-k8s.io/v1beta2", "Machine", workerMachine.Metadata.Name, workerMachine.Metadata.UID) || !controllerOwner(controlPlaneDev.Metadata.OwnerReferences, "cluster.x-k8s.io/v1beta2", "Machine", controlPlaneMachine.Metadata.Name, controlPlaneMachine.Metadata.UID) {
		return deny()
	}
	stage = "DevMachine readiness conditions"
	if !conditionsTrue(workerDev.Status.Conditions, "Ready", "ContainerProvisioned") {
		return deny()
	}

	stage = "workload Node"
	nodeRaw, err := runLocalCAPIRaw(ctx, runtime, management.Provider, state.WorkloadKubeconfig, nil,
		"kubectl", "--kubeconfig", state.WorkloadKubeconfig, "--context", "kind-"+state.WorkloadKindName, "get", "nodes", "-o", "json")
	if err != nil {
		return deny()
	}
	var nodeList localCAPIWorkloadReplacementNodeList
	if json.Unmarshal(nodeRaw, &nodeList) != nil || !validLocalCAPIWorkloadListEnvelope(nodeList.APIVersion, nodeList.Kind, "NodeList") || len(nodeList.Items) != 2 {
		return deny()
	}
	var workerNode, cpNode *localCAPIWorkloadReplacementNodeListItem
	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		if node.APIVersion != "v1" || node.Kind != "Node" || node.Metadata.Name == "" || node.Metadata.UID == "" {
			return deny()
		}
		if node.Metadata.Name == workerMachine.Status.NodeRef.Name {
			workerNode = node
		}
		if node.Metadata.Name == controlPlaneMachine.Status.NodeRef.Name {
			cpNode = node
		}
	}
	stage = "Node.spec.providerID and exact Docker container identity"
	workerProviderID, cpProviderID := "", ""
	if workerNode != nil {
		workerProviderID = workerNode.Spec.ProviderID
	}
	if cpNode != nil {
		cpProviderID = cpNode.Spec.ProviderID
	}
	if workerNode == nil || cpNode == nil || workerProviderID == "" || cpProviderID == "" ||
		!optionalProviderIDMatches(workerMachine.Status.ProviderID, workerProviderID) || !optionalProviderIDMatches(workerDev.Status.ProviderID, workerProviderID) ||
		!optionalProviderIDMatches(workerDev.Spec.ProviderID, workerProviderID) ||
		!optionalProviderIDMatches(controlPlaneMachine.Status.ProviderID, cpProviderID) || !optionalProviderIDMatches(controlPlaneDev.Status.ProviderID, cpProviderID) ||
		!optionalProviderIDMatches(controlPlaneDev.Spec.ProviderID, cpProviderID) ||
		!replacementProviderMatches(workerProviderID, *newWorker) || !replacementProviderMatches(cpProviderID, *newCP) ||
		!localCAPIWorkloadNodeIdentityRecorded(nodes, localNodeIdentity{Name: cpNode.Metadata.Name, UID: cpNode.Metadata.UID}) {
		return deny()
	}
	if localCAPIWorkloadNodeIdentityRecorded(state.WorkloadNodes, localNodeIdentity{Name: workerNode.Metadata.Name, UID: workerNode.Metadata.UID}) {
		return deny()
	}
	return localCAPIWorkloadWorkerReplacement{ClusterUID: state.ClusterUID, MachineDeploymentName: md.Metadata.Name, MachineDeploymentUID: md.Metadata.UID,
		MachineSetName: ms.Metadata.Name, MachineSetUID: ms.Metadata.UID, MachineName: workerMachine.Metadata.Name, MachineUID: workerMachine.Metadata.UID,
		DevMachineName: workerDev.Metadata.Name, DevMachineUID: workerDev.Metadata.UID, ProviderID: workerProviderID, Container: *newWorker,
		Node: localNodeIdentity{Name: workerNode.Metadata.Name, UID: workerNode.Metadata.UID}}, nil
}

type localCAPIWorkloadReplacementNodeListItem struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		ProviderID string `json:"providerID"`
	} `json:"spec"`
}

func roleContainer(containers []localContainerIdentity, role string) *localContainerIdentity {
	for i := range containers {
		if containers[i].Role == role {
			return &containers[i]
		}
	}
	return nil
}
func recordedWorkerNodes(state localCAPIWorkloadState) (*localNodeIdentity, *localNodeIdentity) {
	controlPlane := roleContainer(state.WorkloadContainers, "control-plane")
	workerContainer := roleContainer(state.WorkloadContainers, "worker")
	if controlPlane == nil || workerContainer == nil || controlPlane.Name == "" || workerContainer.Name == "" || controlPlane.Name == workerContainer.Name || len(state.WorkloadNodes) != 2 {
		return nil, nil
	}
	var cp, worker *localNodeIdentity
	for i := range state.WorkloadNodes {
		node := &state.WorkloadNodes[i]
		switch node.Name {
		case controlPlane.Name:
			if cp != nil {
				return nil, nil
			}
			cp = node
		case workerContainer.Name:
			if worker != nil {
				return nil, nil
			}
			worker = node
		default:
			return nil, nil
		}
	}
	if cp == nil || worker == nil {
		return nil, nil
	}
	return cp, worker
}
func localCAPIWorkloadNodeIdentityRecorded(nodes []localNodeIdentity, target localNodeIdentity) bool {
	for _, node := range nodes {
		if node == target {
			return true
		}
	}
	return false
}
func conditionsTrue(conditions []localCAPIWorkloadCondition, types ...string) bool {
	for _, typ := range types {
		count := 0
		for _, c := range conditions {
			if c.Type == typ {
				count++
				if c.Status != "True" {
					return false
				}
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

func validLocalCAPIWorkloadWorkerReplacement(state localCAPIWorkloadState, evidence localCAPIWorkloadWorkerReplacement) bool {
	if state.RecoveryFromFailureCode != "CNI_ALREADY_PRESENT" || evidence.ClusterUID == "" || evidence.ClusterUID != state.ClusterUID ||
		evidence.MachineDeploymentName == "" || evidence.MachineDeploymentUID == "" || evidence.MachineSetName == "" || evidence.MachineSetUID == "" ||
		evidence.MachineName == "" || evidence.MachineUID == "" || evidence.DevMachineName == "" || evidence.DevMachineUID == "" || evidence.ProviderID == "" ||
		evidence.Container.Role != "worker" || evidence.Container.ID == "" || evidence.Container.Name == "" || evidence.Node.Name == "" || evidence.Node.UID == "" ||
		!validLocalCAPIWorkloadContainers(state.WorkloadContainers) || !validLocalCAPIWorkloadNodeIdentities(state.WorkloadNodes) {
		return false
	}
	oldCP, oldWorker, oldLB := roleContainer(state.WorkloadContainers, "control-plane"), roleContainer(state.WorkloadContainers, "worker"), roleContainer(state.WorkloadContainers, "external-load-balancer")
	cpNode, workerNode := recordedWorkerNodes(state)
	return oldCP != nil && oldWorker != nil && oldLB != nil && *oldWorker != evidence.Container &&
		cpNode != nil && workerNode != nil && evidence.Node != *workerNode && evidence.Node.Name != cpNode.Name &&
		replacementProviderMatches(evidence.ProviderID, evidence.Container)
}

// Replacement only substitutes the worker identity. Original receipt fields
// intentionally remain immutable historical evidence.
func localCAPIWorkloadEffectiveIdentity(state localCAPIWorkloadState) ([]localContainerIdentity, []localNodeIdentity) {
	containers := append([]localContainerIdentity(nil), state.WorkloadContainers...)
	nodes := append([]localNodeIdentity(nil), state.WorkloadNodes...)
	if state.WorkerReplacement == nil {
		return containers, nodes
	}
	for i := range containers {
		if containers[i].Role == "worker" {
			containers[i] = state.WorkerReplacement.Container
			break
		}
	}
	state.WorkloadNodes = nodes
	_, originalWorker := recordedWorkerNodes(state)
	for i := range nodes {
		if originalWorker != nil && nodes[i] == *originalWorker {
			nodes[i] = state.WorkerReplacement.Node
			break
		}
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return containers, nodes
}

func replacementProviderMatches(providerID string, container localContainerIdentity) bool {
	if !strings.HasPrefix(providerID, "docker://") {
		return false
	}
	resource := strings.TrimLeft(strings.TrimPrefix(providerID, "docker://"), "/")
	return resource != "" && (resource == container.Name || resource == container.ID)
}

func optionalProviderIDMatches(observed, nodeProviderID string) bool {
	return observed == "" || observed == nodeProviderID
}
