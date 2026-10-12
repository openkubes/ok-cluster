package main

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const bareClusterTemplateDigest = "sha256:<replace-with-64-lowercase-hex>"

func runClusterCreateManifestTemplate(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("ok cluster create manifest-template accepts no flags or positional arguments")
	}
	return writeClusterCreateManifestTemplate(stdout, "<contract-namespace>", "<contract-name>", "/private/replace")
}

func writeClusterCreateManifestTemplate(stdout io.Writer, namespace, name, root string) error {
	privatePath := func(elements ...string) string {
		return filepath.Join(append([]string{root}, elements...)...)
	}
	ledger := map[string]any{
		"endpoint": "https://<ledger-api-host>:6443", "namespace": "openkubes-execution-system",
		"tokenFile": privatePath("ledger.token"), "caFile": privatePath("ledger-ca.crt"),
	}
	infra := bareClusterTemplateAuthority(root, "https://<infrastructure-api-host>:6443", "ok-infra", "infrastructure")
	management := bareClusterTemplateAuthority(root, "https://<management-api-host>:6443", "ok-mgmt", "management")
	workload := map[string]any{
		"bindingPath":    privatePath("runtime", "workload-authority.json"),
		"kubeconfigFile": privatePath("runtime", "workload.kubeconfig"),
		"caFile":         privatePath("runtime", "workload-ca.crt"),
	}
	manifest := map[string]any{
		"format": runner.FullRunExecutionManifestFormat,
		"plan": map[string]any{
			"path": privatePath("staged-plan.json"),
			"expected": map[string]any{
				"contractIdentity": map[string]any{"namespace": namespace, "name": name},
				"intentRevision":   bareClusterTemplateDigest, "enablementRevision": bareClusterTemplateDigest,
				"platformRevision": bareClusterTemplateDigest, "executionFixture": bareClusterTemplateDigest,
				"infrastructureAuthority": "ok-infra", "managementAuthority": "ok-mgmt", "gitOpsAuthority": "ok-gitops",
				"completionMode": stageplan.CompletionModeBareClusterMVP,
			},
		},
		"projection": map[string]any{
			"manifestPath": privatePath("projection", "manifest.json"), "root": privatePath("projection"),
		},
		"authorization": map[string]any{
			"endpoint":  "https://ok147-stage-authority.openkubes-execution-system.svc:8443/v1/stage-authorizations",
			"tokenFile": privatePath("authorization.token"), "caFile": privatePath("authorization-ca.crt"),
			"publicKeyPath": privatePath("authorization.pub"), "outputDirectory": privatePath("authorizations"),
		},
		"profiles": map[string]any{
			"network": map[string]any{"path": privatePath("network-profile.json"), "digest": bareClusterTemplateDigest},
		},
		"providerPrerequisites": map[string]any{"ledger": ledger, "authority": infra},
		"providerAccess": map[string]any{
			"policyPath": privatePath("provider-access-policy.json"), "kubeconfigFile": privatePath("provider-access.kubeconfig"),
		},
		"clusterLifecycle": map[string]any{"ledger": ledger, "authority": management},
		"lifecycleObservation": map[string]any{
			"ledger": ledger, "management": management, "pollInterval": "1s", "pollTimeout": "30m",
		},
		"enablement": map[string]any{
			"artifactPath": privatePath("enablement.yaml"),
			"expectedObject": map[string]any{
				"apiVersion": "addons.cluster.x-k8s.io/v1alpha1", "kind": "HelmChartProxy",
				"namespace": namespace, "name": "<enablement-name>",
			},
			"runtime": map[string]any{"ledger": ledger, "authority": management},
		},
		"networkObservation": map[string]any{
			"ledger": ledger, "management": management, "workload": workload, "pollInterval": "1s", "pollTimeout": "30m",
		},
		"runtimeBinding": map[string]any{
			"ledger": ledger, "workload": workload,
			"materialPath": privatePath("runtime", "runtime-binding.json"),
			"receiptPath":  privatePath("runtime", "runtime-binding-receipt.json"),
		},
		"targetAccess": map[string]any{
			"artifactPath": privatePath("target-access.yaml"), "expectedObjects": bareClusterTemplateTargetAccessObjects(name),
			"ledger": ledger, "workload": workload,
		},
		"receiptDirectory": privatePath("receipts"),
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(manifest)
}

func runClusterCreatePlanTemplate(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("ok cluster create plan-template accepts no flags or positional arguments")
	}
	return writeClusterCreatePlanTemplate(stdout, "<contract-namespace>", "<contract-name>")
}

func writeClusterCreatePlanTemplate(stdout io.Writer, namespace, name string) error {
	plan := map[string]any{
		"format":           stageplan.Format,
		"contractIdentity": map[string]any{"namespace": namespace, "name": name},
		"intentRevision":   bareClusterTemplateDigest, "enablementRevision": bareClusterTemplateDigest,
		"platformRevision": bareClusterTemplateDigest, "executionFixture": bareClusterTemplateDigest,
		"authorizationState": "NO-GO", "completionMode": stageplan.CompletionModeBareClusterMVP,
		"authorities": map[string]any{
			"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-gitops",
			"workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1",
		},
		"stages": []map[string]any{
			bareClusterTemplateStage(1, "provider-prerequisites", "Submission", "infrastructure", "CreateProviderPrerequisites", nil, "projection.provider-prerequisites"),
			bareClusterTemplateStage(2, "cluster-lifecycle", "Submission", "management", "CreateCluster", []string{"provider-prerequisites"}, "projection.cluster-lifecycle", "stage.provider-access"),
			bareClusterTemplateStage(3, "lifecycle-observation", "Observation", "management", "", []string{"cluster-lifecycle"}, "stage.lifecycle-observation"),
			bareClusterTemplateStage(4, "enablement", "Submission", "management", "CreateEnablement", []string{"lifecycle-observation"}, "stage.enablement"),
			bareClusterTemplateStage(5, "network-observation", "Observation", "workload", "", []string{"enablement"}, "stage.network-observation"),
			bareClusterTemplateStage(6, "runtime-binding", "Binding", "runner", "", []string{"network-observation"}, "stage.runtime-binding"),
			bareClusterTemplateStage(7, "target-access", "Submission", "workload", "CreateTargetAccess", []string{"runtime-binding"}, "stage.target-access"),
		},
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}

func bareClusterTemplateStage(order int, id, kind, authority, operation string, requires []string, inputNames ...string) map[string]any {
	if requires == nil {
		requires = []string{}
	}
	inputs := make([]map[string]any, 0, len(inputNames))
	for _, name := range inputNames {
		inputs = append(inputs, map[string]any{"name": name, "digest": bareClusterTemplateDigest})
	}
	stage := map[string]any{
		"id": id, "order": order, "kind": kind, "authority": authority,
		"requires": requires, "inputs": inputs,
	}
	if operation != "" {
		stage["grantOperation"] = operation
	}
	return stage
}

func bareClusterTemplateAuthority(root, endpoint, identity, tokenName string) map[string]any {
	return map[string]any{
		"endpoint": endpoint, "authorityIdentity": identity,
		"tokenFile": filepath.Join(root, tokenName+".token"), "caFile": filepath.Join(root, tokenName+"-ca.crt"),
		"caBundleDigest": bareClusterTemplateDigest,
	}
}

func bareClusterTemplateTargetAccessObjects(contractName string) []map[string]any {
	objects := []map[string]any{
		bareClusterTemplateObject("v1", "Namespace", "<target-namespace>", ""),
		bareClusterTemplateObject("v1", "ServiceAccount", "<target-access-service-account>", "<target-namespace>"),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "ClusterRole", "<target-access-cluster-role>", ""),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "<target-access-cluster-role-binding>", ""),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "Role", "<target-access-role-1>", "<target-namespace>"),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "RoleBinding", "<target-access-role-binding-1>", "<target-namespace>"),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "Role", "<target-access-role-2>", "<target-namespace>"),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "RoleBinding", "<target-access-role-binding-2>", "<target-namespace>"),
		bareClusterTemplateObject("v1", "ServiceAccount", "<observability-service-account>", "ok-observability"),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "Role", "<observability-role>", "ok-observability"),
		bareClusterTemplateObject("rbac.authorization.k8s.io/v1", "RoleBinding", "<observability-role-binding>", "ok-observability"),
	}
	for _, identity := range submission.TargetAccessPrerequisiteIdentities(contractName) {
		objects = append(objects, bareClusterTemplateObject(identity.APIVersion, identity.Kind, identity.Name, identity.Namespace))
	}
	return objects
}

func bareClusterTemplateObject(apiVersion, kind, name, namespace string) map[string]any {
	object := map[string]any{"apiVersion": apiVersion, "kind": kind, "name": name}
	if namespace != "" {
		object["namespace"] = namespace
	}
	return object
}
