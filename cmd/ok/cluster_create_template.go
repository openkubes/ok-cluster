package main

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const bareClusterTemplateDigest = "sha256:<replace-with-64-lowercase-hex>"

func runClusterCreateManifestTemplate(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("ok cluster create manifest-template accepts no flags or positional arguments")
	}
	ledger := map[string]any{
		"endpoint": "https://<ledger-api-host>:6443", "namespace": "openkubes-execution-system",
		"tokenFile": "/private/replace/ledger.token", "caFile": "/private/replace/ledger-ca.crt",
	}
	infra := bareClusterTemplateAuthority("https://<infrastructure-api-host>:6443", "ok-infra", "infrastructure")
	management := bareClusterTemplateAuthority("https://<management-api-host>:6443", "ok-mgmt", "management")
	workload := map[string]any{
		"bindingPath":    "/private/replace/runtime/workload-authority.json",
		"kubeconfigFile": "/private/replace/runtime/workload.kubeconfig",
		"caFile":         "/private/replace/runtime/workload-ca.crt",
	}
	manifest := map[string]any{
		"format": runner.FullRunExecutionManifestFormatV4,
		"plan": map[string]any{
			"path": "/private/replace/staged-plan.json",
			"expected": map[string]any{
				"contractIdentity": map[string]any{"namespace": "<contract-namespace>", "name": "<contract-name>"},
				"intentRevision":   bareClusterTemplateDigest, "enablementRevision": bareClusterTemplateDigest,
				"platformRevision": bareClusterTemplateDigest, "executionFixture": bareClusterTemplateDigest,
				"executionAttemptDigest":  bareClusterTemplateDigest,
				"infrastructureAuthority": "ok-infra", "managementAuthority": "ok-mgmt", "gitOpsAuthority": "ok-gitops",
				"completionMode": stageplan.CompletionModeBareClusterMVP,
			},
		},
		"projection": map[string]any{
			"manifestPath": "/private/replace/projection/manifest.json", "root": "/private/replace/projection",
		},
		"authorization": map[string]any{
			"endpoint":  "https://ok147-stage-authority.openkubes-execution-system.svc:8443/v1/stage-authorizations",
			"tokenFile": "/private/replace/authorization.token", "caFile": "/private/replace/authorization-ca.crt",
			"publicKeyPath": "/private/replace/authorization.pub", "outputDirectory": "/private/replace/authorizations",
		},
		"profiles": map[string]any{
			"network": map[string]any{"path": "/private/replace/network-profile.json", "digest": bareClusterTemplateDigest},
		},
		"providerPrerequisites": map[string]any{"ledger": ledger, "authority": infra},
		"providerAccess": map[string]any{
			"policyPath": "/private/replace/provider-access-policy.json", "kubeconfigFile": "/private/replace/provider-access.kubeconfig",
		},
		"clusterLifecycle": map[string]any{"ledger": ledger, "authority": management},
		"lifecycleObservation": map[string]any{
			"ledger": ledger, "management": management, "pollInterval": "1s", "pollTimeout": "30m",
		},
		"enablement": map[string]any{
			"artifactPath": "/private/replace/enablement.yaml",
			"expectedObject": map[string]any{
				"apiVersion": "addons.cluster.x-k8s.io/v1alpha1", "kind": "HelmChartProxy",
				"namespace": "<contract-namespace>", "name": "<enablement-name>",
			},
			"runtime": map[string]any{"ledger": ledger, "authority": management},
		},
		"networkObservation": map[string]any{
			"ledger": ledger, "management": management, "workload": workload, "pollInterval": "1s", "pollTimeout": "30m",
		},
		"runtimeBinding": map[string]any{
			"ledger": ledger, "workload": workload,
			"materialPath": "/private/replace/runtime/runtime-binding.json",
			"receiptPath":  "/private/replace/runtime/runtime-binding-receipt.json",
		},
		"targetAccess": map[string]any{
			"artifactPath": "/private/replace/target-access.yaml", "expectedObjects": bareClusterTemplateTargetAccessObjects(),
			"ledger": ledger, "workload": workload,
		},
		"receiptDirectory": "/private/replace/receipts",
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(manifest)
}

func bareClusterTemplateAuthority(endpoint, identity, tokenName string) map[string]any {
	return map[string]any{
		"endpoint": endpoint, "authorityIdentity": identity,
		"tokenFile": "/private/replace/" + tokenName + ".token", "caFile": "/private/replace/" + tokenName + "-ca.crt",
		"caBundleDigest": bareClusterTemplateDigest,
	}
}

func bareClusterTemplateTargetAccessObjects() []map[string]any {
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
	for _, identity := range submission.TargetAccessPrerequisiteIdentities() {
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
