package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestLoadFullRunExecutionManifestBindsFreshPrivateContract(t *testing.T) {
	manifest, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()

	verified, receipt, err := LoadFullRunExecutionManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := verified.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt != retained || receipt.Format != FullRunExecutionManifestReceiptFormat || receipt.State != "VERIFIED" ||
		receipt.ManifestDigest == "" || receipt.PlanDigest == "" || receipt.ProjectionManifestDigest == "" ||
		receipt.ProjectionAuthorityDigest == "" || receipt.NetworkProfileDigest == "" || receipt.PlatformProfileDigest == "" ||
		receipt.AggregateProfileDigest == "" || receipt.RuntimeIdentityMode != "lifecycle-derived-private/v1" ||
		receipt.AuthorizationMode != "predecessor-bound-tls/v1" || receipt.CapabilityMode != "runtime-bound-in-memory/v1" ||
		receipt.MutationAllowed {
		t.Fatalf("unexpected full-run manifest receipt: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/private/", "token", "endpoint", "kubeconfig", "certificate", "targetidentitydigest"} {
		if strings.Contains(strings.ToLower(string(public)), forbidden) {
			t.Fatalf("public full-run manifest receipt disclosed %q", forbidden)
		}
	}
}

func TestFullRunExecutionManifestFailsClosed(t *testing.T) {
	manifest, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(manifest)
	tests := map[string]func(map[string]any){
		"unknown field": func(value map[string]any) { value["targetIdentityDigest"] = runnerStageSHA("f") },
		"wrong profile": func(value map[string]any) {
			value["profiles"].(map[string]any)["platform"].(map[string]any)["digest"] = runnerStageSHA("f")
		},
		"different workload handoff": func(value map[string]any) {
			value["networkObservation"].(map[string]any)["workload"].(map[string]any)["tokenFile"] = filepath.Join(root, "other-workload-token")
		},
		"different ledger": func(value map[string]any) {
			value["targetAccess"].(map[string]any)["ledger"].(map[string]any)["namespace"] = "other-ledger"
		},
		"relative ledger credential": func(value map[string]any) {
			value["providerPrerequisites"].(map[string]any)["ledger"].(map[string]any)["tokenFile"] = "ledger-token"
		},
		"shared authority credential": func(value map[string]any) {
			managementToken := value["clusterLifecycle"].(map[string]any)["authority"].(map[string]any)["tokenFile"]
			value["providerPrerequisites"].(map[string]any)["authority"].(map[string]any)["tokenFile"] = managementToken
		},
		"unbounded authorization endpoint": func(value map[string]any) {
			value["authorization"].(map[string]any)["endpoint"] = "https://authority.example.invalid/other"
		},
		"wrong capability namespace": func(value map[string]any) {
			value["platformObservation"].(map[string]any)["capability"].(map[string]any)["namespace"] = "default"
		},
		"relative runtime output": func(value map[string]any) {
			value["runtimeBinding"].(map[string]any)["materialPath"] = "runtime-binding.json"
		},
		"duplicate runtime output": func(value map[string]any) {
			binding := value["networkObservation"].(map[string]any)["workload"].(map[string]any)["bindingPath"]
			value["runtimeBinding"].(map[string]any)["materialPath"] = binding
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			path := writeBundleFile(t, root, "unsafe-"+strings.ReplaceAll(name, " ", "-")+".json", mustJSON(t, value))
			if _, _, err := LoadFullRunExecutionManifest(path); err == nil {
				t.Fatal("unsafe full-run execution manifest was accepted")
			}
		})
	}

	existingOutput := filepath.Join(root, "future", "runtime-binding.json")
	if err := os.WriteFile(existingOutput, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFullRunExecutionManifest(manifest); err == nil {
		t.Fatal("full-run manifest accepted an occupied future output")
	}
}

func TestFullRunExecutionManifestRejectsBroadModeAndRelativePath(t *testing.T) {
	manifest, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	if err := os.Chmod(manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFullRunExecutionManifest(manifest); err == nil {
		t.Fatal("broad full-run manifest was accepted")
	}
	if _, _, err := LoadFullRunExecutionManifest("full-run.json"); err == nil {
		t.Fatal("relative full-run manifest was accepted")
	}
}

func TestFullRunExecutionManifestRejectsTargetIdentityInRendererArtifacts(t *testing.T) {
	for _, test := range []struct {
		name       string
		stageIndex int
		field      func(*fullRunExecutionManifestDocument) *string
	}{
		{name: "target registration", stageIndex: 8, field: func(document *fullRunExecutionManifestDocument) *string {
			return &document.TargetRegistration.ArtifactPath
		}},
		{name: "platform applications", stageIndex: 9, field: func(document *fullRunExecutionManifestDocument) *string {
			return &document.PlatformApplications.ArtifactPath
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest, cleanup := fullRunExecutionManifestFixture(t)
			defer cleanup()
			document, _, err := loadFullRunExecutionManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			artifactPath := *test.field(&document)
			artifact, err := os.ReadFile(artifactPath)
			if err != nil {
				t.Fatal(err)
			}
			concrete := []byte(strings.ReplaceAll(string(artifact), "RUNTIME-TARGET-IDENTITY-DIGEST-REQUIRED", runnerStageSHA("9")))
			unsafeArtifactPath := writeBundleFile(t, filepath.Dir(manifest), "unsafe-"+strings.ReplaceAll(test.name, " ", "-")+".yaml", concrete)
			*test.field(&document) = unsafeArtifactPath

			planRaw, err := os.ReadFile(document.Plan.Path)
			if err != nil {
				t.Fatal(err)
			}
			var plan map[string]any
			if err := json.Unmarshal(planRaw, &plan); err != nil {
				t.Fatal(err)
			}
			inputs := plan["stages"].([]any)[test.stageIndex].(map[string]any)["inputs"].([]any)
			inputs[0].(map[string]any)["digest"] = digest.SHA256(concrete)
			document.Plan.Path = writeBundleFile(t, filepath.Dir(manifest), "unsafe-"+strings.ReplaceAll(test.name, " ", "-")+"-plan.json", mustJSON(t, plan))
			unsafeManifest := writeBundleFile(t, filepath.Dir(manifest), "unsafe-"+strings.ReplaceAll(test.name, " ", "-")+"-manifest.json", mustJSON(t, document))
			if _, _, err := LoadFullRunExecutionManifest(unsafeManifest); err == nil {
				t.Fatal("renderer artifact carrying a caller-selected target identity was accepted")
			}
		})
	}
}

func TestFullRunExecutionManifestDigestIsFormattingIndependent(t *testing.T) {
	manifest, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	prettyPath := writeBundleFile(t, filepath.Dir(manifest), "full-run-pretty.json", pretty)
	_, first, err := loadFullRunExecutionManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := loadFullRunExecutionManifest(prettyPath)
	if err != nil || first != second {
		t.Fatalf("semantic full-run manifest identity changed with formatting: %q %q %v", first, second, err)
	}
}

func fullRunExecutionManifestFixture(t *testing.T) (string, func()) {
	t.Helper()
	postManifest, _, cleanup := postRuntimeManifestFixture(t)
	post, _, err := loadPostRuntimeExecutionManifest(postManifest)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	root := filepath.Dir(postManifest)
	expected := post.Plan.Expected

	infra := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: disposable-ok147\n  annotations:\n    openkubes.io/contract-name: disposable-ok147\n    openkubes.io/contract-namespace: disposable-ok147\n    openkubes.io/intent-revision: " + expected.IntentRevision + "\n")
	management := []byte("apiVersion: cluster.x-k8s.io/v1beta2\nkind: Cluster\nmetadata:\n  name: disposable-ok147\n  namespace: disposable-ok147\n  annotations:\n    openkubes.io/contract-name: disposable-ok147\n    openkubes.io/contract-namespace: disposable-ok147\n    openkubes.io/intent-revision: " + expected.IntentRevision + "\nspec:\n  clusterNetwork:\n    services:\n      cidrBlocks: [10.100.0.0/20]\n")
	authority := mustJSON(t, map[string]any{
		"format": "ok141-contract-to-capi-projection/v2", "contractIdentity": expected.ContractIdentity, "intentRevision": expected.IntentRevision,
		"infrastructurePlane": map[string]any{"identity": "ok-infra", "role": "provider-runtime-and-golden-image-prerequisites", "resources": []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "name": "disposable-ok147"}}},
		"managementPlane":     map[string]any{"identity": "ok-mgmt", "role": "single-lifecycle-writer", "resources": []map[string]any{{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "namespace": "disposable-ok147", "name": "disposable-ok147"}}},
		"providerAccess":      map[string]any{}, "excludedRendererArtifacts": []any{},
	})
	writeBundleFile(t, root, "authority-map.json", authority)
	writeBundleFile(t, root, "ok-infra-prerequisites.yaml", infra)
	writeBundleFile(t, root, "ok-mgmt-lifecycle.yaml", management)
	projectionManifest := mustJSON(t, map[string]any{
		"format": "ok141-contract-to-capi-projection/v2", "R": expected.IntentRevision, "authorizationState": "NO-GO",
		"artifacts":      map[string]any{"authority-map.json": digest.SHA256(authority), "ok-infra-prerequisites.yaml": digest.SHA256(infra), "ok-mgmt-lifecycle.yaml": digest.SHA256(management)},
		"objectSets":     map[string]any{"okInfraPrerequisites": map[string]any{"count": 1, "digest": runnerStageSHA("1")}, "okMgmtLifecycle": map[string]any{"count": 1, "digest": runnerStageSHA("2")}},
		"providerAccess": map[string]any{}, "source": map[string]any{},
	})
	projectionManifestPath := writeBundleFile(t, root, "full-projection-manifest.json", projectionManifest)

	enablement := runnerEnablementYAML(stagePlanExpected(expected))
	enablementPath := writeBundleFile(t, root, "enablement.yaml", enablement)
	planRaw, err := os.ReadFile(post.Plan.Path)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planRaw, &plan); err != nil {
		cleanup()
		t.Fatal(err)
	}
	stages := plan["stages"].([]any)
	stages[0].(map[string]any)["inputs"] = []any{map[string]any{"name": "projection.provider-prerequisites", "digest": digest.SHA256(infra)}}
	stages[1].(map[string]any)["inputs"] = []any{map[string]any{"name": "projection.cluster-lifecycle", "digest": digest.SHA256(management)}}
	stages[3].(map[string]any)["inputs"] = []any{map[string]any{"name": "stage.enablement", "digest": digest.SHA256(enablement)}}
	planPath := writeBundleFile(t, root, "full-staged-plan.json", mustJSON(t, plan))

	privateRoot := filepath.Join(root, "future")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		cleanup()
		t.Fatal(err)
	}
	receiptDirectory := filepath.Join(root, "full-receipts")
	if err := os.Mkdir(receiptDirectory, 0o700); err != nil {
		cleanup()
		t.Fatal(err)
	}
	workload := fullRunWorkloadRuntimeDocument{
		BindingPath: filepath.Join(privateRoot, "workload-authority.json"),
		TokenFile:   filepath.Join(privateRoot, "workload-token"),
		CAFile:      filepath.Join(privateRoot, "workload-ca.crt"),
	}
	ledger := post.TargetCredential.Ledger
	managementAuthority := post.AggregateEvidence.Management
	infrastructureAuthority := managementAuthority
	infrastructureAuthority.AuthorityIdentity = expected.InfrastructureAuthority
	infrastructureAuthority.Endpoint = "https://192.0.2.13:6443"
	infrastructureAuthority.TokenFile = "/private/tmp/infra-token"
	infrastructureAuthority.CAFile = "/private/tmp/infra-ca"
	infrastructureAuthority.CABundleDigest = runnerStageSHA("5")
	providerRuntime := fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: infrastructureAuthority}
	managementRuntime := fullRunSubmissionRuntimeDocument{Ledger: ledger, Authority: managementAuthority}
	document := fullRunExecutionManifestDocument{
		Format:                FullRunExecutionManifestFormat,
		Plan:                  fullRunPlanDocument{Path: planPath, Expected: expected},
		Projection:            fullRunProjectionDocument{ManifestPath: projectionManifestPath, Root: root},
		Authorization:         post.Authorization,
		Profiles:              post.Profiles,
		ProviderPrerequisites: providerRuntime,
		ClusterLifecycle:      managementRuntime,
		LifecycleObservation:  fullRunLifecycleObservationDocument{Ledger: ledger, Management: managementAuthority, PollInterval: "1s", PollTimeout: "1m"},
		Enablement: fullRunEnablementDocument{
			ArtifactPath:   enablementPath,
			ExpectedObject: projection.ResourceIdentity{APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: "disposable-ok147", Name: "disposable-ok147-cilium"},
			Runtime:        managementRuntime,
		},
		NetworkObservation: fullRunNetworkObservationDocument{Ledger: ledger, Management: managementAuthority, Workload: workload, PollInterval: "1s", PollTimeout: "1m"},
		RuntimeBinding:     fullRunRuntimeBindingDocument{Ledger: ledger, Workload: workload, MaterialPath: filepath.Join(privateRoot, "runtime-binding.json"), ReceiptPath: filepath.Join(privateRoot, "runtime-binding-receipt.json")},
		TargetAccess:       fullRunTargetAccessDocument{ArtifactPath: post.TargetCredential.TargetAccessArtifactPath, ExpectedObjects: append([]projection.ResourceIdentity(nil), post.TargetCredential.TargetAccessExpectedObjects...), Ledger: ledger, Workload: workload},
		TargetCredential:   fullRunTargetCredentialDocument{PolicyPath: post.TargetCredential.PolicyPath, Ledger: ledger, Workload: workload},
		TargetRegistration: fullRunTargetRegistrationDocument{
			ArtifactPath: post.TargetRegistration.ArtifactPath, ArgoNamespace: post.TargetRegistration.ArgoNamespace,
			ProjectName: post.TargetRegistration.ProjectName, RegistrationName: post.TargetRegistration.RegistrationName,
			TargetName: post.TargetRegistration.TargetName, SourceRepository: post.TargetRegistration.SourceRepository,
			TargetNamespaces: append([]string(nil), post.TargetRegistration.TargetNamespaces...), Ledger: ledger, GitOps: post.TargetRegistration.GitOps,
		},
		PlatformApplications: fullRunPlatformApplicationsDocument{
			ArtifactPath: post.PlatformApplications.ArtifactPath, ArgoNamespace: post.PlatformApplications.ArgoNamespace,
			ProjectName: post.PlatformApplications.ProjectName, RegistrationName: post.PlatformApplications.RegistrationName,
			SourceRepository: post.PlatformApplications.SourceRepository, Ledger: ledger, GitOps: post.PlatformApplications.GitOps,
		},
		PlatformObservation: fullRunPlatformObservationDocument{
			Ledger: ledger, Argo: post.PlatformObservation.Argo,
			Capability:   fullRunCapabilityDocument{Namespace: "ok-observability", Timeout: "10m", CleanupTimeout: "1m"},
			PollInterval: "1s", PollTimeout: "1m",
		},
		AggregateEvidence: fullRunAggregateEvidenceDocument{Ledger: ledger, Management: managementAuthority, Argo: post.AggregateEvidence.Argo, WorkloadTokenFile: workload.TokenFile, WorkloadCAFile: workload.CAFile},
		ReceiptDirectory:  receiptDirectory,
	}
	return writeBundleFile(t, root, "full-run-manifest.json", mustJSON(t, document)), cleanup
}

func stagePlanExpected(document postRuntimePlanExpectedDocument) stageplan.Expected {
	return stageplan.Expected{
		ContractIdentity: document.ContractIdentity,
		IntentRevision:   document.IntentRevision, EnablementRevision: document.EnablementRevision,
		PlatformRevision: document.PlatformRevision, ExecutionFixture: document.ExecutionFixture,
		InfrastructureAuthority: document.InfrastructureAuthority, ManagementAuthority: document.ManagementAuthority,
		GitOpsAuthority: document.GitOpsAuthority,
	}
}
