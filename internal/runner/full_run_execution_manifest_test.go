package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestVerifiedFullRunExecutionManifestBuildsConcreteConfiguration(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	manifest, _, err := LoadFullRunExecutionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC) }
	probe := &recordingPlatformCapabilityProbe{result: PlatformCapabilityProbeResult{Passed: true}}
	capability, err := NewFirstRunPlatformCapabilityResolver(probe, clock)
	if err != nil {
		t.Fatal(err)
	}
	var capabilityBinding FullRunPlatformCapabilityBinding
	config, err := manifest.ExecutionConfig(FullRunExecutionManifestRuntime{
		PlatformCapability: FullRunPlatformCapabilityFactoryFunc(func(binding FullRunPlatformCapabilityBinding) (PlatformCapabilityResolver, error) {
			capabilityBinding = binding
			return capability, nil
		}),
		Clock: clock, Wait: WaitWithTimer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := config.PreRuntime.WorkloadAuthority.(*KubernetesLifecycleWorkloadAuthorityMaterializer); !ok {
		t.Fatalf("manifest did not select lifecycle workload materialization: %T", config.PreRuntime.WorkloadAuthority)
	}
	if config.PreRuntime.NetworkObservation.Workload.KubeconfigFile == "" || config.PreRuntime.NetworkObservation.Workload.TokenFile != "" ||
		config.PostRuntime.TargetCredentialRun.Workload != config.PreRuntime.NetworkObservation.Workload ||
		config.EvidenceIdentityBinder == nil ||
		config.PostRuntime.PlatformObservation.Capability == nil || config.PostRuntime.AggregateEvidence.Capability == nil ||
		config.PostRuntime.TargetRegistration.Expected.TargetIdentityDigest != "" ||
		!config.PostRuntime.TargetRegistration.Runtime.MaterializationTime.IsZero() {
		t.Fatalf("concrete full-run configuration widened a dynamic boundary: %#v", config)
	}
	if _, err := OpenFullRunExecution(config); err != nil {
		t.Fatalf("verified manifest did not open concrete full-run execution: %v", err)
	}
	if probe.calls != 0 {
		t.Fatal("opening the full-run manifest executed the Platform capability probe")
	}
	if capabilityBinding.Namespace != "ok-observability" || capabilityBinding.Timeout != 10*time.Minute ||
		capabilityBinding.CleanupTimeout != time.Minute || capabilityBinding.PollInterval != time.Second ||
		capabilityBinding.PushgatewayImage == "" || capabilityBinding.LogEmitterImage == "" ||
		capabilityBinding.IndependentEvidencePath == "" || capabilityBinding.IndependentEvidenceKeyID == "" || capabilityBinding.IntentRevision == "" ||
		capabilityBinding.PlatformRevision == "" || capabilityBinding.ExecutionFixture == "" ||
		capabilityBinding.ContractDigest == "" || capabilityBinding.ExecutableDigest == "" {
		t.Fatalf("capability factory did not receive the exact manifest binding: %#v", capabilityBinding)
	}
}

func TestOpenFullRunExecutionManifestStopsBeforeAnyRuntimeAction(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	clock := func() time.Time { return time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC) }
	probe := &recordingPlatformCapabilityProbe{result: PlatformCapabilityProbeResult{Passed: true}}
	capability, _ := NewFirstRunPlatformCapabilityResolver(probe, clock)
	execution, receipt, err := OpenFullRunExecutionManifest(manifestPath, FullRunExecutionManifestRuntime{
		PlatformCapability: FullRunPlatformCapabilityFactoryFunc(func(FullRunPlatformCapabilityBinding) (PlatformCapabilityResolver, error) {
			return capability, nil
		}),
		Clock: clock, Wait: WaitWithTimer,
	})
	if err != nil || execution == nil || receipt.State != "VERIFIED" {
		t.Fatalf("direct full-run manifest activation failed: receipt=%#v execution=%#v err=%v", receipt, execution, err)
	}
	if probe.calls != 0 {
		t.Fatal("direct full-run activation executed a runtime capability")
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
		"mutable capability image": func(value map[string]any) {
			value["platformObservation"].(map[string]any)["capability"].(map[string]any)["pushgatewayImage"] = "registry.k8s.io/pushgateway:latest"
		},
		"foreign evidence key": func(value map[string]any) {
			value["platformObservation"].(map[string]any)["capability"].(map[string]any)["independentEvidenceKeyId"] = "mutable"
		},
		"unbounded capability polling": func(value map[string]any) {
			value["platformObservation"].(map[string]any)["capability"].(map[string]any)["pollInterval"] = "1m"
		},
		"evidence path collides with runtime output": func(value map[string]any) {
			binding := value["networkObservation"].(map[string]any)["workload"].(map[string]any)["bindingPath"]
			value["platformObservation"].(map[string]any)["capability"].(map[string]any)["independentEvidencePath"] = binding
		},
		"identity receipt collides with identity": func(value map[string]any) {
			capability := value["platformObservation"].(map[string]any)["capability"].(map[string]any)
			capability["independentEvidenceIdentityReceiptPath"] = capability["independentEvidenceIdentityPath"]
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
		BindingPath:    filepath.Join(privateRoot, "workload-authority.json"),
		KubeconfigFile: filepath.Join(privateRoot, "workload-kubeconfig.yaml"),
		CAFile:         filepath.Join(privateRoot, "workload-ca.crt"),
	}
	ledger := post.TargetCredential.Ledger
	managementAuthority := post.AggregateEvidence.Management
	managementAuthority.TokenFile = writeBundleFile(t, root, "full-management-token", []byte("full-management-token"))
	managementAuthority.CAFile = ledger.CAFile
	managementCA, err := os.ReadFile(ledger.CAFile)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	managementAuthority.CABundleDigest = digest.SHA256(managementCA)
	infrastructureAuthority := managementAuthority
	infrastructureAuthority.AuthorityIdentity = expected.InfrastructureAuthority
	infrastructureAuthority.Endpoint = "https://192.0.2.13:6443"
	infrastructureAuthority.TokenFile = writeBundleFile(t, root, "full-infrastructure-token", []byte("full-infrastructure-token"))
	gitOpsAuthority := post.TargetRegistration.GitOps
	gitOpsAuthority.TokenFile = writeBundleFile(t, root, "full-gitops-token", []byte("full-gitops-token"))
	gitOpsAuthority.CAFile = ledger.CAFile
	gitOpsAuthority.CABundleDigest = digest.SHA256(managementCA)
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
			TargetNamespaces: append([]string(nil), post.TargetRegistration.TargetNamespaces...), Ledger: ledger, GitOps: gitOpsAuthority,
		},
		PlatformApplications: fullRunPlatformApplicationsDocument{
			ArtifactPath: post.PlatformApplications.ArtifactPath, ArgoNamespace: post.PlatformApplications.ArgoNamespace,
			ProjectName: post.PlatformApplications.ProjectName, RegistrationName: post.PlatformApplications.RegistrationName,
			SourceRepository: post.PlatformApplications.SourceRepository, Ledger: ledger, GitOps: gitOpsAuthority,
		},
		PlatformObservation: fullRunPlatformObservationDocument{
			Ledger: ledger, Argo: gitOpsAuthority,
			Capability: fullRunCapabilityDocument{
				Namespace: "ok-observability", Timeout: "10m", CleanupTimeout: "1m", PollInterval: "1s",
				PushgatewayImage: capabilityFixtureConfig().PushgatewayImage, LogEmitterImage: capabilityFixtureConfig().LogEmitterImage,
				IndependentEvidenceIdentityPath:        filepath.Join(privateRoot, "observability-independent-evidence-identity.json"),
				IndependentEvidenceIdentityReceiptPath: filepath.Join(privateRoot, "observability-independent-evidence-identity-receipt.json"),
				IndependentEvidencePath:                filepath.Join(privateRoot, "observability-independent-evidence.json"), IndependentEvidenceKeyID: digestOf("d"),
			},
			PollInterval: "1s", PollTimeout: "1m",
		},
		AggregateEvidence: fullRunAggregateEvidenceDocument{Ledger: ledger, Management: managementAuthority, Argo: gitOpsAuthority, WorkloadKubeconfigFile: workload.KubeconfigFile, WorkloadCAFile: workload.CAFile},
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
