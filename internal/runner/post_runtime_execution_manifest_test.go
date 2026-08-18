package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestOpenPostRuntimeExecutionManifestBindsExactPrivateActivation(t *testing.T) {
	manifest, _, cleanup := postRuntimeManifestFixture(t)
	defer cleanup()
	executor, receipt, err := OpenPostRuntimeExecutionManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if executor == nil || receipt.Format != PostRuntimeExecutionManifestReceiptFormat || receipt.State != "VERIFIED" ||
		receipt.InitialReceiptCount != 7 || receipt.PlanDigest == "" || receipt.ManifestDigest == "" ||
		receipt.TargetIdentityDigest != digest.SHA256([]byte(targetAccessRuntimeUID)) ||
		receipt.AuthorizationMode != "predecessor-bound-tls/v1" || receipt.MutationAllowed {
		t.Fatalf("unexpected post-runtime manifest receipt: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/private/", "token", "endpoint", "kubeconfig", "certificate"} {
		if strings.Contains(strings.ToLower(string(public)), forbidden) {
			t.Fatalf("public manifest receipt disclosed %q", forbidden)
		}
	}
}

func TestPostRuntimeExecutionManifestFailsClosedBeforeActivation(t *testing.T) {
	manifest, factories, cleanup := postRuntimeManifestFixture(t)
	defer cleanup()
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(manifest)
	for name, mutate := range map[string]func(map[string]any){
		"unknown field": func(value map[string]any) { value["unexpected"] = true },
		"wrong target": func(value map[string]any) {
			value["targetRegistration"].(map[string]any)["targetName"] = "different-target"
		},
		"wrong profile": func(value map[string]any) {
			value["profiles"].(map[string]any)["platform"].(map[string]any)["digest"] = runnerStageSHA("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			path := writeBundleFile(t, root, strings.ReplaceAll(name, " ", "-")+".json", mustJSON(t, value))
			if _, _, err := openPostRuntimeExecutionManifest(path, factories); err == nil {
				t.Fatal("unsafe post-runtime manifest was accepted")
			}
		})
	}
	if err := os.Chmod(manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openPostRuntimeExecutionManifest(manifest, factories); err == nil {
		t.Fatal("broad post-runtime manifest was accepted")
	}
	if _, _, err := openPostRuntimeExecutionManifest("relative.json", factories); err == nil {
		t.Fatal("relative post-runtime manifest was accepted")
	}
}

func TestPostRuntimeExecutionManifestDigestIsFormattingIndependent(t *testing.T) {
	manifest, _, cleanup := postRuntimeManifestFixture(t)
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
	prettyPath := writeBundleFile(t, filepath.Dir(manifest), "pretty.json", pretty)
	_, firstDigest, err := loadPostRuntimeExecutionManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, secondDigest, err := loadPostRuntimeExecutionManifest(prettyPath)
	if err != nil || firstDigest != secondDigest {
		t.Fatalf("semantic manifest identity changed with formatting: %q %q %v", firstDigest, secondDigest, err)
	}
}

func postRuntimeManifestFixture(t *testing.T) (string, postRuntimeExecutionFactories, func()) {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 18, 8, 0, 0, 0, time.UTC)
	expected := stageplan.Expected{
		ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision:   runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"),
		PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	targetAccess := runnerTargetAccessYAML()
	policy := targetCredentialPolicyDocument{
		Format: TargetCredentialPolicyFormat, TargetIdentityDigest: submission.RuntimeTargetIdentityDigestPlaceholder,
		ServiceAccount:     targetCredentialServiceAccount{Namespace: "kube-system", Name: "ok147-argocd-manager"},
		RequestedAudiences: []string{}, ExpirationSeconds: 10800, CredentialUse: "argocd-target-registration",
		Retention: "memory-only", NativeRotation: false, ProductionSuitable: false,
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	registration := runnerTargetRegistrationYAML(expected)
	applications, platformProfile := runnerPlatformApplications(t, expected)
	networkProfile := runnerAggregateNetworkProfile(expected)
	networkDigest, err := observation.NetworkProfileDigest(networkProfile)
	if err != nil {
		t.Fatal(err)
	}
	platformDigest, err := observation.PlatformProfileDigest(platformProfile)
	if err != nil {
		t.Fatal(err)
	}
	aggregateProfile := AggregateEvidenceProfile{
		Format: AggregateEvidenceProfileFormat, IntentRevision: expected.IntentRevision,
		EnablementRevision: expected.EnablementRevision, PlatformRevision: expected.PlatformRevision,
		ExecutionFixture: expected.ExecutionFixture, Required: append([]string(nil), aggregateEvidenceRequiredConditions...),
	}
	aggregateDigest, err := AggregateEvidenceProfileDigest(aggregateProfile)
	if err != nil {
		t.Fatal(err)
	}
	planRaw := submissionBundlePlan(t, expected, runnerStageSHA("1"), runnerStageSHA("2"))
	var planDocument map[string]any
	if err := json.Unmarshal(planRaw, &planDocument); err != nil {
		t.Fatal(err)
	}
	stages := planDocument["stages"].([]any)
	stageInputs := []struct {
		index  int
		name   string
		digest string
	}{
		{4, "stage.network-observation", networkDigest},
		{6, "stage.target-access", digest.SHA256(targetAccess)},
		{7, "stage.target-credential", digest.SHA256(policyRaw)},
		{8, "stage.target-registration", digest.SHA256(registration)},
		{9, "stage.platform-applications", digest.SHA256(applications)},
		{10, "stage.platform-observation", platformDigest},
		{11, "stage.aggregate-evidence", aggregateDigest},
	}
	for _, input := range stageInputs {
		stages[input.index].(map[string]any)["inputs"] = []any{map[string]any{"name": input.name, "digest": input.digest}}
	}
	planPath := writeBundleFile(t, root, "staged-plan.json", mustJSON(t, planDocument))
	plan, err := stageplan.Load(planPath, expected)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]StageReceiptSource, 0, 7)
	predecessors := []stagereceipt.Verified{}
	results := []struct{ id, mutation, operation, evidence string }{
		{"provider-prerequisites", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2")},
		{"cluster-lifecycle", "ATTEMPTED", runnerStageSHA("3"), runnerStageSHA("4")},
		{"lifecycle-observation", "NOT_APPLICABLE", "", runnerStageSHA("5")},
		{"enablement", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7")},
		{"network-observation", "NOT_APPLICABLE", "", runnerStageSHA("8")},
		{"runtime-binding", "NOT_APPLICABLE", "", runnerStageSHA("9")},
		{"target-access", "ATTEMPTED", runnerStageSHA("0"), runnerStageSHA("e")},
	}
	for index, result := range results {
		var verified stagereceipt.Verified
		if result.id == "cluster-lifecycle" {
			verified, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, digest.SHA256([]byte(targetAccessRuntimeUID)), at.Add(time.Duration(index-7)*time.Minute))
		} else {
			verified, err = stagereceipt.New(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, at.Add(time.Duration(index-7)*time.Minute))
		}
		if err != nil {
			t.Fatal(err)
		}
		receipts = appendStageReceipt(t, root, receipts, verified, result.id+".json")
		predecessors = []stagereceipt.Verified{verified}
	}
	grantPath, grantKeyPath := writeSubmissionStageGrant(t, root, plan, "target-credential", predecessors, at)
	resume := StageResumeConfig{PlanPath: planPath, PlanExpected: expected, Receipts: receipts}
	plan, _, prefix, err := loadStageResumeWithPrefix(resume)
	if err != nil {
		t.Fatal(err)
	}
	prefixEntries := make([]map[string]any, 0, len(resume.Receipts))
	for _, source := range resume.Receipts {
		prefixEntries = append(prefixEntries, map[string]any{"file": filepath.Base(source.Path), "digest": source.Digest})
	}
	prefixPath := writeBundleFile(t, root, "receipt-prefix.json", mustJSON(t, map[string]any{
		"format": StageReceiptPrefixFormat, "receipts": prefixEntries,
	}))
	runtimeMaterial, runtimeReceipt := writePostRuntimeBindingFiles(t, plan, prefix)

	platformProfilePath := writeBundleFile(t, root, "platform-profile.json", mustJSON(t, platformProfile))
	networkProfilePath := writeBundleFile(t, root, "network-profile.json", mustJSON(t, networkProfile))
	aggregateProfilePath := writeBundleFile(t, root, "aggregate-profile.json", mustJSON(t, aggregateProfile))
	registrationPath := writeBundleFile(t, root, "target-registration.yaml", registration)
	applicationsPath := writeBundleFile(t, root, "platform-applications.yaml", applications)
	targetAccessPath := writeBundleFile(t, root, "target-access.yaml", targetAccess)
	policyPath := writeBundleFile(t, root, "target-credential-policy.json", policyRaw)
	capability := observation.PlatformCapabilityState{
		Format: observation.PlatformCapabilityFormat, ObservedAt: "2026-08-18T08:00:00Z",
		TargetClusterUID: targetAccessRuntimeUID, IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision,
		ExecutionFixture: plan.ExecutionFixture, ContractDigest: platformProfile.CapabilityContractDigest,
		ExecutableDigest: platformProfile.CapabilityExecutableDigest, Passed: true,
	}
	capability.EvidenceDigest, err = observation.PlatformCapabilityDigest(capability)
	if err != nil {
		t.Fatal(err)
	}
	capabilityPath := writeBundleFile(t, root, "platform-capability.json", mustJSON(t, capability))

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	authorizationDirectory := t.TempDir()
	if err := os.Chmod(authorizationDirectory, 0o700); err != nil {
		server.Close()
		t.Fatal(err)
	}
	receiptDirectory := t.TempDir()
	if err := os.Chmod(receiptDirectory, 0o700); err != nil {
		server.Close()
		t.Fatal(err)
	}
	caPath := writeRuntimeBindingServerCA(t, root, "authority-ca.crt", server)
	caRaw, err := os.ReadFile(caPath)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	ledgerDocument := postRuntimeLedgerDocument{
		Endpoint: server.URL, Namespace: "openkubes-execution-system",
		TokenFile: writeBundleFile(t, root, "ledger-token", []byte("ledger-token")), CAFile: caPath,
	}
	workloadBinding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: plan.IntentRevision, TargetClusterUID: targetAccessRuntimeUID,
		TargetIdentityScheme: "capi-cluster-uid/v1", Endpoint: server.URL, CABundleDigest: digest.SHA256(caRaw),
	}
	workloadBindingDigest, err := WorkloadAuthorityBindingDigest(workloadBinding)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	workloadBindingPath := writeBundleFile(t, root, "workload-authority.json", mustJSON(t, workloadBinding))
	workloadTokenPath := writeBundleFile(t, root, "workload-token", []byte("workload-token"))
	gitOpsDocument := postRuntimeAuthorityDocument{Endpoint: "https://192.0.2.11:6443", AuthorityIdentity: "ok-shared", TokenFile: "/private/tmp/argocd-token", CAFile: "/private/tmp/argocd-ca", CABundleDigest: runnerStageSHA("1")}
	document := postRuntimeExecutionManifestDocument{
		Format: PostRuntimeExecutionManifestFormat,
		Plan: postRuntimePlanDocument{
			Path: planPath, Expected: postRuntimePlanExpectedDocument{
				ContractIdentity: plan.ContractIdentity, IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
				PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
				InfrastructureAuthority: plan.Authorities.Infrastructure, ManagementAuthority: plan.Authorities.Management, GitOpsAuthority: plan.Authorities.GitOps,
			},
			ReceiptPrefixPath: prefixPath, ReceiptPrefixDigest: fileSHA(t, prefixPath),
		},
		TargetCredential: postRuntimeTargetCredentialDocument{
			GrantPath: grantPath, GrantPublicKeyPath: grantKeyPath, EvaluationTime: at.Format(time.RFC3339),
			PolicyPath: policyPath, TargetAccessArtifactPath: targetAccessPath,
			TargetAccessExpectedObjects: runnerTargetAccessIdentities(), Ledger: ledgerDocument,
			Workload: postRuntimeWorkloadDocument{Path: workloadBindingPath, ExpectedBindingDigest: workloadBindingDigest, TokenFile: workloadTokenPath, CAFile: caPath},
		},
		Authorization: postRuntimeAuthorizationDocument{
			Endpoint: server.URL + "/v1/stage-authorizations", TokenFile: writeBundleFile(t, root, "authority-token", []byte("authority-token")),
			CAFile:        caPath,
			PublicKeyPath: writeBundleFile(t, root, "authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n")), OutputDirectory: authorizationDirectory,
		},
		TargetRegistration: postRuntimeTargetRegistrationDocument{
			ArtifactPath: registrationPath, ArgoNamespace: "argocd", ProjectName: "openkubes-disposable",
			RegistrationName: "disposable-ok147-cluster", TargetName: plan.ContractIdentity.Name,
			SourceRepository: "https://github.com/openkubes/ok-observability.git", TargetNamespaces: []string{"ok-observability", "kube-system"},
			Ledger: ledgerDocument, GitOps: gitOpsDocument, MaterializationTime: "2026-08-18T08:01:00Z",
		},
		PlatformApplications: postRuntimePlatformApplicationsDocument{
			ArtifactPath: applicationsPath, ArgoNamespace: "argocd", ProjectName: "openkubes-disposable",
			RegistrationName: "disposable-ok147", SourceRepository: "https://github.com/openkubes/ok-observability.git",
			Ledger: ledgerDocument, GitOps: gitOpsDocument,
		},
		Profiles: postRuntimeProfilesDocument{
			Network:   postRuntimeProfileReferenceDocument{Path: networkProfilePath, Digest: networkDigest},
			Platform:  postRuntimeProfileReferenceDocument{Path: platformProfilePath, Digest: platformDigest},
			Aggregate: postRuntimeProfileReferenceDocument{Path: aggregateProfilePath, Digest: aggregateDigest},
		},
		RuntimeBinding: postRuntimeBindingDocument{MaterialPath: runtimeMaterial, ReceiptPath: runtimeReceipt},
		PlatformObservation: postRuntimePlatformObservationDocument{
			Ledger: ledgerDocument, Argo: gitOpsDocument, CapabilityPath: capabilityPath,
			ExpectedCapabilityDigest: capability.EvidenceDigest, PollInterval: "1s", PollTimeout: "1m",
		},
		AggregateEvidence: postRuntimeAggregateEvidenceDocument{
			Ledger: ledgerDocument, Management: postRuntimeAuthorityDocument{Endpoint: "https://192.0.2.12:6443", AuthorityIdentity: "ok-mgmt", TokenFile: "/private/tmp/management-token", CAFile: "/private/tmp/management-ca", CABundleDigest: runnerStageSHA("4")},
			Argo: gitOpsDocument, WorkloadTokenFile: "/private/tmp/aggregate-workload-token", WorkloadCAFile: "/private/tmp/aggregate-workload-ca",
			CapabilityPath: capabilityPath, ExpectedCapabilityDigest: capability.EvidenceDigest,
		},
		ReceiptDirectory: receiptDirectory,
	}
	manifest := writeBundleFile(t, root, "post-runtime-manifest.json", mustJSON(t, document))
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	factories := postRuntimeExecutionFactories{
		credential: func(TargetCredentialStageBundleConfig, TargetCredentialStageRuntimeConfig) (postRuntimeCredentialInvocation, error) {
			return postRuntimeCredentialInvocation{ledger: store, run: func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
				return execution.StagedOperationReceipt{}, nil, errors.New("not executed")
			}}, nil
		},
		registration: func(StageResumeConfig, *VerifiedTargetCredentialStageHandoff, StageAuthorizationSource, PostRuntimeTargetRegistrationConfig, VerifiedRuntimeBindingMaterial) (postRuntimeStagedInvocation, error) {
			return postRuntimeStagedInvocation{ledger: store, run: func(context.Context) (execution.StagedOperationReceipt, error) {
				return execution.StagedOperationReceipt{}, nil
			}}, nil
		},
		applications: func(StageResumeConfig, StageAuthorizationSource, PostRuntimePlatformApplicationsConfig) (postRuntimeStagedInvocation, error) {
			return postRuntimeStagedInvocation{ledger: store, run: func(context.Context) (execution.StagedOperationReceipt, error) {
				return execution.StagedOperationReceipt{}, nil
			}}, nil
		},
		observation: func(StageResumeConfig, PostRuntimePlatformObservationConfig) (postRuntimeObservationInvocation, error) {
			return postRuntimeObservationInvocation{ledger: store, run: func(context.Context) (execution.ObservationStageRunReceipt, error) {
				return execution.ObservationStageRunReceipt{}, nil
			}}, nil
		},
		aggregate: func(StageResumeConfig, PostRuntimeAggregateEvidenceConfig, VerifiedRuntimeBindingMaterial) (postRuntimeEvaluationInvocation, error) {
			return postRuntimeEvaluationInvocation{run: func(context.Context) (execution.EvaluationStageRunReceipt, error) {
				return execution.EvaluationStageRunReceipt{}, nil
			}}, nil
		},
	}
	return manifest, factories, server.Close
}
