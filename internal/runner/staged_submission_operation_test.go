package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestOpenKubernetesSubmissionStageOperationBindsOneAuthority(t *testing.T) {
	plan := runnerStagedPlan(t)
	config := runnerStagedOperationConfig(t, plan, "provider-prerequisites")
	operation, err := OpenKubernetesSubmissionStageOperation(config)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Ledger == nil || operation.Mutator == nil || operation.Clock == nil {
		t.Fatalf("incomplete staged operation: %#v", operation)
	}
	binding := operation.Mutator.Binding()
	if binding.StageID != "provider-prerequisites" || binding.Operation != "CreateProviderPrerequisites" || binding.PlanDigest != plan.PlanDigest {
		t.Fatalf("operation bound a different stage: %#v", binding)
	}
}

func TestOpenKubernetesSubmissionStageOperationRejectsAuthorityAndCredentialAliasing(t *testing.T) {
	plan := runnerStagedPlan(t)
	config := runnerStagedOperationConfig(t, plan, "cluster-lifecycle")
	config.Authority.AuthorityIdentity = plan.Authorities.Infrastructure
	if _, err := OpenKubernetesSubmissionStageOperation(config); err == nil {
		t.Fatal("different stage authority was accepted")
	}

	config = runnerStagedOperationConfig(t, plan, "cluster-lifecycle")
	ledgerToken, err := os.ReadFile(config.Ledger.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Authority.TokenFile, ledgerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesSubmissionStageOperation(config); err == nil {
		t.Fatal("shared ledger and write credential was accepted")
	}
}

func TestOpenKubernetesSubmissionStageOperationRejectsUnsupportedOrForeignInputs(t *testing.T) {
	plan := runnerStagedPlan(t)
	config := runnerStagedOperationConfig(t, plan, "provider-prerequisites")
	config.StageID = "enablement"
	if _, err := OpenKubernetesSubmissionStageOperation(config); err == nil {
		t.Fatal("Enablement was accepted by the CAPI submission composition")
	}
	config = runnerStagedOperationConfig(t, plan, "provider-prerequisites")
	config.Projection.IntentRevision = runnerStageSHA("0")
	if _, err := OpenKubernetesSubmissionStageOperation(config); err == nil {
		t.Fatal("foreign projection revision was accepted")
	}
	config = runnerStagedOperationConfig(t, plan, "provider-prerequisites")
	config.Clock = nil
	if _, err := OpenKubernetesSubmissionStageOperation(config); err == nil {
		t.Fatal("missing explicit clock was accepted")
	}
}

func runnerStagedOperationConfig(t *testing.T, plan stageplan.Binding, stageID string) KubernetesSubmissionStageOperationConfig {
	t.Helper()
	root := t.TempDir()
	caPath := filepath.Join(root, "ca.crt")
	ledgerToken := filepath.Join(root, "ledger-token")
	authorityToken := filepath.Join(root, "authority-token")
	for path, value := range map[string][]byte{
		caPath:         testCA(t),
		ledgerToken:    []byte("short-lived-ledger-token"),
		authorityToken: []byte("short-lived-authority-token"),
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	authority := plan.Authorities.Infrastructure
	endpoint := "https://192.0.2.11:6443"
	if stageID == "cluster-lifecycle" {
		authority = plan.Authorities.Management
		endpoint = "https://192.0.2.12:6443"
	}
	return KubernetesSubmissionStageOperationConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: "https://192.0.2.12:6443", Namespace: "openkubes-execution-system", TokenFile: ledgerToken, CAFile: caPath,
		},
		Authority: KubernetesAuthorityConfig{
			Endpoint: endpoint, AuthorityIdentity: authority, TokenFile: authorityToken, CAFile: caPath,
		},
		Plan: plan, StageID: stageID,
		Projection: runnerSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management),
		Clock:      func() time.Time { return time.Date(2026, 8, 16, 20, 0, 0, 0, time.UTC) },
	}
}

func runnerSubmissionPlan(revision, infrastructure, management string) submission.Plan {
	object := func(apiVersion, kind, namespace, name, value string) submission.Object {
		return submission.Object{
			Identity: projection.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name},
			Digest:   runnerStageSHA(value), CollectionPath: "/apis/example/v1/resources", ObjectPath: "/apis/example/v1/resources/" + name,
			Raw: json.RawMessage("{\"apiVersion\":\"v1\",\"kind\":\"Namespace\"}"),
		}
	}
	return submission.Plan{
		Format: submission.PlanFormat, IntentRevision: revision, AuthorityMapDigest: runnerStageSHA("9"),
		Infrastructure: submission.Plane{Identity: infrastructure, Role: "provider-runtime-and-golden-image-prerequisites", Objects: []submission.Object{object("v1", "Namespace", "", "disposable-ok147", "7")}},
		Management:     submission.Plane{Identity: management, Role: "single-lifecycle-writer", Objects: []submission.Object{object("cluster.x-k8s.io/v1beta2", "Cluster", "disposable-ok147", "disposable-ok147", "8")}},
	}
}

func runnerStagedPlan(t *testing.T) stageplan.Binding {
	t.Helper()
	identity := contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
	ids := []string{"provider-prerequisites", "cluster-lifecycle", "lifecycle-observation", "enablement", "network-observation", "runtime-binding", "target-access", "target-credential", "target-registration", "platform-applications", "platform-observation", "aggregate-evidence"}
	kinds := []string{"Submission", "Submission", "Observation", "Submission", "Observation", "Binding", "Submission", "Credential", "Submission", "Submission", "Observation", "Evaluation"}
	authorities := []string{"infrastructure", "management", "management", "management", "workload", "runner", "workload", "workload", "gitops", "gitops", "gitops", "runner"}
	operations := []string{"CreateProviderPrerequisites", "CreateCluster", "", "CreateEnablement", "", "", "CreateTargetAccess", "IssueTargetCredential", "RegisterTarget", "CreatePlatformApplications", "", ""}
	stages := make([]map[string]any, len(ids))
	for index := range ids {
		requires := []string{}
		if index > 0 {
			requires = []string{ids[index-1]}
		}
		stages[index] = map[string]any{
			"id": ids[index], "order": index + 1, "kind": kinds[index], "authority": authorities[index], "requires": requires,
			"inputs": []map[string]any{{"name": "stage." + ids[index], "digest": runnerStageSHA(string("abcdef012345"[index]))}},
		}
		if operations[index] != "" {
			stages[index]["grantOperation"] = operations[index]
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"format": stageplan.Format, "contractIdentity": identity,
		"intentRevision": runnerStageSHA("a"), "enablementRevision": runnerStageSHA("b"), "platformRevision": runnerStageSHA("c"), "executionFixture": runnerStageSHA("d"),
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	})
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: runnerStageSHA("a"), EnablementRevision: runnerStageSHA("b"), PlatformRevision: runnerStageSHA("c"), ExecutionFixture: runnerStageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func runnerStageSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
