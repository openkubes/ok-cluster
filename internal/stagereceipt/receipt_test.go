package stagereceipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestReceiptChainIncludesMutatingAndReadOnlyStages(t *testing.T) {
	plan := receiptPlan(t)
	at := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)
	provider, err := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := New(plan, "cluster-lifecycle", []Verified{provider}, "SUCCEEDED", "ATTEMPTED", receiptSHA("2"), receiptSHA("b"), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := New(plan, "lifecycle-observation", []Verified{lifecycle}, "SUCCEEDED", "NOT_APPLICABLE", "", receiptSHA("c"), at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := observation.Receipt()
	if err != nil || receipt.StageID != "lifecycle-observation" || receipt.MutationState != "NOT_APPLICABLE" || len(receipt.Predecessors) != 1 {
		t.Fatalf("unexpected observation receipt: %#v %v", receipt, err)
	}
	lifecycleDigest, _ := lifecycle.Digest()
	if receipt.Predecessors[0].ReceiptDigest != lifecycleDigest {
		t.Fatal("observation does not bind the exact lifecycle receipt")
	}
	raw, _ := observation.Bytes()
	observationDigest, _ := observation.Digest()
	reloaded, err := Verify(raw, observationDigest, plan, []Verified{lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	if reloadedDigest, _ := reloaded.Digest(); reloadedDigest == "" {
		t.Fatal("verified receipt has no digest")
	}
}

func TestReceiptRejectsMissingForeignAndFailedPredecessors(t *testing.T) {
	plan := receiptPlan(t)
	at := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)
	if _, err := New(plan, "provider-prerequisites", nil, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at); err == nil {
		t.Fatal("omitted empty predecessor set was accepted")
	}
	provider, _ := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	if _, err := New(plan, "lifecycle-observation", []Verified{provider}, "SUCCEEDED", "NOT_APPLICABLE", "", receiptSHA("b"), at); err == nil {
		t.Fatal("wrong predecessor stage was accepted")
	}
	failedProvider, _ := New(plan, "provider-prerequisites", []Verified{}, "FAILED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	if _, err := New(plan, "cluster-lifecycle", []Verified{failedProvider}, "SUCCEEDED", "ATTEMPTED", receiptSHA("2"), receiptSHA("b"), at); err == nil {
		t.Fatal("failed predecessor opened the next stage")
	}
}

func TestReceiptEnforcesMutationBoundary(t *testing.T) {
	plan := receiptPlan(t)
	at := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)
	if _, err := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "NOT_ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at); err == nil {
		t.Fatal("successful mutation without attempt was accepted")
	}
	provider, _ := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	lifecycle, _ := New(plan, "cluster-lifecycle", []Verified{provider}, "SUCCEEDED", "ATTEMPTED", receiptSHA("2"), receiptSHA("b"), at)
	if _, err := New(plan, "lifecycle-observation", []Verified{lifecycle}, "SUCCEEDED", "ATTEMPTED", receiptSHA("3"), receiptSHA("c"), at); err == nil {
		t.Fatal("read-only stage with mutation state was accepted")
	}
}

func TestLifecycleReceiptBindsOnlyTargetUIDDigest(t *testing.T) {
	plan := receiptPlan(t)
	at := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)
	provider, _ := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	verified, err := NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", []Verified{provider}, "SUCCEEDED", "ATTEMPTED", receiptSHA("2"), receiptSHA("b"), receiptSHA("7"), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := verified.Receipt()
	if receipt.TargetClusterUIDDigest != receiptSHA("7") {
		t.Fatalf("target UID digest differs: %#v", receipt)
	}
	if _, err := NewWithTargetClusterUIDDigest(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), receiptSHA("7"), at); err == nil {
		t.Fatal("target identity binding outside Cluster lifecycle was accepted")
	}
}

func TestReceiptRejectsCompletionBeforePredecessor(t *testing.T) {
	plan := receiptPlan(t)
	at := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)
	provider, err := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(plan, "cluster-lifecycle", []Verified{provider}, "SUCCEEDED", "ATTEMPTED", receiptSHA("2"), receiptSHA("b"), at.Add(-time.Nanosecond)); err == nil {
		t.Fatal("stage receipt completed before its predecessor was accepted")
	}
}

func TestReceiptVerificationFailsClosedOnTamperingAndSymlink(t *testing.T) {
	plan := receiptPlan(t)
	at := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)
	provider, _ := New(plan, "provider-prerequisites", []Verified{}, "SUCCEEDED", "ATTEMPTED", receiptSHA("1"), receiptSHA("a"), at)
	raw, _ := provider.Bytes()
	providerDigest, _ := provider.Digest()
	tampered := strings.Replace(string(raw), `"state":"SUCCEEDED"`, `"state":"FAILED"`, 1)
	if _, err := Verify([]byte(tampered), providerDigest, plan, []Verified{}); err == nil {
		t.Fatal("tampered receipt was accepted")
	}
	pretty := map[string]any{}
	if err := json.Unmarshal(raw, &pretty); err != nil {
		t.Fatal(err)
	}
	nonCanonical, _ := json.MarshalIndent(pretty, "", "  ")
	if _, err := Verify(nonCanonical, providerDigest, plan, []Verified{}); err == nil {
		t.Fatal("non-canonical receipt was accepted")
	}
	root := t.TempDir()
	path := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "receipt-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link, providerDigest, plan, []Verified{}); err == nil {
		t.Fatal("symlinked receipt was accepted")
	}
}

func receiptPlan(t *testing.T) stageplan.Binding {
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
			"inputs": []map[string]any{{"name": "stage." + ids[index], "digest": receiptSHA(string("abcdef012345"[index]))}},
		}
		if operations[index] != "" {
			stages[index]["grantOperation"] = operations[index]
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"format": stageplan.Format, "contractIdentity": identity,
		"intentRevision": receiptSHA("a"), "enablementRevision": receiptSHA("b"), "platformRevision": receiptSHA("c"), "executionFixture": receiptSHA("d"),
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	})
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: receiptSHA("a"), EnablementRevision: receiptSHA("b"), PlatformRevision: receiptSHA("c"), ExecutionFixture: receiptSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func receiptSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
