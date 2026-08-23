package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestStagedOperationRunsOneBoundMutationAndResumesFromOutcome(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	cursor, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	grant := stagedGrant(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	mutator := &fakeStageMutator{
		binding: stagedMutationBinding(t, plan, "provider-prerequisites"),
		result:  StageMutationResult{Outcome: "SUCCEEDED", MutationState: "ATTEMPTED", EvidenceDigest: stagedSHA("e")},
	}
	operation := StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at)}
	receipt, err := operation.Run(context.Background(), plan, cursor, grant)
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageReceiptDigest == "" || mutator.calls != 1 {
		t.Fatalf("unexpected staged run: %#v calls=%d err=%v", receipt, mutator.calls, err)
	}
	if mutator.request.StageID != "provider-prerequisites" || mutator.request.ContractIdentity != plan.ContractIdentity || mutator.request.GrantID == "" {
		t.Fatalf("mutator received a different binding: %#v", mutator.request)
	}
	verified, err := store.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", receipt.StageReceiptDigest, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	next, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{verified})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := next.Decision()
	if decision.State != "NEXT" || decision.StageID != "cluster-lifecycle" {
		t.Fatalf("durable receipt did not advance cursor: %#v", decision)
	}
	replayed, err := operation.Run(context.Background(), plan, cursor, grant)
	if err != nil || replayed.StageReceiptDigest != receipt.StageReceiptDigest || mutator.calls != 1 {
		t.Fatalf("completed outcome replayed mutation: %#v calls=%d err=%v", replayed, mutator.calls, err)
	}
}

func TestStagedOperationPersistsRedactedNonSuccessWithoutRetry(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	cursor, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{})
	grant := stagedGrant(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	mutator := &fakeStageMutator{
		binding: stagedMutationBinding(t, plan, "provider-prerequisites"),
		result:  StageMutationResult{Outcome: "STOPPED", MutationState: "UNKNOWN", EvidenceDigest: stagedSHA("f")},
		err:     errors.New("secret endpoint detail"),
	}
	receipt, err := (StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at)}).Run(context.Background(), plan, cursor, grant)
	var resultErr *StageResultError
	if !errors.As(err, &resultErr) || strings.Contains(err.Error(), "secret") || receipt.State != "COMPLETED_STOPPED" || mutator.calls != 1 {
		t.Fatalf("non-success was not durably redacted: %#v calls=%d err=%v", receipt, mutator.calls, err)
	}
	verified, loadErr := store.LoadStageReceipt(context.Background(), plan, "provider-prerequisites", receipt.StageReceiptDigest, []stagereceipt.Verified{})
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	terminal, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{verified})
	decision, _ := terminal.Decision()
	if decision.State != "STOPPED" || decision.TerminalOutcome != "STOPPED" {
		t.Fatalf("non-success receipt did not close the plan: %#v", decision)
	}
}

func TestStagedOperationInvalidMutatorResultLeavesIndeterminateClaim(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	cursor, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{})
	grant := stagedGrant(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	mutator := &fakeStageMutator{
		binding: stagedMutationBinding(t, plan, "provider-prerequisites"),
		result:  StageMutationResult{Outcome: "SUCCEEDED", MutationState: "ATTEMPTED", EvidenceDigest: stagedSHA("e")},
		err:     errors.New("write result uncertain with sensitive detail"),
	}
	operation := StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at)}
	receipt, err := operation.Run(context.Background(), plan, cursor, grant)
	if err == nil || strings.Contains(err.Error(), "sensitive") || receipt.State != "CLAIMED_INDETERMINATE_STOP" || mutator.calls != 1 {
		t.Fatalf("inconsistent mutator result did not fail closed: %#v calls=%d err=%v", receipt, mutator.calls, err)
	}
	inspection, err := store.InspectStage(context.Background(), grant)
	if err != nil || inspection.State != "CLAIMED_INDETERMINATE_STOP" {
		t.Fatalf("claim is not durably indeterminate: %#v %v", inspection, err)
	}
	if _, err := operation.Run(context.Background(), plan, cursor, grant); err == nil || mutator.calls != 1 {
		t.Fatalf("indeterminate claim retried mutation: calls=%d err=%v", mutator.calls, err)
	}
}

func TestStageMutationValidationAllowsOnlyProviderEnsureWithoutWrite(t *testing.T) {
	result := StageMutationResult{Outcome: "SUCCEEDED", MutationState: "NOT_ATTEMPTED", EvidenceDigest: stagedSHA("e")}
	if err := validateStageMutationResult("provider-prerequisites", result, nil); err != nil {
		t.Fatalf("exact existing provider prerequisites were rejected: %v", err)
	}
	if err := validateStageMutationResult("cluster-lifecycle", result, nil); err == nil {
		t.Fatal("Cluster lifecycle claimed success without a write")
	}
	if err := validateStageMutationResult("provider-prerequisites", result, errors.New("write uncertainty")); err == nil {
		t.Fatal("provider prerequisites hid a mutation error behind no-write success")
	}
}

func TestStagedOperationRejectsWrongMutatorBeforeClaim(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	cursor, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{})
	grant := stagedGrant(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	mutator := &fakeStageMutator{binding: stagedMutationBinding(t, plan, "provider-prerequisites")}
	mutator.binding.Operation = "CreateCluster"
	if _, err := (StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at)}).Run(context.Background(), plan, cursor, grant); err == nil {
		t.Fatal("wrong preconstructed mutator was accepted")
	}
	inspection, err := store.InspectStage(context.Background(), grant)
	if err != nil || inspection.State != "AVAILABLE" || mutator.calls != 0 {
		t.Fatalf("preclaim mismatch consumed grant: %#v calls=%d err=%v", inspection, mutator.calls, err)
	}
}

func TestStagedOperationRejectsReadOnlyCursor(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	first, _ := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stagedSHA("1"), stagedSHA("e"), at)
	second, _ := stagereceipt.New(plan, "cluster-lifecycle", []stagereceipt.Verified{first}, "SUCCEEDED", "ATTEMPTED", stagedSHA("2"), stagedSHA("e"), at.Add(time.Second))
	cursor, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{first, second})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	mutator := &fakeStageMutator{}
	if _, err := (StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at)}).Run(context.Background(), plan, cursor, authorization.VerifiedStageGrant{}); err == nil || mutator.calls != 0 {
		t.Fatalf("read-only cursor reached mutator: calls=%d err=%v", mutator.calls, err)
	}
}

func TestStagedOperationRequiresLifecycleRuntimeIdentityDigest(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stagedSHA("1"), stagedSHA("e"), at)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{provider})
	if err != nil {
		t.Fatal(err)
	}
	grant := stagedGrant(t, plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, at.Add(time.Second))
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	mutator := &fakeStageMutator{
		binding: stagedMutationBinding(t, plan, "cluster-lifecycle"),
		result:  StageMutationResult{Outcome: "SUCCEEDED", MutationState: "ATTEMPTED", EvidenceDigest: stagedSHA("e")},
	}
	receipt, err := (StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at.Add(time.Second))}).Run(context.Background(), plan, cursor, grant)
	if err == nil || receipt.State != "CLAIMED_INDETERMINATE_STOP" || mutator.calls != 1 {
		t.Fatalf("lifecycle result without target correlation did not stop: %#v calls=%d err=%v", receipt, mutator.calls, err)
	}
}

type fakeStageMutator struct {
	binding StageMutationBinding
	result  StageMutationResult
	err     error
	calls   int
	request StageMutationRequest
}

func (mutator *fakeStageMutator) Binding() StageMutationBinding { return mutator.binding }

func (mutator *fakeStageMutator) Mutate(_ context.Context, request StageMutationRequest) (StageMutationResult, error) {
	mutator.calls++
	mutator.request = request
	return mutator.result, mutator.err
}

func stagedMutationBinding(t *testing.T, plan stageplan.Binding, stageID string) StageMutationBinding {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	return StageMutationBinding{
		PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
		Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
	}
}

func stagedGrant(t *testing.T, plan stageplan.Binding, stageID string, predecessors []stagereceipt.Verified, at time.Time) authorization.VerifiedStageGrant {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	signedPredecessors := make([]authorization.StagePredecessor, len(predecessors))
	for index, predecessor := range predecessors {
		receipt, _ := predecessor.Receipt()
		receiptDigest, _ := predecessor.Digest()
		signedPredecessors[index] = authorization.StagePredecessor{StageID: receipt.StageID, OutcomeDigest: receiptDigest}
	}
	payload := authorization.StagePayload{
		Audience: authorization.StageAudience, GrantID: "ok147-staged-operation-20260816-01", Decision: "ALLOW",
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity, ContractRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority,
		Predecessors: signedPredecessors,
		NotBefore:    at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := authorization.StageSigningBytes(payload)
	raw, _ := json.Marshal(map[string]any{
		"format": authorization.StageFormat, "payload": payload,
		"signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
	grant, err := authorization.VerifyStage(raw, []byte(base64.StdEncoding.EncodeToString(publicKey)), plan, stageID, predecessors, at)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func stagedPlan(t *testing.T) stageplan.Binding {
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
			"inputs": []map[string]any{{"name": "stage." + ids[index], "digest": stagedSHA(string("abcdef012345"[index]))}},
		}
		if operations[index] != "" {
			stages[index]["grantOperation"] = operations[index]
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"format": stageplan.Format, "contractIdentity": identity,
		"intentRevision": stagedSHA("a"), "enablementRevision": stagedSHA("b"), "platformRevision": stagedSHA("c"), "executionFixture": stagedSHA("d"),
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	})
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: stagedSHA("a"), EnablementRevision: stagedSHA("b"), PlatformRevision: stagedSHA("c"), ExecutionFixture: stagedSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func stagedClock(start time.Time) func() time.Time {
	next := start
	return func() time.Time {
		current := next
		next = next.Add(time.Second)
		return current
	}
}

func stagedSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
