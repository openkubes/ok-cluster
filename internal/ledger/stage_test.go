package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestStageClaimIsAtomicAndCrashStopsRetry(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 15, 0, 0, 0, time.UTC)
	grant := verifiedStageGrant(t, at)
	available, err := store.InspectStage(context.Background(), grant)
	if err != nil || available.State != "AVAILABLE" || !available.ClaimAllowed {
		t.Fatalf("stage grant is not available: %#v %v", available, err)
	}
	var acquired atomic.Int32
	var consumed atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 24; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := store.ClaimStage(context.Background(), grant, at); err == nil {
				acquired.Add(1)
			} else if errors.Is(err, ErrGrantConsumed) {
				consumed.Add(1)
			} else {
				t.Errorf("claim stage: %v", err)
			}
		}()
	}
	wait.Wait()
	if acquired.Load() != 1 || consumed.Load() != 23 {
		t.Fatalf("acquired=%d consumed=%d", acquired.Load(), consumed.Load())
	}
	inspection, err := store.InspectStage(context.Background(), grant)
	if err != nil || inspection.State != "CLAIMED_INDETERMINATE_STOP" || inspection.ClaimAllowed {
		t.Fatalf("unsafe stage restart decision: %#v %v", inspection, err)
	}
}

func TestStageClaimRechecksWindowAtConsumption(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "ledger"))
	at := time.Date(2026, 8, 16, 15, 0, 0, 0, time.UTC)
	grant := verifiedStageGrant(t, at)
	if _, err := store.ClaimStage(context.Background(), grant, at.Add(30*time.Minute)); err == nil {
		t.Fatal("expired stage grant was consumed")
	}
	if _, err := store.ClaimStage(context.Background(), grant, at); err != nil {
		t.Fatalf("rejected attempt consumed stage grant: %v", err)
	}
}

func TestStageCompletionIsBoundImmutableAndIdempotent(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "ledger"))
	at := time.Date(2026, 8, 16, 15, 0, 0, 0, time.UTC)
	grant := verifiedStageGrant(t, at)
	claim, err := store.ClaimStage(context.Background(), grant, at)
	if err != nil {
		t.Fatal(err)
	}
	evidence := stageSHA("e")
	if _, err := store.CompleteStage(context.Background(), claim, "SUCCEEDED", "NOT_ATTEMPTED", evidence, at.Add(time.Second)); err == nil {
		t.Fatal("successful stage without attempted mutation was accepted")
	}
	first, err := store.CompleteStage(context.Background(), claim, "SUCCEEDED", "ATTEMPTED", evidence, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CompleteStage(context.Background(), claim, "SUCCEEDED", "ATTEMPTED", evidence, at.Add(time.Second))
	if err != nil || second != first {
		t.Fatalf("identical stage completion is not idempotent: %#v %v", second, err)
	}
	if _, err := store.CompleteStage(context.Background(), claim, "FAILED", "UNKNOWN", evidence, at.Add(2*time.Second)); err == nil {
		t.Fatal("conflicting stage completion was accepted")
	}
	inspection, err := store.InspectStage(context.Background(), grant)
	if err != nil || inspection.State != "COMPLETED" || inspection.Outcome == nil || inspection.Outcome.Outcome != "SUCCEEDED" {
		t.Fatalf("unexpected completed stage inspection: %#v %v", inspection, err)
	}
}

func verifiedStageGrant(t *testing.T, at time.Time) authorization.VerifiedStageGrant {
	t.Helper()
	plan := verifiedStagePlan(t)
	return verifiedStageGrantFor(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
}

func verifiedStageGrantFor(t *testing.T, plan stageplan.Binding, stageID string, predecessors []stagereceipt.Verified, at time.Time) authorization.VerifiedStageGrant {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	signedPredecessors := make([]authorization.StagePredecessor, len(predecessors))
	for index, predecessor := range predecessors {
		receipt, err := predecessor.Receipt()
		if err != nil {
			t.Fatal(err)
		}
		receiptDigest, err := predecessor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		signedPredecessors[index] = authorization.StagePredecessor{StageID: receipt.StageID, OutcomeDigest: receiptDigest}
	}
	payload := authorization.StagePayload{
		Audience: authorization.StageAudience, GrantID: "ok147-stage-ledger-20260816-01", Decision: "ALLOW",
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity, ContractRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority,
		Predecessors: signedPredecessors,
		NotBefore:    at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := authorization.StageSigningBytes(payload)
	document, _ := json.Marshal(map[string]any{
		"format": authorization.StageFormat, "payload": payload,
		"signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
	grant, err := authorization.VerifyStage(document, []byte(base64.StdEncoding.EncodeToString(publicKey)), plan, stage.ID, predecessors, at)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func verifiedStagePlan(t *testing.T) stageplan.Binding {
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
			"inputs": []map[string]any{{"name": "stage." + ids[index], "digest": stageSHA(string("abcdef012345"[index]))}},
		}
		if operations[index] != "" {
			stages[index]["grantOperation"] = operations[index]
		}
	}
	planRaw, _ := json.Marshal(map[string]any{
		"format": stageplan.Format, "contractIdentity": identity,
		"intentRevision": stageSHA("a"), "enablementRevision": stageSHA("b"), "platformRevision": stageSHA("c"), "executionFixture": stageSHA("d"),
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	})
	plan, err := stageplan.Verify(planRaw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: stageSHA("a"), EnablementRevision: stageSHA("b"), PlatformRevision: stageSHA("c"), ExecutionFixture: stageSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func stageSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
