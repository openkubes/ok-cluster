package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestVerifyStageAcceptsExactMutatingStage(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := stagePayloadFixture(t, plan, "enablement", at)
	raw := signStage(t, payload, publicKey, privateKey)
	grant, err := VerifyStage(raw, []byte(base64.StdEncoding.EncodeToString(publicKey)), plan, "enablement", stagePredecessorReceipts(t, plan, "enablement", at), at)
	if err != nil {
		t.Fatal(err)
	}
	receipt := grant.Receipt()
	if receipt.State != "VERIFIED" || receipt.StageID != "enablement" || receipt.Operation != "CreateEnablement" || receipt.PlanDigest != plan.PlanDigest {
		t.Fatalf("unexpected stage receipt: %#v", receipt)
	}
	binding, err := grant.ConsumptionBinding()
	if err != nil || binding.StageDigest != receipt.StageDigest || binding.GrantID != payload.GrantID {
		t.Fatalf("unexpected consumption binding: %#v %v", binding, err)
	}
}

func TestVerifyStageRejectsReadOnlyStageAndCrossStageReuse(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	payload := stagePayloadFixture(t, plan, "enablement", at)
	raw := signStage(t, payload, publicKey, privateKey)
	key := []byte(base64.StdEncoding.EncodeToString(publicKey))
	platformPredecessors := stagePredecessorReceipts(t, plan, "platform-applications", at)
	if _, err := VerifyStage(raw, key, plan, "platform-applications", platformPredecessors, at); err == nil {
		t.Fatal("enablement grant was reused for Platform submission")
	}
	readPayload := stagePayloadFixture(t, plan, "lifecycle-observation", at)
	if _, err := VerifyStage(signStage(t, readPayload, publicKey, privateKey), key, plan, "lifecycle-observation", stagePredecessorReceipts(t, plan, "lifecycle-observation", at), at); err == nil {
		t.Fatal("mutation grant was accepted for a read-only stage")
	}
}

func TestVerifyStageRequiresExplicitPredecessorReceipts(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	key := []byte(base64.StdEncoding.EncodeToString(publicKey))
	payload := stagePayloadFixture(t, plan, "provider-prerequisites", at)
	payload.Predecessors = nil
	if _, err := VerifyStage(signStage(t, payload, publicKey, privateKey), key, plan, "provider-prerequisites", []stagereceipt.Verified{}, at); err == nil {
		t.Fatal("omitted empty predecessor set was accepted for the first stage")
	}
}

func TestVerifyStageRejectsEveryChangedBinding(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	key := []byte(base64.StdEncoding.EncodeToString(publicKey))
	tests := map[string]func(*StagePayload){
		"decision":            func(payload *StagePayload) { payload.Decision = "DENY" },
		"plan":                func(payload *StagePayload) { payload.PlanDigest = authSHA("0") },
		"identity":            func(payload *StagePayload) { payload.ContractIdentity.Name = "another" },
		"R":                   func(payload *StagePayload) { payload.ContractRevision = authSHA("1") },
		"E":                   func(payload *StagePayload) { payload.EnablementRevision = authSHA("2") },
		"P":                   func(payload *StagePayload) { payload.PlatformRevision = authSHA("3") },
		"fixture":             func(payload *StagePayload) { payload.ExecutionFixture = authSHA("4") },
		"stage":               func(payload *StagePayload) { payload.StageID = "cluster-lifecycle" },
		"order":               func(payload *StagePayload) { payload.StageOrder++ },
		"stage digest":        func(payload *StagePayload) { payload.StageDigest = authSHA("5") },
		"operation":           func(payload *StagePayload) { payload.Operation = "CreateCluster" },
		"authority":           func(payload *StagePayload) { payload.Authority = "gitops" },
		"predecessor":         func(payload *StagePayload) { payload.Predecessors[0].OutcomeDigest = authSHA("0") },
		"missing predecessor": func(payload *StagePayload) { payload.Predecessors = nil },
		"uses":                func(payload *StagePayload) { payload.MaxUses = 2 },
		"expired":             func(payload *StagePayload) { payload.NotAfter = at.Format(time.RFC3339) },
		"oversized time":      func(payload *StagePayload) { payload.NotAfter = at.Add(31 * time.Minute).Format(time.RFC3339) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload := stagePayloadFixture(t, plan, "enablement", at)
			mutate(&payload)
			expectedPredecessors := stagePredecessorReceipts(t, plan, "enablement", at)
			if _, err := VerifyStage(signStage(t, payload, publicKey, privateKey), key, plan, "enablement", expectedPredecessors, at); err == nil {
				t.Fatal("changed stage authorization was accepted")
			}
		})
	}
}

func TestVerifyStageRejectsTamperingAndNonStrictEnvelope(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	raw := signStage(t, stagePayloadFixture(t, plan, "enablement", at), publicKey, privateKey)
	key := []byte(base64.StdEncoding.EncodeToString(publicKey))
	tampered := strings.Replace(string(raw), `"operation":"CreateEnablement"`, `"operation":"CreateCluster"`, 1)
	predecessors := stagePredecessorReceipts(t, plan, "enablement", at)
	if _, err := VerifyStage([]byte(tampered), key, plan, "enablement", predecessors, at); err == nil {
		t.Fatal("tampered stage authorization was accepted")
	}
	unknown := strings.Replace(string(raw), `"format":"`+StageFormat+`"`, `"format":"`+StageFormat+`","unknown":true`, 1)
	if _, err := VerifyStage([]byte(unknown), key, plan, "enablement", predecessors, at); err == nil {
		t.Fatal("unknown stage authorization field was accepted")
	}
}

func TestBindStageGrantAcceptsExactCursorStage(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	predecessors := stagePredecessorReceipts(t, plan, "enablement", at)
	payload := stagePayloadFixture(t, plan, "enablement", at)
	grant, err := VerifyStage(
		signStage(t, payload, publicKey, privateKey),
		[]byte(base64.StdEncoding.EncodeToString(publicKey)),
		plan,
		"enablement",
		predecessors,
		at,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := BindStageGrant(grant, plan, "enablement", predecessors)
	if err != nil {
		t.Fatal(err)
	}
	if binding.StageID != "enablement" || binding.PlanDigest != plan.PlanDigest || binding.PredecessorDigest != grant.Receipt().PredecessorDigest {
		t.Fatalf("unexpected cursor binding: %#v", binding)
	}
}

func TestBindStageGrantRejectsCrossStageAndSubstitutedPredecessor(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	predecessors := stagePredecessorReceipts(t, plan, "enablement", at)
	payload := stagePayloadFixture(t, plan, "enablement", at)
	grant, err := VerifyStage(
		signStage(t, payload, publicKey, privateKey),
		[]byte(base64.StdEncoding.EncodeToString(publicKey)),
		plan,
		"enablement",
		predecessors,
		at,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindStageGrant(grant, plan, "platform-applications", stagePredecessorReceipts(t, plan, "platform-applications", at)); err == nil {
		t.Fatal("enablement grant was rebound to the Platform cursor stage")
	}
	lifecyclePredecessors := stagePredecessorReceipts(t, plan, "lifecycle-observation", at)
	alternative, err := stagereceipt.New(plan, "lifecycle-observation", lifecyclePredecessors, "SUCCEEDED", "NOT_APPLICABLE", "", authSHA("d"), at.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindStageGrant(grant, plan, "enablement", []stagereceipt.Verified{alternative}); err == nil {
		t.Fatal("grant was rebound to a substituted predecessor receipt")
	}
}

func TestBindStageGrantRejectsUnverifiedGrantAndReadOnlyStage(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	if _, err := BindStageGrant(VerifiedStageGrant{}, plan, "enablement", stagePredecessorReceipts(t, plan, "enablement", at)); err == nil {
		t.Fatal("unverified stage grant was accepted")
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	predecessors := stagePredecessorReceipts(t, plan, "enablement", at)
	grant, err := VerifyStage(
		signStage(t, stagePayloadFixture(t, plan, "enablement", at), publicKey, privateKey),
		[]byte(base64.StdEncoding.EncodeToString(publicKey)),
		plan,
		"enablement",
		predecessors,
		at,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindStageGrant(grant, plan, "lifecycle-observation", stagePredecessorReceipts(t, plan, "lifecycle-observation", at)); err == nil {
		t.Fatal("read-only cursor stage accepted a mutation grant")
	}
}

func TestLoadStageReadsBoundedGrantAndTrustedKey(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	grantPath := filepath.Join(root, "stage-grant.json")
	keyPath := filepath.Join(root, "stage-authority.pub")
	if err := os.WriteFile(grantPath, signStage(t, stagePayloadFixture(t, plan, "enablement", at), publicKey, privateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	grant, err := LoadStage(grantPath, keyPath, plan, "enablement", stagePredecessorReceipts(t, plan, "enablement", at), at)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Receipt().StageID != "enablement" || grant.Receipt().State != "VERIFIED" {
		t.Fatalf("unexpected loaded grant: %#v", grant.Receipt())
	}
}

func TestLoadStageRejectsUnsafeFilesWithoutPathDisclosure(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	grantPath := filepath.Join(root, "stage-grant.json")
	keyPath := filepath.Join(root, "stage-authority.pub")
	if err := os.WriteFile(grantPath, signStage(t, stagePayloadFixture(t, plan, "enablement", at), publicKey, privateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(root, "grant-link")
	if err := os.Symlink(grantPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStage(linkPath, keyPath, plan, "enablement", stagePredecessorReceipts(t, plan, "enablement", at), at); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("unsafe symlink accepted or disclosed path: %v", err)
	}
	if err := os.WriteFile(grantPath, []byte(strings.Repeat("x", maximumStageGrantBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStage(grantPath, keyPath, plan, "enablement", stagePredecessorReceipts(t, plan, "enablement", at), at); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("oversized grant accepted or disclosed path: %v", err)
	}
}

func stagePayloadFixture(t *testing.T, plan stageplan.Binding, stageID string, at time.Time) StagePayload {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	predecessorReceipts := stagePredecessorReceipts(t, plan, stageID, at)
	predecessors := make([]StagePredecessor, len(predecessorReceipts))
	for index, predecessor := range predecessorReceipts {
		receipt, err := predecessor.Receipt()
		if err != nil {
			t.Fatal(err)
		}
		receiptDigest, err := predecessor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		predecessors[index] = StagePredecessor{StageID: receipt.StageID, OutcomeDigest: receiptDigest}
	}
	return StagePayload{
		Audience: StageAudience, GrantID: "ok147-stage-20260816-01", Decision: "ALLOW",
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity, ContractRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision,
		ExecutionFixture: plan.ExecutionFixture, StageID: stage.ID, StageOrder: stage.Order,
		StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority,
		Predecessors: predecessors,
		NotBefore:    at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
}

func stagePredecessorReceipts(t *testing.T, plan stageplan.Binding, stageID string, at time.Time) []stagereceipt.Verified {
	t.Helper()
	predecessors := []stagereceipt.Verified{}
	for _, stage := range plan.Stages {
		if stage.ID == stageID {
			return predecessors
		}
		mutationState := "NOT_APPLICABLE"
		operationOutcome := ""
		if stageplan.IsMutating(stage) {
			mutationState = "ATTEMPTED"
			operationOutcome = authSHA("f")
		}
		receipt, err := stagereceipt.New(plan, stage.ID, predecessors, "SUCCEEDED", mutationState, operationOutcome, authSHA("e"), at.Add(time.Duration(stage.Order)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		predecessors = []stagereceipt.Verified{receipt}
	}
	t.Fatalf("stage %s is not in plan", stageID)
	return nil
}

func signStage(t *testing.T, payload StagePayload, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	signed, err := StageSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(stageEnvelope{
		Format: StageFormat, Payload: payload,
		Signature: signature{Algorithm: "Ed25519", KeyID: digest.SHA256(publicKey), Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func stagePlanFixture(t *testing.T) stageplan.Binding {
	t.Helper()
	identity := contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
	type stage struct {
		id, kind, authority, operation string
		requires                       []string
	}
	sequence := []stage{
		{id: "provider-prerequisites", kind: "Submission", authority: "infrastructure", operation: "CreateProviderPrerequisites"},
		{id: "cluster-lifecycle", kind: "Submission", authority: "management", operation: "CreateCluster", requires: []string{"provider-prerequisites"}},
		{id: "lifecycle-observation", kind: "Observation", authority: "management", requires: []string{"cluster-lifecycle"}},
		{id: "enablement", kind: "Submission", authority: "management", operation: "CreateEnablement", requires: []string{"lifecycle-observation"}},
		{id: "network-observation", kind: "Observation", authority: "workload", requires: []string{"enablement"}},
		{id: "runtime-binding", kind: "Binding", authority: "runner", requires: []string{"network-observation"}},
		{id: "target-access", kind: "Submission", authority: "workload", operation: "CreateTargetAccess", requires: []string{"runtime-binding"}},
		{id: "target-credential", kind: "Credential", authority: "workload", operation: "IssueTargetCredential", requires: []string{"target-access"}},
		{id: "target-registration", kind: "Submission", authority: "gitops", operation: "RegisterTarget", requires: []string{"target-credential"}},
		{id: "platform-applications", kind: "Submission", authority: "gitops", operation: "CreatePlatformApplications", requires: []string{"target-registration"}},
		{id: "platform-observation", kind: "Observation", authority: "gitops", requires: []string{"platform-applications"}},
		{id: "aggregate-evidence", kind: "Evaluation", authority: "runner", requires: []string{"platform-observation"}},
	}
	stages := make([]map[string]any, 0, len(sequence))
	for index, item := range sequence {
		value := map[string]any{
			"id": item.id, "order": index + 1, "kind": item.kind, "authority": item.authority,
			"requires": item.requires, "inputs": []map[string]any{{"name": "stage." + item.id, "digest": authSHA(string("abcdef012345"[index]))}},
		}
		if item.requires == nil {
			value["requires"] = []string{}
		}
		if item.operation != "" {
			value["grantOperation"] = item.operation
		}
		stages = append(stages, value)
	}
	document := map[string]any{
		"format": stageplan.Format, "contractIdentity": identity,
		"intentRevision": authSHA("a"), "enablementRevision": authSHA("b"), "platformRevision": authSHA("c"), "executionFixture": authSHA("d"),
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: authSHA("a"), EnablementRevision: authSHA("b"), PlatformRevision: authSHA("c"), ExecutionFixture: authSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func authSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
