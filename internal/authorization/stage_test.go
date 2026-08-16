package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
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
	grant, err := VerifyStage(raw, []byte(base64.StdEncoding.EncodeToString(publicKey)), plan, "enablement", at)
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
	if _, err := VerifyStage(raw, key, plan, "platform-applications", at); err == nil {
		t.Fatal("enablement grant was reused for Platform submission")
	}
	readPayload := stagePayloadFixture(t, plan, "lifecycle-observation", at)
	if _, err := VerifyStage(signStage(t, readPayload, publicKey, privateKey), key, plan, "lifecycle-observation", at); err == nil {
		t.Fatal("mutation grant was accepted for a read-only stage")
	}
}

func TestVerifyStageRejectsEveryChangedBinding(t *testing.T) {
	plan := stagePlanFixture(t)
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	key := []byte(base64.StdEncoding.EncodeToString(publicKey))
	tests := map[string]func(*StagePayload){
		"decision":       func(payload *StagePayload) { payload.Decision = "DENY" },
		"plan":           func(payload *StagePayload) { payload.PlanDigest = authSHA("0") },
		"identity":       func(payload *StagePayload) { payload.ContractIdentity.Name = "another" },
		"R":              func(payload *StagePayload) { payload.ContractRevision = authSHA("1") },
		"E":              func(payload *StagePayload) { payload.EnablementRevision = authSHA("2") },
		"P":              func(payload *StagePayload) { payload.PlatformRevision = authSHA("3") },
		"fixture":        func(payload *StagePayload) { payload.ExecutionFixture = authSHA("4") },
		"stage":          func(payload *StagePayload) { payload.StageID = "cluster-lifecycle" },
		"order":          func(payload *StagePayload) { payload.StageOrder++ },
		"stage digest":   func(payload *StagePayload) { payload.StageDigest = authSHA("5") },
		"operation":      func(payload *StagePayload) { payload.Operation = "CreateCluster" },
		"authority":      func(payload *StagePayload) { payload.Authority = "gitops" },
		"uses":           func(payload *StagePayload) { payload.MaxUses = 2 },
		"expired":        func(payload *StagePayload) { payload.NotAfter = at.Format(time.RFC3339) },
		"oversized time": func(payload *StagePayload) { payload.NotAfter = at.Add(31 * time.Minute).Format(time.RFC3339) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload := stagePayloadFixture(t, plan, "enablement", at)
			mutate(&payload)
			if _, err := VerifyStage(signStage(t, payload, publicKey, privateKey), key, plan, "enablement", at); err == nil {
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
	if _, err := VerifyStage([]byte(tampered), key, plan, "enablement", at); err == nil {
		t.Fatal("tampered stage authorization was accepted")
	}
	unknown := strings.Replace(string(raw), `"format":"`+StageFormat+`"`, `"format":"`+StageFormat+`","unknown":true`, 1)
	if _, err := VerifyStage([]byte(unknown), key, plan, "enablement", at); err == nil {
		t.Fatal("unknown stage authorization field was accepted")
	}
}

func stagePayloadFixture(t *testing.T, plan stageplan.Binding, stageID string, at time.Time) StagePayload {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	return StagePayload{
		Audience: StageAudience, GrantID: "ok147-stage-20260816-01", Decision: "ALLOW",
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity, ContractRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision,
		ExecutionFixture: plan.ExecutionFixture, StageID: stage.ID, StageOrder: stage.Order,
		StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority,
		NotBefore: at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
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
