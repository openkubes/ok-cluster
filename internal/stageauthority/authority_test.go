package stageauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestAuthorityIssuesOneExactVerifiableGrant(t *testing.T) {
	material := testMaterial(t)
	authority, receipt, err := Open(material.config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "VERIFIED" || receipt.PolicyDigest == "" || receipt.KeyID != digest.SHA256(material.publicKey) || receipt.MutationAllowed {
		t.Fatalf("unexpected open receipt: %#v", receipt)
	}

	requestRaw := requestBytes(t, material.request)
	response := performRequest(authority, material.token, requestMediaType, requestRaw)
	if response.Code != http.StatusCreated || response.Header().Get("Content-Type") != responseMediaType {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
	publicRaw := []byte(base64.StdEncoding.EncodeToString(material.publicKey))
	verified, err := authorization.VerifyStage(response.Body.Bytes(), publicRaw, material.plan, material.request.StageID, []stagereceipt.Verified{}, material.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	grant := verified.Receipt()
	if grant.State != "VERIFIED" || grant.StageID != material.request.StageID || grant.PlanDigest != material.request.PlanDigest || grant.MaxUses != 1 {
		t.Fatalf("unexpected verified grant: %#v", grant)
	}

	replay := performRequest(authority, material.token, requestMediaType, requestRaw)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay returned %d", replay.Code)
	}
	entries, err := os.ReadDir(material.stateDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("single-use claim differs: %d %v", len(entries), err)
	}
}

func TestFromPlanDerivesOnlyMutatingStagesDeterministically(t *testing.T) {
	plan := verifiedPlan(t)
	first, receipt, err := FromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, secondReceipt, err := FromPlan(plan)
	if err != nil || !bytes.Equal(first, second) || receipt != secondReceipt {
		t.Fatalf("derived policy is not deterministic: %v", err)
	}
	if receipt.StageCount != 7 || receipt.PlanDigest != plan.PlanDigest || receipt.PolicyDigest != digest.SHA256(first) || receipt.MutationAllowed {
		t.Fatalf("unexpected policy receipt: %#v", receipt)
	}
	var policy Policy
	if err := json.Unmarshal(first, &policy); err != nil {
		t.Fatal(err)
	}
	for _, stage := range policy.Stages {
		if stage.Operation == "" {
			t.Fatalf("read-only stage entered authority policy: %#v", stage)
		}
	}
}

func TestAuthorityRejectsBeforeSingleUseClaim(t *testing.T) {
	tests := map[string]func(testMaterialValue) *httptest.ResponseRecorder{
		"wrong token": func(material testMaterialValue) *httptest.ResponseRecorder {
			return performRequest(material.authority, "other-token", requestMediaType, requestBytes(t, material.request))
		},
		"recovery media type": func(material testMaterialValue) *httptest.ResponseRecorder {
			return performRequest(material.authority, material.token, "application/vnd.openkubes.target-credential-recovery-authorization-request+json", requestBytes(t, material.request))
		},
		"foreign operation": func(material testMaterialValue) *httptest.ResponseRecorder {
			request := material.request
			request.Operation = "DeleteCluster"
			request.RequestDigest = stageRequestDigest(t, request)
			return performRequest(material.authority, material.token, requestMediaType, requestBytes(t, request))
		},
		"non canonical body": func(material testMaterialValue) *httptest.ResponseRecorder {
			var generic any
			if err := json.Unmarshal(requestBytes(t, material.request), &generic); err != nil {
				t.Fatal(err)
			}
			raw, err := json.MarshalIndent(generic, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			return performRequest(material.authority, material.token, requestMediaType, raw)
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			material := testMaterial(t)
			response := run(material)
			if response.Code < 400 {
				t.Fatalf("request was accepted: %d", response.Code)
			}
			entries, err := os.ReadDir(material.stateDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected request consumed state: %d %v", len(entries), err)
			}
		})
	}
}

func TestOpenRejectsUnsafePrivateMaterialAndPolicy(t *testing.T) {
	t.Run("world readable token", func(t *testing.T) {
		material := testMaterial(t)
		if err := os.Chmod(material.config.TokenFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(material.config); err == nil {
			t.Fatal("world-readable token was accepted")
		}
	})
	t.Run("unknown policy field", func(t *testing.T) {
		material := testMaterial(t)
		raw, err := os.ReadFile(material.config.PolicyPath)
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Replace(raw, []byte(`"format"`), []byte(`"unknown":true,"format"`), 1)
		if err := os.WriteFile(material.config.PolicyPath, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(material.config); err == nil {
			t.Fatal("unknown policy field was accepted")
		}
	})
	t.Run("public state directory", func(t *testing.T) {
		material := testMaterial(t)
		if err := os.Chmod(material.stateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(material.config); err == nil {
			t.Fatal("public state directory was accepted")
		}
	})
}

type testMaterialValue struct {
	authority *Authority
	config    Config
	plan      stageplan.Binding
	request   runner.StageAuthorizationRequest
	publicKey ed25519.PublicKey
	token     string
	stateDir  string
	now       time.Time
}

func testMaterial(t *testing.T) testMaterialValue {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := verifiedPlan(t)
	stage, stageDigest, err := plan.Stage("provider-prerequisites")
	if err != nil {
		t.Fatal(err)
	}
	request := runner.StageAuthorizationRequest{
		Format: runner.StageAuthorizationRequestFormat, Audience: authorization.StageAudience,
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity, ContractRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority,
		Predecessors: []stagecursor.Predecessor{}, MaxUses: 1,
	}
	request.RequestDigest = stageRequestDigest(t, request)
	policy := Policy{
		Format: PolicyFormat, PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity,
		ContractRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		Stages: []StagePolicy{{StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority, Requires: []string{}}},
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := writeFile(t, root, "policy.json", policyRaw, 0o600)
	privatePath := writeFile(t, root, "authority.key", []byte(base64.StdEncoding.EncodeToString(privateKey)), 0o600)
	token := "bounded-authority-token"
	tokenPath := writeFile(t, root, "token", []byte(token), 0o600)
	now := time.Date(2026, 8, 21, 8, 0, 0, 0, time.UTC)
	canonicalPolicy, err := canonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{PolicyPath: policyPath, ExpectedPolicyDigest: digest.SHA256(canonicalPolicy), PrivateKeyPath: privatePath, TokenFile: tokenPath, StateDirectory: stateDir, GrantValidFor: 10 * time.Minute, Clock: func() time.Time { return now }}
	authority, _, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	return testMaterialValue{authority: authority, config: config, plan: plan, request: request, publicKey: publicKey, token: token, stateDir: stateDir, now: now}
}

func performRequest(authority *Authority, token, contentType string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, requestPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", responseMediaType)
	response := httptest.NewRecorder()
	authority.ServeHTTP(response, request)
	return response
}

func requestBytes(t *testing.T, request runner.StageAuthorizationRequest) []byte {
	t.Helper()
	raw, err := request.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func stageRequestDigest(t *testing.T, request runner.StageAuthorizationRequest) string {
	t.Helper()
	payload := map[string]any{
		"format": request.Format, "audience": request.Audience, "planDigest": request.PlanDigest,
		"contractIdentity": request.ContractIdentity, "contractRevision": request.ContractRevision,
		"enablementRevision": request.EnablementRevision, "platformRevision": request.PlatformRevision,
		"executionFixture": request.ExecutionFixture, "stageId": request.StageID, "stageOrder": request.StageOrder,
		"stageDigest": request.StageDigest, "operation": request.Operation, "authority": request.Authority,
		"predecessors": request.Predecessors, "maxUses": request.MaxUses,
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	return digest.SHA256(canonical)
}

func verifiedPlan(t *testing.T) stageplan.Binding {
	t.Helper()
	identity := contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
	r := testDigest("1")
	e := testDigest("2")
	p := testDigest("3")
	fixture := testDigest("4")
	rules := []map[string]any{
		{"id": "provider-prerequisites", "kind": "Submission", "authority": "infrastructure", "grantOperation": "CreateProviderPrerequisites", "requires": []string{}},
		{"id": "cluster-lifecycle", "kind": "Submission", "authority": "management", "grantOperation": "CreateCluster", "requires": []string{"provider-prerequisites"}},
		{"id": "lifecycle-observation", "kind": "Observation", "authority": "management", "requires": []string{"cluster-lifecycle"}},
		{"id": "enablement", "kind": "Submission", "authority": "management", "grantOperation": "CreateEnablement", "requires": []string{"lifecycle-observation"}},
		{"id": "network-observation", "kind": "Observation", "authority": "workload", "requires": []string{"enablement"}},
		{"id": "runtime-binding", "kind": "Binding", "authority": "runner", "requires": []string{"network-observation"}},
		{"id": "target-access", "kind": "Submission", "authority": "workload", "grantOperation": "CreateTargetAccess", "requires": []string{"runtime-binding"}},
		{"id": "target-credential", "kind": "Credential", "authority": "workload", "grantOperation": "IssueTargetCredential", "requires": []string{"target-access"}},
		{"id": "target-registration", "kind": "Submission", "authority": "gitops", "grantOperation": "RegisterTarget", "requires": []string{"target-credential"}},
		{"id": "platform-applications", "kind": "Submission", "authority": "gitops", "grantOperation": "CreatePlatformApplications", "requires": []string{"target-registration"}},
		{"id": "platform-observation", "kind": "Observation", "authority": "gitops", "requires": []string{"platform-applications"}},
		{"id": "aggregate-evidence", "kind": "Evaluation", "authority": "runner", "requires": []string{"platform-observation"}},
	}
	stages := make([]map[string]any, len(rules))
	for index, rule := range rules {
		rule["order"] = index + 1
		rule["inputs"] = []map[string]string{{"name": "stage.input-" + string(rune('a'+index)), "digest": testDigest(string("abcdef012345"[index]))}}
		stages[index] = rule
	}
	document := map[string]any{
		"format": stageplan.Format, "contractIdentity": identity, "intentRevision": r, "enablementRevision": e,
		"platformRevision": p, "executionFixture": fixture, "authorizationState": "NO-GO",
		"authorities": map[string]any{"infrastructure": "ok-infra", "management": "ok-mgmt", "gitOps": "ok-shared", "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":      stages,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: r, EnablementRevision: e, PlatformRevision: p, ExecutionFixture: fixture,
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func writeFile(t *testing.T, root, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }
