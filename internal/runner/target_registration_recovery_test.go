package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestTargetRegistrationRecoveryClaimsIndependentGrantBeforeExactRefresh(t *testing.T) {
	fixture := targetRegistrationRecoveryFixture(t)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	refreshAPI, gitopsAPI := newTargetRegistrationRecoveryAPI(t, fixture.material)
	defer gitopsAPI.Close()
	runtime := targetRegistrationRecoveryRuntime(t, fixture, ledgerAPI.Server, gitopsAPI)

	var observed TargetRegistrationRecoveryAuthorizationRequest
	resolved, err := ResolveTargetRegistrationRecoveryAuthorization(context.Background(), fixture.handoff, fixture.prior,
		TargetRegistrationRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			observed = request
			return writeTargetRegistrationRecoveryGrant(t, t.TempDir(), request, fixture.now), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Stage.StageID != "target-registration" || observed.PriorStageReceiptDigest != fixture.prior.Digest ||
		observed.CredentialRecoveryRequestDigest != fixture.recoveryRequest || observed.CredentialIssueReceiptDigest != fixture.credentialEvidence ||
		observed.RequestDigest == "" {
		t.Fatalf("registration recovery request is incomplete: %#v", observed)
	}
	if raw, err := observed.Bytes(); err != nil || len(raw) == 0 {
		t.Fatalf("registration recovery request is not canonical: %v", err)
	}

	receipt, err := RecoverTargetRegistration(context.Background(), TargetRegistrationRecoveryConfig{
		Handoff: fixture.handoff, PriorStageReceipt: fixture.prior, Authorization: resolved,
		ArtifactPath: fixture.registration.bundleConfig.ArtifactPath, Expected: fixture.registration.bundleConfig.Expected,
		Ledger: runtime.Ledger, GitOps: runtime.GitOps, Runtime: fixture.registration.runtime,
		MaterializationTime: fixture.registration.config.MaterializationTime, Clock: func() time.Time { return fixture.now },
	})
	if err != nil || receipt.State != "REFRESHED" || receipt.Claim == nil || receipt.Outcome == nil || receipt.Refresh == nil ||
		receipt.Outcome.Outcome != "SUCCEEDED" || receipt.Outcome.MutationState != "ATTEMPTED" || receipt.StageReceiptRewritten ||
		!receipt.Refresh.StaticRegistrationPreserved || receipt.Refresh.CredentialBytesInReceipt {
		t.Fatalf("target-registration recovery did not complete safely: %#v err=%v", receipt, err)
	}
	if got := refreshAPI.requestSummary(); !equalStringSlices(got, []string{"GET project", "GET registration", "PUT registration"}) {
		t.Fatalf("registration refresh request boundary differs: %v", got)
	}
	if got := countLedgerRecordType(ledgerAPI, "stage-receipt"); got != 0 {
		t.Fatalf("registration recovery rewrote Stage-9 receipt: count=%d", got)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{string(fixture.registration.credential.token), fixture.registration.credential.endpoint, runtime.GitOps.Endpoint, "short-lived-gitops-token"} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("registration recovery receipt leaked private value %q", forbidden)
		}
	}

	secondHandoff := newRecoveredTargetRegistrationHandoff(t, fixture.registration, fixture.recoveryRequest)
	if _, err := RecoverTargetRegistration(context.Background(), TargetRegistrationRecoveryConfig{
		Handoff: secondHandoff, PriorStageReceipt: fixture.prior, Authorization: resolved,
		ArtifactPath: fixture.registration.bundleConfig.ArtifactPath, Expected: fixture.registration.bundleConfig.Expected,
		Ledger: runtime.Ledger, GitOps: runtime.GitOps, Runtime: fixture.registration.runtime,
		MaterializationTime: fixture.registration.config.MaterializationTime, Clock: func() time.Time { return fixture.now },
	}); err == nil || refreshAPI.puts != 1 {
		t.Fatalf("consumed recovery grant reached a second replacement: puts=%d err=%v", refreshAPI.puts, err)
	}
}

func TestTargetRegistrationRecoveryDurablyStopsBeforeWriteOnDrift(t *testing.T) {
	fixture := targetRegistrationRecoveryFixture(t)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	refreshAPI, gitopsAPI := newTargetRegistrationRecoveryAPI(t, fixture.material)
	defer gitopsAPI.Close()
	refreshAPI.objects["project"].(map[string]any)["spec"].(map[string]any)["description"] = "foreign"
	runtime := targetRegistrationRecoveryRuntime(t, fixture, ledgerAPI.Server, gitopsAPI)
	resolved, err := ResolveTargetRegistrationRecoveryAuthorization(context.Background(), fixture.handoff, fixture.prior,
		TargetRegistrationRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return writeTargetRegistrationRecoveryGrant(t, t.TempDir(), request, fixture.now), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	receipt, recoveryErr := RecoverTargetRegistration(context.Background(), TargetRegistrationRecoveryConfig{
		Handoff: fixture.handoff, PriorStageReceipt: fixture.prior, Authorization: resolved,
		ArtifactPath: fixture.registration.bundleConfig.ArtifactPath, Expected: fixture.registration.bundleConfig.Expected,
		Ledger: runtime.Ledger, GitOps: runtime.GitOps, Runtime: fixture.registration.runtime,
		MaterializationTime: fixture.registration.config.MaterializationTime, Clock: func() time.Time { return fixture.now },
	})
	if recoveryErr == nil || receipt.State != "COMPLETED_STOPPED" || receipt.Outcome == nil || receipt.Refresh == nil ||
		receipt.Outcome.Outcome != "STOPPED" || receipt.Outcome.MutationState != "NOT_ATTEMPTED" || receipt.Refresh.MutationState != "NOT_ATTEMPTED" ||
		refreshAPI.puts != 0 {
		t.Fatalf("registration drift was not durably stopped before write: %#v puts=%d err=%v", receipt, refreshAPI.puts, recoveryErr)
	}
}

func TestTargetRegistrationRecoveryDurablyPreservesUnknownReplaceOutcome(t *testing.T) {
	fixture := targetRegistrationRecoveryFixture(t)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	refreshAPI, gitopsAPI := newTargetRegistrationRecoveryAPI(t, fixture.material)
	defer gitopsAPI.Close()
	refreshAPI.failPut = true
	runtime := targetRegistrationRecoveryRuntime(t, fixture, ledgerAPI.Server, gitopsAPI)
	resolved, err := ResolveTargetRegistrationRecoveryAuthorization(context.Background(), fixture.handoff, fixture.prior,
		TargetRegistrationRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return writeTargetRegistrationRecoveryGrant(t, t.TempDir(), request, fixture.now), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	receipt, recoveryErr := RecoverTargetRegistration(context.Background(), TargetRegistrationRecoveryConfig{
		Handoff: fixture.handoff, PriorStageReceipt: fixture.prior, Authorization: resolved,
		ArtifactPath: fixture.registration.bundleConfig.ArtifactPath, Expected: fixture.registration.bundleConfig.Expected,
		Ledger: runtime.Ledger, GitOps: runtime.GitOps, Runtime: fixture.registration.runtime,
		MaterializationTime: fixture.registration.config.MaterializationTime, Clock: func() time.Time { return fixture.now },
	})
	if recoveryErr == nil || receipt.State != "COMPLETED_STOPPED" || receipt.Outcome == nil || receipt.Refresh == nil ||
		receipt.Outcome.Outcome != "STOPPED" || receipt.Outcome.MutationState != "UNKNOWN" || receipt.Refresh.MutationState != "UNKNOWN" ||
		refreshAPI.puts != 1 {
		t.Fatalf("unknown registration outcome was not durably preserved: %#v puts=%d err=%v", receipt, refreshAPI.puts, recoveryErr)
	}
}

func TestTargetRegistrationRecoveryRejectsMissingHistoryAndNormalHandoffBeforeAuthority(t *testing.T) {
	registration := targetRegistrationMaterialFixture(t)
	normal, err := newVerifiedTargetCredentialStageHandoff(registration.bundle.plan, registration.bundle.prefix[:7], registration.bundle.prefix[7], registration.credential)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolver := TargetRegistrationRecoveryAuthorizationResolverFunc(func(context.Context, TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
		calls++
		return StageAuthorizationSource{}, errors.New("unexpected")
	})
	missing := StageReceiptSource{Path: t.TempDir() + "/missing.json", Digest: runnerStageSHA("7")}
	if _, err := ResolveTargetRegistrationRecoveryAuthorization(context.Background(), normal, missing, resolver); err == nil || calls != 0 {
		t.Fatalf("normal handoff or missing receipt reached recovery authority: calls=%d err=%v", calls, err)
	}
	recovered := newRecoveredTargetRegistrationHandoff(t, registration, runnerStageSHA("8"))
	if _, err := ResolveTargetRegistrationRecoveryAuthorization(context.Background(), recovered, missing, resolver); err == nil || calls != 0 {
		t.Fatalf("missing Stage-9 history reached recovery authority: calls=%d err=%v", calls, err)
	}
}

type targetRegistrationRecoveryTestFixture struct {
	registration       targetRegistrationMaterialTestFixture
	handoff            *VerifiedTargetCredentialStageHandoff
	prior              StageReceiptSource
	material           VerifiedTargetRegistrationMaterial
	recoveryRequest    string
	credentialEvidence string
	now                time.Time
}

func targetRegistrationRecoveryFixture(t *testing.T) targetRegistrationRecoveryTestFixture {
	t.Helper()
	registration := targetRegistrationMaterialFixture(t)
	recoveryRequest := runnerStageSHA("8")
	handoff := newRecoveredTargetRegistrationHandoff(t, registration, recoveryRequest)
	predecessors, err := registration.bundle.cursor.Predecessors()
	if err != nil {
		t.Fatal(err)
	}
	now := registration.config.MaterializationTime.Add(time.Minute)
	stage, err := stagereceipt.New(registration.bundle.plan, "target-registration", predecessors, "SUCCEEDED", "ATTEMPTED",
		runnerStageSHA("9"), runnerStageSHA("a"), now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stage.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	stageDigest, err := stage.Digest()
	if err != nil {
		t.Fatal(err)
	}
	prior := StageReceiptSource{Path: writeBundleFile(t, t.TempDir(), "stage-9.json", raw), Digest: stageDigest}
	material, err := BuildTargetRegistrationMaterial(registration.config)
	if err != nil {
		t.Fatal(err)
	}
	credentialEvidence, _, err := handoff.credentialEvidence()
	if err != nil {
		t.Fatal(err)
	}
	return targetRegistrationRecoveryTestFixture{
		registration: registration, handoff: handoff, prior: prior, material: material,
		recoveryRequest: recoveryRequest, credentialEvidence: credentialEvidence, now: now,
	}
}

func newRecoveredTargetRegistrationHandoff(t *testing.T, registration targetRegistrationMaterialTestFixture, recoveryRequest string) *VerifiedTargetCredentialStageHandoff {
	t.Helper()
	issued, err := registration.credential.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalTargetRegistrationValue(issued)
	if err != nil {
		t.Fatal(err)
	}
	credentialEvidence := digest.SHA256(raw)
	priorDigest, err := registration.bundle.prefix[7].Digest()
	if err != nil {
		t.Fatal(err)
	}
	recovery := TargetCredentialRecoveryReceipt{
		Format: TargetCredentialRecoveryReceiptFormat, State: "REISSUED", PlanDigest: registration.bundle.plan.PlanDigest,
		PriorStageReceiptDigest: priorDigest, RecoveryRequestDigest: recoveryRequest,
		TargetIdentityDigest: registration.bundle.receipt.TargetIdentityDigest, CredentialIssueReceiptDigest: credentialEvidence,
		Outcome: &ledger.StageOutcomeReceipt{Outcome: "SUCCEEDED", MutationState: "ATTEMPTED", EvidenceDigest: credentialEvidence},
	}
	handoff, err := newVerifiedRecoveredTargetCredentialStageHandoff(
		registration.bundle.plan, registration.bundle.prefix[:7], registration.bundle.prefix[7], registration.credential, recovery,
	)
	if err != nil {
		t.Fatal(err)
	}
	return handoff
}

func writeTargetRegistrationRecoveryGrant(t *testing.T, root string, request TargetRegistrationRecoveryAuthorizationRequest, at time.Time) StageAuthorizationSource {
	t.Helper()
	payload := authorization.StagePayload{
		Audience: request.Stage.Audience, GrantID: "ok147-target-registration-recovery-01", Decision: "ALLOW",
		PlanDigest: request.Stage.PlanDigest, ContractIdentity: request.Stage.ContractIdentity,
		ContractRevision: request.Stage.ContractRevision, EnablementRevision: request.Stage.EnablementRevision,
		PlatformRevision: request.Stage.PlatformRevision, ExecutionFixture: request.Stage.ExecutionFixture,
		StageID: request.Stage.StageID, StageOrder: request.Stage.StageOrder, StageDigest: request.Stage.StageDigest,
		Operation: request.Stage.Operation, Authority: request.Stage.Authority, MaxUses: 1,
		NotBefore: at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339),
	}
	for _, predecessor := range request.Stage.Predecessors {
		payload.Predecessors = append(payload.Predecessors, authorization.StagePredecessor{StageID: predecessor.StageID, OutcomeDigest: predecessor.ReceiptDigest})
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := authorization.StageSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mustJSON(t, map[string]any{
		"format": authorization.StageFormat, "payload": payload,
		"signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
	return StageAuthorizationSource{
		GrantPath:      writeBundleFile(t, root, "registration-recovery-grant.json", envelope),
		PublicKeyPath:  writeBundleFile(t, root, "registration-recovery-authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n")),
		EvaluationTime: at,
	}
}

func newTargetRegistrationRecoveryAPI(t *testing.T, material VerifiedTargetRegistrationMaterial) (*targetRegistrationRefreshAPI, *httptest.Server) {
	t.Helper()
	api := newTargetRegistrationRefreshAPI(t, material)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		result, err := api.client().Transport.RoundTrip(request)
		if err != nil {
			return
		}
		defer result.Body.Close()
		for key, values := range result.Header {
			for _, value := range values {
				response.Header().Add(key, value)
			}
		}
		response.WriteHeader(result.StatusCode)
		_, _ = io.Copy(response, result.Body)
	}))
	return api, server
}

func targetRegistrationRecoveryRuntime(t *testing.T, fixture targetRegistrationRecoveryTestFixture, ledgerServer, gitopsServer *httptest.Server) TargetRegistrationStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ledgerCA := writeRuntimeBindingServerCA(t, root, "ledger-ca.crt", ledgerServer)
	gitopsCA := writeRuntimeBindingServerCA(t, root, "gitops-ca.crt", gitopsServer)
	gitopsCABytes, err := os.ReadFile(gitopsCA)
	if err != nil {
		t.Fatal(err)
	}
	return TargetRegistrationStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: ledgerServer.URL, Namespace: "openkubes-execution-system",
			TokenFile: writeBundleFile(t, root, "ledger-token", []byte("ledger-token")), CAFile: ledgerCA,
		},
		GitOps: KubernetesAuthorityConfig{
			Endpoint: gitopsServer.URL, AuthorityIdentity: "ok-shared",
			TokenFile: writeBundleFile(t, root, "gitops-token", []byte("short-lived-gitops-token")), CAFile: gitopsCA,
			CABundleDigest: digest.SHA256(gitopsCABytes),
		},
		Runtime: fixture.registration.runtime, MaterializationTime: fixture.registration.config.MaterializationTime,
		Clock: func() time.Time { return fixture.now },
	}
}
