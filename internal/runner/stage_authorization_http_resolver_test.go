package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestStageAuthorizationHTTPResolverRequestsAndPersistsExactGrant(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	resume := StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, httpRequest *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != "/v1/stage-authorizations" ||
			httpRequest.Header.Get("Authorization") != "Bearer authority-token" ||
			httpRequest.Header.Get("Content-Type") != "application/vnd.openkubes.stage-authorization-request+json" ||
			httpRequest.Header.Get("Accept") != "application/vnd.openkubes.stage-authorization+json" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		var request StageAuthorizationRequest
		if err := json.NewDecoder(httpRequest.Body).Decode(&request); err != nil || request.StageID != "target-credential" || request.RequestDigest == "" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/vnd.openkubes.stage-authorization+json")
		response.WriteHeader(http.StatusCreated)
		response.Write(stageAuthorizationEnvelopeForRequest(t, request, publicKey, privateKey))
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := writeBundleFile(t, root, "authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"))
	resolver, err := OpenStageAuthorizationHTTPResolver(StageAuthorizationHTTPResolverConfig{
		Endpoint: server.URL + "/v1/stage-authorizations", TokenFile: writeBundleFile(t, root, "token", []byte("authority-token")),
		CAFile: writeRuntimeBindingServerCA(t, root, "ca.crt", server), PublicKeyPath: keyPath,
		OutputDirectory: root, Clock: func() time.Time { return time.Date(2026, 8, 18, 8, 5, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveStageAuthorization(context.Background(), resume, resolver)
	if err != nil {
		t.Fatal(err)
	}
	source, err := resolved.Source()
	if err != nil || source.PublicKeyPath != keyPath || source.EvaluationTime != time.Date(2026, 8, 18, 8, 5, 0, 0, time.UTC) {
		t.Fatalf("unexpected HTTP authorization source: %#v %v", source, err)
	}
	info, err := os.Lstat(source.GrantPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || filepath.Dir(source.GrantPath) != root {
		t.Fatalf("HTTP grant was not persisted privately: %#v %v", info, err)
	}
	if _, err := ResolveStageAuthorization(context.Background(), resume, resolver); err == nil {
		t.Fatal("same authorization request was sent twice")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("authority requests=%d, want 1", requests)
	}
}

func TestStageAuthorizationHTTPResolverReportsOnlySafeHTTPStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte("sensitive authority detail"))
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := OpenStageAuthorizationHTTPResolver(StageAuthorizationHTTPResolverConfig{
		Endpoint: server.URL + "/v1/stage-authorizations", TokenFile: writeBundleFile(t, root, "token", []byte("authority-token")),
		CAFile:          writeRuntimeBindingServerCA(t, root, "ca.crt", server),
		PublicKeyPath:   writeBundleFile(t, root, "authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n")),
		OutputDirectory: root, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := "sha256:" + strings.Repeat("a", 64)
	_, err = resolver.resolve(context.Background(), requestDigest, []byte(`{}`), stageAuthorizationRequestMediaType)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "sensitive authority detail") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("unsafe or incomplete HTTP error: %v", err)
	}
}

func TestStageAuthorizationHTTPResolverRejectsRedirectAndUnsafeConfiguration(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	resume := StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetCalls := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls++ }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", target.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	config := StageAuthorizationHTTPResolverConfig{
		Endpoint: redirect.URL + "/v1/stage-authorizations", TokenFile: writeBundleFile(t, root, "token", []byte("authority-token")),
		CAFile:          writeRuntimeBindingServerCA(t, root, "ca.crt", redirect),
		PublicKeyPath:   writeBundleFile(t, root, "authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n")),
		OutputDirectory: root, Clock: time.Now,
	}
	resolver, err := OpenStageAuthorizationHTTPResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, cursor, _, err := loadStageResumeWithPrefix(resume)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := cursor.Decision()
	unsafeRequest, err := newStageAuthorizationRequest(plan, decision)
	if err != nil {
		t.Fatal(err)
	}
	unsafeRequest.StageID = "../../escape"
	unsafeRequest.RequestDigest, _ = stageAuthorizationRequestDigest(unsafeRequest)
	if _, err := resolver.ResolveStageAuthorization(context.Background(), unsafeRequest); err == nil {
		t.Fatal("path-capable stage identity reached HTTP resolver")
	}
	if _, err := ResolveStageAuthorization(context.Background(), resume, resolver); err == nil || targetCalls != 0 {
		t.Fatalf("authority redirect was followed: targetCalls=%d err=%v", targetCalls, err)
	}
	config.Endpoint = "http://example.invalid:80/v1/stage-authorizations"
	if _, err := OpenStageAuthorizationHTTPResolver(config); err == nil {
		t.Fatal("cleartext non-loopback authority was accepted")
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	config.Endpoint = redirect.URL + "/v1/stage-authorizations"
	if _, err := OpenStageAuthorizationHTTPResolver(config); err == nil {
		t.Fatal("broad grant directory was accepted")
	}
}

func TestStageAuthorizationHTTPResolverCarriesRecoveryEvidenceToAuthority(t *testing.T) {
	credentialFixture := targetCredentialBundleFixture(t)
	plan, cursor, _, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: credentialFixture.config.PlanPath, PlanExpected: credentialFixture.config.PlanExpected, Receipts: credentialFixture.config.Receipts,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := cursor.Decision()
	if err != nil {
		t.Fatal(err)
	}
	credentialStage, err := newStageAuthorizationRequest(plan, decision)
	if err != nil {
		t.Fatal(err)
	}
	credentialRequest := TargetCredentialRecoveryAuthorizationRequest{
		Format: TargetCredentialRecoveryAuthorizationRequestFormat, Stage: credentialStage,
		PriorStageReceiptDigest: runnerStageSHA("1"), OriginalAuthorizationDigest: runnerStageSHA("2"),
	}
	credentialRequest.RequestDigest, err = targetCredentialRecoveryAuthorizationRequestDigest(credentialRequest)
	if err != nil {
		t.Fatal(err)
	}

	registrationFixture := targetRegistrationRecoveryFixture(t)
	registrationPlan, registrationCursor, _, err := registrationFixture.handoff.registrationContext()
	if err != nil {
		t.Fatal(err)
	}
	registrationDecision, err := registrationCursor.Decision()
	if err != nil {
		t.Fatal(err)
	}
	registrationStage, err := newStageAuthorizationRequest(registrationPlan, registrationDecision)
	if err != nil {
		t.Fatal(err)
	}
	registrationRequest := TargetRegistrationRecoveryAuthorizationRequest{
		Format: TargetRegistrationRecoveryAuthorizationRequestFormat, Stage: registrationStage,
		PriorStageReceiptDigest:         registrationFixture.prior.Digest,
		CredentialRecoveryRequestDigest: registrationFixture.recoveryRequest,
		CredentialIssueReceiptDigest:    registrationFixture.credentialEvidence,
	}
	registrationRequest.RequestDigest, err = targetRegistrationRecoveryAuthorizationRequestDigest(registrationRequest)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	mediaTypes := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var stage StageAuthorizationRequest
		switch mediaType := request.Header.Get("Content-Type"); mediaType {
		case targetCredentialRecoveryAuthorizationRequestMediaType:
			var recovery TargetCredentialRecoveryAuthorizationRequest
			if json.NewDecoder(request.Body).Decode(&recovery) != nil || recovery.RequestDigest != credentialRequest.RequestDigest {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			stage = recovery.Stage
		case targetRegistrationRecoveryAuthorizationRequestMediaType:
			var recovery TargetRegistrationRecoveryAuthorizationRequest
			if json.NewDecoder(request.Body).Decode(&recovery) != nil || recovery.RequestDigest != registrationRequest.RequestDigest {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			stage = recovery.Stage
		default:
			response.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		mu.Lock()
		mediaTypes = append(mediaTypes, request.Header.Get("Content-Type"))
		mu.Unlock()
		response.Header().Set("Content-Type", stageAuthorizationResponseMediaType)
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write(stageAuthorizationEnvelopeForRequest(t, stage, publicKey, privateKey))
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver, err := OpenStageAuthorizationHTTPResolver(StageAuthorizationHTTPResolverConfig{
		Endpoint: server.URL + "/v1/stage-authorizations", TokenFile: writeBundleFile(t, root, "token", []byte("authority-token")),
		CAFile:          writeRuntimeBindingServerCA(t, root, "ca.crt", server),
		PublicKeyPath:   writeBundleFile(t, root, "authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n")),
		OutputDirectory: root, Clock: func() time.Time { return time.Date(2026, 8, 18, 8, 5, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialSource, err := resolver.ResolveTargetCredentialRecoveryAuthorization(context.Background(), credentialRequest)
	if err != nil {
		t.Fatal(err)
	}
	registrationSource, err := resolver.ResolveTargetRegistrationRecoveryAuthorization(context.Background(), registrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if credentialSource.GrantPath == registrationSource.GrantPath || credentialSource.PublicKeyPath != registrationSource.PublicKeyPath {
		t.Fatalf("recovery grant sources are not independently persisted: %#v %#v", credentialSource, registrationSource)
	}
	if _, err := resolver.ResolveTargetCredentialRecoveryAuthorization(context.Background(), credentialRequest); err == nil {
		t.Fatal("same credential-recovery request was sent twice")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(mediaTypes) != 2 || mediaTypes[0] != targetCredentialRecoveryAuthorizationRequestMediaType || mediaTypes[1] != targetRegistrationRecoveryAuthorizationRequestMediaType {
		t.Fatalf("recovery request media types differ: %v", mediaTypes)
	}
}

func stageAuthorizationEnvelopeForRequest(t *testing.T, request StageAuthorizationRequest, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	payload := authorization.StagePayload{
		Audience: request.Audience, GrantID: "ok147-http-" + request.StageID, Decision: "ALLOW",
		PlanDigest: request.PlanDigest, ContractIdentity: request.ContractIdentity, ContractRevision: request.ContractRevision,
		EnablementRevision: request.EnablementRevision, PlatformRevision: request.PlatformRevision, ExecutionFixture: request.ExecutionFixture,
		StageID: request.StageID, StageOrder: request.StageOrder, StageDigest: request.StageDigest,
		Operation: request.Operation, Authority: request.Authority,
		NotBefore: "2026-08-18T07:59:00Z", NotAfter: "2026-08-18T08:20:00Z", MaxUses: request.MaxUses,
	}
	for _, predecessor := range request.Predecessors {
		payload.Predecessors = append(payload.Predecessors, authorization.StagePredecessor{StageID: predecessor.StageID, OutcomeDigest: predecessor.ReceiptDigest})
	}
	signed, err := authorization.StageSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON(t, map[string]any{
		"format": authorization.StageFormat, "payload": payload,
		"signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
}
