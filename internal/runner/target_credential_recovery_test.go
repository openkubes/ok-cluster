package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestTargetCredentialRecoveryRequiresIndependentGrantAndClaimsBeforeIssuance(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 16, 1, 0, 0, time.UTC)
	originalAPI, originalRequests := newTargetCredentialExecutionAPI(t, now, http.StatusCreated)
	defer originalAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	originalRuntime := targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, originalAPI, now)
	bound, err := bundle.Open(originalRuntime)
	if err != nil {
		t.Fatal(err)
	}
	stageRun, handoff, err := bound.RunHandoff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	priorRaw, err := handoff.StageReceiptBytes()
	if err != nil {
		t.Fatal(err)
	}
	prior := StageReceiptSource{Path: writeBundleFile(t, t.TempDir(), "stage-8.json", priorRaw), Digest: stageRun.StageReceiptDigest}
	recoveryTime := now.Add(15 * time.Minute)
	recoveryAPI, recoveryRequests := newTargetCredentialExecutionAPI(t, recoveryTime, http.StatusCreated)
	defer recoveryAPI.Close()
	recoveryRuntime := targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, recoveryAPI, recoveryTime)

	if _, err := ResolveTargetCredentialRecoveryAuthorization(context.Background(), bundle, prior,
		TargetCredentialRecoveryAuthorizationResolverFunc(func(context.Context, TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return StageAuthorizationSource{GrantPath: fixture.config.GrantPath, PublicKeyPath: fixture.config.GrantPublicKeyPath, EvaluationTime: fixture.config.EvaluationTime}, nil
		})); err == nil {
		t.Fatal("original Stage-8 grant was accepted as independent recovery authorization")
	}

	root := t.TempDir()
	var observed TargetCredentialRecoveryAuthorizationRequest
	resolved, err := ResolveTargetCredentialRecoveryAuthorization(context.Background(), bundle, prior,
		TargetCredentialRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			observed = request
			return writeTargetCredentialRecoveryGrant(t, root, request, recoveryTime), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Format != TargetCredentialRecoveryAuthorizationRequestFormat || observed.PriorStageReceiptDigest != prior.Digest ||
		observed.OriginalAuthorizationDigest != bundle.receipt.AuthorizationDigest || observed.Stage.StageID != "target-credential" ||
		observed.Stage.Predecessors[0].StageID != "target-access" || observed.RequestDigest == "" {
		t.Fatalf("recovery authority request is incomplete: %#v", observed)
	}

	recovery, recoveredHandoff, err := RecoverTargetCredential(context.Background(), TargetCredentialRecoveryConfig{
		Bundle: bundle, StageReceipt: prior, Authorization: resolved, Ledger: recoveryRuntime.Ledger, Workload: recoveryRuntime.Workload,
		Clock: func() time.Time { return recoveryTime },
	})
	if err != nil || recovery.State != "REISSUED" || recovery.Claim == nil || recovery.Outcome == nil ||
		recovery.Outcome.Outcome != "SUCCEEDED" || recovery.RecoveryAuthorizationDigest == recovery.OriginalAuthorizationDigest ||
		recovery.CredentialBytesInReceipt || recovery.StageReceiptRewritten || recoveredHandoff == nil || originalRequests.Load() != 1 || recoveryRequests.Load() != 1 {
		t.Fatalf("recovery did not complete safely: %#v original=%d recovery=%d err=%v", recovery, originalRequests.Load(), recoveryRequests.Load(), err)
	}
	if recoveredHandoffDigest, err := recoveredHandoff.StageReceiptDigest(); err != nil || recoveredHandoffDigest != prior.Digest {
		t.Fatalf("recovery rewrote authoritative Stage-8 receipt: %q %v", recoveredHandoffDigest, err)
	}
	if got := countLedgerRecordType(ledgerAPI, "stage-receipt"); got != 1 {
		t.Fatalf("recovery created another Stage-8 receipt: count=%d", got)
	}
	if _, _, err := RecoverTargetCredential(context.Background(), TargetCredentialRecoveryConfig{
		Bundle: bundle, StageReceipt: prior, Authorization: resolved, Ledger: recoveryRuntime.Ledger, Workload: recoveryRuntime.Workload,
		Clock: func() time.Time { return recoveryTime },
	}); err == nil || recoveryRequests.Load() != 1 {
		t.Fatalf("consumed recovery grant was reused: requests=%d err=%v", recoveryRequests.Load(), err)
	}
}

func TestTargetCredentialRecoveryDurablyStopsFailedIssuance(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 16, 1, 0, 0, time.UTC)
	successAPI, _ := newTargetCredentialExecutionAPI(t, now, http.StatusCreated)
	defer successAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	originalRuntime := targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, successAPI, now)
	bound, err := bundle.Open(originalRuntime)
	if err != nil {
		t.Fatal(err)
	}
	run, handoff, err := bound.RunHandoff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := handoff.StageReceiptBytes()
	prior := StageReceiptSource{Path: writeBundleFile(t, t.TempDir(), "stage-8.json", raw), Digest: run.StageReceiptDigest}
	resolved, err := ResolveTargetCredentialRecoveryAuthorization(context.Background(), bundle, prior,
		TargetCredentialRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return writeTargetCredentialRecoveryGrant(t, t.TempDir(), request, now), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	recoveryTime := now.Add(15 * time.Minute)
	failureAPI, requests := newTargetCredentialExecutionAPI(t, recoveryTime, http.StatusForbidden)
	defer failureAPI.Close()
	failureRuntime := targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, failureAPI, recoveryTime)
	receipt, recovered, recoveryErr := RecoverTargetCredential(context.Background(), TargetCredentialRecoveryConfig{
		Bundle: bundle, StageReceipt: prior, Authorization: resolved, Ledger: failureRuntime.Ledger, Workload: failureRuntime.Workload,
		Clock: func() time.Time { return recoveryTime },
	})
	if recoveryErr == nil || receipt.State != "COMPLETED_STOPPED" || receipt.Claim == nil || receipt.Outcome == nil ||
		receipt.Outcome.Outcome != "STOPPED" || receipt.Outcome.MutationState != "UNKNOWN" || recovered != nil || requests.Load() != 1 {
		t.Fatalf("failed recovery was not durably stopped: %#v requests=%d err=%v", receipt, requests.Load(), recoveryErr)
	}
	if _, _, err := RecoverTargetCredential(context.Background(), TargetCredentialRecoveryConfig{
		Bundle: bundle, StageReceipt: prior, Authorization: resolved, Ledger: failureRuntime.Ledger, Workload: failureRuntime.Workload,
		Clock: func() time.Time { return recoveryTime },
	}); err == nil || requests.Load() != 1 {
		t.Fatalf("durably stopped recovery was retried: requests=%d err=%v", requests.Load(), err)
	}
}

func TestTargetCredentialRecoveryFailsClosedOnChangedReceiptAndResolution(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	missing := StageReceiptSource{Path: t.TempDir() + "/missing.json", Digest: runnerStageSHA("1")}
	calls := 0
	if _, err := ResolveTargetCredentialRecoveryAuthorization(context.Background(), bundle, missing,
		TargetCredentialRecoveryAuthorizationResolverFunc(func(context.Context, TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			calls++
			return StageAuthorizationSource{}, errors.New("unexpected")
		})); err == nil || calls != 0 {
		t.Fatalf("invalid prior receipt reached recovery authority: calls=%d err=%v", calls, err)
	}
	if _, _, err := RecoverTargetCredential(context.Background(), TargetCredentialRecoveryConfig{}); err == nil {
		t.Fatal("empty recovery config was accepted")
	}
}

func writeTargetCredentialRecoveryGrant(t *testing.T, root string, request TargetCredentialRecoveryAuthorizationRequest, at time.Time) StageAuthorizationSource {
	t.Helper()
	payload := authorization.StagePayload{
		Audience: request.Stage.Audience, GrantID: "ok147-target-credential-recovery-01", Decision: "ALLOW",
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
		GrantPath:      writeBundleFile(t, root, "recovery-grant.json", envelope),
		PublicKeyPath:  writeBundleFile(t, root, "recovery-authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n")),
		EvaluationTime: at,
	}
}

func countLedgerRecordType(api *runtimeBindingLedgerAPI, recordType string) int {
	api.mu.Lock()
	defer api.mu.Unlock()
	count := 0
	for _, object := range api.objects {
		metadata, _ := object["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		if labels["openkubes.io/ledger-record"] == recordType {
			count++
		}
	}
	return count
}
