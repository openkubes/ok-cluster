package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestTargetCredentialStageRunsOnceAndHandsOffMaterialOnce(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 16, 1, 0, 0, time.UTC)
	credentialAPI, requests := newTargetCredentialExecutionAPI(t, now, http.StatusCreated)
	defer credentialAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	runtime := targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, credentialAPI, now)
	bound, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || ledgerAPI.RequestCount() != 0 {
		t.Fatal("opening target-credential stage contacted Kubernetes")
	}
	receipt, material, err := bound.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "target-credential" || receipt.StageReceiptDigest == "" || requests.Load() != 1 {
		t.Fatalf("target-credential stage did not complete: %#v requests=%d err=%v", receipt, requests.Load(), err)
	}
	issued, err := material.Receipt()
	if err != nil || issued.State != "ISSUED" || issued.CredentialBytesInReceipt || issued.PolicyDigest != fixture.policyDigest {
		t.Fatalf("in-memory handoff differs: %#v %v", issued, err)
	}
	if replay, replayMaterial, err := bound.Run(context.Background()); err == nil || replay.State != "COMPLETED_SUCCEEDED" || requests.Load() != 1 {
		t.Fatalf("durable replay recreated credential: %#v %#v requests=%d err=%v", replay, replayMaterial, requests.Load(), err)
	}
}

func TestTargetCredentialStageDurablyStopsFailedIssuance(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 16, 1, 0, 0, time.UTC)
	credentialAPI, requests := newTargetCredentialExecutionAPI(t, now, http.StatusForbidden)
	defer credentialAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	bound, err := bundle.Open(targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, credentialAPI, now))
	if err != nil {
		t.Fatal(err)
	}
	receipt, material, runErr := bound.Run(context.Background())
	var resultErr *execution.StageResultError
	if !errors.As(runErr, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" || requests.Load() != 1 {
		t.Fatalf("failed issuance was not durably stopped: %#v %#v requests=%d err=%v", receipt, material, requests.Load(), runErr)
	}
	if replay, _, err := bound.Run(context.Background()); !errors.As(err, &resultErr) || replay.State != "COMPLETED_STOPPED" || requests.Load() != 1 {
		t.Fatalf("durable stop retried TokenRequest: %#v requests=%d err=%v", replay, requests.Load(), err)
	}
}

func TestTargetCredentialStageRejectsSharedLedgerAndAuthorityCredential(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 16, 1, 0, 0, time.UTC)
	credentialAPI, requests := newTargetCredentialExecutionAPI(t, now, http.StatusCreated)
	defer credentialAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	runtime := targetCredentialExecutionRuntime(t, fixture, ledgerAPI.Server, credentialAPI, now)
	if err := os.WriteFile(runtime.Workload.TokenFile, []byte("ledger-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(runtime); err == nil || requests.Load() != 0 || ledgerAPI.RequestCount() != 0 {
		t.Fatal("shared ledger/authority credential opened target-credential stage")
	}
}

func targetCredentialExecutionRuntime(t *testing.T, fixture targetCredentialBundleTestFixture, ledgerServer, credentialServer *httptest.Server, now time.Time) TargetCredentialStageRuntimeConfig {
	t.Helper()
	base := targetAccessExecutionRuntime(t, fixture.plan, ledgerServer, credentialServer)
	return TargetCredentialStageRuntimeConfig{Ledger: base.Ledger, Workload: base.Workload, Clock: func() time.Time { return now }}
}

func newTargetCredentialExecutionAPI(t *testing.T, now time.Time, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/namespaces/kube-system/serviceaccounts/ok147-argocd-manager/token" || request.Header.Get("Authorization") != "Bearer workload-token" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if status != http.StatusCreated {
			response.WriteHeader(status)
			return
		}
		token := targetCredentialTestJWT(t, now, now.Add(3*time.Hour), "system:serviceaccount:kube-system:ok147-argocd-manager")
		result := map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   map[string]any{"audiences": []string{"https://kubernetes.default.svc"}, "expirationSeconds": 10800},
			"status": map[string]any{"token": token, "expirationTimestamp": now.Add(3 * time.Hour).Format(time.RFC3339)},
		}
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(result)
	}))
	return server, &requests
}
