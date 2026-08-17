package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestPlatformApplicationsStageRunsOnceAndReplaysDurableOutcome(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 0)
	defer gitopsAPI.Close()
	bound, err := bundle.Open(platformApplicationsExecutionRuntime(t, ledgerAPI.Server, gitopsAPI.Server))
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || gitopsAPI.RequestCount() != 0 {
		t.Fatal("opening platform-applications stage contacted Kubernetes")
	}
	receipt, err := bound.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "platform-applications" || receipt.StageReceiptDigest == "" {
		t.Fatalf("platform-applications stage did not complete: %#v %v", receipt, err)
	}
	want := []string{}
	for _, application := range bundle.projection.Applications {
		want = append(want, "GET "+application.ObjectPath)
	}
	for _, application := range bundle.projection.Applications {
		want = append(want, "POST "+application.CollectionPath)
	}
	if !reflect.DeepEqual(gitopsAPI.Requests(), want) {
		t.Fatalf("platform-applications request boundary differs: got %v want %v", gitopsAPI.Requests(), want)
	}
	public, _ := json.Marshal(receipt)
	for _, forbidden := range []string{"ledger-token", "gitops-writer-token", gitopsAPI.URL} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("stage receipt leaked private value %q", forbidden)
		}
	}
	replayed, err := bound.Run(context.Background())
	if err != nil || replayed.StageReceiptDigest != receipt.StageReceiptDigest || !reflect.DeepEqual(gitopsAPI.Requests(), want) {
		t.Fatalf("durable platform-applications outcome replayed mutation: %#v %v", replayed, err)
	}
}

func TestPlatformApplicationsStageDurablyStopsPartialStateWithoutRetry(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 2)
	defer gitopsAPI.Close()
	bound, err := bundle.Open(platformApplicationsExecutionRuntime(t, ledgerAPI.Server, gitopsAPI.Server))
	if err != nil {
		t.Fatal(err)
	}
	receipt, runErr := bound.Run(context.Background())
	var resultErr *execution.StageResultError
	if !errors.As(runErr, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("partial platform-applications state was not durably stopped: %#v %v", receipt, runErr)
	}
	requests := gitopsAPI.Requests()
	if len(requests) != 5 || !strings.HasPrefix(requests[4], "POST ") {
		t.Fatalf("platform-applications did not stop at bound failure: %v", requests)
	}
	if _, err := bound.Run(context.Background()); !errors.As(err, &resultErr) || !reflect.DeepEqual(gitopsAPI.Requests(), requests) {
		t.Fatalf("durable platform-applications stop was retried: requests=%v err=%v", gitopsAPI.Requests(), err)
	}
}

func TestPlatformApplicationsStageRejectsSharedLedgerAndWriterCredentialBeforeAPI(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 0)
	defer gitopsAPI.Close()
	config := platformApplicationsExecutionRuntime(t, ledgerAPI.Server, gitopsAPI.Server)
	if err := os.WriteFile(config.GitOps.TokenFile, []byte("ledger-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(config); err == nil || ledgerAPI.RequestCount() != 0 || gitopsAPI.RequestCount() != 0 {
		t.Fatal("shared ledger/writer credential opened platform-applications runtime")
	}
}

func platformApplicationsExecutionRuntime(t *testing.T, ledgerServer, gitopsServer *httptest.Server) PlatformApplicationsStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ledgerCA := writeRuntimeBindingServerCA(t, root, "ledger-ca.crt", ledgerServer)
	gitopsCA := writeRuntimeBindingServerCA(t, root, "gitops-ca.crt", gitopsServer)
	gitopsCABytes, err := os.ReadFile(gitopsCA)
	if err != nil {
		t.Fatal(err)
	}
	return PlatformApplicationsStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: ledgerServer.URL, Namespace: "openkubes-execution-system",
			TokenFile: writeBundleFile(t, root, "ledger-token", []byte("ledger-token")), CAFile: ledgerCA,
		},
		GitOps: KubernetesAuthorityConfig{
			Endpoint: gitopsServer.URL, AuthorityIdentity: "ok-shared",
			TokenFile: writeBundleFile(t, root, "gitops-token", []byte("gitops-writer-token")), CAFile: gitopsCA,
			CABundleDigest: digest.SHA256(gitopsCABytes),
		},
		Clock: func() time.Time { return time.Date(2026, 8, 17, 20, 1, 0, 0, time.UTC) },
	}
}
