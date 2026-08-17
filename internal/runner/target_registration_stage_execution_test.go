package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestTargetRegistrationStageRunsOnceAndReplaysDurableOutcome(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 0)
	defer gitopsAPI.Close()
	bound, err := fixture.bundle.Open(targetRegistrationExecutionRuntime(t, fixture, ledgerAPI.Server, gitopsAPI.Server))
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || gitopsAPI.RequestCount() != 0 {
		t.Fatal("opening target-registration stage contacted Kubernetes")
	}
	receipt, err := bound.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "target-registration" || receipt.StageReceiptDigest == "" {
		t.Fatalf("target-registration stage did not complete: %#v %v", receipt, err)
	}
	want := []string{
		"GET " + fixture.bundle.projection.Project.ObjectPath,
		"GET " + fixture.bundle.projection.Registration.ObjectPath,
		"POST " + fixture.bundle.projection.Project.CollectionPath,
		"POST " + fixture.bundle.projection.Registration.CollectionPath,
	}
	if !reflect.DeepEqual(gitopsAPI.Requests(), want) {
		t.Fatalf("target-registration request boundary differs: got %v want %v", gitopsAPI.Requests(), want)
	}
	public, _ := json.Marshal(receipt)
	for _, forbidden := range []string{string(fixture.credential.token), fixture.credential.endpoint, targetAccessRuntimeUID, "ledger-token", "gitops-writer-token", gitopsAPI.URL} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("stage receipt leaked private value %q", forbidden)
		}
	}
	replayed, err := bound.Run(context.Background())
	if err != nil || replayed.StageReceiptDigest != receipt.StageReceiptDigest || !reflect.DeepEqual(gitopsAPI.Requests(), want) {
		t.Fatalf("durable target-registration outcome replayed mutation: %#v %v", replayed, err)
	}
}

func TestTargetRegistrationStageDurablyStopsPartialStateWithoutRetry(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 2)
	defer gitopsAPI.Close()
	bound, err := fixture.bundle.Open(targetRegistrationExecutionRuntime(t, fixture, ledgerAPI.Server, gitopsAPI.Server))
	if err != nil {
		t.Fatal(err)
	}
	receipt, runErr := bound.Run(context.Background())
	var resultErr *execution.StageResultError
	if !errors.As(runErr, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("partial target-registration state was not durably stopped: %#v %v", receipt, runErr)
	}
	requests := gitopsAPI.Requests()
	if len(requests) != 4 || requests[3] != "POST "+fixture.bundle.projection.Registration.CollectionPath {
		t.Fatalf("target-registration did not stop at bound failure: %v", requests)
	}
	if _, err := bound.Run(context.Background()); !errors.As(err, &resultErr) || !reflect.DeepEqual(gitopsAPI.Requests(), requests) {
		t.Fatalf("durable target-registration stop was retried: requests=%v err=%v", gitopsAPI.Requests(), err)
	}
}

func TestTargetRegistrationStageRejectsSharedLedgerAndWriterCredentialBeforeAPI(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 0)
	defer gitopsAPI.Close()
	config := targetRegistrationExecutionRuntime(t, fixture, ledgerAPI.Server, gitopsAPI.Server)
	if err := os.WriteFile(config.GitOps.TokenFile, []byte("ledger-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.bundle.Open(config); err == nil || ledgerAPI.RequestCount() != 0 || gitopsAPI.RequestCount() != 0 {
		t.Fatal("shared ledger/writer credential opened target-registration runtime")
	}
}

func TestTargetRegistrationStageLoadsAndRunsFromCredentialHandoff(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	handoff, err := newVerifiedTargetCredentialStageHandoff(
		fixture.bundle.plan, fixture.bundle.prefix[:7], fixture.bundle.prefix[7], fixture.credential,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := LoadTargetRegistrationStageBundleFromHandoff(TargetRegistrationStageHandoffConfig{
		Handoff: handoff, GrantPath: fixture.bundleConfig.GrantPath, GrantPublicKeyPath: fixture.bundleConfig.GrantPublicKeyPath,
		EvaluationTime: fixture.bundleConfig.EvaluationTime, ArtifactPath: fixture.bundleConfig.ArtifactPath, Expected: fixture.bundleConfig.Expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, err := bundle.Receipt()
	if err != nil || public.CredentialMaterialPresent || public.MutationAllowed {
		t.Fatalf("handoff-loaded bundle exposed credential: %#v %v", public, err)
	}
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	gitopsAPI := newTargetRegistrationExecutionAPI(t, 0)
	defer gitopsAPI.Close()
	base := targetRegistrationExecutionRuntime(t, fixture, ledgerAPI.Server, gitopsAPI.Server)
	bound, err := bundle.OpenHandoff(TargetRegistrationStageHandoffRuntimeConfig{
		Ledger: base.Ledger, GitOps: base.GitOps, Runtime: base.Runtime,
		MaterializationTime: base.MaterializationTime, Clock: base.Clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || gitopsAPI.RequestCount() != 0 {
		t.Fatal("opening handoff-loaded target registration contacted Kubernetes")
	}
	receipt, err := bound.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "target-registration" || gitopsAPI.RequestCount() != 4 {
		t.Fatalf("handoff-loaded target registration did not complete: %#v requests=%v err=%v", receipt, gitopsAPI.Requests(), err)
	}
	if _, err := bundle.OpenHandoff(TargetRegistrationStageHandoffRuntimeConfig{}); err == nil {
		t.Fatal("memory-only target credential was consumed twice")
	}
}

func TestTargetRegistrationHandoffRejectsForeignOrConsumedContext(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	if _, err := newVerifiedTargetCredentialStageHandoff(
		fixture.bundle.plan, fixture.bundle.prefix[:6], fixture.bundle.prefix[7], fixture.credential,
	); err == nil {
		t.Fatal("incomplete predecessor prefix produced a target-credential handoff")
	}
	handoff, err := newVerifiedTargetCredentialStageHandoff(
		fixture.bundle.plan, fixture.bundle.prefix[:7], fixture.bundle.prefix[7], fixture.credential,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handoff.takeCredential(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargetRegistrationStageBundleFromHandoff(TargetRegistrationStageHandoffConfig{
		Handoff: handoff, GrantPath: fixture.bundleConfig.GrantPath, GrantPublicKeyPath: fixture.bundleConfig.GrantPublicKeyPath,
		EvaluationTime: fixture.bundleConfig.EvaluationTime, ArtifactPath: fixture.bundleConfig.ArtifactPath, Expected: fixture.bundleConfig.Expected,
	}); err == nil {
		t.Fatal("consumed target credential handoff loaded target registration")
	}
}

func targetRegistrationExecutionRuntime(t *testing.T, fixture targetRegistrationMaterialTestFixture, ledgerServer, gitopsServer *httptest.Server) TargetRegistrationStageRuntimeConfig {
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
			TokenFile: writeBundleFile(t, root, "gitops-token", []byte("gitops-writer-token")), CAFile: gitopsCA,
			CABundleDigest: digest.SHA256(gitopsCABytes),
		},
		Runtime: fixture.runtime, Credential: fixture.credential,
		MaterializationTime: fixture.config.MaterializationTime,
		Clock:               func() time.Time { return fixture.config.MaterializationTime.Add(time.Minute) },
	}
}

type targetRegistrationExecutionAPI struct {
	*httptest.Server
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []string
	posts    int
	failPost int
}

func newTargetRegistrationExecutionAPI(t *testing.T, failPost int) *targetRegistrationExecutionAPI {
	t.Helper()
	api := &targetRegistrationExecutionAPI{objects: map[string]map[string]any{}, failPost: failPost}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer gitops-writer-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.Method {
		case http.MethodGet:
			object, exists := api.objects[request.URL.Path]
			if !exists {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(response).Encode(object)
		case http.MethodPost:
			api.posts++
			if api.failPost > 0 && api.posts == api.failPost {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			var object map[string]any
			if json.NewDecoder(request.Body).Decode(&object) != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			metadata, _ := object["metadata"].(map[string]any)
			metadata["uid"] = "target-registration-runtime-uid-" + string(rune('0'+api.posts))
			metadata["resourceVersion"] = "1"
			name, _ := metadata["name"].(string)
			api.objects[strings.TrimSuffix(request.URL.Path, "/")+"/"+name] = object
			response.WriteHeader(http.StatusCreated)
			json.NewEncoder(response).Encode(object)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return api
}

func (api *targetRegistrationExecutionAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func (api *targetRegistrationExecutionAPI) RequestCount() int { return len(api.Requests()) }
