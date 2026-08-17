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
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestTargetAccessStageRunsExactlyOnceAgainstRuntimeBoundTarget(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	bundle, err := LoadTargetAccessStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	targetAPI := newTargetAccessAPI(t, 0)
	defer targetAPI.Close()
	bound, err := bundle.Open(targetAccessExecutionRuntime(t, fixture.plan, ledgerAPI.Server, targetAPI.Server))
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || targetAPI.RequestCount() != 0 {
		t.Fatal("opening target-access stage contacted Kubernetes")
	}

	receipt, err := bound.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "target-access" || receipt.StageReceiptDigest == "" {
		t.Fatalf("target-access stage did not complete: %#v %v", receipt, err)
	}
	want := targetAccessRequests(bundle.projection)
	if !reflect.DeepEqual(targetAPI.Requests(), want) {
		t.Fatalf("target-access request boundary differs:\n got %v\nwant %v", targetAPI.Requests(), want)
	}
	public, _ := json.Marshal(receipt)
	for _, forbidden := range []string{targetAccessRuntimeUID, "ledger-token", "workload-token", ledgerAPI.URL, targetAPI.URL} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("target-access receipt exposed private value %q", forbidden)
		}
	}

	replayed, err := bound.Run(context.Background())
	if err != nil || replayed.StageReceiptDigest != receipt.StageReceiptDigest || !reflect.DeepEqual(targetAPI.Requests(), want) {
		t.Fatalf("durable target-access outcome replayed mutation: %#v %v", replayed, err)
	}
}

func TestTargetAccessStagePersistsPartialStopWithoutRetry(t *testing.T) {
	fixture := targetAccessBundleFixture(t)
	bundle, err := LoadTargetAccessStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	targetAPI := newTargetAccessAPI(t, 3)
	defer targetAPI.Close()
	bound, err := bundle.Open(targetAccessExecutionRuntime(t, fixture.plan, ledgerAPI.Server, targetAPI.Server))
	if err != nil {
		t.Fatal(err)
	}
	receipt, runErr := bound.Run(context.Background())
	var resultErr *execution.StageResultError
	if !errors.As(runErr, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("partial target-access state was not durably stopped: %#v %v", receipt, runErr)
	}
	requests := targetAPI.Requests()
	if len(requests) != 6 || requests[5] != "POST "+bundle.projection.Workload.Objects[2].CollectionPath {
		t.Fatalf("target-access did not stop at the bound failure: %v", requests)
	}
	if _, err := bound.Run(context.Background()); !errors.As(err, &resultErr) || !reflect.DeepEqual(targetAPI.Requests(), requests) {
		t.Fatalf("durable target-access stop was retried: requests=%v err=%v", targetAPI.Requests(), err)
	}
}

func targetAccessExecutionRuntime(t *testing.T, plan stageplan.Binding, ledgerServer, targetServer *httptest.Server) TargetAccessStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ledgerCAPath := writeRuntimeBindingServerCA(t, root, "ledger-ca.crt", ledgerServer)
	targetCAPath := writeRuntimeBindingServerCA(t, root, "target-ca.crt", targetServer)
	targetCA, err := os.ReadFile(targetCAPath)
	if err != nil {
		t.Fatal(err)
	}
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: plan.IntentRevision,
		TargetClusterUID: targetAccessRuntimeUID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: targetServer.URL, CABundleDigest: digest.SHA256(targetCA),
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	bindingRaw, _ := json.Marshal(binding)
	return TargetAccessStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: ledgerServer.URL, Namespace: "openkubes-execution-system",
			TokenFile: writeBundleFile(t, root, "ledger-token", []byte("ledger-token")), CAFile: ledgerCAPath,
		},
		Workload: WorkloadAuthorityFileResolverConfig{
			Path: writeBundleFile(t, root, "runtime-binding.json", bindingRaw), ExpectedBindingDigest: bindingDigest,
			TokenFile: writeBundleFile(t, root, "workload-token", []byte("workload-token")), CAFile: targetCAPath,
		},
		Clock: func() time.Time { return time.Date(2026, 8, 17, 14, 1, 0, 0, time.UTC) },
	}
}

type targetAccessAPI struct {
	*httptest.Server
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []string
	posts    int
	failPost int
}

func newTargetAccessAPI(t *testing.T, failPost int) *targetAccessAPI {
	t.Helper()
	api := &targetAccessAPI{objects: map[string]map[string]any{}, failPost: failPost}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer workload-token" {
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
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			metadata, _ := object["metadata"].(map[string]any)
			metadata["uid"] = "target-object-uid-" + string(rune('0'+api.posts))
			metadata["resourceVersion"] = "1"
			name, _ := metadata["name"].(string)
			objectPath := strings.TrimSuffix(request.URL.Path, "/") + "/" + name
			api.objects[objectPath] = object
			response.WriteHeader(http.StatusCreated)
			json.NewEncoder(response).Encode(object)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return api
}

func (api *targetAccessAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func (api *targetAccessAPI) RequestCount() int { return len(api.Requests()) }

func targetAccessRequests(plan submission.TargetAccessPlan) []string {
	requests := make([]string, 0, 2*len(plan.Workload.Objects))
	for _, object := range plan.Workload.Objects {
		requests = append(requests, "GET "+object.ObjectPath, "POST "+object.CollectionPath)
	}
	return requests
}
