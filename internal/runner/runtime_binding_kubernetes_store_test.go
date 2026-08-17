package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestKubernetesRuntimeBindingStoreCreatesAndVerifiesExactlyOnce(t *testing.T) {
	api := newRuntimeBindingSecretAPI(t)
	defer api.Close()
	store := openRuntimeBindingSecretStore(t, api.Server, "ok-mgmt", "short-lived-binding-token")
	if api.RequestCount() != 0 {
		t.Fatal("opening runtime binding store contacted Kubernetes")
	}
	material, err := BuildRuntimeBindingMaterial(runtimeBindingMaterialConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Store(context.Background(), material)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != KubernetesRuntimeBindingPersistenceReceiptFormat || receipt.State != "CREATED_VERIFIED" || receipt.PersistenceMutationState != "ATTEMPTED" || receipt.LifecycleMutationAllowed || receipt.PrivateMaterialDigest == "" || receipt.ObjectIdentityDigest == "" || receipt.AuthorityIdentityDigest == "" {
		t.Fatalf("runtime binding Secret receipt differs: %#v", receipt)
	}
	want := []string{"POST /api/v1/namespaces/openkubes-execution-system/secrets"}
	if !reflect.DeepEqual(api.Requests(), want) {
		t.Fatalf("runtime binding store request boundary differs: %v", api.Requests())
	}
	public, _ := json.Marshal(receipt)
	private, _ := material.Bytes()
	for _, forbidden := range []string{api.URL, "short-lived-binding-token", "ok147-runtime-binding-run-01", string(private)} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("runtime binding persistence receipt exposed private value %q", forbidden)
		}
	}
	if _, err := store.Store(context.Background(), material); err == nil {
		t.Fatal("single-use runtime binding store wrote twice")
	}
}

func TestKubernetesRuntimeBindingStoreAcceptsOnlyEquivalentConflict(t *testing.T) {
	api := newRuntimeBindingSecretAPI(t)
	defer api.Close()
	material, err := BuildRuntimeBindingMaterial(runtimeBindingMaterialConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	first := openRuntimeBindingSecretStore(t, api.Server, "ok-mgmt", "short-lived-binding-token")
	if _, err := first.Store(context.Background(), material); err != nil {
		t.Fatal(err)
	}
	api.ResetRequests()
	replacement := openRuntimeBindingSecretStore(t, api.Server, "ok-mgmt", "replacement-binding-token")
	receipt, err := replacement.Store(context.Background(), material)
	if err != nil || receipt.State != "EXISTING_VERIFIED" || receipt.PersistenceMutationState != "CONFLICT_OBSERVED" {
		t.Fatalf("equivalent immutable Secret was not resumed: %#v %v", receipt, err)
	}
	want := []string{
		"POST /api/v1/namespaces/openkubes-execution-system/secrets",
		"GET /api/v1/namespaces/openkubes-execution-system/secrets/ok147-runtime-binding-run-01",
	}
	if !reflect.DeepEqual(api.Requests(), want) {
		t.Fatalf("conflict verification request boundary differs: %v", api.Requests())
	}

	api.TamperData()
	conflicting := openRuntimeBindingSecretStore(t, api.Server, "ok-mgmt", "third-binding-token")
	receipt, err = conflicting.Store(context.Background(), material)
	if err == nil || receipt.State != "STOPPED_CONFLICTING_EXISTING" {
		t.Fatalf("conflicting immutable Secret was accepted: %#v %v", receipt, err)
	}
}

func TestKubernetesRuntimeBindingStoreFailsClosedBeforeRequest(t *testing.T) {
	api := newRuntimeBindingSecretAPI(t)
	defer api.Close()
	root := t.TempDir()
	caPath := writeRuntimeBindingServerCA(t, root, "management-ca.crt", api.Server)
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte("short-lived-binding-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := KubernetesAuthorityConfig{Endpoint: api.URL, AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, CAFile: caPath}
	for name, test := range map[string]struct {
		authority KubernetesAuthorityConfig
		expected  string
		namespace string
		secret    string
	}{
		"foreign authority": {authority: base, expected: "ok-infra", namespace: submissionStageInputNamespace, secret: "ok147-runtime-binding-run-01"},
		"foreign namespace": {authority: base, expected: "ok-mgmt", namespace: "other", secret: "ok147-runtime-binding-run-01"},
		"foreign name":      {authority: base, expected: "ok-mgmt", namespace: submissionStageInputNamespace, secret: "other-binding"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenKubernetesRuntimeBindingStore(test.authority, test.expected, test.namespace, test.secret); err == nil {
				t.Fatal("unsafe runtime binding persistence boundary was accepted")
			}
		})
	}
	if api.RequestCount() != 0 {
		t.Fatal("invalid runtime binding store contacted Kubernetes")
	}
	store := openRuntimeBindingSecretStore(t, api.Server, "ok-mgmt", "short-lived-binding-token")
	if _, err := store.Store(context.Background(), VerifiedRuntimeBindingMaterial{}); err == nil || api.RequestCount() != 0 {
		t.Fatalf("unverified material reached Kubernetes: requests=%d err=%v", api.RequestCount(), err)
	}
}

func openRuntimeBindingSecretStore(t *testing.T, server *httptest.Server, authority, token string) *KubernetesRuntimeBindingStore {
	t.Helper()
	root := t.TempDir()
	caPath := writeRuntimeBindingServerCA(t, root, "management-ca.crt", server)
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenKubernetesRuntimeBindingStore(KubernetesAuthorityConfig{
		Endpoint: server.URL, AuthorityIdentity: authority, TokenFile: tokenPath, CAFile: caPath,
	}, "ok-mgmt", submissionStageInputNamespace, "ok147-runtime-binding-run-01")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type runtimeBindingSecretAPI struct {
	*httptest.Server
	mu       sync.Mutex
	object   map[string]any
	requests []string
}

func newRuntimeBindingSecretAPI(t *testing.T) *runtimeBindingSecretAPI {
	t.Helper()
	api := &runtimeBindingSecretAPI{}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(request.Header.Get("Authorization"), "binding-token") {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		collection := "/api/v1/namespaces/openkubes-execution-system/secrets"
		switch {
		case request.Method == http.MethodPost && request.URL.Path == collection:
			if api.object != nil {
				response.WriteHeader(http.StatusConflict)
				return
			}
			if err := json.NewDecoder(request.Body).Decode(&api.object); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			metadata := api.object["metadata"].(map[string]any)
			metadata["uid"], metadata["resourceVersion"] = "runtime-binding-secret-uid", "1"
			response.WriteHeader(http.StatusCreated)
			json.NewEncoder(response).Encode(api.object)
		case request.Method == http.MethodGet && request.URL.Path == collection+"/ok147-runtime-binding-run-01":
			if api.object == nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(response).Encode(api.object)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return api
}

func (api *runtimeBindingSecretAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func (api *runtimeBindingSecretAPI) RequestCount() int { return len(api.Requests()) }

func (api *runtimeBindingSecretAPI) ResetRequests() {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.requests = nil
}

func (api *runtimeBindingSecretAPI) TamperData() {
	api.mu.Lock()
	defer api.mu.Unlock()
	data := api.object["data"].(map[string]any)
	data[runtimeBindingSecretDataKey] = "dGFtcGVyZWQ="
}
