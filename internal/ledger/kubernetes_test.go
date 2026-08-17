package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKubernetesStoreSurvivesExecutorRecreation(t *testing.T) {
	api := newFakeConfigMapAPI(t)
	store := newTestKubernetesStore(t, api.client())
	firstLedger, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	grant := verifiedGrant(t, at)
	ctx := context.Background()

	initial, err := firstLedger.Inspect(ctx, grant)
	if err != nil || initial.State != "AVAILABLE" || !initial.ClaimAllowed {
		t.Fatalf("initial inspection: %#v %v", initial, err)
	}
	claim, err := firstLedger.Claim(ctx, grant, at)
	if err != nil {
		t.Fatal(err)
	}

	// A new store and ledger model a replacement Job/process.
	replacementLedger, err := New(newTestKubernetesStore(t, api.client()))
	if err != nil {
		t.Fatal(err)
	}
	indeterminate, err := replacementLedger.Inspect(ctx, grant)
	if err != nil || indeterminate.State != "CLAIMED_INDETERMINATE_STOP" || indeterminate.ClaimAllowed {
		t.Fatalf("replacement inspection: %#v %v", indeterminate, err)
	}
	if _, err := replacementLedger.Claim(ctx, grant, at.Add(time.Second)); err != ErrGrantConsumed {
		t.Fatalf("replacement reused grant: %v", err)
	}
	evidence := "sha256:" + strings.Repeat("e", 64)
	if _, err := replacementLedger.Complete(ctx, claim, "SUCCEEDED", "ATTEMPTED", evidence, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, err := firstLedger.Inspect(ctx, grant)
	if err != nil || completed.State != "COMPLETED" || completed.Outcome == nil {
		t.Fatalf("completed inspection: %#v %v", completed, err)
	}
	if api.nonExactRequests.Load() != 0 {
		t.Fatalf("store issued %d non-exact requests", api.nonExactRequests.Load())
	}
}

func TestKubernetesStoreAtomicClaim(t *testing.T) {
	api := newFakeConfigMapAPI(t)
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	grant := verifiedGrant(t, at)
	ctx := context.Background()
	var winners atomic.Int32
	var consumed atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 24; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store, err := New(newTestKubernetesStore(t, api.client()))
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := store.Claim(ctx, grant, at); err == nil {
				winners.Add(1)
			} else if err == ErrGrantConsumed {
				consumed.Add(1)
			} else {
				t.Errorf("claim: %v", err)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 || consumed.Load() != 23 {
		t.Fatalf("winners=%d consumed=%d", winners.Load(), consumed.Load())
	}
}

func TestKubernetesStoreFailsClosed(t *testing.T) {
	t.Run("requires HTTPS outside loopback", func(t *testing.T) {
		_, err := NewKubernetesStore(KubernetesStoreConfig{Endpoint: "http://api.example.test", Namespace: "openkubes-execution-system", BearerToken: "token", Client: http.DefaultClient})
		if err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatalf("expected TLS rejection, got %v", err)
		}
	})
	t.Run("rejects noncanonical receipt before request", func(t *testing.T) {
		api := newFakeConfigMapAPI(t)
		store := newTestKubernetesStore(t, api.client())
		err := store.Create(context.Background(), "claims", strings.Repeat("a", 64), []byte(" {\"format\":\"x\"}"))
		if err == nil || !strings.Contains(err.Error(), "canonical") || api.requests.Load() != 0 {
			t.Fatalf("expected local canonical rejection, requests=%d err=%v", api.requests.Load(), err)
		}
	})
	t.Run("does not follow API redirect", func(t *testing.T) {
		var calls atomic.Int32
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return jsonResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/redirected"}), nil
		})}
		store := newTestKubernetesStore(t, client)
		_, err := store.Get(context.Background(), "claims", strings.Repeat("a", 64))
		if err == nil || calls.Load() != 1 {
			t.Fatalf("redirect was followed or accepted: calls=%d err=%v", calls.Load(), err)
		}
	})
	t.Run("maps create conflict to immutable existence", func(t *testing.T) {
		api := newFakeConfigMapAPI(t)
		store := newTestKubernetesStore(t, api.client())
		key := strings.Repeat("a", 64)
		receipt := []byte("{\"format\":\"x\"}")
		if err := store.Create(context.Background(), "claims", key, receipt); err != nil {
			t.Fatal(err)
		}
		if err := store.Create(context.Background(), "claims", key, receipt); err != ErrRecordExists {
			t.Fatalf("second create = %v, want ErrRecordExists", err)
		}
	})
}

func TestKubernetesStoreRejectsTamperedConfigMap(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*configMap)
	}{
		{name: "content digest", mutate: func(object *configMap) {
			object.Metadata.Annotations["openkubes.io/content-digest"] = "sha256:" + strings.Repeat("b", 64)
		}},
		{name: "unexpected label", mutate: func(object *configMap) {
			object.Metadata.Labels["unexpected"] = "value"
		}},
		{name: "missing server identity", mutate: func(object *configMap) {
			object.Metadata.UID = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeConfigMapAPI(t)
			store := newTestKubernetesStore(t, api.client())
			key := strings.Repeat("a", 64)
			if err := store.Create(context.Background(), "claims", key, []byte("{\"format\":\"x\"}")); err != nil {
				t.Fatal(err)
			}
			name, _, err := kubernetesRecordIdentity("claims", key)
			if err != nil {
				t.Fatal(err)
			}
			api.mu.Lock()
			object := api.objects[name]
			test.mutate(&object)
			api.objects[name] = object
			api.mu.Unlock()
			if _, err := store.Get(context.Background(), "claims", key); err == nil {
				t.Fatal("tampered ConfigMap was accepted")
			}
		})
	}
}

type fakeConfigMapAPI struct {
	t                *testing.T
	mu               sync.Mutex
	objects          map[string]configMap
	requests         atomic.Int32
	nonExactRequests atomic.Int32
}

func newFakeConfigMapAPI(t *testing.T) *fakeConfigMapAPI {
	t.Helper()
	return &fakeConfigMapAPI{t: t, objects: map[string]configMap{}}
}

func (api *fakeConfigMapAPI) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(api.roundTrip)}
}

func (api *fakeConfigMapAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.requests.Add(1)
	if request.Header.Get("Authorization") != "Bearer short-lived-test-token" {
		api.t.Errorf("authorization header differs")
		return jsonResponse(http.StatusUnauthorized, nil, nil), nil
	}
	prefix := "/api/v1/namespaces/openkubes-execution-system/configmaps"
	if request.Method == http.MethodPost && request.URL.Path == prefix {
		if request.Header.Get("Content-Type") != "application/json" {
			api.t.Errorf("POST content type differs")
		}
		var object configMap
		if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
			return jsonResponse(http.StatusBadRequest, nil, nil), nil
		}
		api.mu.Lock()
		defer api.mu.Unlock()
		if _, exists := api.objects[object.Metadata.Name]; exists {
			return jsonResponse(http.StatusConflict, nil, nil), nil
		}
		object.Metadata.UID = "test-uid-" + object.Metadata.Name
		object.Metadata.ResourceVersion = "1"
		api.objects[object.Metadata.Name] = object
		return jsonResponse(http.StatusCreated, object, nil), nil
	}
	if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, prefix+"/") && !strings.Contains(strings.TrimPrefix(request.URL.Path, prefix+"/"), "/") {
		name := strings.TrimPrefix(request.URL.Path, prefix+"/")
		api.mu.Lock()
		defer api.mu.Unlock()
		object, exists := api.objects[name]
		if !exists {
			return jsonResponse(http.StatusNotFound, nil, nil), nil
		}
		return jsonResponse(http.StatusOK, object, nil), nil
	}
	api.nonExactRequests.Add(1)
	return jsonResponse(http.StatusMethodNotAllowed, nil, nil), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, value any, headers map[string]string) *http.Response {
	var body []byte
	if value != nil {
		body, _ = json.Marshal(value)
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func newTestKubernetesStore(t *testing.T, client *http.Client) *KubernetesStore {
	t.Helper()
	store, err := NewKubernetesStore(KubernetesStoreConfig{
		Endpoint: "http://127.0.0.1:12345", Namespace: "openkubes-execution-system", BearerToken: "short-lived-test-token", Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
