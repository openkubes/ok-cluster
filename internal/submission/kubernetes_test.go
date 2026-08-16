package submission

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestKubernetesSubmitIsExactCreateOnlyAndIdempotent(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeObjectAPI(t)
	client := newSubmissionClient(t, "ok-infra", api.client())

	first, err := client.Submit(context.Background(), plan.Infrastructure)
	if err != nil || first.State != "SUBMITTED" || len(first.Results) != 1 || first.Results[0].State != "CREATED" {
		t.Fatalf("first submission: %#v %v", first, err)
	}
	second, err := client.Submit(context.Background(), plan.Infrastructure)
	if err != nil || second.Results[0].State != "UNCHANGED" {
		t.Fatalf("second submission: %#v %v", second, err)
	}
	if api.posts != 1 {
		t.Fatalf("POST count=%d, want 1", api.posts)
	}
	for _, request := range api.requests {
		if request.method != http.MethodGet && request.method != http.MethodPost {
			t.Fatalf("unbounded method observed: %#v", request)
		}
		if strings.Contains(request.path, "?") || strings.HasSuffix(request.path, "/namespaces") && request.method == http.MethodGet {
			t.Fatalf("collection GET observed: %#v", request)
		}
	}
}

func TestKubernetesSubmitFailsClosedForDriftConflictAndAuthority(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong authority", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		client := newSubmissionClient(t, "ok-mgmt", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || len(api.requests) != 0 {
			t.Fatalf("authority mismatch did not fail locally: %#v %v", receipt, err)
		}
	})

	t.Run("existing drift", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, plan.Infrastructure.Objects[0].Raw)
		metadata := object["metadata"].(map[string]any)
		metadata["name"] = "different"
		api.objects[plan.Infrastructure.Objects[0].ObjectPath] = object
		client := newSubmissionClient(t, "ok-infra", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || api.posts != 0 {
			t.Fatalf("drift accepted: %#v %v", receipt, err)
		}
	})

	t.Run("create conflict after absence", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		api.conflict = true
		client := newSubmissionClient(t, "ok-infra", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || !strings.Contains(err.Error(), "conflicted") {
			t.Fatalf("conflict accepted: %#v %v", receipt, err)
		}
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		calls := 0
		client := newSubmissionClient(t, "ok-infra", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/redirected"}), nil
		})})
		if _, err := client.Submit(context.Background(), plan.Infrastructure); err == nil || calls != 1 {
			t.Fatalf("redirect followed or accepted: calls=%d err=%v", calls, err)
		}
	})
}

func TestExecutorPreservesAuthorityOrderAndPartialReceipt(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	infraAPI := newFakeObjectAPI(t)
	mgmtAPI := newFakeObjectAPI(t)
	mgmtAPI.failStatus = http.StatusForbidden
	executor := Executor{
		Infrastructure: newSubmissionClient(t, "ok-infra", infraAPI.client()),
		Management:     newSubmissionClient(t, "ok-mgmt", mgmtAPI.client()),
	}
	receipt, err := executor.Execute(context.Background(), plan)
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.Infrastructure == nil || receipt.Management == nil {
		t.Fatalf("partial execution receipt: %#v %v", receipt, err)
	}
	if receipt.Infrastructure.State != "SUBMITTED" || receipt.Management.State != "STOPPED_PARTIAL_OR_UNKNOWN" || infraAPI.posts != 1 || mgmtAPI.posts != 0 {
		t.Fatalf("authority order/stop differs: %#v infraPosts=%d mgmtPosts=%d", receipt, infraAPI.posts, mgmtAPI.posts)
	}
}

func TestExecutorSuccessfulReceiptIsNotLifecycleSuccess(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	executor := Executor{
		Infrastructure: newSubmissionClient(t, "ok-infra", newFakeObjectAPI(t).client()),
		Management:     newSubmissionClient(t, "ok-mgmt", newFakeObjectAPI(t).client()),
	}
	receipt, err := executor.Execute(context.Background(), plan)
	if err != nil || receipt.State != "SUBMITTED_OBSERVATION_PENDING" {
		t.Fatalf("submission outcome incorrectly classified: %#v %v", receipt, err)
	}
}

type recordedRequest struct {
	method string
	path   string
}

type fakeObjectAPI struct {
	t          *testing.T
	mu         sync.Mutex
	objects    map[string]map[string]any
	requests   []recordedRequest
	posts      int
	conflict   bool
	failStatus int
}

func newFakeObjectAPI(t *testing.T) *fakeObjectAPI {
	t.Helper()
	return &fakeObjectAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *fakeObjectAPI) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(api.roundTrip)}
}

func (api *fakeObjectAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.requests = append(api.requests, recordedRequest{method: request.Method, path: request.URL.Path})
	if request.Header.Get("Authorization") != "Bearer short-lived-test-token" {
		return jsonResponse(http.StatusUnauthorized, nil, nil), nil
	}
	if api.failStatus != 0 {
		return jsonResponse(api.failStatus, map[string]any{"reason": "Denied"}, nil), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return jsonResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		return jsonResponse(http.StatusOK, object, nil), nil
	case http.MethodPost:
		api.posts++
		if api.conflict {
			return jsonResponse(http.StatusConflict, map[string]any{"reason": "AlreadyExists"}, nil), nil
		}
		var object map[string]any
		decoder := json.NewDecoder(request.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			api.t.Error(err)
			return jsonResponse(http.StatusBadRequest, nil, nil), nil
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "test-uid"
		metadata["resourceVersion"] = "1"
		name := metadata["name"].(string)
		path := request.URL.Path + "/" + name
		api.objects[path] = object
		return jsonResponse(http.StatusCreated, object, nil), nil
	default:
		return jsonResponse(http.StatusMethodNotAllowed, nil, nil), nil
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, value any, headers map[string]string) *http.Response {
	var raw []byte
	if value != nil {
		raw, _ = json.Marshal(value)
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(raw))}
}

func apiObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	metadata := value["metadata"].(map[string]any)
	metadata["uid"] = "existing-uid"
	metadata["resourceVersion"] = "7"
	return value
}

func newSubmissionClient(t *testing.T, authority string, client *http.Client) *KubernetesClient {
	t.Helper()
	result, err := NewKubernetesClient(KubernetesClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: authority, Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
