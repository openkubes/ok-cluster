package runner

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

func TestKubernetesCapabilityFixtureClientPreflightsCreatesAndCleansExactObjects(t *testing.T) {
	api := newCapabilityFixtureAPI(t)
	client := newCapabilityFixtureClient(t, api.client())
	created, err := client.Create(context.Background())
	if err != nil || created.State != "CREATED" || created.MutationState != "ATTEMPTED" || len(created.Results) != 4 {
		t.Fatalf("fixture create failed: %#v %v", created, err)
	}
	if len(api.requests) != 8 {
		t.Fatalf("expected four preflight GETs and four POSTs, got %v", api.requests)
	}
	for index := 0; index < 4; index++ {
		if api.requests[index].method != http.MethodGet || api.requests[index+4].method != http.MethodPost {
			t.Fatalf("zero-write preflight/order differs: %v", api.requests)
		}
	}
	api.requests = nil
	cleaned, err := client.Cleanup(context.Background(), created)
	if err != nil || cleaned.State != "CLEANUP_ACCEPTED" || len(cleaned.Results) != 4 {
		t.Fatalf("fixture cleanup failed: %#v %v", cleaned, err)
	}
	if len(api.requests) != 8 {
		t.Fatalf("expected four identity GETs and four DELETEs, got %v", api.requests)
	}
	for index := 0; index < 4; index++ {
		getRequest := api.requests[index*2]
		deleteRequest := api.requests[index*2+1]
		expectedObject := client.fixture.Objects[3-index]
		if getRequest.method != http.MethodGet || getRequest.path != expectedObject.ObjectPath || deleteRequest.method != http.MethodDelete || deleteRequest.path != expectedObject.ObjectPath {
			t.Fatalf("cleanup was not exact reverse order: %v", api.requests)
		}
		var options map[string]any
		if err := json.Unmarshal(deleteRequest.body, &options); err != nil {
			t.Fatal(err)
		}
		preconditions := options["preconditions"].(map[string]any)
		if preconditions["uid"] != created.Results[3-index].UID || preconditions["resourceVersion"] == "" || options["propagationPolicy"] != "Foreground" {
			t.Fatalf("cleanup preconditions differ: %#v", options)
		}
	}
}

func TestKubernetesCapabilityFixtureClientStopsZeroWriteWhenAnyObjectExists(t *testing.T) {
	api := newCapabilityFixtureAPI(t)
	client := newCapabilityFixtureClient(t, api.client())
	existing := client.fixture.Objects[2]
	api.objects[existing.ObjectPath] = api.runtimeObject(existing, "existing-uid", "7")
	receipt, err := client.Create(context.Background())
	if err == nil || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(receipt.Results) != 0 {
		t.Fatalf("existing object did not stop before first write: %#v posts=%d err=%v", receipt, api.posts, err)
	}
	for _, request := range api.requests {
		if request.method != http.MethodGet {
			t.Fatalf("mutation occurred during failed preflight: %#v", request)
		}
	}
}

func TestKubernetesCapabilityFixtureClientPreservesPartialCreatePrefix(t *testing.T) {
	api := newCapabilityFixtureAPI(t)
	api.failPost = 3
	client := newCapabilityFixtureClient(t, api.client())
	receipt, err := client.Create(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 2 {
		t.Fatalf("partial create prefix was not preserved: %#v %v", receipt, err)
	}
	if receipt.Results[0].Identity != client.fixture.Objects[0].Identity || receipt.Results[1].Identity != client.fixture.Objects[1].Identity {
		t.Fatalf("partial receipt does not describe exact created prefix: %#v", receipt)
	}
}

func TestKubernetesCapabilityFixtureClientRejectsForeignAuthorityAndRedirect(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixtureConfig := capabilityFixtureConfig()
	if _, err := NewKubernetesCapabilityFixtureClient(KubernetesCapabilityFixtureClientConfig{
		Endpoint: "https://192.0.2.10:6443", BearerToken: "token", AuthorityIdentity: "foreign", Client: &http.Client{},
	}, run, fixtureConfig); err == nil {
		t.Fatal("foreign workload authority accepted")
	}
	calls := 0
	client, err := NewKubernetesCapabilityFixtureClient(KubernetesCapabilityFixtureClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: run.TargetClusterUID,
		Client: &http.Client{Transport: capabilityRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return capabilityJSONResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/foreign"}), nil
		})},
	}, run, fixtureConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(context.Background()); err == nil || calls != 1 {
		t.Fatalf("redirect followed or accepted: calls=%d err=%v", calls, err)
	}
}

func TestKubernetesCapabilityFixtureClientAcceptsExplicitClientCertificateTransport(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	authorization := "unobserved"
	client, err := NewKubernetesCapabilityFixtureClient(KubernetesCapabilityFixtureClientConfig{
		Endpoint: "http://127.0.0.1:12345", ClientCertificate: true, AuthorityIdentity: run.TargetClusterUID,
		Client: &http.Client{Transport: capabilityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			authorization = request.Header.Get("Authorization")
			return capabilityJSONResponse(http.StatusNotFound, nil, nil), nil
		})},
	}, run, capabilityFixtureConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(context.Background()); err == nil {
		t.Fatal("incomplete fixture preflight unexpectedly succeeded")
	}
	if authorization != "" || !client.clientCertificate || client.token != "" {
		t.Fatalf("client-certificate fixture transport synthesized bearer authority: authorization=%q", authorization)
	}

	for name, mutate := range map[string]func(*KubernetesCapabilityFixtureClientConfig){
		"ambiguous token and certificate": func(config *KubernetesCapabilityFixtureClientConfig) { config.BearerToken = "token" },
		"missing transport identity":      func(config *KubernetesCapabilityFixtureClientConfig) { config.ClientCertificate = false },
	} {
		t.Run(name, func(t *testing.T) {
			config := KubernetesCapabilityFixtureClientConfig{
				Endpoint: "http://127.0.0.1:12345", ClientCertificate: true,
				AuthorityIdentity: run.TargetClusterUID, Client: &http.Client{},
			}
			mutate(&config)
			if _, err := NewKubernetesCapabilityFixtureClient(config, run, capabilityFixtureConfig()); err == nil {
				t.Fatal("unsafe capability credential mode was accepted")
			}
		})
	}
}

type capabilityRecordedRequest struct {
	method string
	path   string
	body   []byte
}

type capabilityFixtureAPI struct {
	t        *testing.T
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []capabilityRecordedRequest
	posts    int
	failPost int
}

func newCapabilityFixtureAPI(t *testing.T) *capabilityFixtureAPI {
	return &capabilityFixtureAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *capabilityFixtureAPI) client() *http.Client {
	return &http.Client{Transport: capabilityRoundTripFunc(api.roundTrip)}
}

func (api *capabilityFixtureAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, capabilityRecordedRequest{method: request.Method, path: request.URL.Path, body: body})
	if request.Header.Get("Authorization") != "Bearer short-lived-test-token" {
		return capabilityJSONResponse(http.StatusUnauthorized, nil, nil), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return capabilityJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		// Simulate controller/status updates between create and cleanup.
		object["metadata"].(map[string]any)["resourceVersion"] = "current-9"
		return capabilityJSONResponse(http.StatusOK, object, nil), nil
	case http.MethodPost:
		api.posts++
		if api.failPost == api.posts {
			return capabilityJSONResponse(http.StatusForbidden, map[string]any{"reason": "Denied"}, nil), nil
		}
		var object map[string]any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			api.t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		uid := "created-uid-" + string(rune('a'+api.posts-1))
		metadata["uid"], metadata["resourceVersion"] = uid, "1"
		path := request.URL.Path + "/" + metadata["name"].(string)
		api.objects[path] = object
		return capabilityJSONResponse(http.StatusCreated, object, nil), nil
	case http.MethodDelete:
		if _, ok := api.objects[request.URL.Path]; !ok {
			return capabilityJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		delete(api.objects, request.URL.Path)
		return capabilityJSONResponse(http.StatusOK, map[string]any{"kind": "Status", "status": "Success"}, nil), nil
	default:
		return capabilityJSONResponse(http.StatusMethodNotAllowed, nil, nil), nil
	}
}

func (api *capabilityFixtureAPI) runtimeObject(object CapabilityObject, uid, resourceVersion string) map[string]any {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(object.Raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		api.t.Fatal(err)
	}
	metadata := value["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = uid, resourceVersion
	return value
}

func newCapabilityFixtureClient(t *testing.T, httpClient *http.Client) *KubernetesCapabilityFixtureClient {
	t.Helper()
	run, err := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewKubernetesCapabilityFixtureClient(KubernetesCapabilityFixtureClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: run.TargetClusterUID, Client: httpClient,
	}, run, capabilityFixtureConfig())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func capabilityFixtureConfig() ObservabilitySyntheticFixtureConfig {
	return ObservabilitySyntheticFixtureConfig{
		PushgatewayImage: "prom/pushgateway@sha256:" + strings.Repeat("1", 64),
		LogEmitterImage:  "busybox@sha256:" + strings.Repeat("2", 64),
	}
}

type capabilityRoundTripFunc func(*http.Request) (*http.Response, error)

func (function capabilityRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func capabilityJSONResponse(status int, value any, headers map[string]string) *http.Response {
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
