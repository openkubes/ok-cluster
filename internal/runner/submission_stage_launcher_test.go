package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestSubmissionStageLauncherPreflightsSixThenCreatesInFixedOrder(t *testing.T) {
	stage, credentials, runtime, ledgerToken, authorityToken := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 6 {
		t.Fatalf("launch failed: receipt=%#v err=%v", receipt, err)
	}
	if len(api.requests) != 12 || api.posts != 6 {
		t.Fatalf("requests=%d posts=%d, want six GETs then six POSTs", len(api.requests), api.posts)
	}
	for index := 0; index < 6; index++ {
		preflight, create := api.requests[index], api.requests[index+6]
		if preflight.method != http.MethodGet || preflight.path != launcher.plan.Preflights[index].ObjectPath || create.method != http.MethodPost || create.path != launcher.plan.Creates[index].CollectionPath || digest.SHA256(create.body) != launcher.plan.Creates[index].ObjectDigest {
			t.Fatalf("request order %d differs: preflight=%#v create=%#v", index+1, preflight, create)
		}
		if preflight.accept != "application/json" {
			t.Fatalf("object preflight %d media type differs: %q", index+1, preflight.accept)
		}
		result := receipt.Results[index]
		if result.Order != index+1 || result.Kind != launcher.plan.Creates[index].Kind || result.ObjectState != "CREATED" || !stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			t.Fatalf("result %d differs: %#v", index+1, result)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{ledgerToken, authorityToken, credentials.objects[0].raw, credentials.objects[1].raw, []byte("short-lived-installer-token"), []byte("created-uid")} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("launch receipt exposed private content")
		}
	}
	requests := len(api.requests)
	retry, retryErr := launcher.Launch(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("launcher retried: receipt=%#v err=%v", retry, retryErr)
	}
}

func TestSubmissionStageLauncherTreatsExactDuplicateAsAlreadyLaunched(t *testing.T) {
	stage, credentials, runtime, ledgerToken, authorityToken := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	now := time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC)
	first := newSubmissionStageLauncher(t, stage, credentials, runtime, api, now)
	firstReceipt, err := first.Launch(context.Background())
	if err != nil || firstReceipt.State != "LAUNCHED" || api.posts != 6 {
		t.Fatalf("first launch failed: %#v posts=%d err=%v", firstReceipt, api.posts, err)
	}
	requests := len(api.requests)
	duplicate := newSubmissionStageLauncher(t, stage, credentials, runtime, api, now)
	receipt, err := duplicate.Launch(context.Background())
	if err != nil || receipt.State != "ALREADY_LAUNCHED" || receipt.MutationState != "NOT_ATTEMPTED" || len(receipt.Results) != 6 || api.posts != 6 || len(api.requests) != requests+6 {
		t.Fatalf("exact duplicate was not idempotent: %#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
	for index, result := range receipt.Results {
		if result.Order != index+1 || result.ObjectState != "EXISTING_VERIFIED" {
			t.Fatalf("duplicate result %d differs: %#v", index+1, result)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{ledgerToken, authorityToken, credentials.objects[0].raw, credentials.objects[1].raw, []byte("short-lived-installer-token"), []byte("created-uid")} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("duplicate launch receipt exposed private content")
		}
	}
}

func TestSubmissionStageLauncherRejectsChangedDuplicateSecret(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	now := time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC)
	first := newSubmissionStageLauncher(t, stage, credentials, runtime, api, now)
	if receipt, err := first.Launch(context.Background()); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("first launch failed: %#v %v", receipt, err)
	}
	secret := api.objects[first.plan.Preflights[1].ObjectPath]
	data := secret["data"].(map[string]any)
	data["token"] = "dGFtcGVyZWQ="
	requests, posts := len(api.requests), api.posts
	duplicate := newSubmissionStageLauncher(t, stage, credentials, runtime, api, now)
	receipt, err := duplicate.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != requests+2 || api.posts != posts || len(receipt.Results) != 0 {
		t.Fatalf("changed duplicate Secret was accepted: %#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
}

func TestSubmissionStageLauncherAcceptsOnlyExactExistingRuntime(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	runtimeObject := decodeCapabilityJSONForTest(t, runtime.raw)
	runtimeMetadata := runtimeObject["metadata"].(map[string]any)
	runtimeMetadata["uid"], runtimeMetadata["resourceVersion"] = "runtime-existing-uid", "7"
	api.objects[stageRuntimeObjectPath] = runtimeObject
	launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || len(receipt.Results) != 6 || receipt.Results[0].ObjectState != "EXISTING_VERIFIED" || api.posts != 5 || len(api.requests) != 11 {
		t.Fatalf("existing runtime was not reused exactly: receipt=%#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}

	stage, credentials, runtime, _, _ = submissionStageLaunchFixture(t)
	api = newSubmissionStageLauncherAPI(t)
	runtimeObject = decodeCapabilityJSONForTest(t, runtime.raw)
	runtimeObject["automountServiceAccountToken"] = true
	runtimeMetadata = runtimeObject["metadata"].(map[string]any)
	runtimeMetadata["uid"], runtimeMetadata["resourceVersion"] = "runtime-existing-uid", "7"
	api.objects[stageRuntimeObjectPath] = runtimeObject
	launcher = newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	receipt, err = launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || api.posts != 0 || len(api.requests) != 1 {
		t.Fatalf("changed runtime reached create phase: receipt=%#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
}

func TestSubmissionStageLauncherStopsGloballyBeforeWrite(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	api.objects[launcher.plan.Preflights[4].ObjectPath] = map[string]any{"kind": "NetworkPolicy"}
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 5 || len(receipt.Results) != 0 {
		t.Fatalf("global preflight did not stop zero-write: receipt=%#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
}

func TestSubmissionStageLauncherRejectsExactPartialState(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	existing := decodeCapabilityJSONForTest(t, launcher.objects[1].raw)
	metadata := existing["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "existing-network-policy-uid", "9"
	api.objects[launcher.plan.Preflights[4].ObjectPath] = existing
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 6 || len(receipt.Results) != 0 {
		t.Fatalf("exact partial state reached mutation: receipt=%#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
}

func TestSubmissionStageLauncherResumesExactVerifiedPrefix(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	now := time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC)
	first := newSubmissionStageLauncher(t, stage, credentials, runtime, api, now)
	if receipt, err := first.Launch(context.Background()); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("first launch failed: %#v %v", receipt, err)
	}
	delete(api.objects, first.plan.Preflights[5].ObjectPath)
	api.requests, api.posts = nil, 0

	resume := newSubmissionStageLauncher(t, stage, credentials, runtime, api, now)
	receipt, err := resume.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 6 || api.posts != 1 || len(api.requests) != 7 {
		t.Fatalf("exact prefix was not resumed: receipt=%#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
	for index, result := range receipt.Results {
		wantState := "EXISTING_VERIFIED"
		if index == 5 {
			wantState = "CREATED"
		}
		if result.Order != index+1 || result.ObjectState != wantState {
			t.Fatalf("result %d differs: %#v", index+1, result)
		}
	}
}

func TestSubmissionStageCreatedNetworkPolicyAcceptsOmittedEmptyIngress(t *testing.T) {
	stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	expected := launcher.objects[1]
	observed := decodeCapabilityJSONForTest(t, expected.raw)
	metadata := observed["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "network-policy-uid", "17"
	delete(observed["spec"].(map[string]any), "ingress")
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySubmissionStageCreatedObject(raw, expected); err != nil {
		t.Fatalf("semantically identical API-defaulted NetworkPolicy was rejected: %v", err)
	}
}

func TestSubmissionStageLauncherPreservesPartialPrefixAndStaleCredentialsStopLocally(t *testing.T) {
	t.Run("partial prefix", func(t *testing.T) {
		stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
		api := newSubmissionStageLauncherAPI(t)
		api.failPost = 4
		launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
		receipt, err := launcher.Launch(context.Background())
		if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 3 || api.posts != 4 || len(api.requests) != 10 {
			t.Fatalf("partial prefix differs: receipt=%#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
		}
	})

	t.Run("stale credentials", func(t *testing.T) {
		stage, credentials, runtime, _, _ := submissionStageLaunchFixture(t)
		api := newSubmissionStageLauncherAPI(t)
		launcher := newSubmissionStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC))
		receipt, err := launcher.Launch(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
			t.Fatalf("stale credentials reached API: receipt=%#v requests=%d err=%v", receipt, len(api.requests), err)
		}
	})
}

func newSubmissionStageLauncher(t *testing.T, stage VerifiedSubmissionStagePackage, credentials VerifiedSubmissionStageCredentialPackage, runtime VerifiedSubmissionStageRuntimePrerequisite, api *submissionStageLauncherAPI, now time.Time) *KubernetesSubmissionStageLauncher {
	t.Helper()
	launcher, err := newKubernetesSubmissionStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: api.client(), Clock: func() time.Time { return now },
	}, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}

type submissionStageLauncherRequest struct {
	method string
	path   string
	accept string
	body   []byte
}

type submissionStageLauncherAPI struct {
	t        *testing.T
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []submissionStageLauncherRequest
	posts    int
	failPost int
}

func newSubmissionStageLauncherAPI(t *testing.T) *submissionStageLauncherAPI {
	return &submissionStageLauncherAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *submissionStageLauncherAPI) client() *http.Client {
	return &http.Client{Transport: submissionStageLauncherRoundTripFunc(api.roundTrip)}
}

func (api *submissionStageLauncherAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, submissionStageLauncherRequest{method: request.Method, path: request.URL.Path, accept: request.Header.Get("Accept"), body: body})
	if request.Header.Get("Authorization") != "Bearer short-lived-installer-token" {
		return submissionStageLauncherJSONResponse(http.StatusUnauthorized, map[string]any{"reason": "Unauthorized"}), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return submissionStageLauncherJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}), nil
		}
		return submissionStageLauncherJSONResponse(http.StatusOK, object), nil
	case http.MethodPost:
		api.posts++
		if api.failPost == api.posts {
			return submissionStageLauncherJSONResponse(http.StatusForbidden, map[string]any{"reason": "Denied"}), nil
		}
		var object map[string]any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			api.t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "created-uid-" + string(rune('a'+api.posts-1))
		metadata["resourceVersion"] = string(rune('1' + api.posts - 1))
		name, _ := metadata["name"].(string)
		api.objects[request.URL.Path+"/"+name] = object
		return submissionStageLauncherJSONResponse(http.StatusCreated, object), nil
	default:
		return submissionStageLauncherJSONResponse(http.StatusMethodNotAllowed, map[string]any{"reason": "MethodNotAllowed"}), nil
	}
}

type submissionStageLauncherRoundTripFunc func(*http.Request) (*http.Response, error)

func (function submissionStageLauncherRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func submissionStageLauncherJSONResponse(status int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}
}

func decodeCapabilityJSONForTest(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
