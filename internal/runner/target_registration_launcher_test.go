package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestTargetRegistrationLauncherPreflightsThenCreatesExactObjects(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, err := BuildTargetRegistrationMaterial(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	api := newTargetRegistrationLauncherAPI(t)
	launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
	receipt, err := launcher.Install(context.Background())
	if err != nil || receipt.State != "INSTALLED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 2 {
		t.Fatalf("target registration failed: %#v %v", receipt, err)
	}
	if receipt.Format != TargetRegistrationLaunchReceiptFormat || receipt.StageID != "target-registration" ||
		receipt.PlanDigest != material.receipt.PlanDigest || receipt.TargetIdentityDigest != material.receipt.TargetIdentityDigest ||
		receipt.MaterializationBindingDigest != material.receipt.MaterializationBindingDigest || receipt.Authority != "ok-shared" || receipt.CredentialBytesInReceipt {
		t.Fatalf("unexpected target-registration receipt: %#v", receipt)
	}
	if len(api.requests) != 4 {
		t.Fatalf("requests=%d, want two GETs then two POSTs", len(api.requests))
	}
	for index, object := range launcher.objects {
		preflight, submission := api.requests[index], api.requests[index+2]
		if preflight.method != http.MethodGet || preflight.path != object.objectPath || len(preflight.body) != 0 ||
			submission.method != http.MethodPost || submission.path != object.collectionPath || digest.SHA256(submission.body) != object.privateDigest {
			t.Fatalf("request %d differs from exact material", index)
		}
		result := receipt.Results[index]
		if result.Order != index+1 || result.Role != object.role || result.Namespace != object.namespace || result.Name != object.name ||
			result.BoundDigest != object.boundDigest || result.State != "CREATED" || result.MaterializedObjectDigestRetained ||
			!stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			t.Fatalf("result %d differs: %#v", index, result)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		string(fixture.credential.token), string(fixture.credential.caBundle), fixture.credential.endpoint,
		fixture.runtime.material.Target.CAPIClusterUID, fixture.runtime.material.Target.KubeSystemUID,
		material.registrationDigest, "created-target-registration-uid",
	} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("public launch receipt leaked %q", forbidden)
		}
	}
}

func TestTargetRegistrationLauncherStopsZeroWriteForExistingOrStaleMaterial(t *testing.T) {
	t.Run("existing registration", func(t *testing.T) {
		fixture := targetRegistrationMaterialFixture(t)
		material, _ := BuildTargetRegistrationMaterial(fixture.config)
		api := newTargetRegistrationLauncherAPI(t)
		launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
		api.objects[launcher.objects[1].objectPath] = map[string]any{"kind": "Secret"}
		receipt, err := launcher.Install(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 2 {
			t.Fatalf("existing registration did not stop before writes: %#v requests=%d err=%v", receipt, len(api.requests), err)
		}
	})
	t.Run("near expiry", func(t *testing.T) {
		fixture := targetRegistrationMaterialFixture(t)
		material, _ := BuildTargetRegistrationMaterial(fixture.config)
		api := newTargetRegistrationLauncherAPI(t)
		launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.credential.expiresAt.Add(-29*time.Minute))
		receipt, err := launcher.Install(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
			t.Fatalf("stale material reached API: %#v requests=%d err=%v", receipt, len(api.requests), err)
		}
	})
	t.Run("before materialization", func(t *testing.T) {
		fixture := targetRegistrationMaterialFixture(t)
		material, _ := BuildTargetRegistrationMaterial(fixture.config)
		api := newTargetRegistrationLauncherAPI(t)
		launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(-time.Second))
		receipt, err := launcher.Install(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || len(api.requests) != 0 {
			t.Fatalf("pre-materialization launch reached API: %#v requests=%d err=%v", receipt, len(api.requests), err)
		}
	})
}

func TestTargetRegistrationLauncherPreservesPartialStateAndCannotRetry(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, _ := BuildTargetRegistrationMaterial(fixture.config)
	api := newTargetRegistrationLauncherAPI(t)
	api.failPost = 2
	launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
	receipt, err := launcher.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 1 || receipt.Results[0].Role != "project" {
		t.Fatalf("partial state differs: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	retry, retryErr := launcher.Install(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("single-use launcher retried: %#v %v", retry, retryErr)
	}
}

func TestTargetRegistrationLauncherFailsClosedForTamperingUnknownOutcomeAndRedirect(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, _ := BuildTargetRegistrationMaterial(fixture.config)
	tampered := material
	tampered.registrationPath = "/api/v1/namespaces/argocd/secrets/foreign"
	if _, err := newKubernetesTargetRegistrationLauncher(targetRegistrationLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared",
		Client: newTargetRegistrationLauncherAPI(t).client(), Clock: time.Now,
	}, tampered); err == nil {
		t.Fatal("tampered material opened launcher")
	}
	if _, err := newKubernetesTargetRegistrationLauncher(targetRegistrationLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: string(fixture.credential.token), AuthorityIdentity: "ok-shared",
		Client: newTargetRegistrationLauncherAPI(t).client(), Clock: time.Now,
	}, material); err == nil {
		t.Fatal("workload target credential was accepted as GitOps writer credential")
	}

	api := newTargetRegistrationLauncherAPI(t)
	api.errorPost = 1
	launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
	receipt, err := launcher.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 0 || strings.Contains(err.Error(), string(fixture.credential.token)) {
		t.Fatalf("unknown outcome accepted or leaked: %#v %v", receipt, err)
	}

	calls := 0
	redirect := &http.Client{Transport: targetRegistrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return targetRegistrationJSONResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/foreign"}), nil
	})}
	launcher = newTargetRegistrationLauncher(t, material, redirect, fixture.config.MaterializationTime.Add(time.Minute))
	receipt, err = launcher.Install(context.Background())
	if err == nil || calls != 1 || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("redirect followed or accepted: calls=%d receipt=%#v err=%v", calls, receipt, err)
	}
}

func newTargetRegistrationLauncher(t *testing.T, material VerifiedTargetRegistrationMaterial, client *http.Client, now time.Time) *KubernetesTargetRegistrationLauncher {
	t.Helper()
	launcher, err := newKubernetesTargetRegistrationLauncher(targetRegistrationLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared",
		Client: client, Clock: func() time.Time { return now },
	}, material)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}

type targetRegistrationLauncherRequest struct {
	method string
	path   string
	body   []byte
}

type targetRegistrationLauncherAPI struct {
	t            *testing.T
	mu           sync.Mutex
	objects      map[string]map[string]any
	requests     []targetRegistrationLauncherRequest
	posts        int
	failPost     int
	errorPost    int
	mismatchPost int
}

func newTargetRegistrationLauncherAPI(t *testing.T) *targetRegistrationLauncherAPI {
	return &targetRegistrationLauncherAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *targetRegistrationLauncherAPI) client() *http.Client {
	return &http.Client{Transport: targetRegistrationRoundTripFunc(api.roundTrip)}
}

func (api *targetRegistrationLauncherAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, targetRegistrationLauncherRequest{method: request.Method, path: request.URL.Path, body: body})
	if request.Header.Get("Authorization") != "Bearer short-lived-gitops-token" {
		return targetRegistrationJSONResponse(http.StatusUnauthorized, map[string]any{"reason": "Unauthorized"}, nil), nil
	}
	if request.Method == http.MethodGet && request.Header.Get("Accept") != partialObjectMetadataAccept {
		return targetRegistrationJSONResponse(http.StatusNotAcceptable, map[string]any{"reason": "NotAcceptable"}, nil), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, exists := api.objects[request.URL.Path]
		if !exists {
			return targetRegistrationJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		return targetRegistrationJSONResponse(http.StatusOK, object, nil), nil
	case http.MethodPost:
		api.posts++
		if api.errorPost == api.posts {
			return nil, errors.New("simulated transport error")
		}
		if api.failPost == api.posts {
			return targetRegistrationJSONResponse(http.StatusForbidden, map[string]any{"reason": "Denied"}, nil), nil
		}
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			api.t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "created-target-registration-uid-" + string(rune('a'+api.posts-1))
		metadata["resourceVersion"] = string(rune('1' + api.posts - 1))
		path := request.URL.Path + "/" + metadata["name"].(string)
		api.objects[path] = object
		if api.mismatchPost == api.posts {
			metadata["name"] = "foreign-object"
		}
		return targetRegistrationJSONResponse(http.StatusCreated, object, nil), nil
	default:
		return targetRegistrationJSONResponse(http.StatusMethodNotAllowed, map[string]any{"reason": "MethodNotAllowed"}, nil), nil
	}
}

type targetRegistrationRoundTripFunc func(*http.Request) (*http.Response, error)

func (function targetRegistrationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func targetRegistrationJSONResponse(status int, value any, headers map[string]string) *http.Response {
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
