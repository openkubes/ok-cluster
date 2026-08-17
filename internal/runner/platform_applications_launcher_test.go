package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlatformApplicationsLauncherPreflightsThenCreatesExactApplications(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, err := LoadPlatformApplicationsStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	api := newPlatformApplicationsLauncherAPI(t)
	launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
	receipt, err := launcher.Install(context.Background())
	if err != nil || receipt.State != "INSTALLED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 3 {
		t.Fatalf("platform Applications launch failed: %#v %v", receipt, err)
	}
	if receipt.Format != PlatformApplicationsLaunchReceiptFormat || receipt.StageID != "platform-applications" || receipt.PlanDigest != bundle.receipt.PlanDigest || receipt.ArtifactDigest != bundle.receipt.ArtifactDigest || receipt.TargetIdentityDigest != bundle.receipt.TargetIdentityDigest || receipt.ProfileDigest != bundle.receipt.ProfileDigest || receipt.Authority != "ok-shared" {
		t.Fatalf("unexpected platform Applications receipt: %#v", receipt)
	}
	if len(api.requests) != 6 {
		t.Fatalf("requests=%d, want three GETs then three POSTs", len(api.requests))
	}
	for index, object := range launcher.objects {
		preflight, submission := api.requests[index], api.requests[index+3]
		if preflight.method != http.MethodGet || preflight.path != object.objectPath || len(preflight.body) != 0 || submission.method != http.MethodPost || submission.path != object.collectionPath || digest.SHA256(submission.body) != object.digest {
			t.Fatalf("request %d differs from exact Application", index)
		}
		result := receipt.Results[index]
		if result.Order != index+1 || result.Phase != "platform-application" || result.APIVersion != object.apiVersion || result.Kind != object.kind || result.Namespace != object.namespace || result.Name != object.name || result.ObjectDigest != object.digest || result.ObjectState != "CREATED" || !stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			t.Fatalf("result %d differs: %#v", index, result)
		}
	}
}

func TestPlatformApplicationsLauncherStopsZeroWriteForExistingApplication(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	api := newPlatformApplicationsLauncherAPI(t)
	launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
	api.objects[launcher.objects[1].objectPath] = map[string]any{"kind": "Application"}
	receipt, err := launcher.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 2 {
		t.Fatalf("existing Application did not stop before writes: %#v requests=%d err=%v", receipt, len(api.requests), err)
	}
}

func TestPlatformApplicationsLauncherPreservesPartialStateAndCannotRetry(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	api := newPlatformApplicationsLauncherAPI(t)
	api.failPost = 2
	launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
	receipt, err := launcher.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 1 {
		t.Fatalf("partial state differs: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	retry, retryErr := launcher.Install(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("single-use launcher retried: %#v %v", retry, retryErr)
	}
}

func TestPlatformApplicationsLauncherFailsClosedForTamperingUnknownOutcomeAndRedirect(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	tampered := bundle
	tampered.projection.Applications[0].Raw[0] ^= 1
	if _, err := newKubernetesPlatformApplicationsLauncher(platformApplicationsLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared", Client: newPlatformApplicationsLauncherAPI(t).client(),
	}, tampered); err == nil {
		t.Fatal("tampered platform Applications bundle opened launcher")
	}
	bundle, _ = LoadPlatformApplicationsStageBundle(fixture.config)

	api := newPlatformApplicationsLauncherAPI(t)
	api.errorPost = 1
	launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
	receipt, err := launcher.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 0 || strings.Contains(err.Error(), "short-lived-gitops-token") {
		t.Fatalf("unknown outcome accepted or leaked: %#v %v", receipt, err)
	}

	calls := 0
	redirect := &http.Client{Transport: targetRegistrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return targetRegistrationJSONResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/foreign"}), nil
	})}
	launcher = newPlatformApplicationsLauncher(t, bundle, redirect)
	receipt, err = launcher.Install(context.Background())
	if err == nil || calls != 1 || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("redirect followed or accepted: calls=%d receipt=%#v err=%v", calls, receipt, err)
	}
}

func newPlatformApplicationsLauncher(t *testing.T, bundle VerifiedPlatformApplicationsStageBundle, client *http.Client) *KubernetesPlatformApplicationsLauncher {
	t.Helper()
	launcher, err := newKubernetesPlatformApplicationsLauncher(platformApplicationsLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared", Client: client,
	}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}

type platformApplicationsLauncherRequest struct {
	method string
	path   string
	body   []byte
}

type platformApplicationsLauncherAPI struct {
	t         *testing.T
	mu        sync.Mutex
	objects   map[string]map[string]any
	requests  []platformApplicationsLauncherRequest
	posts     int
	failPost  int
	errorPost int
}

func newPlatformApplicationsLauncherAPI(t *testing.T) *platformApplicationsLauncherAPI {
	return &platformApplicationsLauncherAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *platformApplicationsLauncherAPI) client() *http.Client {
	return &http.Client{Transport: targetRegistrationRoundTripFunc(api.roundTrip)}
}

func (api *platformApplicationsLauncherAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, platformApplicationsLauncherRequest{method: request.Method, path: request.URL.Path, body: body})
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
		metadata["uid"] = "created-platform-application-uid-" + string(rune('a'+api.posts-1))
		metadata["resourceVersion"] = string(rune('1' + api.posts - 1))
		path := request.URL.Path + "/" + metadata["name"].(string)
		api.objects[path] = object
		return targetRegistrationJSONResponse(http.StatusCreated, object, nil), nil
	default:
		return targetRegistrationJSONResponse(http.StatusMethodNotAllowed, map[string]any{"reason": "MethodNotAllowed"}, nil), nil
	}
}
