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

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestSubmissionStageInstallerPreflightsAllObjectsThenCreatesExactOrder(t *testing.T) {
	packaged := submissionStageInstallerPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	installer := newSubmissionStageInstaller(t, packaged, api.client())
	receipt, err := installer.Install(context.Background())
	if err != nil || receipt.State != "INSTALLED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 3 {
		t.Fatalf("stage package installation failed: %#v %v", receipt, err)
	}
	plan, err := PlanSubmissionStageInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != SubmissionStageInstallationReceiptFormat || receipt.PackageDigest != plan.PackageDigest || receipt.StageID != plan.StageID || receipt.Authority != "ok-mgmt" {
		t.Fatalf("installation receipt identity differs: %#v", receipt)
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(receiptJSON, []byte("created-stage-uid")) || bytes.Contains(receiptJSON, []byte("short-lived-installer-token")) {
		t.Fatal("installation receipt exposed raw runtime identity or credential")
	}
	if len(api.requests) != 6 {
		t.Fatalf("requests=%d, want three GETs then three POSTs: %#v", len(api.requests), api.requests)
	}
	for index, create := range plan.Creates {
		preflight, submission := api.requests[index], api.requests[index+3]
		if preflight.method != http.MethodGet || preflight.path != create.ObjectPath || len(preflight.body) != 0 {
			t.Fatalf("preflight %d differs: %#v", index, preflight)
		}
		if submission.method != http.MethodPost || submission.path != create.CollectionPath || len(submission.body) == 0 {
			t.Fatalf("create %d differs: %#v", index, submission)
		}
		if digest.SHA256(submission.body) != create.ObjectDigest {
			t.Fatalf("create body %d differs from verified object digest", index)
		}
		result := receipt.Results[index]
		if result.Order != create.Order || result.Kind != create.Kind || result.Name != create.Name || result.ObjectDigest != create.ObjectDigest || result.State != "CREATED" || !stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			t.Fatalf("result %d differs: %#v", index, result)
		}
		if strings.Contains(strings.ToLower(preflight.path+submission.path), "secret") {
			t.Fatalf("installer accessed credential object: %#v %#v", preflight, submission)
		}
	}
}

func TestSubmissionStageInstallerStopsZeroWriteWhenAnyObjectExists(t *testing.T) {
	packaged := submissionStageInstallerPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	plan, err := PlanSubmissionStageInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	api.objects[plan.Creates[2].ObjectPath] = map[string]any{"kind": "Job"}
	installer := newSubmissionStageInstaller(t, packaged, api.client())
	receipt, err := installer.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(receipt.Results) != 0 || api.posts != 0 {
		t.Fatalf("existing object did not stop zero-write: %#v posts=%d err=%v", receipt, api.posts, err)
	}
	if len(api.requests) != 3 {
		t.Fatalf("preflight did not reach bound existing object: %#v", api.requests)
	}
	for _, request := range api.requests {
		if request.method != http.MethodGet {
			t.Fatalf("write observed in failed preflight: %#v", request)
		}
	}
}

func TestSubmissionStageInstallerPreservesPartialPrefixAndCannotRetry(t *testing.T) {
	packaged := submissionStageInstallerPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	api.failPost = 2
	installer := newSubmissionStageInstaller(t, packaged, api.client())
	receipt, err := installer.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 1 || receipt.Results[0].Kind != "ConfigMap" {
		t.Fatalf("partial prefix differs: %#v %v", receipt, err)
	}
	requestCount := len(api.requests)
	retry, retryErr := installer.Install(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || retry.MutationState != "NOT_ATTEMPTED" || len(api.requests) != requestCount {
		t.Fatalf("single-use boundary failed: %#v requests=%d/%d err=%v", retry, len(api.requests), requestCount, retryErr)
	}
}

func TestSubmissionStageInstallerTreatsUnverifiedResponseAndTransportFailureAsUnknown(t *testing.T) {
	for name, configure := range map[string]func(*submissionStageInstallerAPI){
		"response identity differs": func(api *submissionStageInstallerAPI) { api.mismatchPost = 1 },
		"transport outcome unknown": func(api *submissionStageInstallerAPI) { api.errorPost = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			packaged := submissionStageInstallerPackage(t)
			api := newSubmissionStageInstallerAPI(t)
			configure(api)
			installer := newSubmissionStageInstaller(t, packaged, api.client())
			receipt, err := installer.Install(context.Background())
			if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 0 {
				t.Fatalf("unknown outcome accepted: %#v %v", receipt, err)
			}
			if strings.Contains(err.Error(), "short-lived-installer-token") {
				t.Fatal("installer error exposed bearer token")
			}
		})
	}
}

func TestSubmissionStageInstallerRejectsForeignAuthorityTamperingAndRedirect(t *testing.T) {
	packaged := submissionStageInstallerPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	if _, err := newKubernetesSubmissionStagePackageInstaller(submissionStageInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-infra", Client: api.client(),
	}, packaged); err == nil || len(api.requests) != 0 {
		t.Fatal("foreign installer authority was accepted")
	}

	tampered := packaged
	tampered.raw = append([]byte(nil), packaged.raw...)
	tampered.raw[0] = 'x'
	if _, err := newKubernetesSubmissionStagePackageInstaller(submissionStageInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: api.client(),
	}, tampered); err == nil || len(api.requests) != 0 {
		t.Fatal("tampered package reached credentials or API")
	}

	calls := 0
	redirectClient := &http.Client{Transport: stageInstallerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return stageInstallerJSONResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/foreign"}), nil
	})}
	installer := newSubmissionStageInstaller(t, packaged, redirectClient)
	receipt, err := installer.Install(context.Background())
	if err == nil || calls != 1 || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("redirect followed or accepted: calls=%d receipt=%#v err=%v", calls, receipt, err)
	}
}

func TestSubmissionStageInstallerRejectsNonIPOrUnboundedEndpoint(t *testing.T) {
	packaged := submissionStageInstallerPackage(t)
	for _, endpoint := range []string{
		"https://ok-mgmt.example:6443", "https://192.0.2.10", "https://192.0.2.10:6443/path",
		"https://user@192.0.2.10:6443", "https://192.0.2.10:6443?x=1", "http://192.0.2.10:6443",
	} {
		if _, err := newKubernetesSubmissionStagePackageInstaller(submissionStageInstallerClientConfig{
			Endpoint: endpoint, BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: &http.Client{},
		}, packaged); err == nil {
			t.Fatalf("unbounded endpoint accepted: %s", endpoint)
		}
	}
}

func submissionStageInstallerPackage(t *testing.T) VerifiedSubmissionStagePackage {
	t.Helper()
	fixture := submissionBundleFixture(t, false, "")
	packaged, err := BuildSubmissionStagePackage(submissionStagePackageConfig(t, fixture, "provider-prerequisites"))
	if err != nil {
		t.Fatal(err)
	}
	return packaged
}

func newSubmissionStageInstaller(t *testing.T, packaged VerifiedSubmissionStagePackage, client *http.Client) *KubernetesSubmissionStagePackageInstaller {
	t.Helper()
	installer, err := newKubernetesSubmissionStagePackageInstaller(submissionStageInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: client,
	}, packaged)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}

type submissionStageInstallerRequest struct {
	method string
	path   string
	body   []byte
}

type submissionStageInstallerAPI struct {
	t            *testing.T
	mu           sync.Mutex
	objects      map[string]map[string]any
	requests     []submissionStageInstallerRequest
	posts        int
	failPost     int
	mismatchPost int
	errorPost    int
}

func newSubmissionStageInstallerAPI(t *testing.T) *submissionStageInstallerAPI {
	return &submissionStageInstallerAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *submissionStageInstallerAPI) client() *http.Client {
	return &http.Client{Transport: stageInstallerRoundTripFunc(api.roundTrip)}
}

func (api *submissionStageInstallerAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, submissionStageInstallerRequest{method: request.Method, path: request.URL.Path, body: body})
	if request.Header.Get("Authorization") != "Bearer short-lived-installer-token" {
		return stageInstallerJSONResponse(http.StatusUnauthorized, map[string]any{"reason": "Unauthorized"}, nil), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return stageInstallerJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		return stageInstallerJSONResponse(http.StatusOK, object, nil), nil
	case http.MethodPost:
		api.posts++
		if api.errorPost == api.posts {
			return nil, errors.New("simulated transport failure")
		}
		if api.failPost == api.posts {
			return stageInstallerJSONResponse(http.StatusForbidden, map[string]any{"reason": "Denied"}, nil), nil
		}
		var object map[string]any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			api.t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "created-stage-uid-" + string(rune('a'+api.posts-1))
		metadata["resourceVersion"] = string(rune('1' + api.posts - 1))
		path := request.URL.Path + "/" + metadata["name"].(string)
		api.objects[path] = object
		if api.mismatchPost == api.posts {
			metadata["name"] = "foreign-object"
		}
		return stageInstallerJSONResponse(http.StatusCreated, object, nil), nil
	default:
		return stageInstallerJSONResponse(http.StatusMethodNotAllowed, map[string]any{"reason": "MethodNotAllowed"}, nil), nil
	}
}

type stageInstallerRoundTripFunc func(*http.Request) (*http.Response, error)

func (function stageInstallerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func stageInstallerJSONResponse(status int, value any, headers map[string]string) *http.Response {
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
