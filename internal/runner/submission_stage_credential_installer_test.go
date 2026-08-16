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

func TestSubmissionStageCredentialInstallerPreflightsThenCreatesExactSecrets(t *testing.T) {
	packaged, _, _ := submissionStageCredentialInstallerPackage(t)
	api := newStageCredentialInstallerAPI(t)
	installer := newStageCredentialInstaller(t, packaged, api.client(), time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC), "short-lived-installer-token")
	receipt, err := installer.Install(context.Background())
	if err != nil || receipt.State != "INSTALLED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 2 {
		t.Fatalf("credential installation failed: %#v %v", receipt, err)
	}
	credentialReceipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != SubmissionStageCredentialInstallationReceiptFormat || receipt.StageID != credentialReceipt.StageID || receipt.StagePackageDigest != credentialReceipt.StagePackageDigest || receipt.CredentialPackageDigest != credentialReceipt.PackageDigest || receipt.Authority != "ok-mgmt" {
		t.Fatalf("credential installation receipt identity differs: %#v", receipt)
	}
	if len(api.requests) != 4 {
		t.Fatalf("requests=%d, want two GETs then two POSTs", len(api.requests))
	}
	for index, object := range installer.objects {
		preflight, submission := api.requests[index], api.requests[index+2]
		if preflight.method != http.MethodGet || preflight.path != object.objectPath || len(preflight.body) != 0 || submission.method != http.MethodPost || submission.path != object.collectionPath || digest.SHA256(submission.body) != object.objectDigest {
			t.Fatalf("credential request %d differs from binding", index)
		}
		result := receipt.Results[index]
		if result.Order != index+1 || result.Role != object.role || result.Authority != object.authority || result.Name != object.name || result.ObjectDigest != object.objectDigest || result.State != "CREATED" || !stageReceiptPrefixDigestPattern.MatchString(result.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(result.ResourceVersionDigest) {
			t.Fatalf("credential result %d differs: %#v", index, result)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"short-lived-installer-token", "created-secret-uid", string(installer.objects[0].token), string(installer.objects[1].token)} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("credential installation receipt exposed %q", forbidden)
		}
	}
}

func TestSubmissionStageCredentialInstallerStopsZeroWriteForExistingOrStaleCredentials(t *testing.T) {
	t.Run("existing second Secret", func(t *testing.T) {
		packaged, _, _ := submissionStageCredentialInstallerPackage(t)
		api := newStageCredentialInstallerAPI(t)
		installer := newStageCredentialInstaller(t, packaged, api.client(), time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC), "short-lived-installer-token")
		api.objects[installer.objects[1].objectPath] = map[string]any{"kind": "Secret"}
		receipt, err := installer.Install(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 2 {
			t.Fatalf("existing Secret did not stop zero-write: %#v posts=%d requests=%d err=%v", receipt, api.posts, len(api.requests), err)
		}
	})

	t.Run("insufficient remaining lifetime", func(t *testing.T) {
		packaged, _, _ := submissionStageCredentialInstallerPackage(t)
		api := newStageCredentialInstallerAPI(t)
		installer := newStageCredentialInstaller(t, packaged, api.client(), time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC), "short-lived-installer-token")
		receipt, err := installer.Install(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
			t.Fatalf("stale credential reached API: %#v requests=%d err=%v", receipt, len(api.requests), err)
		}
	})
}

func TestSubmissionStageCredentialInstallerPreservesPartialPrefixAndCannotRetry(t *testing.T) {
	packaged, _, _ := submissionStageCredentialInstallerPackage(t)
	api := newStageCredentialInstallerAPI(t)
	api.failPost = 2
	installer := newStageCredentialInstaller(t, packaged, api.client(), time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC), "short-lived-installer-token")
	receipt, err := installer.Install(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 1 || receipt.Results[0].Role != "ledger" {
		t.Fatalf("partial credential prefix differs: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	retry, retryErr := installer.Install(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("credential installer retried: %#v %v", retry, retryErr)
	}
}

func TestSubmissionStageCredentialInstallerRejectsSharedCredentialTamperingAndRedirect(t *testing.T) {
	packaged, ledgerToken, _ := submissionStageCredentialInstallerPackage(t)
	api := newStageCredentialInstallerAPI(t)
	if _, err := newKubernetesSubmissionStageCredentialInstaller(submissionStageCredentialInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: string(ledgerToken), AuthorityIdentity: "ok-mgmt", Client: api.client(), Clock: time.Now,
	}, packaged); err == nil || len(api.requests) != 0 {
		t.Fatal("Job credential was accepted as installer credential")
	}

	tampered := packaged
	tampered.objects = cloneStageCredentialObjects(packaged.objects)
	tampered.objects[0].raw[0] = 'x'
	if _, err := newKubernetesSubmissionStageCredentialInstaller(submissionStageCredentialInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: api.client(), Clock: time.Now,
	}, tampered); err == nil || len(api.requests) != 0 {
		t.Fatal("tampered credential package reached API")
	}

	calls := 0
	redirect := &http.Client{Transport: stageCredentialInstallerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return stageCredentialInstallerJSONResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/foreign"}), nil
	})}
	installer := newStageCredentialInstaller(t, packaged, redirect, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC), "short-lived-installer-token")
	receipt, err := installer.Install(context.Background())
	if err == nil || calls != 1 || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("redirect followed or accepted: calls=%d receipt=%#v err=%v", calls, receipt, err)
	}
}

func TestSubmissionStageCredentialInstallerTreatsResponseMismatchAndTransportAsUnknown(t *testing.T) {
	for name, configure := range map[string]func(*stageCredentialInstallerAPI){
		"response mismatch": func(api *stageCredentialInstallerAPI) { api.mismatchPost = 1 },
		"transport error":   func(api *stageCredentialInstallerAPI) { api.errorPost = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			packaged, _, _ := submissionStageCredentialInstallerPackage(t)
			api := newStageCredentialInstallerAPI(t)
			configure(api)
			installer := newStageCredentialInstaller(t, packaged, api.client(), time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC), "short-lived-installer-token")
			receipt, err := installer.Install(context.Background())
			if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 0 || strings.Contains(err.Error(), "short-lived-installer-token") {
				t.Fatalf("unknown credential outcome accepted or leaked: %#v %v", receipt, err)
			}
		})
	}
}

func submissionStageCredentialInstallerPackage(t *testing.T) (VerifiedSubmissionStageCredentialPackage, []byte, []byte) {
	t.Helper()
	config, ledgerToken, authorityToken := submissionStageCredentialConfig(t)
	packaged, err := BuildSubmissionStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	return packaged, ledgerToken, authorityToken
}

func newStageCredentialInstaller(t *testing.T, packaged VerifiedSubmissionStageCredentialPackage, client *http.Client, now time.Time, token string) *KubernetesSubmissionStageCredentialInstaller {
	t.Helper()
	installer, err := newKubernetesSubmissionStageCredentialInstaller(submissionStageCredentialInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: token, AuthorityIdentity: "ok-mgmt", Client: client,
		Clock: func() time.Time { return now },
	}, packaged)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}

type stageCredentialInstallerRequest struct {
	method string
	path   string
	body   []byte
}

type stageCredentialInstallerAPI struct {
	t            *testing.T
	mu           sync.Mutex
	objects      map[string]map[string]any
	requests     []stageCredentialInstallerRequest
	posts        int
	failPost     int
	mismatchPost int
	errorPost    int
}

func newStageCredentialInstallerAPI(t *testing.T) *stageCredentialInstallerAPI {
	return &stageCredentialInstallerAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *stageCredentialInstallerAPI) client() *http.Client {
	return &http.Client{Transport: stageCredentialInstallerRoundTripFunc(api.roundTrip)}
}

func (api *stageCredentialInstallerAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, stageCredentialInstallerRequest{method: request.Method, path: request.URL.Path, body: body})
	if request.Header.Get("Authorization") != "Bearer short-lived-installer-token" {
		return stageCredentialInstallerJSONResponse(http.StatusUnauthorized, map[string]any{"reason": "Unauthorized"}, nil), nil
	}
	if request.Method == http.MethodGet && request.Header.Get("Accept") != partialObjectMetadataAccept {
		return stageCredentialInstallerJSONResponse(http.StatusNotAcceptable, map[string]any{"reason": "NotAcceptable"}, nil), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return stageCredentialInstallerJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		return stageCredentialInstallerJSONResponse(http.StatusOK, object, nil), nil
	case http.MethodPost:
		api.posts++
		if api.errorPost == api.posts {
			return nil, errors.New("simulated transport error")
		}
		if api.failPost == api.posts {
			return stageCredentialInstallerJSONResponse(http.StatusForbidden, map[string]any{"reason": "Denied"}, nil), nil
		}
		var secret map[string]any
		if err := json.Unmarshal(body, &secret); err != nil {
			api.t.Fatal(err)
		}
		metadata := secret["metadata"].(map[string]any)
		metadata["uid"] = "created-secret-uid-" + string(rune('a'+api.posts-1))
		metadata["resourceVersion"] = string(rune('1' + api.posts - 1))
		path := request.URL.Path + "/" + metadata["name"].(string)
		api.objects[path] = secret
		if api.mismatchPost == api.posts {
			metadata["name"] = "foreign-secret"
		}
		return stageCredentialInstallerJSONResponse(http.StatusCreated, secret, nil), nil
	default:
		return stageCredentialInstallerJSONResponse(http.StatusMethodNotAllowed, map[string]any{"reason": "MethodNotAllowed"}, nil), nil
	}
}

type stageCredentialInstallerRoundTripFunc func(*http.Request) (*http.Response, error)

func (function stageCredentialInstallerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func stageCredentialInstallerJSONResponse(status int, value any, headers map[string]string) *http.Response {
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
