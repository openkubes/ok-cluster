package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestSubmissionStageRuntimeInstallerCreatesOrVerifiesExactServiceAccount(t *testing.T) {
	t.Run("create absent", func(t *testing.T) {
		prerequisite := submissionStageRuntimePrerequisite(t)
		api := newStageRuntimeInstallerAPI(t)
		installer := newStageRuntimeInstaller(t, prerequisite, api.client())
		receipt, err := installer.Ensure(context.Background())
		if err != nil || receipt.State != "READY" || receipt.MutationState != "ATTEMPTED" || receipt.ObjectState != "CREATED" || len(api.requests) != 2 || api.requests[0].method != http.MethodGet || api.requests[1].method != http.MethodPost || digest.SHA256(api.requests[1].body) != receipt.ObjectDigest {
			t.Fatalf("runtime creation differs: %#v requests=%#v err=%v", receipt, api.requests, err)
		}
		assertRuntimeReceiptRedacted(t, receipt)
	})

	t.Run("verify existing", func(t *testing.T) {
		prerequisite := submissionStageRuntimePrerequisite(t)
		api := newStageRuntimeInstallerAPI(t)
		api.objects[stageRuntimeObjectPath] = api.runtimeObject(prerequisite.raw, "existing-runtime-uid", "7")
		installer := newStageRuntimeInstaller(t, prerequisite, api.client())
		receipt, err := installer.Ensure(context.Background())
		if err != nil || receipt.State != "READY" || receipt.MutationState != "NOT_ATTEMPTED" || receipt.ObjectState != "EXISTING_VERIFIED" || len(api.requests) != 1 || api.posts != 0 {
			t.Fatalf("existing runtime verification differs: %#v requests=%#v err=%v", receipt, api.requests, err)
		}
		assertRuntimeReceiptRedacted(t, receipt)
	})
}

func TestSubmissionStageRuntimeInstallerStopsForDriftAndCannotRetry(t *testing.T) {
	prerequisite := submissionStageRuntimePrerequisite(t)
	api := newStageRuntimeInstallerAPI(t)
	drifted := api.runtimeObject(prerequisite.raw, "existing-runtime-uid", "7")
	drifted["automountServiceAccountToken"] = true
	api.objects[stageRuntimeObjectPath] = drifted
	installer := newStageRuntimeInstaller(t, prerequisite, api.client())
	receipt, err := installer.Ensure(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 {
		t.Fatalf("drifted runtime accepted: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	retry, retryErr := installer.Ensure(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("runtime installer retried: %#v %v", retry, retryErr)
	}
}

func TestSubmissionStageRuntimeInstallerRejectsAdditionalServiceAccountSemantics(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"image pull Secret": func(object map[string]any) {
			object["imagePullSecrets"] = []any{map[string]any{"name": "foreign"}}
		},
		"identity annotation": func(object map[string]any) {
			metadata := object["metadata"].(map[string]any)
			metadata["annotations"] = map[string]any{"example.invalid/identity": "foreign"}
		},
		"extra label": func(object map[string]any) {
			metadata := object["metadata"].(map[string]any)
			metadata["labels"].(map[string]any)["example.invalid/extra"] = "true"
		},
	} {
		t.Run(name, func(t *testing.T) {
			prerequisite := submissionStageRuntimePrerequisite(t)
			api := newStageRuntimeInstallerAPI(t)
			existing := api.runtimeObject(prerequisite.raw, "existing-runtime-uid", "7")
			mutate(existing)
			api.objects[stageRuntimeObjectPath] = existing
			installer := newStageRuntimeInstaller(t, prerequisite, api.client())
			receipt, err := installer.Ensure(context.Background())
			if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 {
				t.Fatalf("additional ServiceAccount semantics accepted: %#v %v", receipt, err)
			}
		})
	}
}

func TestSubmissionStageRuntimeInstallerTreatsUnknownCreateAsPartial(t *testing.T) {
	for name, configure := range map[string]func(*stageRuntimeInstallerAPI){
		"response mismatch": func(api *stageRuntimeInstallerAPI) { api.mismatch = true },
		"transport error":   func(api *stageRuntimeInstallerAPI) { api.transportError = true },
	} {
		t.Run(name, func(t *testing.T) {
			prerequisite := submissionStageRuntimePrerequisite(t)
			api := newStageRuntimeInstallerAPI(t)
			configure(api)
			installer := newStageRuntimeInstaller(t, prerequisite, api.client())
			receipt, err := installer.Ensure(context.Background())
			if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || strings.Contains(err.Error(), "short-lived-runtime-installer-token") {
				t.Fatalf("unknown runtime outcome accepted or leaked: %#v %v", receipt, err)
			}
		})
	}
}

func TestSubmissionStageRuntimePrerequisiteAndInstallerRejectTamperingOrForeignAuthority(t *testing.T) {
	prerequisite := submissionStageRuntimePrerequisite(t)
	tampered := prerequisite
	tampered.raw = append([]byte(nil), prerequisite.raw...)
	tampered.raw[0] = 'x'
	if _, err := newKubernetesSubmissionStageRuntimeInstaller(submissionStageRuntimeInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-runtime-installer-token", AuthorityIdentity: "ok-mgmt", Client: newStageRuntimeInstallerAPI(t).client(),
	}, tampered); err == nil {
		t.Fatal("tampered runtime prerequisite was accepted")
	}
	if _, err := newKubernetesSubmissionStageRuntimeInstaller(submissionStageRuntimeInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-runtime-installer-token", AuthorityIdentity: "ok-infra", Client: newStageRuntimeInstallerAPI(t).client(),
	}, prerequisite); err == nil {
		t.Fatal("foreign runtime installer authority was accepted")
	}

	manifest := submissionStageRuntimeManifest(t)
	changed := bytes.Replace(manifest, []byte("automountServiceAccountToken: false"), []byte("automountServiceAccountToken: true"), 1)
	stagePackage := submissionStageInstallerPackage(t)
	if _, err := BuildSubmissionStageRuntimePrerequisite(stagePackage, changed, digest.SHA256(changed)); err == nil {
		t.Fatal("token-bearing runtime prerequisite was accepted")
	}
}

func submissionStageRuntimePrerequisite(t *testing.T) VerifiedSubmissionStageRuntimePrerequisite {
	t.Helper()
	manifest := submissionStageRuntimeManifest(t)
	prerequisite, err := BuildSubmissionStageRuntimePrerequisite(submissionStageInstallerPackage(t), manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return prerequisite
}

func submissionStageRuntimeManifest(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve runtime prerequisite test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-stage-runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newStageRuntimeInstaller(t *testing.T, prerequisite VerifiedSubmissionStageRuntimePrerequisite, client *http.Client) *KubernetesSubmissionStageRuntimeInstaller {
	t.Helper()
	installer, err := newKubernetesSubmissionStageRuntimeInstaller(submissionStageRuntimeInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-runtime-installer-token", AuthorityIdentity: "ok-mgmt", Client: client,
	}, prerequisite)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}

func assertRuntimeReceiptRedacted(t *testing.T, receipt SubmissionStageRuntimeInstallationReceipt) {
	t.Helper()
	if receipt.Format != SubmissionStageRuntimeInstallationReceiptFormat || receipt.Authority != "ok-mgmt" || receipt.Namespace != submissionStageInputNamespace || receipt.Name != "ok147-contract-executor-runtime" || !stageReceiptPrefixDigestPattern.MatchString(receipt.StagePackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(receipt.ManifestDigest) || !stageReceiptPrefixDigestPattern.MatchString(receipt.ObjectDigest) || !stageReceiptPrefixDigestPattern.MatchString(receipt.UIDDigest) || !stageReceiptPrefixDigestPattern.MatchString(receipt.ResourceVersionDigest) {
		t.Fatalf("runtime receipt identity differs: %#v", receipt)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("short-lived-runtime-installer-token")) || bytes.Contains(raw, []byte("runtime-uid")) {
		t.Fatal("runtime receipt exposed credential or raw UID")
	}
}

const stageRuntimeObjectPath = "/api/v1/namespaces/openkubes-execution-system/serviceaccounts/ok147-contract-executor-runtime"

type stageRuntimeInstallerRequest struct {
	method string
	path   string
	body   []byte
}

type stageRuntimeInstallerAPI struct {
	t              *testing.T
	mu             sync.Mutex
	objects        map[string]map[string]any
	requests       []stageRuntimeInstallerRequest
	posts          int
	mismatch       bool
	transportError bool
}

func newStageRuntimeInstallerAPI(t *testing.T) *stageRuntimeInstallerAPI {
	return &stageRuntimeInstallerAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *stageRuntimeInstallerAPI) client() *http.Client {
	return &http.Client{Transport: stageRuntimeInstallerRoundTripFunc(api.roundTrip)}
}

func (api *stageRuntimeInstallerAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, stageRuntimeInstallerRequest{method: request.Method, path: request.URL.Path, body: body})
	if request.Header.Get("Authorization") != "Bearer short-lived-runtime-installer-token" {
		return stageRuntimeInstallerJSONResponse(http.StatusUnauthorized, map[string]any{"reason": "Unauthorized"}), nil
	}
	switch request.Method {
	case http.MethodGet:
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return stageRuntimeInstallerJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}), nil
		}
		return stageRuntimeInstallerJSONResponse(http.StatusOK, object), nil
	case http.MethodPost:
		api.posts++
		if api.transportError {
			return nil, errors.New("simulated transport failure")
		}
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			api.t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"], metadata["resourceVersion"] = "created-runtime-uid", "1"
		api.objects[stageRuntimeObjectPath] = object
		if api.mismatch {
			object["automountServiceAccountToken"] = true
		}
		return stageRuntimeInstallerJSONResponse(http.StatusCreated, object), nil
	default:
		return stageRuntimeInstallerJSONResponse(http.StatusMethodNotAllowed, map[string]any{"reason": "MethodNotAllowed"}), nil
	}
}

func (api *stageRuntimeInstallerAPI) runtimeObject(raw []byte, uid, resourceVersion string) map[string]any {
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		api.t.Fatal(err)
	}
	metadata := object["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = uid, resourceVersion
	return object
}

type stageRuntimeInstallerRoundTripFunc func(*http.Request) (*http.Response, error)

func (function stageRuntimeInstallerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func stageRuntimeInstallerJSONResponse(status int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(raw))}
}
