package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTargetRegistrationRefresherReplacesOnlyExactBoundSecret(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, err := BuildTargetRegistrationMaterial(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	api := newTargetRegistrationRefreshAPI(t, material)
	refresher, err := newKubernetesTargetRegistrationRefresher(targetRegistrationLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared",
		Client: api.client(), Clock: func() time.Time { return fixture.config.MaterializationTime.Add(time.Minute) },
	}, material)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := refresher.Refresh(context.Background())
	if err != nil || receipt.State != "REFRESHED" || receipt.MutationState != "ATTEMPTED" || !receipt.StaticRegistrationPreserved ||
		receipt.CredentialBytesInReceipt || receipt.ProjectUIDDigest == "" || receipt.RegistrationUIDDigest == "" || receipt.ResourceVersionDigest == "" {
		t.Fatalf("target-registration refresh failed: %#v %v", receipt, err)
	}
	want := []string{"GET project", "GET registration", "PUT registration"}
	if got := api.requestSummary(); !equalStringSlices(got, want) {
		t.Fatalf("refresh request boundary differs: got=%v want=%v", got, want)
	}
	public, _ := json.Marshal(receipt)
	for _, forbidden := range []string{string(fixture.credential.token), fixture.credential.endpoint, "old-target-token"} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("refresh receipt leaked private value %q", forbidden)
		}
	}
	if _, err := refresher.Refresh(context.Background()); err == nil || len(api.requestSummary()) != 3 {
		t.Fatal("single-use target-registration refresher ran twice")
	}
}

func TestTargetRegistrationRefresherStopsBeforeWriteOnDrift(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"project drift": func(objects map[string]any) {
			project := objects["project"].(map[string]any)
			project["spec"].(map[string]any)["description"] = "foreign"
		},
		"target drift": func(objects map[string]any) {
			secret := objects["registration"].(map[string]any)
			data := secret["data"].(map[string]any)
			data["server"] = base64.StdEncoding.EncodeToString([]byte("https://foreign.invalid"))
		},
		"metadata drift": func(objects map[string]any) {
			secret := objects["registration"].(map[string]any)
			secret["metadata"].(map[string]any)["annotations"].(map[string]any)["foreign"] = "value"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := targetRegistrationMaterialFixture(t)
			material, _ := BuildTargetRegistrationMaterial(fixture.config)
			api := newTargetRegistrationRefreshAPI(t, material)
			mutate(api.objects)
			refresher, err := newKubernetesTargetRegistrationRefresher(targetRegistrationLauncherClientConfig{
				Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared",
				Client: api.client(), Clock: func() time.Time { return fixture.config.MaterializationTime.Add(time.Minute) },
			}, material)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := refresher.Refresh(context.Background())
			if err == nil || receipt.MutationState != "NOT_ATTEMPTED" || api.puts != 0 {
				t.Fatalf("drift reached registration replacement: %#v puts=%d err=%v", receipt, api.puts, err)
			}
		})
	}
}

func TestTargetRegistrationRefresherPreservesUnknownPutOutcome(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, _ := BuildTargetRegistrationMaterial(fixture.config)
	api := newTargetRegistrationRefreshAPI(t, material)
	api.failPut = true
	refresher, err := newKubernetesTargetRegistrationRefresher(targetRegistrationLauncherClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "short-lived-gitops-token", AuthorityIdentity: "ok-shared",
		Client: api.client(), Clock: func() time.Time { return fixture.config.MaterializationTime.Add(time.Minute) },
	}, material)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := refresher.Refresh(context.Background())
	if err == nil || receipt.State != "REPLACING" || receipt.MutationState != "UNKNOWN" || api.puts != 1 {
		t.Fatalf("unknown replacement outcome was not preserved: %#v %v", receipt, err)
	}
}

type targetRegistrationRefreshAPI struct {
	t        *testing.T
	mu       sync.Mutex
	objects  map[string]any
	requests []string
	puts     int
	failPut  bool
}

func newTargetRegistrationRefreshAPI(t *testing.T, material VerifiedTargetRegistrationMaterial) *targetRegistrationRefreshAPI {
	t.Helper()
	project := decodeRefreshObject(t, material.project)
	projectMetadata := project["metadata"].(map[string]any)
	projectMetadata["uid"], projectMetadata["resourceVersion"] = "project-runtime-uid", "7"
	registration := decodeRefreshObject(t, material.registration)
	registrationMetadata := registration["metadata"].(map[string]any)
	registrationMetadata["uid"], registrationMetadata["resourceVersion"] = "registration-runtime-uid", "11"
	stringData := registration["stringData"].(map[string]any)
	var config targetRegistrationSecretConfig
	if err := json.Unmarshal([]byte(stringData["config"].(string)), &config); err != nil {
		t.Fatal(err)
	}
	config.BearerToken = strings.Repeat("old-target-token-", 8)
	configRaw, _ := json.Marshal(config)
	stringData["config"] = string(configRaw)
	registration["data"] = encodeRefreshData(t, stringData)
	delete(registration, "stringData")
	return &targetRegistrationRefreshAPI{t: t, objects: map[string]any{"project": project, "registration": registration}}
}

func (api *targetRegistrationRefreshAPI) client() *http.Client {
	return &http.Client{Transport: targetRegistrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		api.mu.Lock()
		defer api.mu.Unlock()
		if request.Header.Get("Authorization") != "Bearer short-lived-gitops-token" || request.Header.Get("Accept") != "application/json" {
			return targetRegistrationJSONResponse(http.StatusUnauthorized, nil, nil), nil
		}
		switch request.Method {
		case http.MethodGet:
			if strings.Contains(request.URL.Path, "appprojects") {
				api.requests = append(api.requests, "GET project")
				return targetRegistrationJSONResponse(http.StatusOK, api.objects["project"], nil), nil
			}
			api.requests = append(api.requests, "GET registration")
			return targetRegistrationJSONResponse(http.StatusOK, api.objects["registration"], nil), nil
		case http.MethodPut:
			api.requests = append(api.requests, "PUT registration")
			api.puts++
			if api.failPut {
				return nil, errors.New("simulated unknown PUT outcome")
			}
			body, _ := io.ReadAll(request.Body)
			updated := decodeRefreshObject(api.t, body)
			metadata := updated["metadata"].(map[string]any)
			if metadata["uid"] != "registration-runtime-uid" || metadata["resourceVersion"] != "11" {
				return targetRegistrationJSONResponse(http.StatusConflict, nil, nil), nil
			}
			updated["data"] = encodeRefreshData(api.t, updated["stringData"].(map[string]any))
			delete(updated, "stringData")
			metadata["resourceVersion"] = "12"
			api.objects["registration"] = updated
			return targetRegistrationJSONResponse(http.StatusOK, updated, nil), nil
		default:
			return targetRegistrationJSONResponse(http.StatusMethodNotAllowed, nil, nil), nil
		}
	})}
}

func (api *targetRegistrationRefreshAPI) requestSummary() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func decodeRefreshObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func encodeRefreshData(t *testing.T, values map[string]any) map[string]any {
	t.Helper()
	encoded := make(map[string]any, len(values))
	for key, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("non-string Secret value %s", key)
		}
		encoded[key] = base64.StdEncoding.EncodeToString([]byte(text))
	}
	return encoded
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
