package observation

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestKubernetesPlatformReaderAllowsOnlyExactApplications(t *testing.T) {
	_, profile, _ := validPlatformFixture(t)
	requests := []string{}
	client := &http.Client{Transport: platformRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer short-lived-token" || request.Header.Get("Accept") != "application/json" {
			t.Error("bounded platform request headers differ")
		}
		return platformResponse(http.StatusOK, "application/json", `{}`), nil
	})}
	reader, err := NewKubernetesPlatformReader(KubernetesPlatformReaderConfig{
		Endpoint: "https://ok-shared.example.invalid", BearerToken: "short-lived-token", Client: client,
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, application := range profile.RequiredApplications {
		path := platformApplicationPath(profile.ArgoNamespace, application.Name)
		if _, err := reader.Get(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	if len(requests) != len(profile.RequiredApplications) {
		t.Fatalf("unexpected request count: %v", requests)
	}
	for _, path := range []string{
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications",
		platformApplicationPath(profile.ArgoNamespace, profile.RequiredApplications[0].Name) + "?watch=true",
		"/api/v1/secrets",
	} {
		if _, err := reader.Get(context.Background(), path); err == nil {
			t.Fatalf("path outside exact Application allowlist accepted: %s", path)
		}
	}
	if len(requests) != len(profile.RequiredApplications) {
		t.Fatal("forbidden platform path reached the server")
	}
}

func TestKubernetesPlatformReaderFailsClosedOnTransportShape(t *testing.T) {
	_, profile, _ := validPlatformFixture(t)
	path := platformApplicationPath(profile.ArgoNamespace, profile.RequiredApplications[0].Name)
	for name, response := range map[string]*http.Response{
		"redirect":  platformResponse(http.StatusFound, "application/json", `{}`),
		"non json":  platformResponse(http.StatusOK, "text/plain", `{}`),
		"oversized": platformResponse(http.StatusOK, "application/json", strings.Repeat("x", maximumPlatformSourceBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: platformRoundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil })}
			reader, err := NewKubernetesPlatformReader(KubernetesPlatformReaderConfig{Endpoint: "https://ok-shared.example.invalid", BearerToken: "token", Client: client}, profile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Get(context.Background(), path); err == nil {
				t.Fatal("unsafe platform transport response accepted")
			}
		})
	}
}

type platformRoundTripFunc func(*http.Request) (*http.Response, error)

func (function platformRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func platformResponse(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestNewKubernetesPlatformReaderRejectsUnsafeConfiguration(t *testing.T) {
	_, profile, _ := validPlatformFixture(t)
	client := &http.Client{}
	for name, config := range map[string]KubernetesPlatformReaderConfig{
		"plaintext":      {Endpoint: "http://10.0.0.1:6443", BearerToken: "token", Client: client},
		"endpoint path":  {Endpoint: "https://10.0.0.1:6443/api", BearerToken: "token", Client: client},
		"token newline":  {Endpoint: "https://10.0.0.1:6443", BearerToken: "token\n", Client: client},
		"missing client": {Endpoint: "https://10.0.0.1:6443", BearerToken: "token"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewKubernetesPlatformReader(config, profile); err == nil {
				t.Fatal("unsafe platform reader configuration accepted")
			}
		})
	}
}
