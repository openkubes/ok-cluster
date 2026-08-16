package observation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestKubernetesManagementNetworkReaderUsesExactAllowlist(t *testing.T) {
	wantHCP, wantHRP := managementNetworkPaths("disposable-ok141", "disposable-ok141", "disposable-ok141-cilium")
	var requests []string
	client := &http.Client{Transport: networkRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.URL.RequestURI())
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer management-token" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unbounded management request: %s %#v", request.Method, request.Header)
		}
		return networkJSONResponse(http.StatusOK, `{}`), nil
	})}
	reader, err := NewKubernetesManagementNetworkReader(KubernetesNetworkReaderConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "management-token", Client: client,
	}, "disposable-ok141", "disposable-ok141", "disposable-ok141-cilium")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{wantHCP, wantHRP} {
		if _, err := reader.Get(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reader.Get(context.Background(), "/api/v1/nodes"); err == nil {
		t.Fatal("management reader accepted a workload or arbitrary path")
	}
	if !reflect.DeepEqual(requests, []string{wantHCP, wantHRP}) {
		t.Fatalf("management request boundary differs: %#v", requests)
	}
}

func TestKubernetesWorkloadNetworkReaderUsesExactAllowlist(t *testing.T) {
	var requests []string
	client := &http.Client{Transport: networkRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer workload-token" {
			t.Fatal("workload credential was not isolated")
		}
		return networkJSONResponse(http.StatusOK, `{}`), nil
	})}
	reader, err := NewKubernetesWorkloadNetworkReader(KubernetesNetworkReaderConfig{
		Endpoint: "http://127.0.0.1:23456", BearerToken: "workload-token", Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := workloadNetworkPaths()
	for _, path := range want {
		if _, err := reader.Get(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reader.Get(context.Background(), "/api/v1/secrets"); err == nil {
		t.Fatal("workload reader accepted a Secret or arbitrary path")
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("workload request boundary differs: %#v", requests)
	}
}

func TestKubernetesNetworkReaderFailsClosedAndRedacts(t *testing.T) {
	for name, client := range map[string]*http.Client{
		"transport error": {Transport: networkRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("sensitive endpoint and token")
		})},
		"redirect": {Transport: networkRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return networkJSONResponse(http.StatusTemporaryRedirect, `{}`), nil
		})},
		"non JSON": {Transport: networkRoundTripFunc(func(*http.Request) (*http.Response, error) {
			response := networkJSONResponse(http.StatusOK, `{}`)
			response.Header.Set("Content-Type", "text/plain")
			return response, nil
		})},
		"oversized": {Transport: networkRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return networkJSONResponse(http.StatusOK, string(bytes.Repeat([]byte("x"), maximumNetworkSourceBytes+1))), nil
		})},
	} {
		t.Run(name, func(t *testing.T) {
			reader, err := NewKubernetesWorkloadNetworkReader(KubernetesNetworkReaderConfig{
				Endpoint: "http://localhost:12345", BearerToken: "workload-token", Client: client,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Get(context.Background(), "/api/v1/nodes"); err == nil {
				t.Fatal("unsafe network source response accepted")
			} else if strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("raw transport error leaked: %v", err)
			}
		})
	}

	for name, config := range map[string]KubernetesNetworkReaderConfig{
		"remote HTTP":    {Endpoint: "http://api.example.test", BearerToken: "token", Client: http.DefaultClient},
		"endpoint path":  {Endpoint: "https://api.example.test/api", BearerToken: "token", Client: http.DefaultClient},
		"token newline":  {Endpoint: "https://api.example.test", BearerToken: "token\n", Client: http.DefaultClient},
		"missing client": {Endpoint: "https://api.example.test", BearerToken: "token"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewKubernetesWorkloadNetworkReader(config); err == nil {
				t.Fatal("unsafe network reader configuration accepted")
			}
		})
	}
}

func TestKubernetesFixedCiliumProbeBindsExactCommand(t *testing.T) {
	executor := &fakeCiliumPodExecutor{response: []byte(`{"nodes":[]}`)}
	probe, err := NewKubernetesFixedCiliumProbe(executor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := probe.Probe(context.Background(), "cilium-abc12", "pod-uid-1")
	if err != nil {
		t.Fatal(err)
	}
	want := CiliumProbeExecRequest{
		Namespace: "kube-system", PodName: "cilium-abc12", PodUID: "pod-uid-1", Container: "cilium-agent",
		Command: [5]string{"cilium-health", "status", "--probe", "--output", "json"},
	}
	if executor.calls != 1 || executor.request != want || string(raw) != `{"nodes":[]}` {
		t.Fatalf("fixed probe boundary differs: calls=%d request=%#v raw=%q", executor.calls, executor.request, raw)
	}
	raw[0] = 'x'
	if executor.response[0] == 'x' {
		t.Fatal("probe returned an alias of transport-owned memory")
	}
}

func TestKubernetesFixedCiliumProbeFailsClosed(t *testing.T) {
	if _, err := NewKubernetesFixedCiliumProbe(nil); err == nil {
		t.Fatal("nil Pod executor accepted")
	}
	executor := &fakeCiliumPodExecutor{err: errors.New("sensitive exec details")}
	probe, _ := NewKubernetesFixedCiliumProbe(executor)
	if _, err := probe.Probe(context.Background(), "cilium-abc12", "pod-uid-1"); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("raw Pod exec error leaked or was accepted: %v", err)
	}
	if _, err := probe.Probe(context.Background(), "../pod", "pod-uid-1"); err == nil || executor.calls != 1 {
		t.Fatal("invalid Pod identity reached the executor")
	}
}

type fakeCiliumPodExecutor struct {
	request  CiliumProbeExecRequest
	response []byte
	err      error
	calls    int
}

func (executor *fakeCiliumPodExecutor) Exec(_ context.Context, request CiliumProbeExecRequest) ([]byte, error) {
	executor.calls++
	executor.request = request
	return executor.response, executor.err
}

type networkRoundTripFunc func(*http.Request) (*http.Response, error)

func (function networkRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func networkJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
