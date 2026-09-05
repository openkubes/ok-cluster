package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestOpenKubernetesRuntimeBindingSourceBindsExactAuthority(t *testing.T) {
	root := t.TempDir()
	ca := testCA(t)
	tokenPath, caPath := filepath.Join(root, "token"), filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte("short-lived-runtime-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: digestOf("a"),
		TargetClusterUID: "cluster-runtime-uid-147", TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: "https://192.0.2.20:6443", CABundleDigest: digest.SHA256(ca),
	}
	authority := KubernetesAuthorityConfig{
		Endpoint: binding.Endpoint, AuthorityIdentity: binding.TargetClusterUID,
		TokenFile: tokenPath, CAFile: caPath, CABundleDigest: binding.CABundleDigest,
	}
	if _, err := OpenKubernetesRuntimeBindingSource(authority, binding); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*KubernetesAuthorityConfig){
		"endpoint":  func(config *KubernetesAuthorityConfig) { config.Endpoint = "https://192.0.2.21:6443" },
		"identity":  func(config *KubernetesAuthorityConfig) { config.AuthorityIdentity = "replacement-cluster-uid" },
		"CA digest": func(config *KubernetesAuthorityConfig) { config.CABundleDigest = digestOf("b") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := authority
			mutate(&changed)
			if _, err := OpenKubernetesRuntimeBindingSource(changed, binding); err == nil {
				t.Fatal("mismatched runtime authority was accepted")
			}
		})
	}
}

func TestRuntimeBindingSourceUsesExactlyTwoGETs(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer runtime-token" || request.Header.Get("Accept") != "application/json" {
			t.Error("runtime source credential headers differ")
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case runtimeBindingKubeSystemPath:
			fmt.Fprint(response, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"kube-system-runtime-uid","resourceVersion":"1"}}`)
		case runtimeBindingLocalPathPath:
			fmt.Fprint(response, `{"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":"local-path","uid":"local-path-runtime-uid"},"provisioner":"rancher.io/local-path"}`)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := source.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observed.KubeSystemUID != "kube-system-runtime-uid" || observed.LocalPathStorageClassUID != "local-path-runtime-uid" || observed.LocalPathProvisioner != "rancher.io/local-path" {
		t.Fatalf("runtime observation differs: %#v", observed)
	}
	want := []string{"GET " + runtimeBindingKubeSystemPath, "GET " + runtimeBindingLocalPathPath}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("runtime request boundary differs: got=%v want=%v", requests, want)
	}
}

func TestRuntimeBindingSourceFailsClosed(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"first request fails": func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusForbidden) },
		"replacement namespace": func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			if request.URL.Path == runtimeBindingKubeSystemPath {
				fmt.Fprint(response, `{"kind":"Namespace","metadata":{"uid":""}}`)
			}
		},
		"foreign provisioner": func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			if request.URL.Path == runtimeBindingKubeSystemPath {
				fmt.Fprint(response, `{"kind":"Namespace","metadata":{"uid":"kube-system-runtime-uid"}}`)
				return
			}
			fmt.Fprint(response, `{"kind":"StorageClass","metadata":{"uid":"local-path-runtime-uid"},"provisioner":"foreign.example/storage"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Observe(context.Background()); err == nil {
				t.Fatal("unsafe runtime source response was accepted")
			}
		})
	}
	if _, err := (&KubernetesRuntimeBindingSource{}).Observe(context.Background()); err == nil {
		t.Fatal("unopened runtime binding source could observe")
	}
}

func TestRuntimeBindingSourcePollsTransientAbsenceThenSucceeds(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if request.URL.Path == runtimeBindingKubeSystemPath {
			fmt.Fprint(response, `{"kind":"Namespace","metadata":{"uid":"kube-system-runtime-uid"}}`)
			return
		}
		fmt.Fprint(response, `{"kind":"StorageClass","metadata":{"uid":"local-path-runtime-uid"},"provisioner":"rancher.io/local-path"}`)
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	source.wait = func(context.Context, time.Duration) error { waits++; return nil }
	if _, err := source.Observe(context.Background()); err != nil || waits != 1 || requests != 3 {
		t.Fatalf("transient convergence did not succeed: requests=%d waits=%d err=%v", requests, waits, err)
	}
}

func TestRuntimeBindingSourceFailsWhenSeenIdentityDisappears(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			fmt.Fprint(response, `{"kind":"Namespace","metadata":{"uid":"kube-system-runtime-uid"}}`)
		case 2:
			response.WriteHeader(http.StatusServiceUnavailable)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	source.wait = func(context.Context, time.Duration) error { waits++; return nil }
	if _, err := source.Observe(context.Background()); err == nil || waits != 1 || requests != 3 {
		t.Fatalf("seen-then-missing identity was retried: requests=%d waits=%d err=%v", requests, waits, err)
	}
}

func TestRuntimeBindingSourceFailsWhenSeenIdentityChanges(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == runtimeBindingLocalPathPath {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		uid := "kube-system-runtime-uid-a"
		if requests > 2 {
			uid = "kube-system-runtime-uid-b"
		}
		fmt.Fprintf(response, `{"kind":"Namespace","metadata":{"uid":%q}}`, uid)
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	source.wait = func(context.Context, time.Duration) error { waits++; return nil }
	if _, err := source.Observe(context.Background()); err == nil || waits != 1 || requests != 3 {
		t.Fatalf("changed identity was retried: requests=%d waits=%d err=%v", requests, waits, err)
	}
}

func TestRuntimeBindingSourceBoundsTransientPollingByAttempts(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	source.maximumAttempts = 2
	waits := 0
	source.wait = func(context.Context, time.Duration) error { waits++; return nil }
	if _, err := source.Observe(context.Background()); err == nil || waits != 1 || requests != 2 {
		t.Fatalf("attempt bound was not enforced: requests=%d waits=%d err=%v", requests, waits, err)
	}
}

func TestRuntimeBindingSourcePermanentHTTPFailuresAreNotPolled(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotImplemented} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				requests++
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(status)
			}))
			defer server.Close()
			source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			source.wait = func(context.Context, time.Duration) error { t.Fatal("permanent failure reached waiter"); return nil }
			if _, err := source.Observe(context.Background()); err == nil || requests != 1 {
				t.Fatalf("permanent HTTP failure was accepted or retried: requests=%d err=%v", requests, err)
			}
		})
	}
}

func TestRuntimeBindingSourceHTTPTransientAllowlistIsExact(t *testing.T) {
	transient := map[int]bool{
		http.StatusNotFound: true, http.StatusTooManyRequests: true, http.StatusInternalServerError: true,
		http.StatusBadGateway: true, http.StatusServiceUnavailable: true, http.StatusGatewayTimeout: true,
	}
	for _, status := range []int{400, 401, 403, 404, 408, 409, 422, 429, 500, 501, 502, 503, 504, 505} {
		if got := transientRuntimeBindingStatus(status); got != transient[status] {
			t.Fatalf("HTTP %d transient=%t want=%t", status, got, transient[status])
		}
	}
}

func TestRuntimeBindingSourceBoundsTransientPollingByDeadline(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 8, 0, 0, 0, time.UTC)
	source.clock = func() time.Time { return now }
	source.interval, source.timeout, source.maximumAttempts = time.Second, 2*time.Second, 20
	waits := 0
	source.wait = func(_ context.Context, duration time.Duration) error { waits++; now = now.Add(duration); return nil }
	if _, err := source.Observe(context.Background()); err == nil || waits != 2 || requests != 3 {
		t.Fatalf("deadline bound was not enforced: requests=%d waits=%d err=%v", requests, waits, err)
	}
}

func TestRuntimeBindingSourceContextCancellationIsTerminal(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	source, err := newKubernetesRuntimeBindingSource(server.URL, "runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	source.wait = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	if _, err := source.Observe(ctx); err == nil || requests != 1 {
		t.Fatalf("cancelled convergence was accepted or retried: requests=%d err=%v", requests, err)
	}
}
