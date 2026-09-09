package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestObservabilityCollectorObserverCredentialIssuesOnceInMemory(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	target := digest.SHA256([]byte("collector-observer-target"))
	token := string(stageCredentialJWT(t, "https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ok-observability:"+observabilityCollectorObserverSA,
		[]string{"https://kubernetes.default.svc"}, now, now.Add(time.Hour), 'o'))
	requests := 0
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return observerAuthorityTestResponse(request.URL.Path), nil
		}
		requests++
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/namespaces/ok-observability/serviceaccounts/ok147-observability-autonomy/token" ||
			request.Header.Get("Authorization") != "Bearer workload-admin" || !bytes.Contains(body, []byte(`"audiences":["https://kubernetes.default.svc"]`)) ||
			bytes.Contains(body, []byte(`"boundObjectRef"`)) {
			t.Fatalf("unexpected collector observer TokenRequest: %s %s %s", request.Method, request.URL.Path, body)
		}
		return targetCredentialTestResponse(http.StatusCreated, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   observerCredentialResponseSpec([]string{"https://kubernetes.default.svc"}),
			"status": map[string]any{"token": token, "expirationTimestamp": now.Add(time.Hour).Format(time.RFC3339)},
		}), nil
	})}
	issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"),
		CAFile: "/private/tmp/workload-ca.crt", TargetIdentity: target, Client: client, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source, privateToken, receipt, err := credential.Material()
	if err != nil || receipt.Format != ObservabilityCollectorObserverCredentialReceiptFormat || receipt.State != "ISSUED" ||
		receipt.TargetIdentityDigest != target || receipt.AudienceMode != observabilityCollectorObserverAudienceMode || receipt.LifetimeSeconds != 3600 || receipt.CredentialBytesInReceipt ||
		source.TokenFile != "" || source.TokenDigest != digest.SHA256([]byte(token)) || string(privateToken) != token || requests != 1 {
		t.Fatalf("unexpected observer credential: %#v %#v requests=%d err=%v", source, receipt, requests, err)
	}
	public, _ := json.Marshal(receipt)
	if bytes.Contains(public, []byte(token)) || bytes.Contains(public, []byte("workload-admin")) {
		t.Fatal("observer credential receipt exposed private material")
	}
	if _, err := issuer.Issue(context.Background()); err == nil || requests != 1 {
		t.Fatal("single-use collector observer credential issuer retried")
	}
}

func TestObservabilityCollectorObserverCredentialRejectsDifferentReturnedAudience(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	target := digest.SHA256([]byte("collector-observer-target"))
	foreignAudience := "https://kubernetes.default.svc.cluster.local"
	token := string(stageCredentialJWT(t, foreignAudience, "system:serviceaccount:ok-observability:"+observabilityCollectorObserverSA,
		[]string{foreignAudience}, now, now.Add(time.Hour), 'o'))
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return observerAuthorityTestResponse(request.URL.Path), nil
		}
		body, _ := io.ReadAll(request.Body)
		if !bytes.Contains(body, []byte(`"audiences":["https://kubernetes.default.svc"]`)) {
			t.Fatalf("observer request did not bind the explicit audience: %s", body)
		}
		return targetCredentialTestResponse(http.StatusCreated, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   observerCredentialResponseSpec([]string{foreignAudience}),
			"status": map[string]any{"token": token, "expirationTimestamp": now.Add(time.Hour).Format(time.RFC3339)},
		}), nil
	})}
	issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"),
		CAFile: "/private/tmp/workload-ca.crt", TargetIdentity: target, Client: client, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(context.Background()); err == nil || redactedStopCategory(err) != "POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH" {
		t.Fatal("observer credential with a different returned audience was accepted")
	}
}

func TestObservabilityCollectorObserverCredentialBindsReturnedObjectReference(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	token := string(stageCredentialJWT(t, "https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ok-observability:"+observabilityCollectorObserverSA,
		[]string{observabilityCollectorObserverAudience}, now, now.Add(time.Hour), 'o'))
	for _, test := range []struct {
		name, field, value, want string
	}{
		{name: "missing", field: "missing", want: "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_INVALID"},
		{name: "api version", field: "apiVersion", value: "v2", want: "POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH"},
		{name: "kind", field: "kind", value: "User", want: "POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH"},
		{name: "name", field: "name", value: "foreign", want: "POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH"},
		{name: "uid", field: "uid", value: "foreign-uid", want: "POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					return observerAuthorityTestResponse(request.URL.Path), nil
				}
				spec := observerCredentialResponseSpec([]string{observabilityCollectorObserverAudience})
				if test.field == "missing" {
					delete(spec, "boundObjectRef")
				} else {
					spec["boundObjectRef"].(map[string]any)[test.field] = test.value
				}
				return targetCredentialTestResponse(http.StatusCreated, map[string]any{
					"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{}, "spec": spec,
					"status": map[string]any{"token": token, "expirationTimestamp": now.Add(time.Hour).Format(time.RFC3339)},
				}), nil
			})}
			issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
				Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"),
				CAFile: "/private/tmp/workload-ca.crt", TargetIdentity: digest.SHA256([]byte("target")), Client: client, Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Issue(context.Background()); err == nil || redactedStopCategory(err) != test.want {
				t.Fatalf("bound object mismatch accepted: category=%q", redactedStopCategory(err))
			}
		})
	}
}

func TestObserverCredentialSubcategoriesAreRedactedAndAccepted(t *testing.T) {
	private := "https://private-workload.example.invalid bearer-secret"
	for _, category := range []string{
		"POST_PREFIX_OBSERVER_AUTHORITY_CONVERGENCE_EXHAUSTED",
		"POST_PREFIX_OBSERVER_AUTHORITY_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_TRANSPORT_STOPPED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CONVERGENCE_EXHAUSTED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_HTTP_REJECTED",
		"POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_ENVELOPE_INVALID",
		"POST_PREFIX_OBSERVER_CREDENTIAL_CLAIMS_MISMATCH",
		"POST_PREFIX_OBSERVER_CREDENTIAL_MATERIALIZATION_STOPPED",
	} {
		err := newFixedRedactedStop(category, errors.New(private))
		if !validPostPrefixActivationStopCategory(category) || !validRedactedStopCategory(category) ||
			redactedStopCategory(postPrefixObserverCredentialStopOrFallback(err)) != category {
			t.Fatalf("observer credential category was not preserved: %s", category)
		}
		if strings.Contains(err.Error(), private) {
			t.Fatalf("observer credential category exposed private cause: %s", category)
		}
	}
	for _, category := range []string{"AUTHORIZATION_HTTP_REJECTED", "POST_PREFIX_LAUNCH_STOPPED"} {
		foreign := newFixedRedactedStop(category, errors.New(private))
		if got := redactedStopCategory(postPrefixObserverCredentialStopOrFallback(foreign)); got != "POST_PREFIX_OBSERVER_CREDENTIAL_STOPPED" {
			t.Fatalf("foreign category crossed observer boundary: source=%q got=%q", category, got)
		}
	}
}

func TestObservabilityCollectorObserverCredentialFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	target := digest.SHA256([]byte("collector-observer-target"))
	for name, subject := range map[string]string{
		"foreign subject": "system:serviceaccount:ok-observability:foreign",
		"wrong namespace": "system:serviceaccount:openkubes-execution-system:" + observabilityCollectorObserverSA,
	} {
		t.Run(name, func(t *testing.T) {
			token := string(stageCredentialJWT(t, "https://kubernetes.default.svc.cluster.local", subject,
				[]string{"https://kubernetes.default.svc"}, now, now.Add(time.Hour), 'o'))
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					return observerAuthorityTestResponse(request.URL.Path), nil
				}
				return targetCredentialTestResponse(http.StatusCreated, map[string]any{
					"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
					"spec":   observerCredentialResponseSpec([]string{"https://kubernetes.default.svc"}),
					"status": map[string]any{"token": token, "expirationTimestamp": now.Add(time.Hour).Format(time.RFC3339)},
				}), nil
			})}
			issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
				Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"),
				CAFile: "/private/tmp/workload-ca.crt", TargetIdentity: target, Client: client, Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Issue(context.Background()); err == nil {
				t.Fatal("foreign collector observer identity was accepted")
			}
		})
	}
	if _, _, _, err := (VerifiedObservabilityCollectorObserverCredential{}).Material(); err == nil {
		t.Fatal("unverified observer credential exposed private material")
	}
}

func TestObserverAuthorityConvergesBeforeExactlyOneTokenRequest(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	clock := now
	getCalls, postCalls := 0, 0
	token := string(stageCredentialJWT(t, "https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ok-observability:"+observabilityCollectorObserverSA,
		[]string{observabilityCollectorObserverAudience}, now, now.Add(time.Hour), 'o'))
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			getCalls++
			if getCalls == 1 {
				return targetCredentialTestResponse(http.StatusNotFound, map[string]any{}), nil
			}
			return observerAuthorityTestResponse(request.URL.Path), nil
		}
		postCalls++
		return targetCredentialTestResponse(http.StatusCreated, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   observerCredentialResponseSpec([]string{observabilityCollectorObserverAudience}),
			"status": map[string]any{"token": token, "expirationTimestamp": now.Add(time.Hour).Format(time.RFC3339)},
		}), nil
	})}
	issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"),
		CAFile: "/private/tmp/workload-ca.crt", TargetIdentity: digest.SHA256([]byte("target")), Client: client, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer.pollClock = func() time.Time { return clock }
	issuer.wait = func(_ context.Context, delay time.Duration) error { clock = clock.Add(delay); return nil }
	if _, err := issuer.Issue(context.Background()); err != nil || getCalls != 9 || postCalls != 1 {
		t.Fatalf("unexpected authority convergence: get=%d post=%d err=%v", getCalls, postCalls, err)
	}
}

func TestObserverAuthorityMismatchIsTerminalBeforeTokenRequest(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	postCalls := 0
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			postCalls++
			return targetCredentialTestResponse(http.StatusCreated, map[string]any{}), nil
		}
		response := observerAuthorityTestResponse(request.URL.Path)
		if strings.Contains(request.URL.Path, "/roles/") && !strings.Contains(request.URL.Path, "/rolebindings/") {
			return targetCredentialTestResponse(http.StatusOK, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": map[string]any{"name": observabilityCollectorObserverSA, "namespace": "ok-observability", "uid": "uid-role"}, "rules": []any{}}), nil
		}
		return response, nil
	})}
	issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"), CAFile: "/private/tmp/workload-ca.crt",
		TargetIdentity: digest.SHA256([]byte("target")), Client: client, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(context.Background()); err == nil || redactedStopCategory(err) != "POST_PREFIX_OBSERVER_AUTHORITY_INVALID" || postCalls != 0 {
		t.Fatalf("authority mismatch was not terminal: category=%q posts=%d", redactedStopCategory(err), postCalls)
	}
}

func TestObserverAuthorityUIDChangeIsTerminalBeforeTokenRequest(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	namespaceGets, postCalls := 0, 0
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			postCalls++
			return targetCredentialTestResponse(http.StatusCreated, map[string]any{}), nil
		}
		if request.URL.Path == "/api/v1/namespaces/ok-observability" {
			namespaceGets++
			return targetCredentialTestResponse(http.StatusOK, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "ok-observability", "uid": fmt.Sprintf("uid-%d", namespaceGets)}}), nil
		}
		return observerAuthorityTestResponse(request.URL.Path), nil
	})}
	issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"), CAFile: "/private/tmp/workload-ca.crt",
		TargetIdentity: digest.SHA256([]byte("target")), Client: client, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	issuer.pollClock = func() time.Time { return clock }
	issuer.wait = func(_ context.Context, delay time.Duration) error { clock = clock.Add(delay); return nil }
	if _, err := issuer.Issue(context.Background()); err == nil || redactedStopCategory(err) != "POST_PREFIX_OBSERVER_AUTHORITY_INVALID" || postCalls != 0 {
		t.Fatalf("authority UID change was not terminal: category=%q posts=%d", redactedStopCategory(err), postCalls)
	}
}

func TestPartiallyVisibleObserverAuthorityCannotDisappearOrChangeUID(t *testing.T) {
	for _, test := range []struct {
		name         string
		secondStatus int
		secondUID    string
	}{
		{name: "disappears", secondStatus: http.StatusNotFound},
		{name: "changes UID", secondStatus: http.StatusOK, secondUID: "uid-namespace-2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
			namespaceGets, postCalls := 0, 0
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodPost {
					postCalls++
					return targetCredentialTestResponse(http.StatusCreated, map[string]any{}), nil
				}
				if request.URL.Path == "/api/v1/namespaces/ok-observability" {
					namespaceGets++
					if namespaceGets == 2 {
						return targetCredentialTestResponse(test.secondStatus, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "ok-observability", "uid": test.secondUID}}), nil
					}
					return targetCredentialTestResponse(http.StatusOK, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "ok-observability", "uid": "uid-namespace-1"}}), nil
				}
				if strings.Contains(request.URL.Path, "/roles/") && !strings.Contains(request.URL.Path, "/rolebindings/") {
					return targetCredentialTestResponse(http.StatusNotFound, map[string]any{}), nil
				}
				return observerAuthorityTestResponse(request.URL.Path), nil
			})}
			issuer, err := newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
				Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundleDigest: runnerStageSHA("a"), CAFile: "/private/tmp/workload-ca.crt",
				TargetIdentity: digest.SHA256([]byte("target")), Client: client, Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			clock := now
			issuer.pollClock = func() time.Time { return clock }
			issuer.wait = func(_ context.Context, delay time.Duration) error { clock = clock.Add(delay); return nil }
			if _, err := issuer.Issue(context.Background()); err == nil || redactedStopCategory(err) != "POST_PREFIX_OBSERVER_AUTHORITY_INVALID" || postCalls != 0 {
				t.Fatalf("partial authority regression was not terminal: category=%q posts=%d", redactedStopCategory(err), postCalls)
			}
		})
	}
}

func TestObserverCredentialSingleRequestSeparatesHTTPAndEnvelopeFailures(t *testing.T) {
	for _, test := range []struct {
		name                    string
		status                  int
		contentType, body, want string
	}{
		{"http", http.StatusForbidden, "application/json", `{}`, "POST_PREFIX_OBSERVER_CREDENTIAL_HTTP_REJECTED"},
		{"envelope", http.StatusCreated, "text/plain", `{}`, "POST_PREFIX_OBSERVER_CREDENTIAL_RESPONSE_ENVELOPE_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			endpoint, _ := url.Parse("https://workload.example.invalid/token")
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				response := collectorCredentialResponse(test.status, test.body)
				response.Header.Set("Content-Type", test.contentType)
				return response, nil
			})}
			_, err := issueObservabilityCollectorCredentialOnce(context.Background(), observabilityCollectorCredentialPollConfig{client: client, endpoint: *endpoint, authorityToken: "authority", request: []byte(`{}`), pollClock: time.Now, pollTimeout: time.Second})
			if err == nil || calls != 1 || redactedStopCategory(err) != test.want {
				t.Fatalf("calls=%d category=%q", calls, redactedStopCategory(err))
			}
		})
	}
}

func observerAuthorityTestResponse(path string) *http.Response {
	metadata := map[string]any{"uid": "uid-" + path}
	var object map[string]any
	switch path {
	case "/api/v1/namespaces/ok-observability":
		metadata["name"] = "ok-observability"
		object = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": metadata}
	case "/api/v1/namespaces/ok-observability/serviceaccounts/ok147-observability-autonomy":
		metadata["name"], metadata["namespace"] = observabilityCollectorObserverSA, "ok-observability"
		object = map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata, "automountServiceAccountToken": false}
	case "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-observability/roles/ok147-observability-autonomy":
		metadata["name"], metadata["namespace"] = observabilityCollectorObserverSA, "ok-observability"
		object = map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": metadata, "rules": []any{
			map[string]any{"apiGroups": []string{""}, "resources": []string{"services"}, "verbs": []string{"get"}},
			map[string]any{"apiGroups": []string{"discovery.k8s.io"}, "resources": []string{"endpointslices"}, "verbs": []string{"list"}},
		}}
	case "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-observability/rolebindings/ok147-observability-autonomy":
		metadata["name"], metadata["namespace"] = observabilityCollectorObserverSA, "ok-observability"
		object = map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": metadata,
			"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": observabilityCollectorObserverSA},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": observabilityCollectorObserverSA, "namespace": "ok-observability"}},
		}
	default:
		return targetCredentialTestResponse(http.StatusNotFound, map[string]any{})
	}
	return targetCredentialTestResponse(http.StatusOK, object)
}

func observerCredentialResponseSpec(audiences []string) map[string]any {
	return map[string]any{
		"audiences": audiences, "expirationSeconds": 3600,
		"boundObjectRef": map[string]any{
			"apiVersion": "v1", "kind": "ServiceAccount", "name": observabilityCollectorObserverSA,
			"uid": "uid-/api/v1/namespaces/ok-observability/serviceaccounts/ok147-observability-autonomy",
		},
	}
}
