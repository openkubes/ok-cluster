package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestTargetCredentialIssuerIssuesOneRedactedInMemoryCredential(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 17, 0, 0, 0, time.UTC)
	token := targetCredentialTestJWT(t, now, now.Add(3*time.Hour), "system:serviceaccount:kube-system:ok147-argocd-manager")
	requests := 0
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/namespaces/kube-system/serviceaccounts/ok147-argocd-manager/token" || request.Header.Get("Authorization") != "Bearer issuer-token" || request.Header.Get("Content-Type") != "application/json" || bytes.Contains(body, []byte("audiences")) {
			t.Fatalf("unexpected TokenRequest: %s %s %s", request.Method, request.URL.Path, body)
		}
		var requested targetCredentialTokenRequest
		if err := json.Unmarshal(body, &requested); err != nil || requested.Spec.ExpirationSeconds != 10800 || len(requested.Spec.Audiences) != 0 {
			t.Fatalf("unexpected TokenRequest body: %#v %v", requested, err)
		}
		return targetCredentialTestResponse(http.StatusCreated, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   map[string]any{"audiences": []string{"https://kubernetes.default.svc"}, "expirationSeconds": 10800},
			"status": map[string]any{"token": token, "expirationTimestamp": now.Add(3 * time.Hour).Format(time.RFC3339)},
		}), nil
	})}
	issuer, err := newKubernetesTargetCredentialIssuer(targetCredentialIssuerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "issuer-token", CABundle: []byte("private-ca"),
		TargetIdentity: bundle.receipt.TargetIdentityDigest, Client: client, Clock: func() time.Time { return now },
	}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	material, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil || receipt.Format != TargetCredentialIssueReceiptFormat || receipt.State != "ISSUED" || receipt.StageID != "target-credential" || receipt.PolicyDigest != fixture.policyDigest || receipt.AudienceMode != "server-default" || receipt.LifetimeSeconds != 10800 || receipt.CredentialBytesInReceipt || receipt.MutationState != "ATTEMPTED" || requests != 1 {
		t.Fatalf("unexpected issuance receipt: %#v requests=%d err=%v", receipt, requests, err)
	}
	if string(material.token) != token || string(material.caBundle) != "private-ca" || material.endpoint != "http://127.0.0.1:12345" {
		t.Fatal("private target-credential material was not retained exactly in memory")
	}
	public, _ := json.Marshal(receipt)
	if bytes.Contains(public, []byte(token)) || bytes.Contains(public, material.caBundle) || bytes.Contains(public, []byte("issuer-token")) {
		t.Fatal("target-credential receipt exposed private material")
	}
	if _, err := issuer.Issue(context.Background()); err == nil || requests != 1 {
		t.Fatal("single-use target-credential issuer retried")
	}
}

func TestOpenTargetCredentialIssuerBindsRuntimeTarget(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := targetAccessRuntime(t, fixture.plan)
	if _, err := OpenTargetCredentialIssuer(bundle, TargetCredentialIssuerConfig{Workload: runtime.Workload, Clock: time.Now}); err != nil {
		t.Fatal(err)
	}
	binding, err := loadWorkloadAuthorityBinding(runtime.Workload.Path, runtime.Workload.ExpectedBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding.TargetClusterUID = "foreign-runtime-uid"
	raw, _ := json.Marshal(binding)
	if err := os.WriteFile(runtime.Workload.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.Workload.ExpectedBindingDigest, _ = WorkloadAuthorityBindingDigest(binding)
	if _, err := OpenTargetCredentialIssuer(bundle, TargetCredentialIssuerConfig{Workload: runtime.Workload, Clock: time.Now}); err == nil {
		t.Fatal("foreign runtime target opened target-credential issuer")
	}
	if _, err := OpenTargetCredentialIssuer(VerifiedTargetCredentialStageBundle{}, TargetCredentialIssuerConfig{}); err == nil {
		t.Fatal("unverified target-credential bundle opened issuer")
	}
}

func TestTargetCredentialIssuerFailsClosedOnResponseClaims(t *testing.T) {
	now := time.Date(2026, 8, 17, 17, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		subject   string
		expires   time.Time
		audiences []string
		status    int
		mediaType string
	}{
		"foreign subject":            {subject: "system:serviceaccount:kube-system:foreign", expires: now.Add(3 * time.Hour), audiences: []string{"default"}, status: http.StatusCreated, mediaType: "application/json"},
		"short lifetime":             {subject: "system:serviceaccount:kube-system:ok147-argocd-manager", expires: now.Add(time.Hour), audiences: []string{"default"}, status: http.StatusCreated, mediaType: "application/json"},
		"missing defaulted audience": {subject: "system:serviceaccount:kube-system:ok147-argocd-manager", expires: now.Add(3 * time.Hour), audiences: []string{}, status: http.StatusCreated, mediaType: "application/json"},
		"wrong status":               {subject: "system:serviceaccount:kube-system:ok147-argocd-manager", expires: now.Add(3 * time.Hour), audiences: []string{"default"}, status: http.StatusForbidden, mediaType: "application/json"},
		"wrong media type":           {subject: "system:serviceaccount:kube-system:ok147-argocd-manager", expires: now.Add(3 * time.Hour), audiences: []string{"default"}, status: http.StatusCreated, mediaType: "text/plain"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := targetCredentialBundleFixture(t)
			bundle, err := LoadTargetCredentialStageBundle(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			token := targetCredentialTestJWT(t, now, test.expires, test.subject)
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(*http.Request) (*http.Response, error) {
				response := targetCredentialTestResponse(test.status, map[string]any{
					"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
					"spec":   map[string]any{"audiences": test.audiences, "expirationSeconds": 10800},
					"status": map[string]any{"token": token, "expirationTimestamp": test.expires.Format(time.RFC3339)},
				})
				response.Header.Set("Content-Type", test.mediaType)
				return response, nil
			})}
			issuer, err := newKubernetesTargetCredentialIssuer(targetCredentialIssuerClientConfig{
				Endpoint: "http://127.0.0.1:12345", BearerToken: "issuer-token", CABundle: []byte("private-ca"),
				TargetIdentity: bundle.receipt.TargetIdentityDigest, Client: client, Clock: func() time.Time { return now },
			}, bundle)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Issue(context.Background()); err == nil {
				t.Fatal("invalid target-credential response was accepted")
			}
		})
	}
	if _, err := (VerifiedTargetCredentialMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified target-credential material exposed receipt")
	}
}

func targetCredentialTestJWT(t *testing.T, issuedAt, expiresAt time.Time, subject string) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(map[string]any{"alg": "RS256", "typ": "JWT"}) + "." + encode(map[string]any{
		"sub": subject, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(), "aud": []string{"https://kubernetes.default.svc"},
	}) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
}

func targetCredentialTestResponse(status int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}
}
