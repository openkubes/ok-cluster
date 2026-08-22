package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestObservabilityCollectorInstallerCredentialIssuesOnceInMemory(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	target := digest.SHA256([]byte("collector-installer-target"))
	ca := []byte("collector-installer-ca")
	token := targetCredentialTestJWT(t, now, now.Add(observabilityCollectorInstallerLifetime),
		"system:serviceaccount:"+observabilityCollectorInstallerNamespace+":"+observabilityCollectorInstallerServiceAccount)
	requests := 0
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/namespaces/openkubes-execution-system/serviceaccounts/ok147-observability-collector-installer/token" ||
			request.Header.Get("Authorization") != "Bearer workload-admin" || request.Header.Get("Content-Type") != "application/json" ||
			bytes.Contains(body, []byte("audiences")) {
			t.Fatalf("unexpected collector installer TokenRequest: %s %s %s", request.Method, request.URL.Path, body)
		}
		var requested targetCredentialTokenRequest
		if err := json.Unmarshal(body, &requested); err != nil || requested.Spec.ExpirationSeconds != 1800 || len(requested.Spec.Audiences) != 0 {
			t.Fatalf("unexpected TokenRequest body: %#v %v", requested, err)
		}
		return targetCredentialTestResponse(http.StatusCreated, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   map[string]any{"audiences": []string{"https://kubernetes.default.svc"}, "expirationSeconds": 1800},
			"status": map[string]any{"token": token, "expirationTimestamp": now.Add(observabilityCollectorInstallerLifetime).Format(time.RFC3339)},
		}), nil
	})}
	issuer, err := newKubernetesObservabilityCollectorInstallerCredentialIssuer(observabilityCollectorInstallerClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundle: ca, CABundleDigest: digest.SHA256(ca),
		TargetIdentity: target, Client: client, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil || receipt.Format != ObservabilityCollectorInstallerCredentialReceiptFormat || receipt.State != "ISSUED" ||
		receipt.TargetIdentityDigest != target || receipt.CABundleDigest != digest.SHA256(ca) || receipt.AudienceMode != "server-default" ||
		receipt.LifetimeSeconds != 1800 || receipt.CredentialBytesInReceipt || receipt.MutationState != "ATTEMPTED" || requests != 1 {
		t.Fatalf("unexpected collector installer credential receipt: %#v requests=%d err=%v", receipt, requests, err)
	}
	launcher, err := material.launcherConfig()
	if err != nil || launcher.BearerToken != token || launcher.Endpoint != "https://127.0.0.1:12345" || launcher.AuthorityIdentity != target || launcher.Client == nil {
		t.Fatalf("private collector installer credential was not retained in memory: %#v %v", launcher, err)
	}
	public, _ := json.Marshal(receipt)
	if bytes.Contains(public, []byte(token)) || bytes.Contains(public, []byte("workload-admin")) || bytes.Contains(public, ca) {
		t.Fatal("collector installer credential receipt exposed private material")
	}
	if _, err := issuer.Issue(context.Background()); err == nil || requests != 1 {
		t.Fatal("single-use collector installer credential issuer retried")
	}
}

func TestObservabilityCollectorInstallerCredentialFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	target := digest.SHA256([]byte("collector-installer-target"))
	ca := []byte("collector-installer-ca")
	tests := map[string]struct {
		subject   string
		expires   time.Time
		audiences []string
		status    int
	}{
		"foreign subject":  {subject: "system:serviceaccount:openkubes-execution-system:foreign", expires: now.Add(30 * time.Minute), audiences: []string{"default"}, status: http.StatusCreated},
		"short lifetime":   {subject: "system:serviceaccount:openkubes-execution-system:ok147-observability-collector-installer", expires: now.Add(10 * time.Minute), audiences: []string{"default"}, status: http.StatusCreated},
		"missing audience": {subject: "system:serviceaccount:openkubes-execution-system:ok147-observability-collector-installer", expires: now.Add(30 * time.Minute), audiences: []string{}, status: http.StatusCreated},
		"foreign audience": {subject: "system:serviceaccount:openkubes-execution-system:ok147-observability-collector-installer", expires: now.Add(30 * time.Minute), audiences: []string{"foreign"}, status: http.StatusCreated},
		"wrong status":     {subject: "system:serviceaccount:openkubes-execution-system:ok147-observability-collector-installer", expires: now.Add(30 * time.Minute), audiences: []string{"default"}, status: http.StatusForbidden},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := targetCredentialTestJWT(t, now, test.expires, test.subject)
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return targetCredentialTestResponse(test.status, map[string]any{
					"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
					"spec":   map[string]any{"audiences": test.audiences, "expirationSeconds": 1800},
					"status": map[string]any{"token": token, "expirationTimestamp": test.expires.Format(time.RFC3339)},
				}), nil
			})}
			issuer, err := newKubernetesObservabilityCollectorInstallerCredentialIssuer(observabilityCollectorInstallerClientConfig{
				Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", CABundle: ca, CABundleDigest: digest.SHA256(ca),
				TargetIdentity: target, Client: client, Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Issue(context.Background()); err == nil {
				t.Fatal("invalid collector installer credential response was accepted")
			}
		})
	}
	if _, err := (VerifiedObservabilityCollectorInstallerCredential{}).Receipt(); err == nil {
		t.Fatal("unverified collector installer credential exposed receipt")
	}
}

func TestOpenObservabilityCollectorInstallerCredentialIssuerBindsRuntimeTarget(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	runtime := targetAccessRuntime(t, fixture.plan)
	binding, err := loadWorkloadAuthorityBinding(runtime.Workload.Path, runtime.Workload.ExpectedBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	target := digest.SHA256([]byte(binding.TargetClusterUID))
	if _, err := OpenKubernetesObservabilityCollectorInstallerCredentialIssuer(ObservabilityCollectorInstallerCredentialConfig{
		Workload: runtime.Workload, ExpectedTargetDigest: target, Clock: time.Now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesObservabilityCollectorInstallerCredentialIssuer(ObservabilityCollectorInstallerCredentialConfig{
		Workload: runtime.Workload, ExpectedTargetDigest: digest.SHA256([]byte("foreign")), Clock: time.Now,
	}); err == nil {
		t.Fatal("foreign runtime target opened collector installer credential issuer")
	}
}
