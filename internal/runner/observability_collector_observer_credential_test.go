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

func TestObservabilityCollectorObserverCredentialIssuesOnceInMemory(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	target := digest.SHA256([]byte("collector-observer-target"))
	token := string(stageCredentialJWT(t, "https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ok-observability:"+observabilityCollectorObserverSA,
		[]string{"https://kubernetes.default.svc"}, now, now.Add(time.Hour), 'o'))
	requests := 0
	client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/namespaces/ok-observability/serviceaccounts/ok147-observability-autonomy/token" ||
			request.Header.Get("Authorization") != "Bearer workload-admin" || bytes.Contains(body, []byte("audiences")) {
			t.Fatalf("unexpected collector observer TokenRequest: %s %s %s", request.Method, request.URL.Path, body)
		}
		return targetCredentialTestResponse(http.StatusCreated, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
			"spec":   map[string]any{"audiences": []string{"https://kubernetes.default.svc"}, "expirationSeconds": 3600},
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
		receipt.TargetIdentityDigest != target || receipt.LifetimeSeconds != 3600 || receipt.CredentialBytesInReceipt ||
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
			client := &http.Client{Transport: submissionStageLauncherRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return targetCredentialTestResponse(http.StatusCreated, map[string]any{
					"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "metadata": map[string]any{},
					"spec":   map[string]any{"audiences": []string{"https://kubernetes.default.svc"}, "expirationSeconds": 3600},
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
