package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

type observabilityCredentialRoundTripFunc func(*http.Request) (*http.Response, error)

func (function observabilityCredentialRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestObservabilityCredentialInstallerCreatesExactPrivateSecretOnce(t *testing.T) {
	privateValues := []string{"admin", strings.Repeat("g", 48), strings.Repeat("o", 48)}
	expected := observabilityCredentialSecretFixture(t, privateValues)
	requests := 0
	client := &http.Client{Transport: observabilityCredentialRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			if request.Method != http.MethodGet || request.URL.Path != "/api/v1/namespaces/ok-observability/secrets/ok-observability-credentials" {
				t.Fatalf("unexpected preflight: %s %s", request.Method, request.URL.Path)
			}
			return observabilityCredentialResponse(http.StatusNotFound, nil), nil
		}
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/namespaces/ok-observability/secrets" {
			t.Fatalf("unexpected create: %s %s", request.Method, request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || !bytes.Equal(body, expected) {
			t.Fatal("create body differs from exact private Secret")
		}
		return observabilityCredentialResponse(http.StatusCreated, observabilityCredentialObserved(t, expected, "uid-created", "17")), nil
	})}
	installer := &observabilityCredentialInstaller{
		endpoint: &url.URL{Scheme: "https", Host: "127.0.0.1:6443"}, client: client,
		token: "private-workload-token", raw: expected, digest: digest.SHA256(expected),
	}
	receipt, err := installer.Install(context.Background())
	if err != nil || receipt.State != "CREATED" || receipt.MutationState != "ATTEMPTED" || requests != 2 {
		t.Fatalf("install differs: %#v requests=%d err=%v", receipt, requests, err)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(privateValues, "private-workload-token", "127.0.0.1") {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("receipt leaked private material")
		}
	}
	second, secondErr := installer.Install(context.Background())
	if secondErr == nil || second.MutationState != "NOT_ATTEMPTED" || requests != 2 {
		t.Fatalf("single-use installer retried: %#v %v", second, secondErr)
	}
}

func TestObservabilityCredentialInstallerAcceptsOnlyExactExistingSecret(t *testing.T) {
	expected := observabilityCredentialSecretFixture(t, []string{"admin", strings.Repeat("g", 48), strings.Repeat("o", 48)})
	for name, mutate := range map[string]func(map[string]any){
		"extra data key": func(value map[string]any) { value["data"].(map[string]any)["extra"] = "dmFsdWU=" },
		"changed value":  func(value map[string]any) { value["data"].(map[string]any)["grafana-admin-user"] = "Zm9yZWlnbg==" },
		"mutable":        func(value map[string]any) { value["immutable"] = false },
		"stringData":     func(value map[string]any) { value["stringData"] = map[string]any{"grafana-admin-user": "private"} },
	} {
		t.Run(name, func(t *testing.T) {
			observed := observabilityCredentialObserved(t, expected, "uid-existing", "23")
			var value map[string]any
			if err := json.Unmarshal(observed, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			observed, _ = json.Marshal(value)
			requests := 0
			installer := &observabilityCredentialInstaller{
				endpoint: &url.URL{Scheme: "https", Host: "127.0.0.1:6443"}, raw: expected, digest: digest.SHA256(expected),
				client: &http.Client{Transport: observabilityCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
					requests++
					return observabilityCredentialResponse(http.StatusOK, observed), nil
				})},
			}
			receipt, err := installer.Install(context.Background())
			if err == nil || receipt.MutationState != "NOT_ATTEMPTED" || requests != 1 || redactedStopCategory(err) != "OBSERVABILITY_CREDENTIAL_INSTALLATION_MISMATCH" {
				t.Fatalf("mismatch accepted: %#v requests=%d err=%v", receipt, requests, err)
			}
		})
	}
}

func TestObservabilityCredentialValuesRejectWhitespaceAndLineTerminators(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, []byte(" value"), []byte("value "), []byte("value\n"), []byte("value\r"), []byte{'a', 0, 'b'}} {
		if validObservabilityCredentialValue(raw) {
			t.Fatalf("invalid private value accepted: %q", raw)
		}
	}
	if !validObservabilityCredentialValue([]byte(strings.Repeat("x", 64))) {
		t.Fatal("bounded private value rejected")
	}
}

func TestOpenObservabilityCredentialInstallerBindsThreeDistinctPrivateFiles(t *testing.T) {
	root := t.TempDir()
	write := func(name, value string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tokenPath := write("workload-token", "private-workload-token")
	caPath := filepath.Join(root, "workload-ca.crt")
	if err := os.WriteFile(caPath, testCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	config := ObservabilityCredentialInstallationConfig{
		Authority:            KubernetesAuthorityConfig{Endpoint: "https://192.0.2.90:6443", AuthorityIdentity: "cluster-runtime-uid", TokenFile: tokenPath, CAFile: caPath},
		GrafanaAdminUserFile: write("grafana-user", "admin"), GrafanaAdminPasswordFile: write("grafana-password", strings.Repeat("g", 48)),
		OpenSearchAdminPasswordFile: write("opensearch-password", strings.Repeat("o", 48)),
	}
	installer, err := OpenObservabilityCredentialInstaller(config)
	if err != nil || installer == nil || installer.digest == "" || bytes.Contains(installer.raw, []byte("private-workload-token")) {
		t.Fatalf("private installer did not open safely: %#v %v", installer, err)
	}
	duplicate := config
	duplicate.OpenSearchAdminPasswordFile = duplicate.GrafanaAdminPasswordFile
	if _, err := OpenObservabilityCredentialInstaller(duplicate); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("duplicate private source accepted or disclosed: %v", err)
	}
	invalid := config
	invalid.GrafanaAdminPasswordFile = write("newline-password", "secret\n")
	if _, err := OpenObservabilityCredentialInstaller(invalid); err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), root) {
		t.Fatalf("invalid private source accepted or disclosed: %v", err)
	}
}

func observabilityCredentialSecretFixture(t *testing.T, values []string) []byte {
	t.Helper()
	secret := observabilityCredentialSecret{APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque"}
	secret.Metadata.Name, secret.Metadata.Namespace = observabilityCredentialSecretName, observabilityCredentialNamespace
	secret.Data = map[string]string{
		"grafana-admin-user": base64.StdEncoding.EncodeToString([]byte(values[0])), "grafana-admin-password": base64.StdEncoding.EncodeToString([]byte(values[1])),
		"opensearch-admin-password": base64.StdEncoding.EncodeToString([]byte(values[2])),
	}
	raw, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func observabilityCredentialObserved(t *testing.T, expected []byte, uid, resourceVersion string) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(expected, &value); err != nil {
		t.Fatal(err)
	}
	metadata := value["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"], metadata["creationTimestamp"] = uid, resourceVersion, "2026-10-10T00:00:00Z"
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func observabilityCredentialResponse(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}
}
