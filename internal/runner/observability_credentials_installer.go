package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	ObservabilityCredentialInstallationReceiptFormat = "ok147-observability-credential-installation-receipt/v1"
	observabilityCredentialNamespace                 = "ok-observability"
	observabilityCredentialSecretName                = "ok-observability-credentials"
	maximumObservabilityCredentialBytes              = 4 * 1024
)

type ObservabilityCredentialInstallationConfig struct {
	Authority                   KubernetesAuthorityConfig
	GrafanaAdminUserFile        string
	GrafanaAdminPasswordFile    string
	OpenSearchAdminPasswordFile string
}

type ObservabilityCredentialInstallationReceipt struct {
	Format        string `json:"format"`
	State         string `json:"state"`
	MutationState string `json:"mutationState"`
	ObjectDigest  string `json:"objectDigest"`
	UIDDigest     string `json:"uidDigest,omitempty"`
}

type observabilityCredentialInstaller struct {
	mu       sync.Mutex
	used     bool
	endpoint *url.URL
	client   *http.Client
	token    string
	raw      []byte
	digest   string
}

type observabilityCredentialSecret struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		UID             string `json:"uid,omitempty"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Immutable bool              `json:"immutable"`
	Type      string            `json:"type"`
	Data      map[string]string `json:"data"`
}

func OpenObservabilityCredentialInstaller(config ObservabilityCredentialInstallationConfig) (*observabilityCredentialInstaller, error) {
	if config.Authority.AuthorityIdentity == "" || config.GrafanaAdminUserFile == "" ||
		config.GrafanaAdminPasswordFile == "" || config.OpenSearchAdminPasswordFile == "" {
		return nil, errors.New("observability credential installation configuration is incomplete")
	}
	paths := []string{config.GrafanaAdminUserFile, config.GrafanaAdminPasswordFile, config.OpenSearchAdminPasswordFile}
	if paths[0] == paths[1] || paths[0] == paths[2] || paths[1] == paths[2] {
		return nil, errors.New("observability credential source identities must be distinct")
	}
	values := make([][]byte, len(paths))
	for index, path := range paths {
		raw, err := readBoundedRegular(path, maximumObservabilityCredentialBytes)
		if err != nil || !validObservabilityCredentialValue(raw) {
			return nil, errors.New("read bounded observability credential material")
		}
		values[index] = raw
	}
	transport, err := openBoundedKubernetesAuthorityTransport(config.Authority)
	if err != nil {
		return nil, errors.New("open bounded observability credential authority")
	}
	client := *transport.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	endpoint, err := url.Parse(config.Authority.Endpoint)
	if err != nil {
		return nil, errors.New("parse observability credential authority")
	}
	secret := observabilityCredentialSecret{APIVersion: "v1", Kind: "Secret", Immutable: true, Type: "Opaque"}
	secret.Metadata.Name, secret.Metadata.Namespace = observabilityCredentialSecretName, observabilityCredentialNamespace
	secret.Data = map[string]string{
		"grafana-admin-user":        base64.StdEncoding.EncodeToString(values[0]),
		"grafana-admin-password":    base64.StdEncoding.EncodeToString(values[1]),
		"opensearch-admin-password": base64.StdEncoding.EncodeToString(values[2]),
	}
	raw, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.New("encode observability credential Secret")
	}
	return &observabilityCredentialInstaller{
		endpoint: endpoint, client: &client, token: transport.bearerToken,
		raw: raw, digest: digest.SHA256(raw),
	}, nil
}

func validObservabilityCredentialValue(raw []byte) bool {
	return len(raw) > 0 && len(raw) <= maximumObservabilityCredentialBytes &&
		bytes.IndexAny(raw, "\x00\r\n") < 0 && strings.TrimSpace(string(raw)) == string(raw)
}

func (installer *observabilityCredentialInstaller) Install(ctx context.Context) (ObservabilityCredentialInstallationReceipt, error) {
	receipt := ObservabilityCredentialInstallationReceipt{
		Format: ObservabilityCredentialInstallationReceiptFormat, State: "PREFLIGHT",
		MutationState: "NOT_ATTEMPTED",
	}
	if installer == nil || installer.client == nil || installer.endpoint == nil {
		return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_STOPPED", errors.New("observability credential installer is unavailable"))
	}
	receipt.ObjectDigest = installer.digest
	installer.mu.Lock()
	if installer.used {
		installer.mu.Unlock()
		return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_STOPPED", errors.New("observability credential installer is single-use"))
	}
	installer.used = true
	installer.mu.Unlock()

	objectPath := "/api/v1/namespaces/" + observabilityCredentialNamespace + "/secrets/" + observabilityCredentialSecretName
	raw, status, err := installer.request(ctx, http.MethodGet, objectPath, nil)
	if err != nil {
		return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_STOPPED", err)
	}
	if status == http.StatusOK {
		uid, verifyErr := verifyObservabilityCredentialSecret(raw, installer.raw)
		if verifyErr != nil {
			return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_MISMATCH", verifyErr)
		}
		receipt.State, receipt.UIDDigest = "EXISTING_VERIFIED", digest.SHA256([]byte(uid))
		return receipt, nil
	}
	if status != http.StatusNotFound {
		return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_STOPPED", errors.New("observability credential preflight was rejected"))
	}
	receipt.State, receipt.MutationState = "CREATING", "ATTEMPTED"
	raw, status, err = installer.request(ctx, http.MethodPost, "/api/v1/namespaces/"+observabilityCredentialNamespace+"/secrets", installer.raw)
	if err != nil || status != http.StatusCreated {
		return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_STOPPED", errors.New("observability credential create was not confirmed"))
	}
	uid, err := verifyObservabilityCredentialSecret(raw, installer.raw)
	if err != nil {
		return receipt, newFixedRedactedStop("OBSERVABILITY_CREDENTIAL_INSTALLATION_RESPONSE_INVALID", err)
	}
	receipt.State, receipt.UIDDigest = "CREATED", digest.SHA256([]byte(uid))
	return receipt, nil
}

func (installer *observabilityCredentialInstaller) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *installer.endpoint
	endpoint.Path, endpoint.RawPath = path, ""
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct observability credential request")
	}
	request.Header.Set("Accept", "application/json")
	if installer.token != "" {
		request.Header.Set("Authorization", "Bearer "+installer.token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := installer.client.Do(request)
	if err != nil {
		return nil, 0, errors.New("observability credential transport stopped")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("observability credential response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/json" {
			return nil, 0, errors.New("observability credential response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func verifyObservabilityCredentialSecret(observed, expected []byte) (string, error) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(observed, &envelope) != nil || len(envelope) != 6 {
		return "", errors.New("observability credential response envelope is invalid")
	}
	for _, key := range []string{"apiVersion", "kind", "metadata", "immutable", "type", "data"} {
		if _, present := envelope[key]; !present {
			return "", errors.New("observability credential response envelope is invalid")
		}
	}
	var actual, desired observabilityCredentialSecret
	if json.Unmarshal(observed, &actual) != nil || json.Unmarshal(expected, &desired) != nil {
		return "", errors.New("observability credential response is invalid")
	}
	if actual.APIVersion != desired.APIVersion || actual.Kind != desired.Kind ||
		actual.Metadata.Name != desired.Metadata.Name || actual.Metadata.Namespace != desired.Metadata.Namespace ||
		actual.Metadata.UID == "" || actual.Metadata.ResourceVersion == "" || actual.Immutable != desired.Immutable ||
		actual.Type != desired.Type || len(actual.Data) != 3 {
		return "", errors.New("observability credential response identity differs")
	}
	for key, value := range desired.Data {
		if actual.Data[key] != value {
			return "", errors.New("observability credential response content differs")
		}
	}
	return actual.Metadata.UID, nil
}
