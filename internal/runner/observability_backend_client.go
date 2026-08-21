package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maximumObservabilityBackendResponseBytes = 4 * 1024 * 1024

var grafanaDatasourceUIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type KubernetesObservabilityBackendClientConfig struct {
	Endpoint          string
	ClientCertificate bool
	AuthorityIdentity string
	Client            *http.Client
	Profile           ObservabilityCapabilityCheckProfile
}

type kubernetesObservabilityBackendClient struct {
	endpoint          *url.URL
	authorityIdentity string
	client            *http.Client
	profile           ObservabilityCapabilityCheckProfile
}

type observabilityBackendCredentials struct {
	grafanaUser        string
	grafanaPassword    string
	opensearchPassword string
}

type observabilityBackendResponse struct {
	status int
	raw    []byte
}

// newKubernetesObservabilityBackendClient opens an mTLS-only client for the
// fixed standard profile. mTLS leaves the HTTP Authorization header available
// for the profile's upstream Basic-Auth services without weakening Kubernetes
// API authentication. Opening performs no request.
func newKubernetesObservabilityBackendClient(config KubernetesObservabilityBackendClientConfig) (*kubernetesObservabilityBackendClient, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || config.Client == nil || !config.ClientCertificate || !runtimeInputUIDPattern.MatchString(config.AuthorityIdentity) ||
		config.Profile.Digest() == "" || config.Profile.Digest() != standard.Digest() {
		return nil, errors.New("Kubernetes observability backend binding is invalid")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("Kubernetes observability backend endpoint is invalid")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("Kubernetes observability backend endpoint must use HTTPS")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &kubernetesObservabilityBackendClient{endpoint: endpoint, authorityIdentity: config.AuthorityIdentity, client: &client, profile: config.Profile}, nil
}

func (client *kubernetesObservabilityBackendClient) credentials(ctx context.Context, run ObservabilityCapabilityRun) (observabilityBackendCredentials, error) {
	if err := client.validateRun(run); err != nil {
		return observabilityBackendCredentials{}, err
	}
	path := "/api/v1/namespaces/" + client.profile.namespace + "/secrets/" + client.profile.credentialsSecret
	response, err := client.request(ctx, http.MethodGet, path, nil, nil, "", "", true)
	if err != nil || response.status != http.StatusOK {
		return observabilityBackendCredentials{}, errors.New("read exact observability credential Secret")
	}
	var secret struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Data       map[string]string `json:"data"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(response.raw, &secret); err != nil || secret.APIVersion != "v1" || secret.Kind != "Secret" ||
		secret.Metadata.Name != client.profile.credentialsSecret || secret.Metadata.Namespace != client.profile.namespace || len(secret.Data) != 3 {
		return observabilityBackendCredentials{}, errors.New("observability credential Secret identity is invalid")
	}
	decode := func(key string) (string, error) {
		encoded, ok := secret.Data[key]
		if !ok || encoded == "" {
			return "", errors.New("missing credential key")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) == 0 || len(raw) > maximumTokenBytes || bytes.IndexByte(raw, 0) >= 0 {
			return "", errors.New("invalid credential value")
		}
		return string(raw), nil
	}
	user, userErr := decode(client.profile.grafanaUserKey)
	grafanaPassword, grafanaErr := decode(client.profile.grafanaPasswordKey)
	opensearchPassword, opensearchErr := decode(client.profile.opensearchPasswordKey)
	if userErr != nil || grafanaErr != nil || opensearchErr != nil {
		return observabilityBackendCredentials{}, errors.New("observability credential Secret data is invalid")
	}
	return observabilityBackendCredentials{grafanaUser: user, grafanaPassword: grafanaPassword, opensearchPassword: opensearchPassword}, nil
}

func (client *kubernetesObservabilityBackendClient) dashboard(ctx context.Context, run ObservabilityCapabilityRun) (observabilityBackendResponse, error) {
	if err := client.validateRun(run); err != nil {
		return observabilityBackendResponse{}, err
	}
	path := "/api/v1/namespaces/" + client.profile.namespace + "/configmaps/" + client.profile.dashboardConfigMap
	return client.request(ctx, http.MethodGet, path, nil, nil, "", "", true)
}

func (client *kubernetesObservabilityBackendClient) pushMetrics(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (observabilityBackendResponse, error) {
	if err := client.validateFixture(run, fixture); err != nil {
		return observabilityBackendResponse{}, err
	}
	body := []byte(fmt.Sprintf("%s 1\n%s 1\n", fixture.MetricName, fixture.AlertTriggerMetric))
	path := client.serviceProxyPath(observabilityServiceBinding{Name: fixture.MetricsWorkload, Port: 9091, Scheme: "http"}, "metrics/job/"+fixture.MetricsWorkload)
	return client.request(ctx, http.MethodPost, path, nil, body, "", "", false)
}

func (client *kubernetesObservabilityBackendClient) prometheusQuery(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (observabilityBackendResponse, error) {
	if err := client.validateFixture(run, fixture); err != nil {
		return observabilityBackendResponse{}, err
	}
	query := url.Values{"query": []string{fixture.MetricName}}
	return client.request(ctx, http.MethodGet, client.serviceProxyPath(client.profile.prometheus, "api/v1/query"), query, nil, "", "", true)
}

func (client *kubernetesObservabilityBackendClient) grafanaDatasources(ctx context.Context, run ObservabilityCapabilityRun, credentials observabilityBackendCredentials) (observabilityBackendResponse, error) {
	if err := client.validateRun(run); err != nil || credentials.grafanaUser == "" || credentials.grafanaPassword == "" {
		return observabilityBackendResponse{}, errors.New("Grafana capability request binding is invalid")
	}
	return client.request(ctx, http.MethodGet, client.serviceProxyPath(client.profile.grafana, "api/datasources"), nil, nil, credentials.grafanaUser, credentials.grafanaPassword, true)
}

func (client *kubernetesObservabilityBackendClient) grafanaQuery(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, datasourceUID string, credentials observabilityBackendCredentials) (observabilityBackendResponse, error) {
	if err := client.validateFixture(run, fixture); err != nil || !grafanaDatasourceUIDPattern.MatchString(datasourceUID) || credentials.grafanaUser == "" || credentials.grafanaPassword == "" {
		return observabilityBackendResponse{}, errors.New("Grafana datasource capability request binding is invalid")
	}
	query := url.Values{"query": []string{fixture.MetricName}}
	path := client.serviceProxyPath(client.profile.grafana, "api/datasources/proxy/uid/"+datasourceUID+"/api/v1/query")
	return client.request(ctx, http.MethodGet, path, query, nil, credentials.grafanaUser, credentials.grafanaPassword, true)
}

func (client *kubernetesObservabilityBackendClient) searchLogs(ctx context.Context, run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture, credentials observabilityBackendCredentials) (observabilityBackendResponse, error) {
	if err := client.validateFixture(run, fixture); err != nil || credentials.opensearchPassword == "" {
		return observabilityBackendResponse{}, errors.New("OpenSearch capability request binding is invalid")
	}
	body, _ := json.Marshal(map[string]any{"query": map[string]any{"match_phrase": map[string]any{"log": fixture.LogMarker}}})
	path := client.serviceProxyPath(client.profile.opensearch, client.profile.logIndexPattern+"/_search")
	return client.request(ctx, http.MethodPost, path, nil, body, "admin", credentials.opensearchPassword, true)
}

func (client *kubernetesObservabilityBackendClient) alerts(ctx context.Context, run ObservabilityCapabilityRun) (observabilityBackendResponse, error) {
	if err := client.validateRun(run); err != nil {
		return observabilityBackendResponse{}, err
	}
	return client.request(ctx, http.MethodGet, client.serviceProxyPath(client.profile.alertmanager, "api/v2/alerts"), nil, nil, "", "", true)
}

func (client *kubernetesObservabilityBackendClient) validateRun(run ObservabilityCapabilityRun) error {
	if client == nil || client.client == nil || validateObservabilityCapabilityRun(run) != nil || run.TargetClusterUID != client.authorityIdentity || run.Namespace != client.profile.namespace {
		return errors.New("observability backend run differs from bound authority")
	}
	return nil
}

func (client *kubernetesObservabilityBackendClient) validateFixture(run ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) error {
	if err := client.validateRun(run); err != nil || fixture.RunID != run.RunID || fixture.Namespace != run.Namespace {
		return errors.New("observability backend fixture differs from run")
	}
	digestValue, err := ObservabilitySyntheticFixtureDigest(fixture)
	if err != nil || digestValue != fixture.FixtureDigest {
		return errors.New("observability backend fixture identity is invalid")
	}
	return nil
}

func (client *kubernetesObservabilityBackendClient) serviceProxyPath(service observabilityServiceBinding, suffix string) string {
	return "/api/v1/namespaces/" + client.profile.namespace + "/services/" + service.Scheme + ":" + service.Name + ":" + fmt.Sprint(service.Port) + "/proxy/" + suffix
}

func (client *kubernetesObservabilityBackendClient) request(ctx context.Context, method, path string, query url.Values, body []byte, basicUser, basicPassword string, requireJSON bool) (observabilityBackendResponse, error) {
	endpoint := *client.endpoint
	endpoint.Path = path
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return observabilityBackendResponse{}, errors.New("construct bounded observability backend request")
	}
	request.Header.Set("Accept", "application/json")
	if basicUser != "" || basicPassword != "" {
		request.SetBasicAuth(basicUser, basicPassword)
	}
	if body != nil {
		if requireJSON {
			request.Header.Set("Content-Type", "application/json")
		} else {
			request.Header.Set("Content-Type", "text/plain; version=0.0.4")
		}
	}
	response, err := client.client.Do(request)
	if err != nil {
		return observabilityBackendResponse{}, errors.New("bounded observability backend request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumObservabilityBackendResponseBytes+1))
	if readErr != nil || len(raw) > maximumObservabilityBackendResponseBytes {
		return observabilityBackendResponse{}, errors.New("bounded observability backend response exceeds accepted size")
	}
	if requireJSON && len(raw) > 0 {
		mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" {
			return observabilityBackendResponse{}, errors.New("bounded observability backend response is not JSON")
		}
	}
	return observabilityBackendResponse{status: response.StatusCode, raw: raw}, nil
}

func validObservabilityCredential(value string) bool {
	return value != "" && strings.IndexByte(value, 0) < 0
}
