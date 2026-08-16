package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const (
	CapabilityFixtureReceiptFormat = "ok147-capability-fixture-receipt/v1"
	maximumCapabilityAPIBytes      = 4 * 1024 * 1024
)

type KubernetesCapabilityFixtureClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
}

type CapabilityFixtureObjectResult struct {
	Identity CapabilityObjectIdentity `json:"identity"`
	Digest   string                   `json:"digest"`
	UID      string                   `json:"uid"`
	State    string                   `json:"state"`
}

type CapabilityFixtureReceipt struct {
	Format        string                          `json:"format"`
	FixtureDigest string                          `json:"fixtureDigest"`
	State         string                          `json:"state"`
	MutationState string                          `json:"mutationState"`
	Results       []CapabilityFixtureObjectResult `json:"results"`
}

// KubernetesCapabilityFixtureClient freezes one generated fixture and one
// workload authority. Create and cleanup accept no manifests, names or paths.
type KubernetesCapabilityFixtureClient struct {
	endpoint *url.URL
	token    string
	client   *http.Client
	fixture  ObservabilitySyntheticFixture
}

func NewKubernetesCapabilityFixtureClient(config KubernetesCapabilityFixtureClientConfig, run ObservabilityCapabilityRun, fixtureConfig ObservabilitySyntheticFixtureConfig) (*KubernetesCapabilityFixtureClient, error) {
	if config.AuthorityIdentity != run.TargetClusterUID {
		return nil, errors.New("capability fixture authority differs from runtime-bound target")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("capability fixture Kubernetes endpoint is invalid")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("capability fixture Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("capability fixture Kubernetes credential or client is invalid")
	}
	fixture, err := BuildObservabilitySyntheticFixture(run, fixtureConfig)
	if err != nil {
		return nil, errors.New("build bound observability synthetic fixture")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesCapabilityFixtureClient{endpoint: endpoint, token: config.BearerToken, client: &client, fixture: cloneSyntheticFixture(fixture)}, nil
}

func (client *KubernetesCapabilityFixtureClient) FixtureDigest() string {
	if client == nil {
		return ""
	}
	return client.fixture.FixtureDigest
}

// Create performs all exact absence GETs before the first collection POST.
// Existing state therefore causes a zero-write stop rather than adoption.
func (client *KubernetesCapabilityFixtureClient) Create(ctx context.Context) (CapabilityFixtureReceipt, error) {
	receipt := client.newReceipt("PREFLIGHT", "NOT_ATTEMPTED")
	if client == nil || client.client == nil {
		return receipt, errors.New("capability fixture client is required")
	}
	for _, object := range client.fixture.Objects {
		_, status, err := client.request(ctx, http.MethodGet, object.ObjectPath, nil)
		if err != nil {
			return stoppedCapabilityFixture(receipt, err)
		}
		if status != http.StatusNotFound {
			if status == http.StatusOK {
				return stoppedCapabilityFixture(receipt, errors.New("synthetic capability object already exists; zero-write preflight stopped"))
			}
			return stoppedCapabilityFixture(receipt, capabilityStatusError(http.MethodGet, status))
		}
	}
	receipt.State = "CREATING"
	for _, object := range client.fixture.Objects {
		receipt.MutationState = "ATTEMPTED"
		raw, status, err := client.request(ctx, http.MethodPost, object.CollectionPath, object.Raw)
		if err != nil {
			return stoppedCapabilityFixture(receipt, err)
		}
		if status != http.StatusCreated {
			return stoppedCapabilityFixture(receipt, capabilityStatusError(http.MethodPost, status))
		}
		uid, _, err := verifyCapabilityObject(raw, object)
		if err != nil {
			return stoppedCapabilityFixture(receipt, errors.New("created synthetic capability object differs from fixture"))
		}
		receipt.Results = append(receipt.Results, CapabilityFixtureObjectResult{Identity: object.Identity, Digest: object.Digest, UID: uid, State: "CREATED"})
	}
	receipt.State = "CREATED"
	return receipt, nil
}

// Cleanup removes only the successfully created receipt prefix, in reverse
// order. Each DELETE is bound to the observed UID and current resourceVersion.
func (client *KubernetesCapabilityFixtureClient) Cleanup(ctx context.Context, created CapabilityFixtureReceipt) (CapabilityFixtureReceipt, error) {
	receipt := client.newReceipt("CLEANING", "NOT_ATTEMPTED")
	validCreatedState := created.State == "CREATED" || created.State == "STOPPED_PARTIAL_OR_UNKNOWN"
	if client == nil || client.client == nil || created.Format != CapabilityFixtureReceiptFormat || created.FixtureDigest != client.fixture.FixtureDigest || !validCreatedState || created.MutationState != "ATTEMPTED" || len(created.Results) == 0 || len(created.Results) > len(client.fixture.Objects) {
		return receipt, errors.New("capability fixture cleanup receipt is invalid")
	}
	for index := range created.Results {
		expected := client.fixture.Objects[index]
		result := created.Results[index]
		if result.Identity != expected.Identity || result.Digest != expected.Digest || result.State != "CREATED" || !runtimeInputUIDPattern.MatchString(result.UID) {
			return stoppedCapabilityFixture(receipt, errors.New("capability fixture cleanup identity differs from created prefix"))
		}
	}
	for index := len(created.Results) - 1; index >= 0; index-- {
		object := client.fixture.Objects[index]
		createdResult := created.Results[index]
		raw, status, err := client.request(ctx, http.MethodGet, object.ObjectPath, nil)
		if err != nil {
			return stoppedCapabilityFixture(receipt, err)
		}
		if status != http.StatusOK {
			return stoppedCapabilityFixture(receipt, capabilityStatusError(http.MethodGet, status))
		}
		uid, resourceVersion, err := verifyCapabilityObject(raw, object)
		if err != nil || uid != createdResult.UID {
			return stoppedCapabilityFixture(receipt, errors.New("synthetic capability cleanup target identity changed"))
		}
		deleteOptions, err := json.Marshal(map[string]any{
			"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
			"preconditions": map[string]any{"uid": uid, "resourceVersion": resourceVersion},
		})
		if err != nil {
			return stoppedCapabilityFixture(receipt, errors.New("encode capability fixture delete preconditions"))
		}
		receipt.MutationState = "ATTEMPTED"
		_, status, err = client.request(ctx, http.MethodDelete, object.ObjectPath, deleteOptions)
		if err != nil {
			return stoppedCapabilityFixture(receipt, err)
		}
		if status != http.StatusOK && status != http.StatusAccepted {
			return stoppedCapabilityFixture(receipt, capabilityStatusError(http.MethodDelete, status))
		}
		receipt.Results = append(receipt.Results, CapabilityFixtureObjectResult{Identity: object.Identity, Digest: object.Digest, UID: uid, State: "DELETE_ACCEPTED"})
	}
	receipt.State = "CLEANUP_ACCEPTED"
	return receipt, nil
}

func (client *KubernetesCapabilityFixtureClient) newReceipt(state, mutation string) CapabilityFixtureReceipt {
	digestValue := ""
	if client != nil {
		digestValue = client.fixture.FixtureDigest
	}
	return CapabilityFixtureReceipt{Format: CapabilityFixtureReceiptFormat, FixtureDigest: digestValue, State: state, MutationState: mutation, Results: []CapabilityFixtureObjectResult{}}
}

func stoppedCapabilityFixture(receipt CapabilityFixtureReceipt, err error) (CapabilityFixtureReceipt, error) {
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	return receipt, err
}

func (client *KubernetesCapabilityFixtureClient) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *client.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded capability fixture request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded capability fixture %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumCapabilityAPIBytes+1))
	if readErr != nil || len(raw) > maximumCapabilityAPIBytes {
		return nil, 0, errors.New("bounded capability fixture response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded capability fixture response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func verifyCapabilityObject(raw []byte, expected CapabilityObject) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	desired, err := decodeCapabilityJSONObject(expected.Raw)
	if err != nil || !capabilitySubset(desired, observed) {
		return "", "", errors.New("observed object does not contain exact fixture fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if !runtimeInputUIDPattern.MatchString(uid) || resourceVersion == "" {
		return "", "", errors.New("observed object lacks runtime identity")
	}
	return uid, resourceVersion, nil
}

func decodeCapabilityJSONObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

func capabilitySubset(expected, observed any) bool {
	switch expectedValue := expected.(type) {
	case map[string]any:
		observedValue, ok := observed.(map[string]any)
		if !ok {
			return false
		}
		for key, expectedChild := range expectedValue {
			observedChild, exists := observedValue[key]
			if !exists || !capabilitySubset(expectedChild, observedChild) {
				return false
			}
		}
		return true
	case []any:
		observedValue, ok := observed.([]any)
		if !ok || len(expectedValue) != len(observedValue) {
			return false
		}
		for index := range expectedValue {
			if !capabilitySubset(expectedValue[index], observedValue[index]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(expected, observed)
	}
}

func capabilityStatusError(method string, status int) error {
	return fmt.Errorf("bounded capability fixture %s returned HTTP %d", method, status)
}

func cloneSyntheticFixture(fixture ObservabilitySyntheticFixture) ObservabilitySyntheticFixture {
	fixture.Objects = append([]CapabilityObject(nil), fixture.Objects...)
	for index := range fixture.Objects {
		fixture.Objects[index].Raw = append(json.RawMessage(nil), fixture.Objects[index].Raw...)
	}
	return fixture
}
