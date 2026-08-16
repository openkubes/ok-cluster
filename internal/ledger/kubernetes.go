package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

const receiptDataKey = "receipt.json"

// KubernetesStoreConfig contains an already trust-configured HTTP client and a
// short-lived bearer token. TLS and credential materialization stay outside the
// ledger so local CLI and in-cluster Job adapters can use different sources.
type KubernetesStoreConfig struct {
	Endpoint    string
	Namespace   string
	BearerToken string
	Client      *http.Client
}

// KubernetesStore persists immutable receipts as exact-name ConfigMaps. It
// performs only POST collection creates and GET-by-name requests.
type KubernetesStore struct {
	endpoint  *url.URL
	namespace string
	token     string
	client    *http.Client
}

// NewKubernetesStore validates the transport boundary. Non-TLS endpoints are
// accepted only for loopback test servers.
func NewKubernetesStore(config KubernetesStoreConfig) (*KubernetesStore, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("Kubernetes ledger endpoint is invalid")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("Kubernetes ledger endpoint must not contain a path")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("Kubernetes ledger endpoint must use HTTPS")
	}
	if !regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`).MatchString(config.Namespace) || len(config.Namespace) > 63 {
		return nil, errors.New("Kubernetes ledger namespace is invalid")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") {
		return nil, errors.New("Kubernetes ledger bearer token is invalid")
	}
	if config.Client == nil {
		return nil, errors.New("Kubernetes ledger requires an explicitly configured HTTP client")
	}
	client := *config.Client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path = ""
	return &KubernetesStore{endpoint: endpoint, namespace: config.Namespace, token: config.BearerToken, client: &client}, nil
}

func (store *KubernetesStore) Create(ctx context.Context, category, key string, raw []byte) error {
	name, recordType, err := kubernetesRecordIdentity(category, key)
	if err != nil {
		return err
	}
	if err := validateCanonicalReceipt(raw); err != nil {
		return err
	}
	object := configMap{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: objectMeta{
			Name:      name,
			Namespace: store.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "ok-cluster-contract-executor",
				"openkubes.io/ledger-record":   recordType,
			},
			Annotations: map[string]string{
				"openkubes.io/record-key":     key,
				"openkubes.io/content-digest": digest.SHA256(raw),
			},
		},
		Immutable: boolPointer(true),
		Data:      map[string]string{receiptDataKey: string(raw)},
	}
	body, err := json.Marshal(object)
	if err != nil {
		return err
	}
	response, status, err := store.request(ctx, http.MethodPost, store.collectionPath(), body)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		return ErrRecordExists
	}
	if status != http.StatusCreated {
		return apiStatusError(http.MethodPost, status, response)
	}
	return verifyConfigMap(response, object, raw, true)
}

func (store *KubernetesStore) Get(ctx context.Context, category, key string) ([]byte, error) {
	name, recordType, err := kubernetesRecordIdentity(category, key)
	if err != nil {
		return nil, err
	}
	expected := configMap{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: objectMeta{
			Name: name, Namespace: store.namespace,
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "ok-cluster-contract-executor", "openkubes.io/ledger-record": recordType},
			Annotations: map[string]string{"openkubes.io/record-key": key},
		},
	}
	response, status, err := store.request(ctx, http.MethodGet, store.objectPath(name), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrRecordNotFound
	}
	if status != http.StatusOK {
		return nil, apiStatusError(http.MethodGet, status, response)
	}
	var observed configMap
	if err := json.Unmarshal(response, &observed); err != nil {
		return nil, errors.New("Kubernetes API returned an invalid ConfigMap")
	}
	raw, ok := observed.Data[receiptDataKey]
	if !ok {
		return nil, errors.New("Kubernetes ledger ConfigMap has no receipt.json")
	}
	expected.Metadata.Annotations["openkubes.io/content-digest"] = digest.SHA256([]byte(raw))
	expected.Immutable = boolPointer(true)
	expected.Data = map[string]string{receiptDataKey: raw}
	if err := verifyConfigMap(response, expected, []byte(raw), true); err != nil {
		return nil, err
	}
	if err := validateCanonicalReceipt([]byte(raw)); err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

type objectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

type configMap struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   objectMeta        `json:"metadata"`
	Immutable  *bool             `json:"immutable,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
	BinaryData map[string]string `json:"binaryData,omitempty"`
}

func (store *KubernetesStore) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *store.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+store.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := store.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("Kubernetes ledger %s request failed", method)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read Kubernetes ledger response: %w", err)
	}
	return raw, response.StatusCode, nil
}

func (store *KubernetesStore) collectionPath() string {
	return "/api/v1/namespaces/" + store.namespace + "/configmaps"
}

func (store *KubernetesStore) objectPath(name string) string {
	return store.collectionPath() + "/" + name
}

func kubernetesRecordIdentity(category, key string) (string, string, error) {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) {
		return "", "", errors.New("Kubernetes ledger record key is invalid")
	}
	var recordType string
	switch category {
	case "claims":
		recordType = "claim"
	case "outcomes":
		recordType = "outcome"
	default:
		return "", "", fmt.Errorf("Kubernetes ledger record category %q is invalid", category)
	}
	return "ok147-" + recordType + "-" + key[:48], recordType, nil
}

func validateCanonicalReceipt(raw []byte) error {
	if len(raw) == 0 || len(raw) > 256*1024 {
		return errors.New("Kubernetes ledger receipt size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("Kubernetes ledger receipt is invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("Kubernetes ledger receipt has trailing JSON")
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return fmt.Errorf("canonicalize Kubernetes ledger receipt: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return errors.New("Kubernetes ledger receipt is not canonical JSON")
	}
	return nil
}

func verifyConfigMap(raw []byte, expected configMap, receipt []byte, requireServerIdentity bool) error {
	var observed configMap
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&observed); err != nil {
		return errors.New("Kubernetes API returned an invalid ConfigMap")
	}
	if observed.APIVersion != expected.APIVersion || observed.Kind != expected.Kind || observed.Metadata.Name != expected.Metadata.Name || observed.Metadata.Namespace != expected.Metadata.Namespace {
		return errors.New("Kubernetes API returned a different ledger ConfigMap identity")
	}
	if requireServerIdentity && (observed.Metadata.UID == "" || observed.Metadata.ResourceVersion == "") {
		return errors.New("Kubernetes API response lacks ConfigMap UID or resourceVersion")
	}
	if observed.Immutable == nil || !*observed.Immutable || len(observed.BinaryData) != 0 || len(observed.Data) != 1 || observed.Data[receiptDataKey] != string(receipt) {
		return errors.New("Kubernetes ledger ConfigMap payload or immutable flag differs")
	}
	for key, value := range expected.Metadata.Labels {
		if observed.Metadata.Labels[key] != value {
			return fmt.Errorf("Kubernetes ledger ConfigMap label %s differs", key)
		}
	}
	if len(observed.Metadata.Labels) != len(expected.Metadata.Labels) {
		return errors.New("Kubernetes ledger ConfigMap has unexpected labels")
	}
	for key, value := range expected.Metadata.Annotations {
		if observed.Metadata.Annotations[key] != value {
			return fmt.Errorf("Kubernetes ledger ConfigMap annotation %s differs", key)
		}
	}
	if len(observed.Metadata.Annotations) != len(expected.Metadata.Annotations) {
		return errors.New("Kubernetes ledger ConfigMap has unexpected annotations")
	}
	return nil
}

func apiStatusError(method string, status int, raw []byte) error {
	var response struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &response)
	if response.Reason == "" {
		response.Reason = http.StatusText(status)
	}
	return fmt.Errorf("Kubernetes ledger %s returned status %d (%s)", method, status, response.Reason)
}

func boolPointer(value bool) *bool { return &value }
