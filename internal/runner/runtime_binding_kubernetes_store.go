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
	"strings"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	KubernetesRuntimeBindingPersistenceReceiptFormat = "ok147-kubernetes-runtime-binding-persistence-receipt/v1"
	maximumRuntimeBindingSecretResponse              = 1024 * 1024
	runtimeBindingSecretDataKey                      = "runtime-binding.json"
)

type KubernetesRuntimeBindingPersistenceReceipt struct {
	Format                   string `json:"format"`
	State                    string `json:"state"`
	PrivateMaterialDigest    string `json:"privateMaterialDigest"`
	ObjectIdentityDigest     string `json:"objectIdentityDigest"`
	AuthorityIdentityDigest  string `json:"authorityIdentityDigest"`
	PersistenceMutationState string `json:"persistenceMutationState"`
	LifecycleMutationAllowed bool   `json:"lifecycleMutationAllowed"`
}

type KubernetesRuntimeBindingStore struct {
	mu        sync.Mutex
	used      bool
	endpoint  *url.URL
	token     string
	client    *http.Client
	namespace string
	name      string
	authority string
}

type runtimeBindingSecret struct {
	APIVersion string                         `json:"apiVersion"`
	Kind       string                         `json:"kind"`
	Metadata   runtimeBindingSecretObjectMeta `json:"metadata"`
	Immutable  bool                           `json:"immutable"`
	Type       string                         `json:"type"`
	Data       map[string][]byte              `json:"data"`
}

type runtimeBindingSecretObjectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
}

// OpenKubernetesRuntimeBindingStore binds one management authority to one
// exact immutable Secret identity. It reads bounded credentials but performs
// no API request.
func OpenKubernetesRuntimeBindingStore(authority KubernetesAuthorityConfig, expectedAuthority, namespace, name string) (*KubernetesRuntimeBindingStore, error) {
	if authority.AuthorityIdentity == "" || authority.AuthorityIdentity != expectedAuthority {
		return nil, errors.New("runtime binding persistence authority differs from management")
	}
	if namespace != submissionStageInputNamespace || !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || !strings.HasPrefix(name, "ok147-runtime-binding-") {
		return nil, errors.New("runtime binding Secret identity is invalid")
	}
	endpoint, err := url.Parse(authority.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("runtime binding persistence endpoint is invalid")
	}
	token, _, client, err := openBoundedKubernetesMaterial(authority.TokenFile, authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded runtime binding persistence credential")
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &KubernetesRuntimeBindingStore{
		endpoint: endpoint, token: token, client: &bounded, namespace: namespace, name: name, authority: authority.AuthorityIdentity,
	}, nil
}

// Store performs one create-if-absent. A conflict is followed by exactly one
// GET-by-name and succeeds only when the immutable Secret is byte-equivalent.
// There is no update, patch, delete, list, watch or retry path.
func (store *KubernetesRuntimeBindingStore) Store(ctx context.Context, material VerifiedRuntimeBindingMaterial) (KubernetesRuntimeBindingPersistenceReceipt, error) {
	receipt := KubernetesRuntimeBindingPersistenceReceipt{
		Format: KubernetesRuntimeBindingPersistenceReceiptFormat, State: "PREWRITE",
		PersistenceMutationState: "NOT_ATTEMPTED", LifecycleMutationAllowed: false,
	}
	if store == nil || store.endpoint == nil || store.client == nil {
		return receipt, errors.New("runtime binding Kubernetes store is required")
	}
	store.mu.Lock()
	if store.used {
		store.mu.Unlock()
		return receipt, errors.New("runtime binding Kubernetes store is single-use")
	}
	store.used = true
	store.mu.Unlock()
	raw, err := material.Bytes()
	if err != nil {
		return receipt, errors.New("runtime binding material is not verified")
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return receipt, errors.New("runtime binding material receipt is invalid")
	}
	receipt.PrivateMaterialDigest = digest.SHA256(raw)
	receipt.ObjectIdentityDigest = digest.SHA256([]byte(store.namespace + "/" + store.name))
	receipt.AuthorityIdentityDigest = digest.SHA256([]byte(store.authority))
	secret := runtimeBindingSecret{
		APIVersion: "v1", Kind: "Secret",
		Metadata: runtimeBindingSecretObjectMeta{
			Name: store.name, Namespace: store.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "ok-cluster-contract-executor", "openkubes.io/stage-id": "runtime-binding",
			},
			Annotations: map[string]string{
				"openkubes.io/content-digest": receipt.PrivateMaterialDigest, "openkubes.io/plan-digest": materialReceipt.PlanDigest,
			},
		},
		Immutable: true, Type: "Opaque", Data: map[string][]byte{runtimeBindingSecretDataKey: raw},
	}
	body, err := json.Marshal(secret)
	if err != nil {
		return receipt, errors.New("encode immutable runtime binding Secret")
	}
	response, status, err := store.request(ctx, http.MethodPost, store.collectionPath(), body)
	receipt.PersistenceMutationState = "ATTEMPTED"
	if err != nil {
		receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
		return receipt, errors.New("create immutable runtime binding Secret failed")
	}
	if status == http.StatusCreated {
		if err := verifyRuntimeBindingSecret(response, secret, true); err != nil {
			receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
			return receipt, errors.New("created runtime binding Secret differs")
		}
		receipt.State = "CREATED_VERIFIED"
		return receipt, nil
	}
	if status != http.StatusConflict {
		receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
		return receipt, fmt.Errorf("create immutable runtime binding Secret returned HTTP %d", status)
	}
	existing, status, err := store.request(ctx, http.MethodGet, store.objectPath(), nil)
	if err != nil || status != http.StatusOK || verifyRuntimeBindingSecret(existing, secret, true) != nil {
		receipt.State = "STOPPED_CONFLICTING_EXISTING"
		return receipt, errors.New("existing runtime binding Secret differs")
	}
	receipt.State = "EXISTING_VERIFIED"
	receipt.PersistenceMutationState = "CONFLICT_OBSERVED"
	return receipt, nil
}

func (store *KubernetesRuntimeBindingStore) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *store.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded runtime binding persistence request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+store.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := store.client.Do(request)
	if err != nil {
		return nil, 0, errors.New("bounded runtime binding persistence request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumRuntimeBindingSecretResponse+1))
	if readErr != nil || len(raw) > maximumRuntimeBindingSecretResponse {
		return nil, 0, errors.New("runtime binding persistence response exceeds accepted size")
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if len(raw) > 0 && (mediaErr != nil || mediaType != "application/json") {
		return nil, 0, errors.New("runtime binding persistence response is not JSON")
	}
	return raw, response.StatusCode, nil
}

func (store *KubernetesRuntimeBindingStore) collectionPath() string {
	return "/api/v1/namespaces/" + store.namespace + "/secrets"
}

func (store *KubernetesRuntimeBindingStore) objectPath() string {
	return store.collectionPath() + "/" + store.name
}

func verifyRuntimeBindingSecret(raw []byte, expected runtimeBindingSecret, requireServerIdentity bool) error {
	var generic map[string]any
	if err := jsonstrict.Decode(raw, &generic); err != nil {
		return err
	}
	var observed runtimeBindingSecret
	if err := json.Unmarshal(raw, &observed); err != nil {
		return err
	}
	if observed.APIVersion != expected.APIVersion || observed.Kind != expected.Kind || observed.Metadata.Name != expected.Metadata.Name || observed.Metadata.Namespace != expected.Metadata.Namespace || observed.Type != expected.Type || !observed.Immutable {
		return errors.New("runtime binding Secret identity differs")
	}
	if requireServerIdentity && (!runtimeInputUIDPattern.MatchString(observed.Metadata.UID) || !runtimeInputUIDPattern.MatchString(observed.Metadata.ResourceVersion)) {
		return errors.New("runtime binding Secret lacks server identity")
	}
	if len(observed.Data) != 1 || !bytes.Equal(observed.Data[runtimeBindingSecretDataKey], expected.Data[runtimeBindingSecretDataKey]) {
		return errors.New("runtime binding Secret payload differs")
	}
	if !equalRuntimeBindingStringMap(observed.Metadata.Labels, expected.Metadata.Labels) || !equalRuntimeBindingStringMap(observed.Metadata.Annotations, expected.Metadata.Annotations) {
		return errors.New("runtime binding Secret metadata differs")
	}
	return nil
}

func equalRuntimeBindingStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}
