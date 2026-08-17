package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	runtimeBindingKubeSystemPath = "/api/v1/namespaces/kube-system"
	runtimeBindingLocalPathPath  = "/apis/storage.k8s.io/v1/storageclasses/local-path"
	maximumRuntimeBindingSource  = 1024 * 1024
)

type KubernetesRuntimeBindingSource struct {
	endpoint *url.URL
	token    string
	client   *http.Client
}

// OpenKubernetesRuntimeBindingSource opens one short-lived, read-only workload
// authority and fixes its request surface to the two runtime-binding GETs. It
// reads credential files but performs no API request.
func OpenKubernetesRuntimeBindingSource(authority KubernetesAuthorityConfig, binding WorkloadAuthorityBinding) (*KubernetesRuntimeBindingSource, error) {
	source, _, err := openKubernetesRuntimeBindingSource(authority, binding)
	return source, err
}

// openKubernetesRuntimeBindingSource also returns the bounded token so stage
// composition can prove that workload reads and ledger writes use distinct
// credentials. The token never leaves this package or enters evidence.
func openKubernetesRuntimeBindingSource(authority KubernetesAuthorityConfig, binding WorkloadAuthorityBinding) (*KubernetesRuntimeBindingSource, string, error) {
	if err := validateWorkloadAuthorityBinding(binding); err != nil {
		return nil, "", errors.New("runtime binding workload authority is invalid")
	}
	if authority.Endpoint != binding.Endpoint || authority.AuthorityIdentity != binding.TargetClusterUID || authority.CABundleDigest != binding.CABundleDigest {
		return nil, "", errors.New("runtime binding source differs from workload authority")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(authority.TokenFile, authority.CAFile)
	if err != nil {
		return nil, "", errors.New("open bounded runtime binding credential")
	}
	if digest.SHA256(ca) != binding.CABundleDigest {
		return nil, "", errors.New("runtime binding source CA differs from workload authority")
	}
	source, err := newKubernetesRuntimeBindingSource(authority.Endpoint, token, client)
	if err != nil {
		return nil, "", err
	}
	return source, token, nil
}

func newKubernetesRuntimeBindingSource(endpoint, token string, client *http.Client) (*KubernetesRuntimeBindingSource, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("runtime binding Kubernetes endpoint is invalid")
	}
	host := parsed.Hostname()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("runtime binding Kubernetes endpoint must use HTTPS")
	}
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") || client == nil {
		return nil, errors.New("runtime binding credential or client is invalid")
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if bounded.Timeout == 0 {
		bounded.Timeout = 15 * time.Second
	}
	parsed.Path, parsed.RawPath = "", ""
	return &KubernetesRuntimeBindingSource{endpoint: parsed, token: token, client: &bounded}, nil
}

// Observe performs exactly the namespace GET followed by the StorageClass GET.
// It exposes only the immutable fields consumed by runtime materialization.
func (source *KubernetesRuntimeBindingSource) Observe(ctx context.Context) (RuntimeBindingObservation, error) {
	if source == nil || source.endpoint == nil || source.client == nil {
		return RuntimeBindingObservation{}, errors.New("runtime binding source is required")
	}
	namespaceRaw, err := source.get(ctx, runtimeBindingKubeSystemPath)
	if err != nil {
		return RuntimeBindingObservation{}, errors.New("read bounded kube-system identity")
	}
	namespace, err := decodeRuntimeBindingObject(namespaceRaw)
	if err != nil || namespace.kind != "Namespace" || !runtimeInputUIDPattern.MatchString(namespace.uid) {
		return RuntimeBindingObservation{}, errors.New("kube-system identity is invalid")
	}
	storageRaw, err := source.get(ctx, runtimeBindingLocalPathPath)
	if err != nil {
		return RuntimeBindingObservation{}, errors.New("read bounded local-path identity")
	}
	storage, err := decodeRuntimeBindingObject(storageRaw)
	if err != nil || storage.kind != "StorageClass" || !runtimeInputUIDPattern.MatchString(storage.uid) || storage.provisioner != "rancher.io/local-path" {
		return RuntimeBindingObservation{}, errors.New("local-path identity is invalid")
	}
	return RuntimeBindingObservation{
		KubeSystemUID: namespace.uid, LocalPathStorageClassUID: storage.uid, LocalPathProvisioner: storage.provisioner,
	}, nil
}

func (source *KubernetesRuntimeBindingSource) get(ctx context.Context, path string) ([]byte, error) {
	if path != runtimeBindingKubeSystemPath && path != runtimeBindingLocalPathPath {
		return nil, errors.New("runtime binding path is outside the fixed allowlist")
	}
	endpoint := *source.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("construct bounded runtime binding request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+source.token)
	response, err := source.client.Do(request)
	if err != nil {
		return nil, errors.New("bounded runtime binding request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumRuntimeBindingSource+1))
	if readErr != nil || len(raw) > maximumRuntimeBindingSource {
		return nil, errors.New("bounded runtime binding response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bounded runtime binding request returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("bounded runtime binding response is not JSON")
	}
	return raw, nil
}

type runtimeBindingObject struct {
	kind        string
	uid         string
	provisioner string
}

func decodeRuntimeBindingObject(raw []byte) (runtimeBindingObject, error) {
	var value map[string]any
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return runtimeBindingObject{}, err
	}
	kind, ok := value["kind"].(string)
	if !ok {
		return runtimeBindingObject{}, errors.New("runtime object kind is missing")
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return runtimeBindingObject{}, errors.New("runtime object metadata is missing")
	}
	uid, ok := metadata["uid"].(string)
	if !ok {
		return runtimeBindingObject{}, errors.New("runtime object UID is missing")
	}
	provisioner, _ := value["provisioner"].(string)
	return runtimeBindingObject{kind: kind, uid: uid, provisioner: provisioner}, nil
}
