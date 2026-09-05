package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	runtimeBindingKubeSystemPath  = "/api/v1/namespaces/kube-system"
	runtimeBindingLocalPathPath   = "/apis/storage.k8s.io/v1/storageclasses/local-path"
	maximumRuntimeBindingSource   = 1024 * 1024
	runtimeBindingPollInterval    = 5 * time.Second
	runtimeBindingPollTimeout     = 30 * time.Minute
	runtimeBindingMaximumAttempts = 361
)

type runtimeBindingWaiter func(context.Context, time.Duration) error

type runtimeBindingSourceError struct {
	transient bool
	missing   bool
	resource  string
}

func (err *runtimeBindingSourceError) Error() string { return "bounded runtime binding source stopped" }

type KubernetesRuntimeBindingSource struct {
	endpoint          *url.URL
	token             string
	clientCertificate bool
	client            *http.Client
	clock             func() time.Time
	wait              runtimeBindingWaiter
	interval          time.Duration
	timeout           time.Duration
	maximumAttempts   int
}

// OpenKubernetesRuntimeBindingSource opens one short-lived, read-only workload
// authority and fixes its request surface to the two runtime-binding GETs. It
// reads credential files but performs no API request.
func OpenKubernetesRuntimeBindingSource(authority KubernetesAuthorityConfig, binding WorkloadAuthorityBinding) (*KubernetesRuntimeBindingSource, error) {
	source, _, err := openKubernetesRuntimeBindingSource(authority, binding)
	return source, err
}

// openKubernetesRuntimeBindingSource also returns a private credential
// identity so stage composition can prove that workload reads and ledger
// writes use distinct credentials. It never enters evidence.
func openKubernetesRuntimeBindingSource(authority KubernetesAuthorityConfig, binding WorkloadAuthorityBinding) (*KubernetesRuntimeBindingSource, string, error) {
	if err := validateWorkloadAuthorityBinding(binding); err != nil {
		return nil, "", errors.New("runtime binding workload authority is invalid")
	}
	if authority.Endpoint != binding.Endpoint || authority.AuthorityIdentity != binding.TargetClusterUID || authority.CABundleDigest != binding.CABundleDigest {
		return nil, "", errors.New("runtime binding source differs from workload authority")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(authority)
	if err != nil {
		return nil, "", errors.New("open bounded runtime binding credential")
	}
	if digest.SHA256(transport.caData) != binding.CABundleDigest {
		return nil, "", errors.New("runtime binding source CA differs from workload authority")
	}
	source, err := newKubernetesRuntimeBindingSourceWithTransport(authority.Endpoint, transport)
	if err != nil {
		return nil, "", err
	}
	return source, transport.credentialIdentity, nil
}

func newKubernetesRuntimeBindingSource(endpoint, token string, client *http.Client) (*KubernetesRuntimeBindingSource, error) {
	return newKubernetesRuntimeBindingSourceWithTransport(endpoint, boundedKubernetesTransport{
		bearerToken: token, credentialIdentity: token, client: client,
	})
}

func newKubernetesRuntimeBindingSourceWithTransport(endpoint string, transport boundedKubernetesTransport) (*KubernetesRuntimeBindingSource, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("runtime binding Kubernetes endpoint is invalid")
	}
	host := parsed.Hostname()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("runtime binding Kubernetes endpoint must use HTTPS")
	}
	tokenMode := transport.bearerToken != ""
	if tokenMode == transport.clientCertificate || strings.TrimSpace(transport.bearerToken) != transport.bearerToken ||
		strings.ContainsAny(transport.bearerToken, "\r\n") || transport.client == nil {
		return nil, errors.New("runtime binding credential or client is invalid")
	}
	bounded := *transport.client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if bounded.Timeout == 0 {
		bounded.Timeout = 15 * time.Second
	}
	parsed.Path, parsed.RawPath = "", ""
	return &KubernetesRuntimeBindingSource{
		endpoint: parsed, token: transport.bearerToken, clientCertificate: transport.clientCertificate, client: &bounded,
		clock: time.Now, wait: WaitWithTimer, interval: runtimeBindingPollInterval, timeout: runtimeBindingPollTimeout,
		maximumAttempts: runtimeBindingMaximumAttempts,
	}, nil
}

// Observe polls only the two fixed read-only identities within hard time and
// attempt bounds. Permanent identity or response failures remain fail-closed.
func (source *KubernetesRuntimeBindingSource) Observe(ctx context.Context) (RuntimeBindingObservation, error) {
	if source == nil || source.endpoint == nil || source.client == nil || source.clock == nil || source.wait == nil ||
		source.interval < time.Second || source.timeout < source.interval || source.maximumAttempts < 1 {
		return RuntimeBindingObservation{}, errors.New("runtime binding source is required")
	}
	deadline := source.clock().Add(source.timeout)
	namespaceSeen, storageSeen := false, false
	namespaceUID := ""
	for attempt := 1; attempt <= source.maximumAttempts; attempt++ {
		previousNamespaceSeen, previousStorageSeen := namespaceSeen, storageSeen
		observation, namespaceObserved, storageObserved, err := source.observeOnce(ctx, namespaceUID)
		if namespaceObserved {
			namespaceUID = observation.KubeSystemUID
		}
		namespaceSeen = namespaceSeen || namespaceObserved
		storageSeen = storageSeen || storageObserved
		if err == nil {
			return observation, nil
		}
		var sourceErr *runtimeBindingSourceError
		categorized := errors.As(err, &sourceErr)
		regressedMissing := categorized && sourceErr.missing &&
			(sourceErr.resource == runtimeBindingKubeSystemPath && previousNamespaceSeen || sourceErr.resource == runtimeBindingLocalPathPath && previousStorageSeen)
		if !categorized || !sourceErr.transient || regressedMissing {
			return RuntimeBindingObservation{}, errors.New("bounded runtime binding source stopped")
		}
		now := source.clock()
		if attempt == source.maximumAttempts || !now.Before(deadline) {
			return RuntimeBindingObservation{}, errors.New("bounded runtime binding convergence exhausted")
		}
		wait := source.interval
		if remaining := deadline.Sub(now); remaining < wait {
			wait = remaining
		}
		if err := source.wait(ctx, wait); err != nil {
			return RuntimeBindingObservation{}, errors.New("bounded runtime binding convergence interrupted")
		}
	}
	return RuntimeBindingObservation{}, errors.New("bounded runtime binding convergence exhausted")
}

func (source *KubernetesRuntimeBindingSource) observeOnce(ctx context.Context, expectedNamespaceUID string) (RuntimeBindingObservation, bool, bool, error) {
	namespaceRaw, err := source.get(ctx, runtimeBindingKubeSystemPath)
	if err != nil {
		return RuntimeBindingObservation{}, false, false, err
	}
	namespace, err := decodeRuntimeBindingObject(namespaceRaw)
	if err != nil || namespace.kind != "Namespace" || !runtimeInputUIDPattern.MatchString(namespace.uid) {
		return RuntimeBindingObservation{}, true, false, errors.New("kube-system identity is invalid")
	}
	if expectedNamespaceUID != "" && namespace.uid != expectedNamespaceUID {
		return RuntimeBindingObservation{}, true, false, errors.New("kube-system identity changed during convergence")
	}
	storageRaw, err := source.get(ctx, runtimeBindingLocalPathPath)
	if err != nil {
		return RuntimeBindingObservation{KubeSystemUID: namespace.uid}, true, false, err
	}
	storage, err := decodeRuntimeBindingObject(storageRaw)
	if err != nil || storage.kind != "StorageClass" || !runtimeInputUIDPattern.MatchString(storage.uid) || storage.provisioner != "rancher.io/local-path" {
		return RuntimeBindingObservation{}, true, true, errors.New("local-path identity is invalid")
	}
	return RuntimeBindingObservation{KubeSystemUID: namespace.uid, LocalPathStorageClassUID: storage.uid, LocalPathProvisioner: storage.provisioner}, true, true, nil
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
	if !source.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+source.token)
	}
	response, err := source.client.Do(request)
	if err != nil {
		return nil, &runtimeBindingSourceError{transient: transientRuntimeBindingTransportError(err), resource: path}
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumRuntimeBindingSource+1))
	if readErr != nil || len(raw) > maximumRuntimeBindingSource {
		return nil, errors.New("bounded runtime binding response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return nil, &runtimeBindingSourceError{transient: transientRuntimeBindingStatus(response.StatusCode), missing: response.StatusCode == http.StatusNotFound, resource: path}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("bounded runtime binding response is not JSON")
	}
	return raw, nil
}

func transientRuntimeBindingStatus(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func transientRuntimeBindingTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var recordHeader tls.RecordHeaderError
	var verification *tls.CertificateVerificationError
	if errors.As(err, &unknownAuthority) || errors.As(err, &certificateInvalid) || errors.As(err, &hostname) || errors.As(err, &recordHeader) || errors.As(err, &verification) {
		return false
	}
	var networkError net.Error
	return errors.As(err, &networkError)
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
