package bootstrapauthority

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

const issuerManagedBy = "ok-bootstrap-issuer"
const namespacePurpose = "cli.openkubes.io/storage-domain"
const metadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"

// KubernetesStoreConfig has no credential/config-file discovery or installation
// defaults. Namespace and immutable fence must already exist under separate
// platform authority. Values here are independently reviewed/pinned inputs.
type KubernetesStoreConfig struct {
	Endpoint                                  string
	CABundle                                  []byte
	BearerToken                               string
	Namespace, NamespaceUID                   string
	FenceName, FenceUID, FenceResourceVersion string
	ExpectedDomainDigest                      string
}

type KubernetesStore struct {
	endpoint, namespace, namespaceUID, fenceName, fenceUID, fenceRV, domain, token string
	client                                                                         *http.Client
}

func safeText(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

func dnsName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) > 63 || !dnsLabel.MatchString(part) {
			return false
		}
	}
	return true
}

// KubernetesDomainDigest computes a proposal identity only, not an authorization.
// The namespace/fence UIDs and API trust identity cannot be self-inferred safely.
func KubernetesDomainDigest(c KubernetesStoreConfig) (string, error) {
	if !utf8.ValidString(c.Endpoint) {
		return "", ErrStop
	}
	for _, r := range c.Endpoint {
		if unicode.IsControl(r) {
			return "", ErrStop
		}
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", ErrStop
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", ErrStop
	}
	if len(c.Namespace) > 63 || !dnsLabel.MatchString(c.Namespace) || c.Namespace == "default" || strings.HasPrefix(c.Namespace, "kube-") || c.Namespace == "openkubes-execution-system" || !dnsName(c.FenceName) || !safeText(c.NamespaceUID) || !safeText(c.FenceUID) || !safeText(c.FenceResourceVersion) || len(c.CABundle) > 256*1024 {
		return "", ErrStop
	}
	trust, err := kubeconfigtarget.TrustDigest(c.CABundle)
	if err != nil {
		return "", ErrStop
	}
	raw, _ := json.Marshal(struct{ Domain, Endpoint, Trust, Namespace, NamespaceUID, Fence, FenceUID string }{"ok147-bootstrap-store-domain-candidate/v1", c.Endpoint, trust, c.Namespace, c.NamespaceUID, c.FenceName, c.FenceUID})
	return digest(raw), nil
}

// NewKubernetesStore performs local validation only; it never contacts an API.
// TLS trust is constructed from explicit public CA bytes, never system roots,
// a proxy, auth plugin, client certificate, redirect or refresh mechanism.
func NewKubernetesStore(c KubernetesStoreConfig) (*KubernetesStore, error) {
	domain, err := KubernetesDomainDigest(c)
	if err != nil || !validDigest(c.ExpectedDomainDigest) || domain != c.ExpectedDomainDigest || len(c.BearerToken) == 0 || len(c.BearerToken) > 65536 {
		return nil, ErrStop
	}
	for _, r := range c.BearerToken {
		if r < 0x21 || r > 0x7e {
			return nil, ErrStop
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CABundle) {
		return nil, ErrStop
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 * 1024, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &KubernetesStore{c.Endpoint, c.Namespace, c.NamespaceUID, c.FenceName, c.FenceUID, c.FenceResourceVersion, domain, c.BearerToken, client}, nil
}

func (s *KubernetesStore) DomainDigest() string { return s.domain }
func (s *KubernetesStore) CreateClaim(c context.Context, k string, r []byte) error {
	return s.create(c, "claim", k, r)
}
func (s *KubernetesStore) ReadClaim(c context.Context, k string) ([]byte, error) {
	return s.read(c, "claim", k)
}
func (s *KubernetesStore) CreateResult(c context.Context, k string, r []byte) error {
	return s.create(c, "result", k, r)
}
func (s *KubernetesStore) ReadResult(c context.Context, k string) ([]byte, error) {
	return s.read(c, "result", k)
}

func (s *KubernetesStore) collection() string {
	return "/api/v1/namespaces/" + s.namespace + "/configmaps"
}
func recordName(kind, key string) (string, error) {
	if (kind != "claim" && kind != "result") || !validDigest(key) {
		return "", ErrStop
	}
	// Full 256-bit slot identity, split into DNS labels rather than truncated.
	return "okbi-" + kind + "-" + key[7:39] + "." + key[39:], nil
}

func (s *KubernetesStore) request(ctx context.Context, method, path, accept string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, ErrStop
	}
	req.GetBody = nil // no automatic replay of a mutating request
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("Cache-Control", "no-cache")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := s.client.Do(req)
	if err != nil {
		return nil, 0, ErrStop
	}
	defer response.Body.Close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, 0, ErrStop
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, 0, ErrStop
	}
	return raw, response.StatusCode, nil
}

type storeMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	DeletionTimestamp json.RawMessage   `json:"deletionTimestamp"`
	OwnerReferences   []json.RawMessage `json:"ownerReferences"`
}
type storeConfigMap struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   storeMetadata     `json:"metadata"`
	Immutable  bool              `json:"immutable"`
	Data       map[string]string `json:"data"`
	BinaryData map[string]string `json:"binaryData,omitempty"`
}

// Strict root keys and identity spelling avoid encoding/json case-alias
// shadowing while accepting unrelated server-managed ObjectMeta fields.
func decodeObject(raw []byte, allowed []string) (map[string]json.RawMessage, storeMetadata, error) {
	var doc map[string]json.RawMessage
	var metadata storeMetadata
	if jsonstrict.Decode(raw, &doc) != nil || doc == nil {
		return nil, metadata, ErrStop
	}
	for field := range doc {
		found := false
		for _, a := range allowed {
			if field == a {
				found = true
			}
		}
		if !found {
			return nil, metadata, ErrStop
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(doc["metadata"], &fields) != nil || fields == nil {
		return nil, metadata, ErrStop
	}
	for field := range fields {
		for _, a := range []string{"name", "namespace", "uid", "resourceVersion", "labels", "annotations", "deletionTimestamp", "ownerReferences"} {
			if field != a && strings.EqualFold(field, a) {
				return nil, metadata, ErrStop
			}
		}
	}
	if json.Unmarshal(doc["metadata"], &metadata) != nil || !safeText(metadata.UID) || !safeText(metadata.ResourceVersion) || len(metadata.OwnerReferences) != 0 {
		return nil, metadata, ErrStop
	}
	if len(metadata.DeletionTimestamp) > 0 && !bytes.Equal(bytes.TrimSpace(metadata.DeletionTimestamp), []byte("null")) {
		return nil, metadata, ErrStop
	}
	return doc, metadata, nil
}

func (s *KubernetesStore) guard(ctx context.Context) error {
	raw, status, err := s.request(ctx, http.MethodGet, "/api/v1/namespaces/"+s.namespace, metadataAccept, nil)
	if err != nil || status != 200 {
		return ErrStop
	}
	doc, m, err := decodeObject(raw, []string{"apiVersion", "kind", "metadata"})
	if err != nil || string(doc["apiVersion"]) != `"meta.k8s.io/v1"` || string(doc["kind"]) != `"PartialObjectMetadata"` || m.Name != s.namespace || m.Namespace != "" || m.UID != s.namespaceUID || m.Labels[namespacePurpose] != "bootstrap-issuer" {
		return ErrStop
	}
	raw, status, err = s.request(ctx, http.MethodGet, s.collection()+"/"+s.fenceName, "application/json", nil)
	if err != nil || status != 200 {
		return ErrStop
	}
	fence, err := s.decodeMap(raw)
	if err != nil || fence.Metadata.Name != s.fenceName || fence.Metadata.UID != s.fenceUID || fence.Metadata.ResourceVersion != s.fenceRV || fence.Metadata.Labels["cli.openkubes.io/issuer-record"] != "fence" || len(fence.Data) != 3 || fence.Data["format"] != "ok147-bootstrap-store-fence-candidate/v1" || fence.Data["state"] != "ACTIVE" || fence.Data["namespaceUID"] != s.namespaceUID {
		return ErrStop
	}
	return nil
}

func (s *KubernetesStore) decodeMap(raw []byte) (storeConfigMap, error) {
	var object storeConfigMap
	_, metadata, err := decodeObject(raw, []string{"apiVersion", "kind", "metadata", "immutable", "data", "binaryData"})
	if err != nil || json.Unmarshal(raw, &object) != nil || object.APIVersion != "v1" || object.Kind != "ConfigMap" || !object.Immutable || len(object.BinaryData) != 0 || metadata.Namespace != s.namespace || metadata.Labels["app.kubernetes.io/managed-by"] != issuerManagedBy {
		return object, ErrStop
	}
	object.Metadata = metadata
	return object, nil
}

func (s *KubernetesStore) object(kind, key string, raw []byte) (storeConfigMap, error) {
	name, err := recordName(kind, key)
	if err != nil || ValidateRecord(kind, key, raw) != nil {
		return storeConfigMap{}, ErrStop
	}
	return storeConfigMap{APIVersion: "v1", Kind: "ConfigMap", Immutable: true, Metadata: storeMetadata{Name: name, Namespace: s.namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": issuerManagedBy, "cli.openkubes.io/issuer-record": kind}, Annotations: map[string]string{"cli.openkubes.io/issuer-domain": s.domain, "cli.openkubes.io/slot": key, "cli.openkubes.io/record-digest": digest(raw), "cli.openkubes.io/storage-namespace-uid": s.namespaceUID}}, Data: map[string]string{"record.json": string(raw)}}, nil
}

func (s *KubernetesStore) verifyMap(raw []byte, kind, key string) ([]byte, error) {
	object, err := s.decodeMap(raw)
	if err != nil || len(object.Data) != 1 {
		return nil, ErrStop
	}
	record := []byte(object.Data["record.json"])
	expected, err := s.object(kind, key, record)
	if err != nil || object.Metadata.Name != expected.Metadata.Name || object.Metadata.Labels["cli.openkubes.io/issuer-record"] != kind {
		return nil, ErrStop
	}
	for k, v := range expected.Metadata.Annotations {
		if object.Metadata.Annotations[k] != v {
			return nil, ErrStop
		}
	}
	return record, nil
}

func statusMatches(raw []byte, code int, reason, name string) bool {
	var status struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
		Code       int    `json:"code"`
		Details    struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			Group string `json:"group"`
		} `json:"details"`
	}
	var doc map[string]json.RawMessage
	if jsonstrict.Decode(raw, &doc) != nil || doc == nil {
		return false
	}
	for field := range doc {
		allowed := false
		for _, a := range []string{"apiVersion", "kind", "metadata", "status", "message", "reason", "details", "code"} {
			if field == a {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
	}
	var details map[string]json.RawMessage
	if json.Unmarshal(doc["details"], &details) != nil || details == nil {
		return false
	}
	for field := range details {
		for _, a := range []string{"name", "kind", "group"} {
			if field != a && strings.EqualFold(field, a) {
				return false
			}
		}
	}
	if json.Unmarshal(raw, &status) != nil {
		return false
	}
	return status.APIVersion == "v1" && status.Kind == "Status" && status.Status == "Failure" && status.Reason == reason && status.Code == code && status.Details.Name == name && status.Details.Kind == "configmaps" && status.Details.Group == ""
}

func (s *KubernetesStore) create(ctx context.Context, kind, key string, raw []byte) error {
	object, err := s.object(kind, key, raw)
	if err != nil {
		return ErrStop
	}
	if s.guard(ctx) != nil {
		return ErrStop
	}
	body, err := json.Marshal(object)
	if err != nil {
		return ErrStop
	}
	response, status, err := s.request(ctx, http.MethodPost, s.collection(), "application/json", body)
	if err != nil {
		return ErrStop
	} // unknown write: never repeat it
	if s.guard(ctx) != nil {
		return ErrStop
	}
	if status == 409 && statusMatches(response, 409, "AlreadyExists", object.Metadata.Name) {
		return ErrExists
	}
	if status != 201 {
		return ErrStop
	}
	actual, err := s.verifyMap(response, kind, key)
	if err != nil || !bytes.Equal(actual, raw) {
		return ErrStop
	}
	return nil
}

func (s *KubernetesStore) read(ctx context.Context, kind, key string) ([]byte, error) {
	name, err := recordName(kind, key)
	if err != nil {
		return nil, ErrStop
	}
	if s.guard(ctx) != nil {
		return nil, ErrStop
	}
	raw, status, err := s.request(ctx, http.MethodGet, s.collection()+"/"+name, "application/json", nil)
	if err != nil {
		return nil, ErrStop
	}
	if s.guard(ctx) != nil {
		return nil, ErrStop
	}
	if status == 404 && statusMatches(raw, 404, "NotFound", name) {
		return nil, ErrNotFound
	}
	if status != 200 {
		return nil, ErrStop
	}
	return s.verifyMap(raw, kind, key)
}
