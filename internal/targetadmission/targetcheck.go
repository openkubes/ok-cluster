package targetadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const MaxTargetIdentityResponseBytes = 64 * 1024

// VerifyLiveTargetBinding performs one read-only GET against the explicitly
// pinned Kubernetes API endpoint and CA, then compares the live kube-system
// namespace UID with the independently signed bundle. It never retries,
// follows redirects, renews credentials, or mutates the cluster.
func VerifyLiveTargetBinding(ctx context.Context, apiEndpoint string, caPEM, bearerToken []byte, expected TargetBinding) error {
	if expected.CAPIClusterUID == "" || len(expected.CAPIClusterUID) > 128 || expected.KubeSystemNamespaceUID == "" || len(expected.KubeSystemNamespaceUID) > 128 {
		return errors.New("signed target identity binding is invalid")
	}
	endpoint, err := url.Parse(apiEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || len(apiEndpoint) > 512 {
		return errors.New("pinned target API endpoint is invalid")
	}
	if len(bearerToken) == 0 || len(bearerToken) > 64*1024 || strings.ContainsAny(string(bearerToken), "\r\n") {
		return errors.New("target read-only credential is invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("pinned target API CA bundle is invalid")
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: endpoint.Hostname()},
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiEndpoint, "/")+"/api/v1/namespaces/kube-system", nil)
	if err != nil {
		return errors.New("construct target identity request")
	}
	request.Header.Set("Authorization", "Bearer "+string(bearerToken))
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("read target Kubernetes identity")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !isJSONContentType(response.Header.Get("Content-Type")) {
		return errors.New("target Kubernetes identity response was not an exact successful JSON read")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, MaxTargetIdentityResponseBytes+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > MaxTargetIdentityResponseBytes {
		return errors.New("target Kubernetes identity response is invalid")
	}
	name, uid, err := targetNamespaceIdentity(responseBody)
	if err != nil || name != "kube-system" {
		return errors.New("target Kubernetes identity object is invalid")
	}
	return VerifyTargetBinding(expected, uid)
}

// VerifyLiveTargetKubernetesVersion performs one pinned read-only GET to
// /version and rejects targets too old for the fail-closed CEL webhook.
func VerifyLiveTargetKubernetesVersion(ctx context.Context, apiEndpoint string, caPEM, bearerToken []byte) (string, error) {
	client, baseURL, err := newTargetAPIClient(apiEndpoint, caPEM, bearerToken)
	if err != nil {
		return "", err
	}
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	raw, err := readTargetAPIJSON(ctx, client, baseURL+"/version", bearerToken)
	if err != nil {
		return "", errors.New("read target Kubernetes version")
	}
	version, err := targetGitVersion(raw)
	if err != nil || ValidateWebhookKubernetesVersion(version) != nil {
		return "", errors.New("target Kubernetes version is invalid or below webhook requirements")
	}
	return version, nil
}

const TargetActivationEvidenceFormat = "ok147-target-activation-preflight/v1"

// TargetActivationEvidence is a read-only, point-in-time observation. It is
// not authorization and must never be reused at the write boundary.
type TargetActivationEvidence struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	PlanDigest                string `json:"planDigest"`
	PolicyDigest              string `json:"policyDigest"`
	TargetBindingDigest       string `json:"targetBindingDigest"`
	TargetAPIDigest           string `json:"targetApiDigest"`
	KubernetesGitVersion      string `json:"kubernetesGitVersion"`
	NamespaceIdentityVerified bool   `json:"namespaceIdentityVerified"`
	KubernetesVersionVerified bool   `json:"kubernetesVersionVerified"`
	APIAccessed               bool   `json:"apiAccessed"`
	MutationAllowed           bool   `json:"mutationAllowed"`
	WebhookActive             bool   `json:"webhookActive"`
	RecheckRequiredAtWrite    bool   `json:"recheckRequiredAtWrite"`
	ObservedAt                string `json:"observedAt"`
}

// VerifyTargetActivationReadOnly verifies the signed offline plan, then makes
// exactly two pinned, read-only requests to one target API: kube-system UID and
// /version. The resulting evidence is informational and stale immediately; a
// future installer must repeat both checks at each mutation boundary.
func VerifyTargetActivationReadOnly(ctx context.Context, plan ActivationPlan, bundle []byte, trustedKey ed25519.PublicKey, webhookCA []byte, apiEndpoint string, apiCA, bearerToken []byte, now time.Time) (TargetActivationEvidence, error) {
	if err := VerifyOfflineActivationPlan(plan, bundle, trustedKey, webhookCA); err != nil {
		return TargetActivationEvidence{}, errors.New("offline activation plan is not valid")
	}
	_, target, err := VerifyBundle(bundle, trustedKey)
	if err != nil {
		return TargetActivationEvidence{}, errors.New("signed target policy is invalid")
	}
	client, baseURL, err := newTargetAPIClient(apiEndpoint, apiCA, bearerToken)
	if err != nil {
		return TargetActivationEvidence{}, err
	}
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	namespaceRaw, err := readTargetAPIJSON(ctx, client, baseURL+"/api/v1/namespaces/kube-system", bearerToken)
	if err != nil {
		return TargetActivationEvidence{}, errors.New("read target namespace identity")
	}
	name, uid, err := targetNamespaceIdentity(namespaceRaw)
	if err != nil || name != "kube-system" || VerifyTargetBinding(target, uid) != nil {
		return TargetActivationEvidence{}, errors.New("live target namespace does not match signed target binding")
	}
	versionRaw, err := readTargetAPIJSON(ctx, client, baseURL+"/version", bearerToken)
	if err != nil {
		return TargetActivationEvidence{}, errors.New("read target Kubernetes version")
	}
	gitVersion, err := targetGitVersion(versionRaw)
	if err != nil || ValidateWebhookKubernetesVersion(gitVersion) != nil {
		return TargetActivationEvidence{}, errors.New("target Kubernetes version is invalid or below webhook requirements")
	}
	if now.IsZero() {
		now = time.Now()
	}
	apiDigest := sha256.Sum256([]byte(baseURL))
	return TargetActivationEvidence{
		Format: TargetActivationEvidenceFormat, State: "READ_ONLY_PREFLIGHT_PASSED_NOT_AUTHORIZED",
		PlanDigest: plan.PlanDigest, PolicyDigest: plan.PolicyDigest, TargetBindingDigest: plan.TargetBindingDigest,
		TargetAPIDigest: "sha256:" + hex.EncodeToString(apiDigest[:]), KubernetesGitVersion: gitVersion,
		NamespaceIdentityVerified: true, KubernetesVersionVerified: true, APIAccessed: true,
		MutationAllowed: false, WebhookActive: false, RecheckRequiredAtWrite: true,
		ObservedAt: now.UTC().Format(time.RFC3339Nano),
	}, nil
}

func newTargetAPIClient(apiEndpoint string, caPEM, bearerToken []byte) (*http.Client, string, error) {
	endpoint, err := url.Parse(apiEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || len(apiEndpoint) > 512 {
		return nil, "", errors.New("pinned target API endpoint is invalid")
	}
	if len(bearerToken) == 0 || len(bearerToken) > 64*1024 || strings.ContainsAny(string(bearerToken), "\r\n") {
		return nil, "", errors.New("target read-only credential is invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, "", errors.New("pinned target API CA bundle is invalid")
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: endpoint.Hostname()},
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, strings.TrimRight(apiEndpoint, "/"), nil
}

func readTargetAPIJSON(ctx context.Context, client *http.Client, endpoint string, bearerToken []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("construct target API read")
	}
	request.Header.Set("Authorization", "Bearer "+string(bearerToken))
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("perform target API read")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !isJSONContentType(response.Header.Get("Content-Type")) {
		return nil, errors.New("target API read was not a successful JSON response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxTargetIdentityResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > MaxTargetIdentityResponseBytes {
		return nil, errors.New("target API JSON response is invalid")
	}
	return body, nil
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func targetGitVersion(raw []byte) (string, error) {
	var versionFields map[string]json.RawMessage
	if err := jsonstrict.Decode(raw, &versionFields); err != nil {
		return "", errors.New("target Kubernetes version document is invalid")
	}
	var version string
	if err := json.Unmarshal(versionFields["gitVersion"], &version); err != nil || version == "" {
		return "", errors.New("target Kubernetes GitVersion is missing")
	}
	return version, nil
}

func targetNamespaceIdentity(raw []byte) (string, string, error) {
	var object map[string]json.RawMessage
	if err := jsonstrict.Decode(raw, &object); err != nil {
		return "", "", errors.New("target namespace document is invalid")
	}
	var apiVersion, kind string
	if err := json.Unmarshal(object["apiVersion"], &apiVersion); err != nil || apiVersion != "v1" {
		return "", "", errors.New("target namespace apiVersion is invalid")
	}
	if err := json.Unmarshal(object["kind"], &kind); err != nil || kind != "Namespace" {
		return "", "", errors.New("target namespace kind is invalid")
	}
	var metadata map[string]json.RawMessage
	if err := jsonstrict.Decode(object["metadata"], &metadata); err != nil {
		return "", "", errors.New("target namespace metadata is invalid")
	}
	var name, uid string
	if err := json.Unmarshal(metadata["name"], &name); err != nil || name == "" {
		return "", "", errors.New("target namespace name is invalid")
	}
	if err := json.Unmarshal(metadata["uid"], &uid); err != nil || uid == "" {
		return "", "", errors.New("target namespace UID is invalid")
	}
	return name, uid, nil
}
