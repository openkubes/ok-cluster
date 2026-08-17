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
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	TargetCredentialIssueReceiptFormat = "ok147-target-credential-issue-receipt/v1"
	maximumTargetCredentialResponse    = 256 * 1024
	minimumTargetCredentialLifetime    = 2 * time.Hour
)

type TargetCredentialIssuerConfig struct {
	Workload WorkloadAuthorityFileResolverConfig
	Clock    func() time.Time
}

type targetCredentialIssuerClientConfig struct {
	Endpoint       string
	BearerToken    string
	CABundle       []byte
	TargetIdentity string
	Client         *http.Client
	Clock          func() time.Time
}

type TargetCredentialIssueReceipt struct {
	Format                       string `json:"format"`
	State                        string `json:"state"`
	StageID                      string `json:"stageId"`
	PolicyDigest                 string `json:"policyDigest"`
	TargetIdentityDigest         string `json:"targetIdentityDigest"`
	ServiceAccountIdentityDigest string `json:"serviceAccountIdentityDigest"`
	RequestDigest                string `json:"requestDigest"`
	AudienceMode                 string `json:"audienceMode"`
	IssuedAt                     string `json:"issuedAt,omitempty"`
	ExpiresAt                    string `json:"expiresAt,omitempty"`
	LifetimeSeconds              int64  `json:"lifetimeSeconds,omitempty"`
	CredentialBytesInReceipt     bool   `json:"credentialBytesInReceipt"`
	MutationState                string `json:"mutationState"`
}

// VerifiedTargetCredentialMaterial retains the bearer token, target CA and
// endpoint only in process memory for the immediately following registration
// stage. None of those bytes are exported by its receipt.
type VerifiedTargetCredentialMaterial struct {
	token          []byte
	caBundle       []byte
	endpoint       string
	targetIdentity string
	expiresAt      time.Time
	receipt        TargetCredentialIssueReceipt
	verified       bool
}

type KubernetesTargetCredentialIssuer struct {
	mu             sync.Mutex
	used           bool
	endpoint       *url.URL
	authorityToken string
	caBundle       []byte
	targetIdentity string
	client         *http.Client
	clock          func() time.Time
	policy         targetCredentialPolicyDocument
	bundleReceipt  TargetCredentialStageBundleReceipt
	request        []byte
}

type targetCredentialTokenRequest struct {
	APIVersion string                           `json:"apiVersion"`
	Kind       string                           `json:"kind"`
	Spec       targetCredentialTokenRequestSpec `json:"spec"`
}

type targetCredentialTokenRequestSpec struct {
	Audiences         []string `json:"audiences,omitempty"`
	ExpirationSeconds int64    `json:"expirationSeconds"`
}

type targetCredentialTokenResponse struct {
	APIVersion string                           `json:"apiVersion"`
	Kind       string                           `json:"kind"`
	Metadata   map[string]any                   `json:"metadata"`
	Spec       targetCredentialTokenRequestSpec `json:"spec"`
	Status     struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	} `json:"status"`
}

type targetCredentialJWTClaims struct {
	Subject  string          `json:"sub"`
	Expires  json.Number     `json:"exp"`
	IssuedAt json.Number     `json:"iat"`
	Audience json.RawMessage `json:"aud"`
}

// OpenTargetCredentialIssuer binds the verified public bundle to the private
// workload authority. It reads bounded credential material but performs no
// TokenRequest or other API call.
func OpenTargetCredentialIssuer(bundle VerifiedTargetCredentialStageBundle, config TargetCredentialIssuerConfig) (*KubernetesTargetCredentialIssuer, error) {
	if err := verifyTargetCredentialStageBundle(bundle); err != nil || config.Clock == nil {
		return nil, errors.New("verified target-credential bundle and clock are required")
	}
	binding, authority, err := loadWorkloadAuthorityFiles(config.Workload)
	if err != nil {
		return nil, errors.New("open target-credential workload authority")
	}
	if binding.IntentRevision != bundle.plan.IntentRevision || digest.SHA256([]byte(binding.TargetClusterUID)) != bundle.receipt.TargetIdentityDigest {
		return nil, errors.New("target-credential workload authority differs from verified target")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(authority.TokenFile, authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded target-credential authority")
	}
	if digest.SHA256(ca) != authority.CABundleDigest {
		return nil, errors.New("target-credential CA differs from runtime binding")
	}
	return newKubernetesTargetCredentialIssuer(targetCredentialIssuerClientConfig{
		Endpoint: authority.Endpoint, BearerToken: token, CABundle: ca,
		TargetIdentity: bundle.receipt.TargetIdentityDigest, Client: client, Clock: config.Clock,
	}, bundle)
}

func newKubernetesTargetCredentialIssuer(config targetCredentialIssuerClientConfig, bundle VerifiedTargetCredentialStageBundle) (*KubernetesTargetCredentialIssuer, error) {
	if err := verifyTargetCredentialStageBundle(bundle); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("target-credential issuer endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("target-credential issuer endpoint must use HTTPS")
	}
	endpoint.Path, endpoint.RawPath = "", ""
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || len(config.CABundle) == 0 || config.TargetIdentity != bundle.receipt.TargetIdentityDigest || config.Client == nil || config.Clock == nil {
		return nil, errors.New("target-credential issuer authority is invalid")
	}
	request := targetCredentialTokenRequest{
		APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest",
		Spec: targetCredentialTokenRequestSpec{ExpirationSeconds: int64(bundle.policy.ExpirationSeconds)},
	}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("encode target-credential TokenRequest")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return &KubernetesTargetCredentialIssuer{
		endpoint: endpoint, authorityToken: config.BearerToken, caBundle: append([]byte(nil), config.CABundle...),
		targetIdentity: config.TargetIdentity, client: &client, clock: config.Clock,
		policy: bundle.policy, bundleReceipt: bundle.receipt, request: requestRaw,
	}, nil
}

// Issue performs exactly one TokenRequest for the bound ServiceAccount. The
// returned token is available only through the verified in-memory material.
func (issuer *KubernetesTargetCredentialIssuer) Issue(ctx context.Context) (VerifiedTargetCredentialMaterial, error) {
	if issuer == nil || issuer.client == nil || issuer.clock == nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential issuer is required")
	}
	issuer.mu.Lock()
	if issuer.used {
		issuer.mu.Unlock()
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential issuer is single-use")
	}
	issuer.used = true
	issuer.mu.Unlock()

	now := issuer.clock().UTC()
	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token", issuer.policy.ServiceAccount.Namespace, issuer.policy.ServiceAccount.Name)
	requestURL := *issuer.endpoint
	requestURL.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(issuer.request))
	if err != nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("construct target-credential request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+issuer.authorityToken)
	response, err := issuer.client.Do(request)
	if err != nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumTargetCredentialResponse))
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential request was not created")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential response media type is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumTargetCredentialResponse+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumTargetCredentialResponse {
		return VerifiedTargetCredentialMaterial{}, errors.New("read bounded target-credential response")
	}
	var value targetCredentialTokenResponse
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("decode target-credential response")
	}
	material, err := issuer.verifyResponse(value, now)
	if err != nil {
		return VerifiedTargetCredentialMaterial{}, err
	}
	return material, nil
}

func (issuer *KubernetesTargetCredentialIssuer) verifyResponse(value targetCredentialTokenResponse, now time.Time) (VerifiedTargetCredentialMaterial, error) {
	if value.APIVersion != "authentication.k8s.io/v1" || value.Kind != "TokenRequest" || len(value.Status.Token) < 80 || strings.TrimSpace(value.Status.Token) != value.Status.Token || strings.ContainsAny(value.Status.Token, "\r\n") {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential response identity or token is invalid")
	}
	if value.Spec.ExpirationSeconds != int64(issuer.policy.ExpirationSeconds) || len(value.Spec.Audiences) == 0 {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential response did not apply the bounded request")
	}
	expiresAt, err := time.Parse(time.RFC3339, value.Status.ExpirationTimestamp)
	if err != nil {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential expiration is invalid")
	}
	lifetime := expiresAt.Sub(now)
	if lifetime < minimumTargetCredentialLifetime || lifetime > time.Duration(issuer.policy.ExpirationSeconds)*time.Second {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential lifetime is outside the bounded window")
	}
	claims, err := decodeTargetCredentialClaims(value.Status.Token)
	if err != nil {
		return VerifiedTargetCredentialMaterial{}, err
	}
	wantSubject := "system:serviceaccount:" + issuer.policy.ServiceAccount.Namespace + ":" + issuer.policy.ServiceAccount.Name
	exp, err := claims.Expires.Int64()
	if err != nil || claims.Subject != wantSubject || exp != expiresAt.Unix() || len(claims.Audience) == 0 || bytes.Equal(bytes.TrimSpace(claims.Audience), []byte("null")) {
		return VerifiedTargetCredentialMaterial{}, errors.New("target-credential token claims differ from bounded identity")
	}
	if claims.IssuedAt != "" {
		iat, err := claims.IssuedAt.Int64()
		if err != nil || time.Unix(iat, 0).After(now.Add(5*time.Second)) || time.Unix(iat, 0).Before(now.Add(-5*time.Minute)) {
			return VerifiedTargetCredentialMaterial{}, errors.New("target-credential issuance claim is invalid")
		}
	}
	receipt := TargetCredentialIssueReceipt{
		Format: TargetCredentialIssueReceiptFormat, State: "ISSUED", StageID: "target-credential",
		PolicyDigest: issuer.bundleReceipt.PolicyDigest, TargetIdentityDigest: issuer.targetIdentity,
		ServiceAccountIdentityDigest: issuer.bundleReceipt.ServiceAccountIdentityDigest,
		RequestDigest:                digest.SHA256(issuer.request), AudienceMode: "server-default",
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		LifetimeSeconds: int64(lifetime / time.Second), CredentialBytesInReceipt: false, MutationState: "ATTEMPTED",
	}
	return VerifiedTargetCredentialMaterial{
		token: []byte(value.Status.Token), caBundle: append([]byte(nil), issuer.caBundle...), endpoint: issuer.endpoint.String(),
		targetIdentity: issuer.targetIdentity, expiresAt: expiresAt.UTC(), receipt: receipt, verified: true,
	}, nil
}

func decodeTargetCredentialClaims(token string) (targetCredentialJWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return targetCredentialJWTClaims{}, errors.New("target-credential token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 64*1024 {
		return targetCredentialJWTClaims{}, errors.New("target-credential token payload is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims targetCredentialJWTClaims
	if err := decoder.Decode(&claims); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return targetCredentialJWTClaims{}, errors.New("target-credential token claims are invalid")
	}
	return claims, nil
}

func (material VerifiedTargetCredentialMaterial) Receipt() (TargetCredentialIssueReceipt, error) {
	if !material.verified || len(material.token) < 80 || len(material.caBundle) == 0 || material.endpoint == "" || !stageReceiptPrefixDigestPattern.MatchString(material.targetIdentity) || material.expiresAt.IsZero() || material.receipt.Format != TargetCredentialIssueReceiptFormat || material.receipt.State != "ISSUED" || material.receipt.CredentialBytesInReceipt {
		return TargetCredentialIssueReceipt{}, errors.New("target-credential material was not produced by verification")
	}
	return material.receipt, nil
}
