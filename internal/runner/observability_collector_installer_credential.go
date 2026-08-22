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
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityCollectorInstallerCredentialReceiptFormat = "ok147-observability-collector-installer-credential-receipt/v1"
	observabilityCollectorInstallerNamespace               = "openkubes-execution-system"
	observabilityCollectorInstallerServiceAccount          = "ok147-contract-executor-runtime"
	observabilityCollectorInstallerLifetime                = 30 * time.Minute
	minimumObservabilityCollectorInstallerLifetime         = 25 * time.Minute
)

type ObservabilityCollectorInstallerCredentialConfig struct {
	Workload             WorkloadAuthorityFileResolverConfig
	ExpectedTargetDigest string
	Clock                func() time.Time
}

type ObservabilityCollectorInstallerCredentialReceipt struct {
	Format                       string `json:"format"`
	State                        string `json:"state"`
	TargetIdentityDigest         string `json:"targetIdentityDigest"`
	ServiceAccountIdentityDigest string `json:"serviceAccountIdentityDigest"`
	RequestDigest                string `json:"requestDigest"`
	CABundleDigest               string `json:"caBundleDigest"`
	AudienceMode                 string `json:"audienceMode"`
	IssuedAt                     string `json:"issuedAt"`
	ExpiresAt                    string `json:"expiresAt"`
	LifetimeSeconds              int64  `json:"lifetimeSeconds"`
	CredentialBytesInReceipt     bool   `json:"credentialBytesInReceipt"`
	MutationState                string `json:"mutationState"`
}

type VerifiedObservabilityCollectorInstallerCredential struct {
	token          []byte
	endpoint       string
	targetIdentity string
	caBundleDigest string
	client         *http.Client
	expiresAt      time.Time
	privateDigest  string
	receipt        ObservabilityCollectorInstallerCredentialReceipt
	verified       bool
}

type observabilityCollectorInstallerPrivateBinding struct {
	Token          []byte `json:"token"`
	Endpoint       string `json:"endpoint"`
	TargetIdentity string `json:"targetIdentity"`
	CABundleDigest string `json:"caBundleDigest"`
	ExpiresAt      string `json:"expiresAt"`
}

type observabilityCollectorInstallerClientConfig struct {
	Endpoint          string
	BearerToken       string
	ClientCertificate bool
	CABundle          []byte
	CABundleDigest    string
	TargetIdentity    string
	Client            *http.Client
	Clock             func() time.Time
}

// KubernetesObservabilityCollectorInstallerCredentialIssuer performs one
// exact TokenRequest after Stage 7. The resulting workload credential is held
// only in memory for the immediately following collector launch.
type KubernetesObservabilityCollectorInstallerCredentialIssuer struct {
	mu                sync.Mutex
	used              bool
	endpoint          *url.URL
	authorityToken    string
	clientCertificate bool
	caBundleDigest    string
	targetIdentity    string
	client            *http.Client
	clock             func() time.Time
	request           []byte
}

func OpenKubernetesObservabilityCollectorInstallerCredentialIssuer(config ObservabilityCollectorInstallerCredentialConfig) (*KubernetesObservabilityCollectorInstallerCredentialIssuer, error) {
	if config.Clock == nil || !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedTargetDigest) {
		return nil, errors.New("collector installer credential binding is incomplete")
	}
	binding, authority, err := loadWorkloadAuthorityFiles(config.Workload)
	if err != nil || digest.SHA256([]byte(binding.TargetClusterUID)) != config.ExpectedTargetDigest {
		return nil, errors.New("collector installer credential differs from runtime workload authority")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(authority)
	if err != nil || digest.SHA256(transport.caData) != authority.CABundleDigest {
		return nil, errors.New("open bounded collector installer issuance authority")
	}
	return newKubernetesObservabilityCollectorInstallerCredentialIssuer(observabilityCollectorInstallerClientConfig{
		Endpoint: authority.Endpoint, BearerToken: transport.bearerToken, ClientCertificate: transport.clientCertificate,
		CABundle: transport.caData, CABundleDigest: authority.CABundleDigest,
		TargetIdentity: config.ExpectedTargetDigest, Client: transport.client, Clock: config.Clock,
	})
}

func newKubernetesObservabilityCollectorInstallerCredentialIssuer(config observabilityCollectorInstallerClientConfig) (*KubernetesObservabilityCollectorInstallerCredentialIssuer, error) {
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.New("collector installer credential endpoint is invalid")
	}
	tokenMode := config.BearerToken != ""
	if tokenMode == config.ClientCertificate || strings.TrimSpace(config.BearerToken) != config.BearerToken ||
		strings.ContainsAny(config.BearerToken, "\r\n") || len(config.CABundle) == 0 ||
		digest.SHA256(config.CABundle) != config.CABundleDigest || !stageReceiptPrefixDigestPattern.MatchString(config.TargetIdentity) ||
		config.Client == nil || config.Clock == nil {
		return nil, errors.New("collector installer issuance authority is invalid")
	}
	requestRaw, err := json.Marshal(targetCredentialTokenRequest{
		APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest",
		Spec: targetCredentialTokenRequestSpec{ExpirationSeconds: int64(observabilityCollectorInstallerLifetime / time.Second)},
	})
	if err != nil {
		return nil, errors.New("encode collector installer TokenRequest")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("parse collector installer credential endpoint")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return &KubernetesObservabilityCollectorInstallerCredentialIssuer{
		endpoint: parsed, authorityToken: config.BearerToken, clientCertificate: config.ClientCertificate,
		caBundleDigest: config.CABundleDigest, targetIdentity: config.TargetIdentity,
		client: &client, clock: config.Clock, request: requestRaw,
	}, nil
}

func (issuer *KubernetesObservabilityCollectorInstallerCredentialIssuer) Issue(ctx context.Context) (VerifiedObservabilityCollectorInstallerCredential, error) {
	if issuer == nil || issuer.client == nil || issuer.clock == nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer credential issuer is required")
	}
	issuer.mu.Lock()
	if issuer.used {
		issuer.mu.Unlock()
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer credential issuer is single-use")
	}
	issuer.used = true
	issuer.mu.Unlock()

	now := issuer.clock().UTC().Truncate(time.Second)
	requestURL := *issuer.endpoint
	requestURL.Path = fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token", observabilityCollectorInstallerNamespace, observabilityCollectorInstallerServiceAccount)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(issuer.request))
	if err != nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("construct collector installer TokenRequest")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if !issuer.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+issuer.authorityToken)
	}
	response, err := issuer.client.Do(request)
	if err != nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer TokenRequest failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumTargetCredentialResponse))
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer TokenRequest was not created")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer TokenRequest response media type is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumTargetCredentialResponse+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumTargetCredentialResponse {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("read bounded collector installer TokenRequest response")
	}
	var value targetCredentialTokenResponse
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("decode collector installer TokenRequest response")
	}
	return issuer.verifyResponse(value, now)
}

func (issuer *KubernetesObservabilityCollectorInstallerCredentialIssuer) verifyResponse(value targetCredentialTokenResponse, now time.Time) (VerifiedObservabilityCollectorInstallerCredential, error) {
	if value.APIVersion != "authentication.k8s.io/v1" || value.Kind != "TokenRequest" || len(value.Status.Token) < 80 ||
		strings.TrimSpace(value.Status.Token) != value.Status.Token || strings.ContainsAny(value.Status.Token, "\r\n") ||
		value.Spec.ExpirationSeconds != int64(observabilityCollectorInstallerLifetime/time.Second) || len(value.Spec.Audiences) == 0 {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer TokenRequest response is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, value.Status.ExpirationTimestamp)
	if err != nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer credential expiration is invalid")
	}
	lifetime := expiresAt.Sub(now)
	if lifetime < minimumObservabilityCollectorInstallerLifetime || lifetime > observabilityCollectorInstallerLifetime {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer credential lifetime is outside the bounded window")
	}
	claims, err := decodeTargetCredentialClaims(value.Status.Token)
	if err != nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("decode collector installer credential claims")
	}
	exp, err := claims.Expires.Int64()
	wantSubject := "system:serviceaccount:" + observabilityCollectorInstallerNamespace + ":" + observabilityCollectorInstallerServiceAccount
	if err != nil || claims.Subject != wantSubject || exp != expiresAt.Unix() || !exactTokenAudienceBinding(claims.Audience, value.Spec.Audiences) {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer credential claims differ from bounded identity")
	}
	if claims.IssuedAt != "" {
		iat, err := claims.IssuedAt.Int64()
		if err != nil || time.Unix(iat, 0).After(now.Add(5*time.Second)) || time.Unix(iat, 0).Before(now.Add(-5*time.Minute)) {
			return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("collector installer credential issuance claim is invalid")
		}
	}
	serviceAccountIdentity := digest.SHA256([]byte("system:serviceaccount:" + observabilityCollectorInstallerNamespace + ":" + observabilityCollectorInstallerServiceAccount))
	material := VerifiedObservabilityCollectorInstallerCredential{
		token: []byte(value.Status.Token), endpoint: issuer.endpoint.String(), targetIdentity: issuer.targetIdentity,
		caBundleDigest: issuer.caBundleDigest, client: issuer.client, expiresAt: expiresAt.UTC(), verified: true,
		receipt: ObservabilityCollectorInstallerCredentialReceipt{
			Format: ObservabilityCollectorInstallerCredentialReceiptFormat, State: "ISSUED",
			TargetIdentityDigest: issuer.targetIdentity, ServiceAccountIdentityDigest: serviceAccountIdentity,
			RequestDigest: digest.SHA256(issuer.request), CABundleDigest: issuer.caBundleDigest, AudienceMode: "server-default",
			IssuedAt: now.Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
			LifetimeSeconds: int64(lifetime / time.Second), CredentialBytesInReceipt: false, MutationState: "ATTEMPTED",
		},
	}
	material.privateDigest, err = observabilityCollectorInstallerPrivateDigest(material)
	if err != nil {
		return VerifiedObservabilityCollectorInstallerCredential{}, errors.New("bind private collector installer credential")
	}
	return material, nil
}

func (material VerifiedObservabilityCollectorInstallerCredential) Receipt() (ObservabilityCollectorInstallerCredentialReceipt, error) {
	privateDigest, err := observabilityCollectorInstallerPrivateDigest(material)
	if err != nil || privateDigest != material.privateDigest || !stageReceiptPrefixDigestPattern.MatchString(material.privateDigest) ||
		!material.verified || len(material.token) < 80 || material.endpoint == "" || material.client == nil ||
		!stageReceiptPrefixDigestPattern.MatchString(material.targetIdentity) || !stageReceiptPrefixDigestPattern.MatchString(material.caBundleDigest) || material.expiresAt.IsZero() ||
		material.receipt.Format != ObservabilityCollectorInstallerCredentialReceiptFormat || material.receipt.State != "ISSUED" ||
		material.receipt.TargetIdentityDigest != material.targetIdentity || material.receipt.CABundleDigest != material.caBundleDigest || material.receipt.ExpiresAt != material.expiresAt.UTC().Format(time.RFC3339) ||
		material.receipt.AudienceMode != "server-default" || material.receipt.CredentialBytesInReceipt || material.receipt.MutationState != "ATTEMPTED" {
		return ObservabilityCollectorInstallerCredentialReceipt{}, errors.New("collector installer credential was not produced by verification")
	}
	for _, value := range []string{material.receipt.TargetIdentityDigest, material.receipt.ServiceAccountIdentityDigest, material.receipt.RequestDigest, material.receipt.CABundleDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return ObservabilityCollectorInstallerCredentialReceipt{}, errors.New("collector installer credential receipt identity is invalid")
		}
	}
	return material.receipt, nil
}

func (material VerifiedObservabilityCollectorInstallerCredential) launcherConfig() (submissionStageInstallerClientConfig, error) {
	if _, err := material.Receipt(); err != nil {
		return submissionStageInstallerClientConfig{}, err
	}
	return submissionStageInstallerClientConfig{
		Endpoint: material.endpoint, BearerToken: string(material.token), AuthorityIdentity: material.targetIdentity, Client: material.client,
	}, nil
}

func observabilityCollectorInstallerPrivateDigest(material VerifiedObservabilityCollectorInstallerCredential) (string, error) {
	raw, err := json.Marshal(observabilityCollectorInstallerPrivateBinding{
		Token: append([]byte(nil), material.token...), Endpoint: material.endpoint,
		TargetIdentity: material.targetIdentity, CABundleDigest: material.caBundleDigest,
		ExpiresAt: material.expiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	return digest.SHA256(raw), nil
}

func exactTokenAudienceBinding(raw json.RawMessage, expected []string) bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || len(expected) == 0 {
		return false
	}
	var actual []string
	if raw[0] == '"' {
		var one string
		if json.Unmarshal(raw, &one) != nil || one == "" {
			return false
		}
		actual = []string{one}
	} else if json.Unmarshal(raw, &actual) != nil || len(actual) == 0 {
		return false
	}
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(actual))
	for _, audience := range actual {
		if audience == "" {
			return false
		}
		if _, exists := seen[audience]; exists {
			return false
		}
		seen[audience] = struct{}{}
	}
	for _, audience := range expected {
		if _, exists := seen[audience]; !exists {
			return false
		}
	}
	return true
}
