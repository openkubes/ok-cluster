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
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityCollectorObserverCredentialReceiptFormat = "ok147-observability-collector-observer-credential-receipt/v1"
	observabilityCollectorObserverLifetime                = time.Hour
	minimumObservabilityCollectorObserverLifetime         = 55 * time.Minute
)

type ObservabilityCollectorObserverCredentialConfig struct {
	Workload             WorkloadAuthorityFileResolverConfig
	ExpectedTargetDigest string
	Clock                func() time.Time
}

type ObservabilityCollectorObserverCredentialReceipt struct {
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

type VerifiedObservabilityCollectorObserverCredential struct {
	token          []byte
	caFile         string
	targetIdentity string
	caBundleDigest string
	source         SubmissionStageCredentialSource
	receipt        ObservabilityCollectorObserverCredentialReceipt
	verified       bool
}

type observabilityCollectorObserverIssuerClientConfig struct {
	Endpoint          string
	BearerToken       string
	ClientCertificate bool
	CABundleDigest    string
	CAFile            string
	TargetIdentity    string
	Client            *http.Client
	Clock             func() time.Time
}

type KubernetesObservabilityCollectorObserverCredentialIssuer struct {
	mu                sync.Mutex
	used              bool
	endpoint          *url.URL
	authorityToken    string
	clientCertificate bool
	caBundleDigest    string
	caFile            string
	targetIdentity    string
	client            *http.Client
	clock             func() time.Time
	request           []byte
}

// OpenKubernetesObservabilityCollectorObserverCredentialIssuer binds the
// lifecycle-derived workload authority. Issue is the sole TokenRequest edge.
func OpenKubernetesObservabilityCollectorObserverCredentialIssuer(config ObservabilityCollectorObserverCredentialConfig) (*KubernetesObservabilityCollectorObserverCredentialIssuer, error) {
	if config.Clock == nil || !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedTargetDigest) {
		return nil, errors.New("collector observer credential binding is incomplete")
	}
	binding, authority, err := loadWorkloadAuthorityFiles(config.Workload)
	if err != nil || digest.SHA256([]byte(binding.TargetClusterUID)) != config.ExpectedTargetDigest {
		return nil, errors.New("collector observer credential differs from runtime workload authority")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(authority)
	if err != nil || digest.SHA256(transport.caData) != authority.CABundleDigest || authority.CAFile != config.Workload.CAFile {
		return nil, errors.New("open bounded collector observer issuance authority")
	}
	return newKubernetesObservabilityCollectorObserverCredentialIssuer(observabilityCollectorObserverIssuerClientConfig{
		Endpoint: authority.Endpoint, BearerToken: transport.bearerToken, ClientCertificate: transport.clientCertificate,
		CABundleDigest: authority.CABundleDigest, CAFile: authority.CAFile, TargetIdentity: config.ExpectedTargetDigest,
		Client: transport.client, Clock: config.Clock,
	})
}

func newKubernetesObservabilityCollectorObserverCredentialIssuer(config observabilityCollectorObserverIssuerClientConfig) (*KubernetesObservabilityCollectorObserverCredentialIssuer, error) {
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.New("collector observer credential endpoint is invalid")
	}
	tokenMode := config.BearerToken != ""
	if tokenMode == config.ClientCertificate || strings.TrimSpace(config.BearerToken) != config.BearerToken ||
		strings.ContainsAny(config.BearerToken, "\r\n") || config.CAFile == "" ||
		!stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.TargetIdentity) || config.Client == nil || config.Clock == nil {
		return nil, errors.New("collector observer issuance authority is invalid")
	}
	requestRaw, err := json.Marshal(targetCredentialTokenRequest{
		APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest",
		Spec: targetCredentialTokenRequestSpec{ExpirationSeconds: int64(observabilityCollectorObserverLifetime / time.Second)},
	})
	if err != nil {
		return nil, errors.New("encode collector observer TokenRequest")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("parse collector observer credential endpoint")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return &KubernetesObservabilityCollectorObserverCredentialIssuer{
		endpoint: parsed, authorityToken: config.BearerToken, clientCertificate: config.ClientCertificate,
		caBundleDigest: config.CABundleDigest, caFile: config.CAFile, targetIdentity: config.TargetIdentity,
		client: &client, clock: config.Clock, request: requestRaw,
	}, nil
}

func (issuer *KubernetesObservabilityCollectorObserverCredentialIssuer) Issue(ctx context.Context) (VerifiedObservabilityCollectorObserverCredential, error) {
	if issuer == nil || issuer.client == nil || issuer.clock == nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer credential issuer is required")
	}
	issuer.mu.Lock()
	if issuer.used {
		issuer.mu.Unlock()
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer credential issuer is single-use")
	}
	issuer.used = true
	issuer.mu.Unlock()
	now := issuer.clock().UTC().Truncate(time.Second)
	requestURL := *issuer.endpoint
	requestURL.Path = fmt.Sprintf("/api/v1/namespaces/ok-observability/serviceaccounts/%s/token", observabilityCollectorObserverSA)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(issuer.request))
	if err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("construct collector observer TokenRequest")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if !issuer.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+issuer.authorityToken)
	}
	response, err := issuer.client.Do(request)
	if err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer TokenRequest failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumTargetCredentialResponse))
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer TokenRequest was not created")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer TokenRequest response media type is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumTargetCredentialResponse+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumTargetCredentialResponse {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("read bounded collector observer TokenRequest response")
	}
	var value targetCredentialTokenResponse
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("decode collector observer TokenRequest response")
	}
	return issuer.verifyResponse(value, now)
}

func (issuer *KubernetesObservabilityCollectorObserverCredentialIssuer) verifyResponse(value targetCredentialTokenResponse, now time.Time) (VerifiedObservabilityCollectorObserverCredential, error) {
	if value.APIVersion != "authentication.k8s.io/v1" || value.Kind != "TokenRequest" || len(value.Status.Token) < 80 ||
		strings.TrimSpace(value.Status.Token) != value.Status.Token || strings.ContainsAny(value.Status.Token, "\r\n") ||
		value.Spec.ExpirationSeconds != int64(observabilityCollectorObserverLifetime/time.Second) || len(value.Spec.Audiences) == 0 {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer TokenRequest response is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, value.Status.ExpirationTimestamp)
	if err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer credential expiration is invalid")
	}
	parts := strings.Split(value.Status.Token, ".")
	if len(parts) != 3 {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("decode collector observer credential claims")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("decode collector observer credential claims")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims submissionStageTokenClaims
	if err := decoder.Decode(&claims); err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("decode collector observer credential claims")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("decode collector observer credential claims")
	}
	issuedAtUnix, err := exactJWTUnix(claims.IssuedAt)
	if err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer credential issued-at is invalid")
	}
	issuedAt := time.Unix(issuedAtUnix, 0).UTC()
	lifetime := expiresAt.Sub(issuedAt)
	wantSubject := "system:serviceaccount:ok-observability:" + observabilityCollectorObserverSA
	audiences, audienceErr := tokenAudiences(claims.Audience)
	exp, expErr := exactJWTUnix(claims.ExpiresAt)
	nbf, nbfErr := exactJWTUnix(claims.NotBefore)
	if audienceErr != nil || len(audiences) != 1 || audiences[0] != "https://kubernetes.default.svc" ||
		expErr != nil || nbfErr != nil || claims.Issuer == "" || claims.Subject != wantSubject || exp != expiresAt.Unix() ||
		nbf != issuedAtUnix || issuedAt.After(now.Add(5*time.Second)) || issuedAt.Before(now.Add(-5*time.Minute)) ||
		lifetime < minimumObservabilityCollectorObserverLifetime || lifetime > observabilityCollectorObserverLifetime {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("collector observer credential claims differ from bounded identity")
	}
	receipt := ObservabilityCollectorObserverCredentialReceipt{
		Format: ObservabilityCollectorObserverCredentialReceiptFormat, State: "ISSUED",
		TargetIdentityDigest:         issuer.targetIdentity,
		ServiceAccountIdentityDigest: digest.SHA256([]byte(wantSubject)), RequestDigest: digest.SHA256(issuer.request),
		CABundleDigest: issuer.caBundleDigest, AudienceMode: "server-default",
		IssuedAt: issuedAt.Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		LifetimeSeconds: int64(lifetime / time.Second), CredentialBytesInReceipt: false, MutationState: "ATTEMPTED",
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("encode collector observer credential receipt")
	}
	source := SubmissionStageCredentialSource{
		AuthorityIdentity: issuer.targetIdentity, TokenDigest: digest.SHA256([]byte(value.Status.Token)),
		CAFile: issuer.caFile, CABundleDigest: issuer.caBundleDigest, TokenRequestEvidenceDigest: digest.SHA256(receiptRaw),
		ExpectedIssuer: claims.Issuer, ExpectedSubject: wantSubject, ExpectedAudiences: []string{"https://kubernetes.default.svc"},
		IssuedAt: issuedAt, ExpiresAt: expiresAt.UTC(),
	}
	if _, err := verifyStageCredentialJWTWithSubject([]byte(value.Status.Token), source, now, func(subject string) bool {
		return subject == wantSubject
	}); err != nil {
		return VerifiedObservabilityCollectorObserverCredential{}, errors.New("verify collector observer credential")
	}
	return VerifiedObservabilityCollectorObserverCredential{
		token: []byte(value.Status.Token), caFile: issuer.caFile, targetIdentity: issuer.targetIdentity,
		caBundleDigest: issuer.caBundleDigest, source: source, receipt: receipt, verified: true,
	}, nil
}

func (credential VerifiedObservabilityCollectorObserverCredential) Material() (SubmissionStageCredentialSource, []byte, ObservabilityCollectorObserverCredentialReceipt, error) {
	if !credential.verified || len(credential.token) < 80 || credential.source.TokenFile != "" ||
		credential.source.TokenDigest != digest.SHA256(credential.token) || credential.source.CAFile != credential.caFile ||
		credential.source.CABundleDigest != credential.caBundleDigest || credential.source.AuthorityIdentity != credential.targetIdentity ||
		credential.receipt.Format != ObservabilityCollectorObserverCredentialReceiptFormat || credential.receipt.State != "ISSUED" ||
		credential.receipt.CredentialBytesInReceipt || credential.receipt.MutationState != "ATTEMPTED" {
		return SubmissionStageCredentialSource{}, nil, ObservabilityCollectorObserverCredentialReceipt{}, errors.New("collector observer credential was not produced by verification")
	}
	receiptRaw, err := json.Marshal(credential.receipt)
	if err != nil || credential.source.TokenRequestEvidenceDigest != digest.SHA256(receiptRaw) {
		return SubmissionStageCredentialSource{}, nil, ObservabilityCollectorObserverCredentialReceipt{}, errors.New("collector observer credential evidence differs")
	}
	source := credential.source
	source.ExpectedAudiences = append([]string(nil), credential.source.ExpectedAudiences...)
	return source, append([]byte(nil), credential.token...), credential.receipt, nil
}
