package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const maximumStageAuthorizationHTTPResponseBytes = 128 * 1024

const (
	stageAuthorizationRequestMediaType                      = "application/vnd.openkubes.stage-authorization-request+json"
	targetCredentialRecoveryAuthorizationRequestMediaType   = "application/vnd.openkubes.target-credential-recovery-authorization-request+json"
	targetRegistrationRecoveryAuthorizationRequestMediaType = "application/vnd.openkubes.target-registration-recovery-authorization-request+json"
	stageAuthorizationResponseMediaType                     = "application/vnd.openkubes.stage-authorization+json"
)

type StageAuthorizationHTTPResolverConfig struct {
	Endpoint        string
	TokenFile       string
	CAFile          string
	PublicKeyPath   string
	OutputDirectory string
	Clock           func() time.Time
}

type StageAuthorizationHTTPResolver struct {
	endpoint        *url.URL
	token           string
	publicKeyPath   string
	outputDirectory string
	client          *http.Client
	clock           func() time.Time
	mu              sync.Mutex
	used            map[string]struct{}
}

// OpenStageAuthorizationHTTPResolver binds one TLS authority endpoint and a
// private create-only grant directory. Opening reads bounded local credential
// files but performs no network request.
func OpenStageAuthorizationHTTPResolver(config StageAuthorizationHTTPResolverConfig) (*StageAuthorizationHTTPResolver, error) {
	token, client, err := openBoundedKubernetesHTTP(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, errors.New("open stage authorization authority credential")
	}
	return newStageAuthorizationHTTPResolver(config, token, client)
}

func newStageAuthorizationHTTPResolver(config StageAuthorizationHTTPResolverConfig, token string, client *http.Client) (*StageAuthorizationHTTPResolver, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.Port() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/v1/stage-authorizations" {
		return nil, errors.New("stage authorization endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("stage authorization endpoint must use HTTPS")
	}
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") || config.PublicKeyPath == "" || config.OutputDirectory == "" || config.Clock == nil || client == nil {
		return nil, errors.New("stage authorization HTTP resolver configuration is incomplete")
	}
	keyInfo, err := os.Lstat(config.PublicKeyPath)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("stage authorization trust key metadata is invalid")
	}
	directoryInfo, err := os.Lstat(config.OutputDirectory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o077 != 0 || !filepath.IsAbs(config.OutputDirectory) || filepath.Clean(config.OutputDirectory) != config.OutputDirectory {
		return nil, errors.New("stage authorization output directory is not private")
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if bounded.Timeout == 0 || bounded.Timeout > 30*time.Second {
		bounded.Timeout = 15 * time.Second
	}
	return &StageAuthorizationHTTPResolver{
		endpoint: endpoint, token: token, publicKeyPath: config.PublicKeyPath,
		outputDirectory: config.OutputDirectory, client: &bounded, clock: config.Clock,
		used: map[string]struct{}{},
	}, nil
}

// ResolveStageAuthorization performs exactly one POST for one canonical
// request digest and persists the returned signed grant create-only as 0600.
// It does not verify or broaden the grant; ResolveStageAuthorization performs
// that independent verification against the current cursor immediately after
// this method returns.
func (resolver *StageAuthorizationHTTPResolver) ResolveStageAuthorization(ctx context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
	requestRaw, err := request.Bytes()
	if err != nil {
		return StageAuthorizationSource{}, err
	}
	return resolver.resolve(ctx, request.RequestDigest, requestRaw, stageAuthorizationRequestMediaType)
}

func (resolver *StageAuthorizationHTTPResolver) ResolveTargetCredentialRecoveryAuthorization(ctx context.Context, request TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
	requestRaw, err := request.Bytes()
	if err != nil {
		return StageAuthorizationSource{}, err
	}
	return resolver.resolve(ctx, request.RequestDigest, requestRaw, targetCredentialRecoveryAuthorizationRequestMediaType)
}

func (resolver *StageAuthorizationHTTPResolver) ResolveTargetRegistrationRecoveryAuthorization(ctx context.Context, request TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
	requestRaw, err := request.Bytes()
	if err != nil {
		return StageAuthorizationSource{}, err
	}
	return resolver.resolve(ctx, request.RequestDigest, requestRaw, targetRegistrationRecoveryAuthorizationRequestMediaType)
}

func (resolver *StageAuthorizationHTTPResolver) resolve(ctx context.Context, requestDigest string, requestRaw []byte, contentType string) (StageAuthorizationSource, error) {
	if resolver == nil || resolver.client == nil || resolver.clock == nil {
		return StageAuthorizationSource{}, errors.New("stage authorization HTTP resolver is required")
	}
	resolver.mu.Lock()
	if _, exists := resolver.used[requestDigest]; exists {
		resolver.mu.Unlock()
		return StageAuthorizationSource{}, errors.New("stage authorization request is single-use")
	}
	resolver.used[requestDigest] = struct{}{}
	resolver.mu.Unlock()
	outputPath := filepath.Join(resolver.outputDirectory, strings.TrimPrefix(requestDigest, "sha256:")+".json")
	if err := validateRuntimeBindingOutputPath(outputPath); err != nil {
		return StageAuthorizationSource{}, errors.New("stage authorization grant destination is invalid")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, resolver.endpoint.String(), bytes.NewReader(requestRaw))
	if err != nil {
		return StageAuthorizationSource{}, errors.New("create stage authorization request")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+resolver.token)
	httpRequest.Header.Set("Content-Type", contentType)
	httpRequest.Header.Set("Accept", stageAuthorizationResponseMediaType)
	response, err := resolver.client.Do(httpRequest)
	if err != nil {
		return StageAuthorizationSource{}, errors.New("perform stage authorization request")
	}
	defer response.Body.Close()
	grantRaw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageAuthorizationHTTPResponseBytes+1))
	if response.StatusCode != http.StatusCreated {
		return StageAuthorizationSource{}, fmt.Errorf("stage authorization authority returned HTTP %d", response.StatusCode)
	}
	if readErr != nil || len(grantRaw) == 0 || len(grantRaw) > maximumStageAuthorizationHTTPResponseBytes ||
		response.Header.Get("Content-Type") != stageAuthorizationResponseMediaType {
		return StageAuthorizationSource{}, errors.New("stage authorization authority response is not accepted")
	}
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return StageAuthorizationSource{}, errors.New("create exclusive stage authorization grant")
	}
	if _, err := file.Write(grantRaw); err != nil {
		file.Close()
		return StageAuthorizationSource{}, errors.New("write stage authorization grant")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return StageAuthorizationSource{}, errors.New("sync stage authorization grant")
	}
	if err := file.Close(); err != nil {
		return StageAuthorizationSource{}, errors.New("close stage authorization grant")
	}
	info, err := os.Lstat(outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(grantRaw)) {
		return StageAuthorizationSource{}, errors.New("persisted stage authorization grant metadata differs")
	}
	stored, err := readBoundedRegular(outputPath, maximumStageAuthorizationHTTPResponseBytes)
	if err != nil || digest.SHA256(stored) != digest.SHA256(grantRaw) {
		return StageAuthorizationSource{}, errors.New("persisted stage authorization grant differs")
	}
	evaluationTime := resolver.clock().UTC()
	if evaluationTime.IsZero() {
		return StageAuthorizationSource{}, errors.New("stage authorization evaluation time is invalid")
	}
	return StageAuthorizationSource{
		GrantPath: outputPath, PublicKeyPath: resolver.publicKeyPath, EvaluationTime: evaluationTime,
	}, nil
}

var _ StageAuthorizationResolver = (*StageAuthorizationHTTPResolver)(nil)
var _ TargetCredentialRecoveryAuthorizationResolver = (*StageAuthorizationHTTPResolver)(nil)
var _ TargetRegistrationRecoveryAuthorizationResolver = (*StageAuthorizationHTTPResolver)(nil)
