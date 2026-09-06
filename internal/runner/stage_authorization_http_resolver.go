package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
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
	defaultStageAuthorizationPollInterval = time.Second
	defaultStageAuthorizationPollTimeout  = 30 * time.Second
	defaultStageAuthorizationMaxAttempts  = 30
)

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
	PollClock       func() time.Time
	PollWait        func(context.Context, time.Duration) error
	PollInterval    time.Duration
	PollTimeout     time.Duration
	MaxAttempts     int
}

type StageAuthorizationHTTPResolver struct {
	endpoint        *url.URL
	token           string
	publicKeyPath   string
	outputDirectory string
	client          *http.Client
	clock           func() time.Time
	pollClock       func() time.Time
	pollWait        func(context.Context, time.Duration) error
	pollInterval    time.Duration
	pollTimeout     time.Duration
	maxAttempts     int
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
	if config.PollClock == nil {
		config.PollClock = time.Now
	}
	if config.PollWait == nil {
		config.PollWait = waitForStageAuthorizationPoll
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultStageAuthorizationPollInterval
	}
	if config.PollTimeout == 0 {
		config.PollTimeout = defaultStageAuthorizationPollTimeout
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = defaultStageAuthorizationMaxAttempts
	}
	if config.PollInterval < time.Millisecond || config.PollTimeout < config.PollInterval || config.PollTimeout > time.Minute || config.MaxAttempts < 1 || config.MaxAttempts > 60 {
		return nil, errors.New("stage authorization polling boundary is invalid")
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
		pollClock: config.PollClock, pollWait: config.PollWait, pollInterval: config.PollInterval,
		pollTimeout: config.PollTimeout, maxAttempts: config.MaxAttempts,
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
	deadline := resolver.pollClock().Add(resolver.pollTimeout)
	var grantRaw []byte
	for attempt := 1; attempt <= resolver.maxAttempts; attempt++ {
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, resolver.endpoint.String(), bytes.NewReader(requestRaw))
		if err != nil {
			return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_RESPONSE_INVALID", "create stage authorization request")
		}
		httpRequest.Header.Set("Authorization", "Bearer "+resolver.token)
		httpRequest.Header.Set("Content-Type", contentType)
		httpRequest.Header.Set("Accept", stageAuthorizationResponseMediaType)
		response, requestErr := resolver.client.Do(httpRequest)
		if requestErr != nil {
			if !transientStageAuthorizationTransportError(requestErr) || !resolver.canPollAgain(ctx, attempt, deadline) {
				return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_TRANSPORT_STOPPED", "perform stage authorization request")
			}
			if err := resolver.pollWait(ctx, resolver.pollInterval); err != nil {
				return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_INTERRUPTED", "stage authorization polling interrupted")
			}
			continue
		}
		grantRaw, err = io.ReadAll(io.LimitReader(response.Body, maximumStageAuthorizationHTTPResponseBytes+1))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			if transientStageAuthorizationHTTPStatus(response.StatusCode) && resolver.canPollAgain(ctx, attempt, deadline) {
				if err := resolver.pollWait(ctx, resolver.pollInterval); err != nil {
					return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_INTERRUPTED", "stage authorization polling interrupted")
				}
				continue
			}
			return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_HTTP_REJECTED", fmt.Sprintf("stage authorization authority returned HTTP %d", response.StatusCode))
		}
		if err != nil || closeErr != nil || len(grantRaw) == 0 || len(grantRaw) > maximumStageAuthorizationHTTPResponseBytes ||
			response.Header.Get("Content-Type") != stageAuthorizationResponseMediaType {
			return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_RESPONSE_INVALID", "stage authorization authority response is not accepted")
		}
		break
	}
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_PERSISTENCE_STOPPED", "create exclusive stage authorization grant")
	}
	if _, err := file.Write(grantRaw); err != nil {
		file.Close()
		return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_PERSISTENCE_STOPPED", "write stage authorization grant")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_PERSISTENCE_STOPPED", "sync stage authorization grant")
	}
	if err := file.Close(); err != nil {
		return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_PERSISTENCE_STOPPED", "close stage authorization grant")
	}
	info, err := os.Lstat(outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(grantRaw)) {
		return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_PERSISTENCE_STOPPED", "persisted stage authorization grant metadata differs")
	}
	stored, err := readBoundedRegular(outputPath, maximumStageAuthorizationHTTPResponseBytes)
	if err != nil || digest.SHA256(stored) != digest.SHA256(grantRaw) {
		return StageAuthorizationSource{}, newStageAuthorizationStop("AUTHORIZATION_PERSISTENCE_STOPPED", "persisted stage authorization grant differs")
	}
	evaluationTime := resolver.clock().UTC()
	if evaluationTime.IsZero() {
		return StageAuthorizationSource{}, errors.New("stage authorization evaluation time is invalid")
	}
	return StageAuthorizationSource{
		GrantPath: outputPath, PublicKeyPath: resolver.publicKeyPath, EvaluationTime: evaluationTime,
	}, nil
}

type stageAuthorizationStopError struct {
	category string
	message  string
}

func (err *stageAuthorizationStopError) Error() string                { return err.message }
func (err *stageAuthorizationStopError) RedactedStopCategory() string { return err.category }

func newStageAuthorizationStop(category, message string) error {
	return &stageAuthorizationStopError{category: category, message: message}
}

func (resolver *StageAuthorizationHTTPResolver) canPollAgain(ctx context.Context, attempt int, deadline time.Time) bool {
	return ctx.Err() == nil && attempt < resolver.maxAttempts && resolver.pollClock().Add(resolver.pollInterval).Before(deadline)
}

func transientStageAuthorizationHTTPStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func transientStageAuthorizationTransportError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostnameError x509.HostnameError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &unknownAuthority) || errors.As(err, &certificateInvalid) || errors.As(err, &hostnameError) || errors.As(err, &recordHeader) {
		return false
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return dnsError.IsTimeout || dnsError.IsTemporary
	}
	var networkError net.Error
	return errors.As(err, &networkError) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func waitForStageAuthorizationPoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ StageAuthorizationResolver = (*StageAuthorizationHTTPResolver)(nil)
var _ TargetCredentialRecoveryAuthorizationResolver = (*StageAuthorizationHTTPResolver)(nil)
var _ TargetRegistrationRecoveryAuthorizationResolver = (*StageAuthorizationHTTPResolver)(nil)
