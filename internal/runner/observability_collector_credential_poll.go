package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	observabilityCollectorCredentialPollInterval = time.Second
	observabilityCollectorCredentialPollTimeout  = 30 * time.Second
	observabilityCollectorCredentialMaxAttempts  = 30
)

type observabilityCollectorCredentialPollConfig struct {
	client            *http.Client
	endpoint          url.URL
	authorityToken    string
	clientCertificate bool
	request           []byte
	pollClock         func() time.Time
	wait              func(context.Context, time.Duration) error
	pollInterval      time.Duration
	pollTimeout       time.Duration
	maxAttempts       int
}

func issueObservabilityCollectorCredential(ctx context.Context, config observabilityCollectorCredentialPollConfig) (targetCredentialTokenResponse, error) {
	if config.client == nil || config.pollClock == nil || config.wait == nil || len(config.request) == 0 ||
		config.pollInterval <= 0 || config.pollTimeout <= 0 || config.maxAttempts < 1 {
		return targetCredentialTokenResponse{}, errors.New("collector credential polling configuration is invalid")
	}
	deadline := config.pollClock().Add(config.pollTimeout)
	for attempt := 1; attempt <= config.maxAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.endpoint.String(), bytes.NewReader(config.request))
		if err != nil {
			return targetCredentialTokenResponse{}, errors.New("construct collector credential TokenRequest")
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		if !config.clientCertificate {
			request.Header.Set("Authorization", "Bearer "+config.authorityToken)
		}
		response, requestErr := config.client.Do(request)
		if requestErr != nil {
			if !transientStageAuthorizationTransportError(requestErr) || !collectorCredentialCanPollAgain(ctx, config, attempt, deadline) {
				return targetCredentialTokenResponse{}, errors.New("collector credential TokenRequest transport stopped")
			}
			if err := config.wait(ctx, config.pollInterval); err != nil {
				return targetCredentialTokenResponse{}, errors.New("collector credential TokenRequest interrupted")
			}
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumTargetCredentialResponse+1))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			if readErr != nil || closeErr != nil || len(raw) > maximumTargetCredentialResponse ||
				!transientObservabilityCollectorCredentialStatus(response.StatusCode) ||
				!collectorCredentialCanPollAgain(ctx, config, attempt, deadline) {
				return targetCredentialTokenResponse{}, errors.New("collector credential TokenRequest was not created")
			}
			if err := config.wait(ctx, config.pollInterval); err != nil {
				return targetCredentialTokenResponse{}, errors.New("collector credential TokenRequest interrupted")
			}
			continue
		}
		mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" {
			return targetCredentialTokenResponse{}, errors.New("collector credential TokenRequest response media type is invalid")
		}
		if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > maximumTargetCredentialResponse {
			return targetCredentialTokenResponse{}, errors.New("read bounded collector credential TokenRequest response")
		}
		var value targetCredentialTokenResponse
		if err := jsonstrict.Decode(raw, &value); err != nil {
			return targetCredentialTokenResponse{}, errors.New("decode collector credential TokenRequest response")
		}
		return value, nil
	}
	return targetCredentialTokenResponse{}, errors.New("collector credential TokenRequest convergence exhausted")
}

func collectorCredentialCanPollAgain(ctx context.Context, config observabilityCollectorCredentialPollConfig, attempt int, deadline time.Time) bool {
	return ctx.Err() == nil && attempt < config.maxAttempts && config.pollClock().Add(config.pollInterval).Before(deadline)
}

func transientObservabilityCollectorCredentialStatus(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
