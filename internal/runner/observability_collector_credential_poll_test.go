package runner

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type collectorCredentialRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn collectorCredentialRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestObservabilityCollectorCredentialPollingConvergesOnlyOnAllowedStatuses(t *testing.T) {
	statuses := []int{http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusCreated}
	requests := 0
	waits := 0
	clock := time.Unix(1_700_000_000, 0)
	client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := statuses[requests]
		requests++
		body := `{}`
		if status == http.StatusCreated {
			body = `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","metadata":{},"spec":{"expirationSeconds":3600},"status":{"token":"token","expirationTimestamp":"2026-09-08T20:00:00Z"}}`
		}
		return collectorCredentialResponse(status, body), nil
	})}
	value, err := issueObservabilityCollectorCredential(context.Background(), collectorCredentialPollConfig(t, client, &clock, func(context.Context, time.Duration) error {
		waits++
		clock = clock.Add(time.Second)
		return nil
	}))
	if err != nil || value.Kind != "TokenRequest" || requests != len(statuses) || waits != len(statuses)-1 {
		t.Fatalf("unexpected convergence result: value=%+v err=%v requests=%d waits=%d", value, err, requests, waits)
	}
}

func TestObservabilityCollectorObserverCredentialDefaultWindowConvergesAfterSlowAuthorityInstallation(t *testing.T) {
	const transientAttempts = 45
	requests := 0
	waits := 0
	clock := time.Unix(1_700_000_000, 0)
	client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		if requests <= transientAttempts {
			return collectorCredentialResponse(http.StatusNotFound, `{}`), nil
		}
		return collectorCredentialResponse(http.StatusCreated, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","metadata":{},"spec":{"expirationSeconds":3600},"status":{"token":"token","expirationTimestamp":"2026-09-08T20:00:00Z"}}`), nil
	})}
	endpoint, err := url.Parse("https://workload.example.invalid/token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := issueObservabilityCollectorCredential(context.Background(), observabilityCollectorCredentialPollConfig{
		client: client, endpoint: *endpoint, authorityToken: "authority", request: []byte(`{}`),
		pollClock: func() time.Time { return clock }, wait: func(_ context.Context, delay time.Duration) error {
			waits++
			clock = clock.Add(delay)
			return nil
		},
		pollInterval: observabilityCollectorCredentialPollInterval,
		pollTimeout:  observabilityCollectorObserverCredentialPollTimeout,
		maxAttempts:  observabilityCollectorObserverCredentialMaxAttempts,
	})
	if err != nil || value.Kind != "TokenRequest" || requests != transientAttempts+1 || waits != transientAttempts {
		t.Fatalf("slow authority installation did not converge: value=%+v err=%v requests=%d waits=%d", value, err, requests, waits)
	}
}

func TestObservabilityCollectorCredentialPollingRejectsTerminalStatusesWithoutRetry(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotImplemented} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			clock := time.Unix(1_700_000_000, 0)
			client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				return collectorCredentialResponse(status, `{}`), nil
			})}
			_, err := issueObservabilityCollectorCredential(context.Background(), collectorCredentialPollConfig(t, client, &clock, func(context.Context, time.Duration) error {
				t.Fatal("terminal status must not wait")
				return nil
			}))
			if err == nil || requests != 1 {
				t.Fatalf("terminal status retried: err=%v requests=%d", err, requests)
			}
		})
	}
}

func TestObservabilityCollectorCredentialPollingBoundsTransientFailure(t *testing.T) {
	requests := 0
	clock := time.Unix(1_700_000_000, 0)
	config := collectorCredentialPollConfig(t, &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return collectorCredentialResponse(http.StatusServiceUnavailable, `{}`), nil
	})}, &clock, func(context.Context, time.Duration) error {
		clock = clock.Add(time.Second)
		return nil
	})
	config.maxAttempts = 3
	_, err := issueObservabilityCollectorCredential(context.Background(), config)
	if err == nil || requests != 3 {
		t.Fatalf("transient failure was not attempt-bounded: err=%v requests=%d", err, requests)
	}
}

func TestObservabilityCollectorCredentialPollingClassifiesTransportErrors(t *testing.T) {
	tests := []struct {
		name      string
		transport error
		wantCalls int
	}{
		{name: "temporary", transport: &net.DNSError{IsTemporary: true}, wantCalls: 2},
		{name: "tls", transport: x509.UnknownAuthorityError{}, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			clock := time.Unix(1_700_000_000, 0)
			client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				if requests == 1 {
					return nil, test.transport
				}
				return collectorCredentialResponse(http.StatusUnauthorized, `{}`), nil
			})}
			_, _ = issueObservabilityCollectorCredential(context.Background(), collectorCredentialPollConfig(t, client, &clock, func(context.Context, time.Duration) error {
				clock = clock.Add(time.Second)
				return nil
			}))
			if requests != test.wantCalls {
				t.Fatalf("unexpected transport retry count: got %d want %d", requests, test.wantCalls)
			}
		})
	}
}

func TestObservabilityCollectorCredentialPollingRejectsMalformedSuccessWithoutRetry(t *testing.T) {
	for _, test := range []struct{ name, contentType, body string }{
		{name: "media", contentType: "text/plain", body: `{}`},
		{name: "trailing", contentType: "application/json", body: `{} {}`},
		{name: "oversized", contentType: "application/json", body: strings.Repeat("x", maximumTargetCredentialResponse+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			clock := time.Unix(1_700_000_000, 0)
			client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				response := collectorCredentialResponse(http.StatusCreated, test.body)
				response.Header.Set("Content-Type", test.contentType)
				return response, nil
			})}
			_, err := issueObservabilityCollectorCredential(context.Background(), collectorCredentialPollConfig(t, client, &clock, func(context.Context, time.Duration) error {
				t.Fatal("malformed success must not wait")
				return nil
			}))
			if err == nil || requests != 1 {
				t.Fatalf("malformed success retried: err=%v requests=%d", err, requests)
			}
		})
	}
}

func TestObservabilityCollectorCredentialPollingRejectsOversizedTransientResponse(t *testing.T) {
	requests := 0
	clock := time.Unix(1_700_000_000, 0)
	client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return collectorCredentialResponse(http.StatusServiceUnavailable, strings.Repeat("x", maximumTargetCredentialResponse+1)), nil
	})}
	_, err := issueObservabilityCollectorCredential(context.Background(), collectorCredentialPollConfig(t, client, &clock, func(context.Context, time.Duration) error {
		t.Fatal("oversized transient response must not wait")
		return nil
	}))
	if err == nil || requests != 1 {
		t.Fatalf("oversized transient response retried: err=%v requests=%d", err, requests)
	}
}

func TestObservabilityCollectorCredentialPollingRejectsSuccessAfterDeadline(t *testing.T) {
	requests := 0
	clock := time.Unix(1_700_000_000, 0)
	client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		clock = clock.Add(30 * time.Second)
		return collectorCredentialResponse(http.StatusCreated, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","metadata":{},"spec":{"expirationSeconds":3600},"status":{"token":"token","expirationTimestamp":"2026-09-08T20:00:00Z"}}`), nil
	})}
	_, err := issueObservabilityCollectorCredential(context.Background(), collectorCredentialPollConfig(t, client, &clock, func(context.Context, time.Duration) error {
		t.Fatal("late success must not wait")
		return nil
	}))
	if err == nil || requests != 1 {
		t.Fatalf("late success was accepted: err=%v requests=%d", err, requests)
	}
}

func TestObservabilityCollectorCredentialPollingCancelsInFlightRequestAtDeadline(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: collectorCredentialRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	clock := time.Now
	endpoint, err := url.Parse("https://workload.example.invalid/token")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = issueObservabilityCollectorCredential(context.Background(), observabilityCollectorCredentialPollConfig{
		client: client, endpoint: *endpoint, authorityToken: "authority", request: []byte(`{}`),
		pollClock: clock, wait: func(context.Context, time.Duration) error { return nil },
		pollInterval: time.Millisecond, pollTimeout: 10 * time.Millisecond, maxAttempts: 30,
	})
	if err == nil || requests != 1 || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("in-flight request was not deadline-bounded: err=%v requests=%d elapsed=%s", err, requests, time.Since(started))
	}
}

func collectorCredentialPollConfig(t *testing.T, client *http.Client, clock *time.Time, wait func(context.Context, time.Duration) error) observabilityCollectorCredentialPollConfig {
	t.Helper()
	endpoint, err := url.Parse("https://workload.example.invalid/token")
	if err != nil {
		t.Fatal(err)
	}
	return observabilityCollectorCredentialPollConfig{
		client: client, endpoint: *endpoint, authorityToken: "authority", request: []byte(`{}`),
		pollClock: func() time.Time { return *clock }, wait: wait, pollInterval: time.Second,
		pollTimeout: 30 * time.Second, maxAttempts: 30,
	}
}

func collectorCredentialResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
