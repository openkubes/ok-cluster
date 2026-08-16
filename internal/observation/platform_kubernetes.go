package observation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maximumPlatformSourceBytes = 4 * 1024 * 1024

type KubernetesPlatformReaderConfig struct {
	Endpoint    string
	BearerToken string
	Client      *http.Client
}

// KubernetesPlatformReader can read only the exact Applications named by the
// immutable profile supplied at construction time.
type KubernetesPlatformReader struct {
	endpoint *url.URL
	token    string
	client   *http.Client
	allowed  map[string]struct{}
}

func NewKubernetesPlatformReader(config KubernetesPlatformReaderConfig, profile PlatformProfile) (*KubernetesPlatformReader, error) {
	if err := ValidatePlatformProfile(profile); err != nil {
		return nil, errors.New("platform reader profile is invalid")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("platform reader Kubernetes endpoint is invalid")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("platform reader credential or client is invalid")
	}
	allowed := make(map[string]struct{}, len(profile.RequiredApplications))
	for _, application := range profile.RequiredApplications {
		path := platformApplicationPath(profile.ArgoNamespace, application.Name)
		allowed[path] = struct{}{}
	}
	client := *config.Client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesPlatformReader{endpoint: endpoint, token: config.BearerToken, client: &client, allowed: allowed}, nil
}

func (reader *KubernetesPlatformReader) Get(ctx context.Context, path string) ([]byte, error) {
	if _, allowed := reader.allowed[path]; !allowed {
		return nil, errors.New("platform reader path is outside the fixed allowlist")
	}
	reference, err := url.ParseRequestURI(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || reference.RawQuery != "" {
		return nil, errors.New("platform reader allowlisted path is invalid")
	}
	endpoint := *reader.endpoint
	endpoint.Path, endpoint.RawPath = reference.Path, reference.RawPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("construct exact Argo Application request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+reader.token)
	response, err := reader.client.Do(request)
	if err != nil {
		return nil, errors.New("exact Argo Application request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumPlatformSourceBytes+1))
	if readErr != nil || len(raw) > maximumPlatformSourceBytes {
		return nil, errors.New("exact Argo Application response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exact Argo Application request returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("exact Argo Application response is not JSON")
	}
	return raw, nil
}

func platformApplicationPath(namespace, name string) string {
	return "/apis/argoproj.io/v1alpha1/namespaces/" + namespace + "/applications/" + name
}
