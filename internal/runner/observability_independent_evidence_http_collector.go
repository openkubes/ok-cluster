package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityIndependentEvidenceCollectionRequestFormat  = "ok147-observability-independent-evidence-collection-request/v1"
	ObservabilityIndependentEvidenceCollectionResponseFormat = "ok147-observability-independent-evidence-collection-response/v1"
	observabilityIndependentEvidenceCollectionPath           = "/v1/observability/independent-evidence"
	maximumObservabilityIndependentEvidenceCollectionBytes   = 64 * 1024
)

type ObservabilityIndependentEvidenceCollectionRequest struct {
	Format           string `json:"format"`
	RunID            string `json:"runId"`
	TargetClusterUID string `json:"targetClusterUid"`
	FixtureDigest    string `json:"fixtureDigest"`
	ProfileDigest    string `json:"profileDigest"`
	AlertName        string `json:"alertName"`
}

type ObservabilityIndependentEvidenceCollectionResponse struct {
	Format                      string `json:"format"`
	RequestDigest               string `json:"requestDigest"`
	ReceiverDeliveryObserved    bool   `json:"receiverDeliveryObserved"`
	ReceiverIdentityDigest      string `json:"receiverIdentityDigest"`
	ClusterLocalServicesReady   bool   `json:"clusterLocalServicesReady"`
	ExternalClusterDependencies int    `json:"externalClusterDependencies"`
	AutonomyProfileDigest       string `json:"autonomyProfileDigest"`
}

type HTTPObservabilityIndependentEvidenceCollectorConfig struct {
	Endpoint       string
	TokenFile      string
	CAFile         string
	CABundleDigest string
}

// HTTPObservabilityIndependentEvidenceCollector performs one exact request to
// a separately operated evidence authority. It has no caller-selected path,
// query, method, payload extension, retry or redirect surface.
type HTTPObservabilityIndependentEvidenceCollector struct {
	endpoint *url.URL
	token    string
	client   *http.Client
}

func OpenHTTPObservabilityIndependentEvidenceCollector(config HTTPObservabilityIndependentEvidenceCollectorConfig) (*HTTPObservabilityIndependentEvidenceCollector, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" && endpoint.Path != "/" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || config.TokenFile == "" || config.CAFile == "" ||
		!platformInputDigestPattern.MatchString(config.CABundleDigest) {
		return nil, errors.New("observability independent evidence collector binding is invalid")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.TokenFile, config.CAFile)
	if err != nil || digest.SHA256(ca) != config.CABundleDigest {
		return nil, errors.New("open observability independent evidence collector authority")
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	endpoint.Path, endpoint.RawPath = "", ""
	return &HTTPObservabilityIndependentEvidenceCollector{endpoint: endpoint, token: token, client: &copyClient}, nil
}

func (collector *HTTPObservabilityIndependentEvidenceCollector) Collect(ctx context.Context, identity ObservabilityCapabilityObservationIdentity, alertName string) (ObservabilityIndependentEvidenceObservation, error) {
	if collector == nil || collector.endpoint == nil || collector.client == nil || collector.token == "" || !validObservabilityObservationIdentity(identity) ||
		alertName == "" || !runtimeInputUIDPattern.MatchString(alertName) {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("observability independent evidence collection input is invalid")
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("observability independent evidence collection requires a live deadline")
	}
	requestDocument := ObservabilityIndependentEvidenceCollectionRequest{
		Format: ObservabilityIndependentEvidenceCollectionRequestFormat, RunID: identity.RunID, TargetClusterUID: identity.TargetClusterUID,
		FixtureDigest: identity.FixtureDigest, ProfileDigest: identity.ProfileDigest, AlertName: alertName,
	}
	requestRaw, requestDigest, err := canonicalObservabilityIndependentEvidenceCollectionRequest(requestDocument)
	if err != nil {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("canonicalize observability independent evidence collection request")
	}
	endpoint := *collector.endpoint
	endpoint.Path = observabilityIndependentEvidenceCollectionPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(requestRaw))
	if err != nil {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("construct observability independent evidence collection request")
	}
	request.Header.Set("Authorization", "Bearer "+collector.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := collector.client.Do(request)
	if err != nil {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("request independent observability evidence")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("independent observability evidence response is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumObservabilityIndependentEvidenceCollectionBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumObservabilityIndependentEvidenceCollectionBytes {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("independent observability evidence response exceeds accepted size")
	}
	var document ObservabilityIndependentEvidenceCollectionResponse
	if err := jsonstrict.Decode(raw, &document); err != nil || document.Format != ObservabilityIndependentEvidenceCollectionResponseFormat ||
		document.RequestDigest != requestDigest || !platformInputDigestPattern.MatchString(document.ReceiverIdentityDigest) ||
		!platformInputDigestPattern.MatchString(document.AutonomyProfileDigest) || document.ExternalClusterDependencies < 0 {
		return ObservabilityIndependentEvidenceObservation{}, errors.New("independent observability evidence response differs from request")
	}
	return ObservabilityIndependentEvidenceObservation{
		ReceiverDeliveryObserved: document.ReceiverDeliveryObserved, ReceiverIdentityDigest: document.ReceiverIdentityDigest,
		ClusterLocalServicesReady: document.ClusterLocalServicesReady, ExternalClusterDependencies: document.ExternalClusterDependencies,
		AutonomyProfileDigest: document.AutonomyProfileDigest,
	}, nil
}

func canonicalObservabilityIndependentEvidenceCollectionRequest(request ObservabilityIndependentEvidenceCollectionRequest) ([]byte, string, error) {
	if request.Format != ObservabilityIndependentEvidenceCollectionRequestFormat || !validObservabilityObservationIdentity(ObservabilityCapabilityObservationIdentity{
		RunID: request.RunID, TargetClusterUID: request.TargetClusterUID, FixtureDigest: request.FixtureDigest, ProfileDigest: request.ProfileDigest,
	}) || request.AlertName == "" || !runtimeInputUIDPattern.MatchString(request.AlertName) || strings.ContainsAny(request.AlertName, "\r\n") {
		return nil, "", errors.New("observability independent evidence collection request is invalid")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return nil, "", err
	}
	return canonical, digest.SHA256(canonical), nil
}

var _ ObservabilityIndependentEvidenceCollector = (*HTTPObservabilityIndependentEvidenceCollector)(nil)
