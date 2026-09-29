package submission

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const (
	maximumAPIResponseBytes = 4 * 1024 * 1024
	PlaneReceiptFormat      = "ok147-bounded-submission-receipt/v2"
)

// KubernetesClientConfig binds one client to one authority plane. Credentials
// are supplied by an execution-environment adapter and are never retained in a
// receipt.
type KubernetesClientConfig struct {
	Endpoint          string
	BearerToken       string
	ClientCertificate bool
	AuthorityIdentity string
	Client            *http.Client
}

// KubernetesClient performs only exact GET and collection POST operations.
type KubernetesClient struct {
	endpoint          *url.URL
	token             string
	clientCertificate bool
	authority         string
	client            *http.Client
}

// ObjectResult records only redacted, immutable submission identity.
type ObjectResult struct {
	Identity ObjectIdentity `json:"identity"`
	Digest   string         `json:"digest"`
	UID      string         `json:"uid"`
	State    string         `json:"state"`
}

// PlaneReceipt is useful even on failure: Results contains the exact prefix
// completed before STOP-PRESERVE-NO-RETRY.
type PlaneReceipt struct {
	Format        string         `json:"format"`
	Authority     string         `json:"authority"`
	Role          string         `json:"role"`
	State         string         `json:"state"`
	MutationState string         `json:"mutationState"`
	Results       []ObjectResult `json:"results"`
}

// ObjectIdentity is the public, non-secret runtime identity used to correlate
// later observation with the exact submission response.
type ObjectIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

// SubmissionError retains the redacted partial receipt and wraps the cause.
type SubmissionError struct {
	Receipt  PlaneReceipt
	Cause    error
	Category string
}

func (err *SubmissionError) Error() string {
	return "bounded submission stopped"
}
func (err *SubmissionError) Unwrap() error                { return err.Cause }
func (err *SubmissionError) RedactedStopCategory() string { return err.Category }

type categorizedSubmissionError struct {
	category string
	message  string
}

func (err *categorizedSubmissionError) Error() string                { return err.message }
func (err *categorizedSubmissionError) RedactedStopCategory() string { return err.category }

func newCategorizedSubmissionError(category, message string) error {
	return &categorizedSubmissionError{category: category, message: message}
}

func NewKubernetesClient(config KubernetesClientConfig) (*KubernetesClient, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("submission Kubernetes endpoint is invalid")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("submission Kubernetes endpoint must not contain a path")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("submission Kubernetes endpoint must use HTTPS")
	}
	tokenMode := config.BearerToken != ""
	if tokenMode == config.ClientCertificate || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") {
		return nil, errors.New("submission Kubernetes transport credential is invalid")
	}
	if (!validName(config.AuthorityIdentity, 63) || strings.Contains(config.AuthorityIdentity, ".")) && !immutableDigestPattern.MatchString(config.AuthorityIdentity) {
		return nil, errors.New("submission authority identity is invalid")
	}
	if config.Client == nil {
		return nil, errors.New("submission requires an explicitly configured HTTP client")
	}
	client := *config.Client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path = ""
	return &KubernetesClient{
		endpoint: endpoint, token: config.BearerToken, clientCertificate: config.ClientCertificate,
		authority: config.AuthorityIdentity, client: &client,
	}, nil
}

// Submit verifies existing objects or creates missing objects in projection
// order. It never updates, patches, deletes, lists, watches, discovers, or
// retries. A conflict after an absence observation is indeterminate and stops.
func (client *KubernetesClient) Submit(ctx context.Context, plane Plane) (PlaneReceipt, error) {
	receipt := PlaneReceipt{
		Format:        PlaneReceiptFormat,
		Authority:     plane.Identity,
		Role:          plane.Role,
		State:         "IN_PROGRESS",
		MutationState: "NOT_ATTEMPTED",
		Results:       make([]ObjectResult, 0, len(plane.Objects)),
	}
	if plane.Identity != client.authority {
		return stopped(receipt, errors.New("submission client authority differs from projection plane"))
	}
	if len(plane.Objects) == 0 {
		return stopped(receipt, errors.New("submission plane has no objects"))
	}
	for _, object := range plane.Objects {
		state, uid, mutationAttempted, err := client.submitObject(ctx, object)
		if mutationAttempted {
			receipt.MutationState = "ATTEMPTED"
		}
		if err != nil {
			return stopped(receipt, err)
		}
		receipt.Results = append(receipt.Results, ObjectResult{
			Identity: ObjectIdentity{APIVersion: object.Identity.APIVersion, Kind: object.Identity.Kind, Name: object.Identity.Name, Namespace: object.Identity.Namespace},
			Digest:   object.Digest,
			UID:      uid,
			State:    state,
		})
	}
	receipt.State = "SUBMITTED"
	return receipt, nil
}

func stopped(receipt PlaneReceipt, cause error) (PlaneReceipt, error) {
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	category := "SUBMISSION_RESPONSE_INVALID"
	var categorized interface{ RedactedStopCategory() string }
	if errors.As(cause, &categorized) {
		category = categorized.RedactedStopCategory()
	}
	return receipt, &SubmissionError{Receipt: receipt, Cause: cause, Category: category}
}

func (client *KubernetesClient) submitObject(ctx context.Context, object Object) (string, string, bool, error) {
	response, status, err := client.request(ctx, http.MethodGet, object.ObjectPath, nil)
	if err != nil {
		return "", "", false, err
	}
	switch status {
	case http.StatusOK:
		uid, err := verifyObservedObject(response, object)
		if err != nil {
			return "", "", false, newCategorizedSubmissionError("SUBMISSION_OBJECT_MISMATCH", "existing Kubernetes object differs from projection")
		}
		return "UNCHANGED", uid, false, nil
	case http.StatusNotFound:
		// Continue to the one authorized create attempt.
	default:
		return "", "", false, apiStatusError(http.MethodGet, status, response)
	}

	response, status, err = client.request(ctx, http.MethodPost, object.CollectionPath, object.Raw)
	if err != nil {
		return "", "", true, err
	}
	if status == http.StatusConflict {
		return "", "", true, newCategorizedSubmissionError("SUBMISSION_CONFLICT_STOPPED", "Kubernetes create conflicted after exact absence observation")
	}
	if status != http.StatusCreated {
		return "", "", true, apiStatusError(http.MethodPost, status, response)
	}
	uid, err := verifyObservedObject(response, object)
	if err != nil {
		return "", "", true, newCategorizedSubmissionError("SUBMISSION_RESPONSE_INVALID", "created Kubernetes object response differs from projection")
	}
	return "CREATED", uid, true, nil
}

func (client *KubernetesClient) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *client.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded Kubernetes request")
	}
	request.Header.Set("Accept", "application/json")
	if !client.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, 0, newCategorizedSubmissionError(submissionTransportStopCategory(err), "bounded Kubernetes request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumAPIResponseBytes+1))
	if err != nil || len(raw) > maximumAPIResponseBytes {
		return nil, 0, newCategorizedSubmissionError("SUBMISSION_RESPONSE_INVALID", "bounded Kubernetes response exceeds accepted size")
	}
	return raw, response.StatusCode, nil
}

// submissionTransportStopCategory retains only the failed transport phase.
// It must never carry the wrapped error, endpoint, address or certificate
// identity into a receipt.
func submissionTransportStopCategory(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "SUBMISSION_TIMEOUT_STOPPED"
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "SUBMISSION_DNS_STOPPED"
	}
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostnameError x509.HostnameError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &unknownAuthority) || errors.As(err, &certificateInvalid) || errors.As(err, &hostnameError) || errors.As(err, &recordHeader) {
		return "SUBMISSION_TLS_STOPPED"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "SUBMISSION_TIMEOUT_STOPPED"
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) && operationError.Op == "dial" {
		return "SUBMISSION_CONNECT_STOPPED"
	}
	return "SUBMISSION_TRANSPORT_STOPPED"
}

func verifyObservedObject(raw []byte, desired Object) (string, error) {
	observed, err := decodeJSONObject(raw)
	if err != nil {
		return "", errors.New("Kubernetes API returned invalid object JSON")
	}
	expected, err := decodeJSONObject(desired.Raw)
	if err != nil {
		return "", errors.New("verified projection object is invalid JSON")
	}
	if !isSubset(expected, observed) {
		return "", errors.New("observed object does not contain the exact projected fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid := text(metadata["uid"])
	if uid == "" || text(metadata["resourceVersion"]) == "" {
		return "", errors.New("Kubernetes API response lacks UID or resourceVersion")
	}
	return uid, nil
}

func decodeJSONObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

func isSubset(expected, observed any) bool {
	switch expectedValue := expected.(type) {
	case map[string]any:
		observedValue, ok := observed.(map[string]any)
		if !ok {
			return false
		}
		for key, expectedChild := range expectedValue {
			observedChild, exists := observedValue[key]
			if !exists || !isSubset(expectedChild, observedChild) {
				return false
			}
		}
		return true
	case []any:
		observedValue, ok := observed.([]any)
		if !ok || len(expectedValue) != len(observedValue) {
			return false
		}
		for index := range expectedValue {
			if !isSubset(expectedValue[index], observedValue[index]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(expected, observed)
	}
}

func text(value any) string {
	result, _ := value.(string)
	return result
}

func apiStatusError(method string, status int, raw []byte) error {
	var response struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &response)
	if response.Reason == "" {
		response.Reason = http.StatusText(status)
	}
	return newCategorizedSubmissionError("SUBMISSION_HTTP_REJECTED", fmt.Sprintf("bounded Kubernetes %s returned status %d (%s)", method, status, response.Reason))
}
