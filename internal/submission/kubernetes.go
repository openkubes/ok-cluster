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
	"sort"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	maximumAPIResponseBytes          = 4 * 1024 * 1024
	objectMismatchConfirmationDelay  = 2 * time.Second
	maximumMismatchConfirmationDelay = 5 * time.Second
	objectMismatchConvergenceTimeout = 30 * time.Minute
	objectMismatchMaximumAttempts    = 900
	PlaneReceiptFormat               = "ok147-bounded-submission-receipt/v2"
)

// KubernetesClientConfig binds one client to one authority plane. Credentials
// are supplied by an execution-environment adapter and are never retained in a
// receipt.
type KubernetesClientConfig struct {
	Endpoint                     string
	BearerToken                  string
	ClientCertificate            bool
	AuthorityIdentity            string
	Client                       *http.Client
	MismatchConfirmationDelay    time.Duration
	MismatchConfirmationAttempts int
	Wait                         func(context.Context, time.Duration) error
}

// KubernetesClient performs only exact GET and collection POST operations.
type KubernetesClient struct {
	endpoint                     *url.URL
	token                        string
	clientCertificate            bool
	authority                    string
	client                       *http.Client
	mismatchConfirmationDelay    time.Duration
	mismatchConfirmationAttempts int
	wait                         func(context.Context, time.Duration) error
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
	Format           string                      `json:"format"`
	Authority        string                      `json:"authority"`
	Role             string                      `json:"role"`
	State            string                      `json:"state"`
	MutationState    string                      `json:"mutationState"`
	Results          []ObjectResult              `json:"results"`
	MismatchEvidence *SubmissionMismatchEvidence `json:"mismatchEvidence,omitempty"`
}

// SubmissionMismatchEvidence is the complete public diagnostic envelope for
// bounded mismatch convergence. It cannot carry field paths, object identity,
// endpoints, credentials, raw responses, or wrapped private errors.
type SubmissionMismatchEvidence struct {
	FirstCategory         string `json:"firstCategory"`
	LastCategory          string `json:"lastCategory"`
	ObservationCount      int    `json:"observationCount"`
	ExpectedDigest        string `json:"expectedDigest"`
	LastObservedDigest    string `json:"lastObservedDigest"`
	RuntimeIdentityStable bool   `json:"runtimeIdentityStable"`
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
	evidence *SubmissionMismatchEvidence
}

func (err *categorizedSubmissionError) Error() string                { return err.message }
func (err *categorizedSubmissionError) RedactedStopCategory() string { return err.category }
func (err *categorizedSubmissionError) RedactedMismatchEvidence() *SubmissionMismatchEvidence {
	return cloneMismatchEvidence(err.evidence)
}

func newCategorizedSubmissionError(category, message string) error {
	return &categorizedSubmissionError{category: category, message: message}
}

func newCategorizedSubmissionErrorWithEvidence(category, message string, evidence *SubmissionMismatchEvidence) error {
	return &categorizedSubmissionError{category: category, message: message, evidence: cloneMismatchEvidence(evidence)}
}

func cloneMismatchEvidence(source *SubmissionMismatchEvidence) *SubmissionMismatchEvidence {
	if source == nil {
		return nil
	}
	clone := *source
	return &clone
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
	if config.MismatchConfirmationDelay < 0 || config.MismatchConfirmationDelay > maximumMismatchConfirmationDelay {
		return nil, errors.New("submission mismatch confirmation delay is invalid")
	}
	if config.MismatchConfirmationAttempts < 0 || config.MismatchConfirmationAttempts > objectMismatchMaximumAttempts {
		return nil, errors.New("submission mismatch confirmation attempts are invalid")
	}
	confirmationDelay := config.MismatchConfirmationDelay
	if confirmationDelay == 0 {
		confirmationDelay = objectMismatchConfirmationDelay
	}
	confirmationAttempts := config.MismatchConfirmationAttempts
	if confirmationAttempts == 0 {
		confirmationAttempts = objectMismatchMaximumAttempts
	}
	wait := config.Wait
	if wait == nil {
		wait = waitForSubmissionConfirmation
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
		mismatchConfirmationDelay: confirmationDelay, mismatchConfirmationAttempts: confirmationAttempts, wait: wait,
	}, nil
}

func waitForSubmissionConfirmation(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Submit verifies existing objects or creates missing objects in projection
// order. It never updates, patches, deletes, lists, watches, discovers, or
// retries a mutation. Existing mismatches are only re-observed in-process
// within one bounded stage receipt. A conflict after an absence observation is
// indeterminate and stops.
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
	for index, object := range plane.Objects {
		state, uid, mutationAttempted, err := client.submitObject(ctx, object)
		if mutationAttempted {
			receipt.MutationState = "ATTEMPTED"
		}
		if err != nil {
			return stopped(receipt, bindSubmissionObjectOrdinal(err, index+1))
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

// bindSubmissionObjectOrdinal adds only the one-based position in the already
// verified projection order. It never exposes the object's kind, name,
// namespace, API path or contents.
func bindSubmissionObjectOrdinal(cause error, ordinal int) error {
	var categorized interface{ RedactedStopCategory() string }
	if !errors.As(cause, &categorized) || (!strings.HasPrefix(categorized.RedactedStopCategory(), "SUBMISSION_OBJECT_") && !strings.HasPrefix(categorized.RedactedStopCategory(), "SUBMISSION_CREATE_RESPONSE_")) {
		return cause
	}
	var evidenceSource interface {
		RedactedMismatchEvidence() *SubmissionMismatchEvidence
	}
	if errors.As(cause, &evidenceSource) {
		return newCategorizedSubmissionErrorWithEvidence(fmt.Sprintf("%s_AT_%02d", categorized.RedactedStopCategory(), ordinal), "Kubernetes object failed bounded verification", evidenceSource.RedactedMismatchEvidence())
	}
	return newCategorizedSubmissionError(fmt.Sprintf("%s_AT_%02d", categorized.RedactedStopCategory(), ordinal), "Kubernetes object failed bounded verification")
}

func stopped(receipt PlaneReceipt, cause error) (PlaneReceipt, error) {
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	category := "SUBMISSION_RESPONSE_INVALID"
	var categorized interface{ RedactedStopCategory() string }
	if errors.As(cause, &categorized) {
		category = categorized.RedactedStopCategory()
	}
	var evidenceSource interface {
		RedactedMismatchEvidence() *SubmissionMismatchEvidence
	}
	if errors.As(cause, &evidenceSource) {
		receipt.MismatchEvidence = evidenceSource.RedactedMismatchEvidence()
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
		if objectIsTerminating(response) {
			return "", "", false, newCategorizedSubmissionError("SUBMISSION_OBJECT_TERMINATING", "existing Kubernetes object is terminating")
		}
		uid, err := verifyObservedObject(response, object)
		if err != nil {
			if categorizedSubmissionCategory(err) == "SUBMISSION_OBJECT_COMPARATOR_INCONSISTENT" {
				return "", "", false, err
			}
			state, confirmedUID, continueCreate, confirmErr := client.confirmObservedMismatch(ctx, object, response, err)
			if confirmErr != nil || !continueCreate {
				return state, confirmedUID, false, confirmErr
			}
			break
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
		category := "SUBMISSION_CREATE_RESPONSE_INVALID"
		var categorized interface{ RedactedStopCategory() string }
		if errors.As(err, &categorized) {
			category = strings.Replace(categorized.RedactedStopCategory(), "SUBMISSION_OBJECT_", "SUBMISSION_CREATE_RESPONSE_", 1)
		}
		return "", "", true, newCategorizedSubmissionError(category, "created Kubernetes object response differs from projection")
	}
	return "CREATED", uid, true, nil
}

// confirmObservedMismatch performs bounded in-process convergence observation
// below the single stage receipt. It is not a stage retry. Stable drift and
// identity turnover remain terminal; only confirmed disappearance reaches the
// existing one-create path.
func (client *KubernetesClient) confirmObservedMismatch(ctx context.Context, object Object, first []byte, firstErr error) (string, string, bool, error) {
	firstUID, firstResourceVersion := observedRuntimeIdentity(first)
	if firstUID == "" || firstResourceVersion == "" {
		return "", "", false, existingObjectMismatch(firstErr)
	}
	convergenceCtx, cancel := context.WithTimeout(ctx, objectMismatchConvergenceTimeout)
	defer cancel()
	lastErr := firstErr
	lastObserved := append([]byte(nil), first...)
	observationCount := 0
	for attempt := 0; attempt < client.mismatchConfirmationAttempts; attempt++ {
		// The final observation is deliberately performed without another wait.
		// This closes the narrow race between the last delayed observation and
		// attempt-cap exhaustion without extending either hard bound.
		if attempt < client.mismatchConfirmationAttempts-1 {
			if err := client.wait(convergenceCtx, client.mismatchConfirmationDelay); err != nil {
				if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
					return "", "", false, existingObjectMismatchConvergenceExhausted(lastErr, mismatchEvidence(object, firstErr, lastErr, observationCount, lastObserved))
				}
				return "", "", false, newCategorizedSubmissionError("SUBMISSION_OBJECT_RESPONSE_INVALID", "existing Kubernetes object confirmation was interrupted")
			}
		}
		response, status, err := client.request(convergenceCtx, http.MethodGet, object.ObjectPath, nil)
		if err != nil {
			if errors.Is(convergenceCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				return "", "", false, existingObjectMismatchConvergenceExhausted(lastErr, mismatchEvidence(object, firstErr, lastErr, observationCount, lastObserved))
			}
			return "", "", false, err
		}
		switch status {
		case http.StatusNotFound:
			return "", "", true, nil
		case http.StatusOK:
			observationCount++
			lastObserved = append(lastObserved[:0], response...)
			if objectIsTerminating(response) {
				return "", "", false, newCategorizedSubmissionError("SUBMISSION_OBJECT_TERMINATING", "existing Kubernetes object is terminating")
			}
			uid, verifyErr := verifyObservedObject(response, object)
			if verifyErr == nil {
				if uid != firstUID {
					return "", "", false, newCategorizedSubmissionError("SUBMISSION_OBJECT_RUNTIME_IDENTITY_INVALID", "existing Kubernetes object identity changed during confirmation")
				}
				return "UNCHANGED", uid, false, nil
			}
			confirmedUID, confirmedResourceVersion := observedRuntimeIdentity(response)
			if confirmedUID == "" || confirmedResourceVersion == "" || confirmedUID != firstUID {
				return "", "", false, newCategorizedSubmissionError("SUBMISSION_OBJECT_RUNTIME_IDENTITY_INVALID", "existing Kubernetes object identity changed during confirmation")
			}
			lastErr = verifyErr
			if attempt == client.mismatchConfirmationAttempts-1 {
				return "", "", false, existingObjectMismatchConvergenceExhausted(lastErr, mismatchEvidence(object, firstErr, lastErr, observationCount, lastObserved))
			}
		default:
			return "", "", false, apiStatusError(http.MethodGet, status, response)
		}
	}
	panic("unreachable bounded mismatch convergence")
}

func existingObjectMismatch(err error) error {
	category := "SUBMISSION_OBJECT_MISMATCH"
	var categorized interface{ RedactedStopCategory() string }
	if errors.As(err, &categorized) {
		category = categorized.RedactedStopCategory()
	}
	return newCategorizedSubmissionError(category, "existing Kubernetes object differs from projection")
}

func existingObjectMismatchConvergenceExhausted(err error, evidence *SubmissionMismatchEvidence) error {
	category := "SUBMISSION_OBJECT_MISMATCH_CONVERGENCE_EXHAUSTED"
	var categorized interface{ RedactedStopCategory() string }
	if errors.As(err, &categorized) {
		switch categorized.RedactedStopCategory() {
		case "SUBMISSION_OBJECT_MISMATCH", "SUBMISSION_OBJECT_IDENTITY_MISMATCH", "SUBMISSION_OBJECT_METADATA_MISMATCH",
			"SUBMISSION_OBJECT_SPEC_MISMATCH", "SUBMISSION_OBJECT_CONTENT_MISMATCH",
			"SUBMISSION_OBJECT_CONTENT_DATA_MISMATCH", "SUBMISSION_OBJECT_CONTENT_STRING_DATA_MISMATCH",
			"SUBMISSION_OBJECT_CONTENT_RULES_MISMATCH", "SUBMISSION_OBJECT_CONTENT_SUBJECTS_MISMATCH",
			"SUBMISSION_OBJECT_CONTENT_ROLE_REF_MISMATCH", "SUBMISSION_OBJECT_CONTENT_TYPE_MISMATCH",
			"SUBMISSION_OBJECT_CONTENT_OTHER_MISMATCH":
			category = categorized.RedactedStopCategory() + "_CONVERGENCE_EXHAUSTED"
		}
	}
	return newCategorizedSubmissionErrorWithEvidence(category, "existing Kubernetes object mismatch did not converge within the bounded window", evidence)
}

func mismatchEvidence(object Object, firstErr, lastErr error, count int, lastObserved []byte) *SubmissionMismatchEvidence {
	return &SubmissionMismatchEvidence{
		FirstCategory:         categorizedSubmissionCategory(firstErr),
		LastCategory:          categorizedSubmissionCategory(lastErr),
		ObservationCount:      count,
		ExpectedDigest:        object.Digest,
		LastObservedDigest:    canonicalObservedDigest(lastObserved),
		RuntimeIdentityStable: true,
	}
}

func categorizedSubmissionCategory(err error) string {
	var categorized interface{ RedactedStopCategory() string }
	if errors.As(err, &categorized) {
		return categorized.RedactedStopCategory()
	}
	return "SUBMISSION_OBJECT_MISMATCH"
}

func canonicalObservedDigest(raw []byte) string {
	value, err := decodeJSONObject(raw)
	if err != nil {
		return ""
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return ""
	}
	return digest.SHA256(canonical)
}

func observedRuntimeIdentity(raw []byte) (string, string) {
	object, err := decodeJSONObject(raw)
	if err != nil {
		return "", ""
	}
	metadata, _ := object["metadata"].(map[string]any)
	return text(metadata["uid"]), text(metadata["resourceVersion"])
}

func objectIsTerminating(raw []byte) bool {
	object, err := decodeJSONObject(raw)
	if err != nil {
		return false
	}
	metadata, _ := object["metadata"].(map[string]any)
	deletionTimestamp, _ := metadata["deletionTimestamp"].(string)
	return deletionTimestamp != ""
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
		return "", newCategorizedSubmissionError("SUBMISSION_OBJECT_RESPONSE_INVALID", "Kubernetes API returned invalid object JSON")
	}
	expected, err := decodeJSONObject(desired.Raw)
	if err != nil {
		return "", newCategorizedSubmissionError("SUBMISSION_OBJECT_PROJECTION_INVALID", "verified projection object is invalid JSON")
	}
	if !isSubset(expected, observed) {
		return "", newCategorizedSubmissionError(objectMismatchCategory(expected, observed), "observed object does not contain the exact projected fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid := text(metadata["uid"])
	if uid == "" || text(metadata["resourceVersion"]) == "" {
		return "", newCategorizedSubmissionError("SUBMISSION_OBJECT_RUNTIME_IDENTITY_INVALID", "Kubernetes API response lacks UID or resourceVersion")
	}
	return uid, nil
}

// objectMismatchCategory exposes only the validation phase that rejected an
// existing object. It deliberately does not retain field names below the
// public Kubernetes envelope, values, object identities or raw evidence.
func objectMismatchCategory(expected, observed map[string]any) string {
	if !isSubset(expected["apiVersion"], observed["apiVersion"]) || !isSubset(expected["kind"], observed["kind"]) {
		return "SUBMISSION_OBJECT_IDENTITY_MISMATCH"
	}
	if !isSubset(expected["metadata"], observed["metadata"]) {
		return "SUBMISSION_OBJECT_METADATA_MISMATCH"
	}
	if expectedSpec, exists := expected["spec"]; exists && !isSubset(expectedSpec, observed["spec"]) {
		return "SUBMISSION_OBJECT_SPEC_MISMATCH"
	}
	mismatched := make([]string, 0, len(expected))
	for key := range expected {
		switch key {
		case "apiVersion", "kind", "metadata", "spec":
		default:
			if !isSubset(expected[key], observed[key]) {
				mismatched = append(mismatched, key)
			}
		}
	}
	sort.Strings(mismatched)
	if len(mismatched) == 0 {
		return "SUBMISSION_OBJECT_COMPARATOR_INCONSISTENT"
	}
	switch mismatched[0] {
	case "data":
		return "SUBMISSION_OBJECT_CONTENT_DATA_MISMATCH"
	case "stringData":
		return "SUBMISSION_OBJECT_CONTENT_STRING_DATA_MISMATCH"
	case "rules":
		return "SUBMISSION_OBJECT_CONTENT_RULES_MISMATCH"
	case "subjects":
		return "SUBMISSION_OBJECT_CONTENT_SUBJECTS_MISMATCH"
	case "roleRef":
		return "SUBMISSION_OBJECT_CONTENT_ROLE_REF_MISMATCH"
	case "type":
		return "SUBMISSION_OBJECT_CONTENT_TYPE_MISMATCH"
	default:
		return "SUBMISSION_OBJECT_CONTENT_OTHER_MISMATCH"
	}
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
	// The category deliberately retains only the protocol-level failure class.
	// Neither the response body, Kubernetes Status reason, request method nor
	// endpoint may cross the submission boundary.
	category := "SUBMISSION_HTTP_REJECTED"
	switch status {
	case http.StatusUnauthorized:
		category = "SUBMISSION_HTTP_UNAUTHORIZED"
	case http.StatusForbidden:
		category = "SUBMISSION_HTTP_FORBIDDEN"
	case http.StatusTooManyRequests:
		category = "SUBMISSION_HTTP_RATE_LIMITED"
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		category = "SUBMISSION_HTTP_SERVER_ERROR"
	}
	return newCategorizedSubmissionError(category, "bounded Kubernetes request was rejected")
}
