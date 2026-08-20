package runner

import (
	"bytes"
	"context"
	"crypto/subtle"
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
)

const TargetRegistrationRefreshReceiptFormat = "ok147-target-registration-refresh/v1"

type TargetRegistrationRefreshReceipt struct {
	Format                       string `json:"format"`
	State                        string `json:"state"`
	PlanDigest                   string `json:"planDigest"`
	TargetIdentityDigest         string `json:"targetIdentityDigest"`
	MaterializationBindingDigest string `json:"materializationBindingDigest"`
	ProjectUIDDigest             string `json:"projectUidDigest,omitempty"`
	RegistrationUIDDigest        string `json:"registrationUidDigest,omitempty"`
	ResourceVersionDigest        string `json:"resourceVersionDigest,omitempty"`
	MutationState                string `json:"mutationState"`
	CredentialBytesInReceipt     bool   `json:"credentialBytesInReceipt"`
	StaticRegistrationPreserved  bool   `json:"staticRegistrationPreserved"`
}

// kubernetesTargetRegistrationRefresher is deliberately package-private. A
// later recovery coordinator must place a fresh independently authorized and
// ledger-claimed Stage-9 operation around this single exact replacement.
type kubernetesTargetRegistrationRefresher struct {
	mu             sync.Mutex
	used           bool
	endpoint       *url.URL
	token          string
	client         *http.Client
	clock          func() time.Time
	expiresAt      time.Time
	materializedAt time.Time
	receipt        TargetRegistrationMaterialReceipt
	project        targetRegistrationLaunchObject
	registration   targetRegistrationLaunchObject
}

func newKubernetesTargetRegistrationRefresher(config targetRegistrationLauncherClientConfig, material VerifiedTargetRegistrationMaterial) (*kubernetesTargetRegistrationRefresher, error) {
	receipt, objects, err := prepareTargetRegistrationLaunchMaterial(material)
	if err != nil || len(objects) != 2 || objects[0].role != "project" || objects[1].role != "registration" {
		return nil, errors.New("target-registration refresh requires exact verified material")
	}
	if config.AuthorityIdentity != material.authority || config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken ||
		strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("target-registration refresh writer boundary is invalid")
	}
	if len(config.BearerToken) == len(objects[1].credentialToken) && subtle.ConstantTimeCompare([]byte(config.BearerToken), objects[1].credentialToken) == 1 {
		return nil, errors.New("GitOps writer and refreshed workload credential must be distinct")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.New("target-registration refresh endpoint is invalid")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("target-registration refresh endpoint is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
	if err != nil {
		return nil, errors.New("target-registration refresh expiration is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return &kubernetesTargetRegistrationRefresher{
		endpoint: parsed, token: config.BearerToken, client: &client, clock: config.Clock,
		expiresAt: expiresAt, materializedAt: material.materializedAt, receipt: receipt,
		project: objects[0], registration: objects[1],
	}, nil
}

func (refresher *kubernetesTargetRegistrationRefresher) Refresh(ctx context.Context) (TargetRegistrationRefreshReceipt, error) {
	receipt := TargetRegistrationRefreshReceipt{Format: TargetRegistrationRefreshReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED"}
	if refresher == nil || refresher.client == nil || refresher.clock == nil {
		return receipt, errors.New("target-registration refresher is required")
	}
	receipt.PlanDigest = refresher.receipt.PlanDigest
	receipt.TargetIdentityDigest = refresher.receipt.TargetIdentityDigest
	receipt.MaterializationBindingDigest = refresher.receipt.MaterializationBindingDigest
	refresher.mu.Lock()
	if refresher.used {
		refresher.mu.Unlock()
		return receipt, errors.New("target-registration refresher is single-use")
	}
	refresher.used = true
	refresher.mu.Unlock()
	now := refresher.clock().UTC()
	if now.Before(refresher.materializedAt) || refresher.expiresAt.Sub(now) < minimumTargetRegistrationCredentialRemaining {
		return receipt, errors.New("target-registration refresh credential has insufficient remaining lifetime")
	}
	projectRaw, status, err := refresher.request(ctx, http.MethodGet, refresher.project.objectPath, nil)
	if err != nil || status != http.StatusOK {
		return receipt, targetRegistrationRefreshError(http.MethodGet, status, err)
	}
	projectUID, err := verifyExactExistingTargetRegistrationProject(projectRaw, refresher.project)
	if err != nil {
		return receipt, errors.New("existing target-registration project differs from exact material")
	}
	receipt.ProjectUIDDigest = digest.SHA256([]byte(projectUID))
	existingRaw, status, err := refresher.request(ctx, http.MethodGet, refresher.registration.objectPath, nil)
	if err != nil || status != http.StatusOK {
		return receipt, targetRegistrationRefreshError(http.MethodGet, status, err)
	}
	replacement, uid, err := prepareExactTargetRegistrationRefresh(existingRaw, refresher.registration)
	if err != nil {
		return receipt, err
	}
	receipt.RegistrationUIDDigest = digest.SHA256([]byte(uid))
	receipt.State, receipt.MutationState = "REPLACING", "UNKNOWN"
	updatedRaw, status, err := refresher.request(ctx, http.MethodPut, refresher.registration.objectPath, replacement)
	if err != nil || status != http.StatusOK {
		return receipt, targetRegistrationRefreshError(http.MethodPut, status, err)
	}
	updatedUID, resourceVersion, err := verifyExactTargetRegistrationRefresh(updatedRaw, refresher.registration, uid)
	if err != nil {
		return receipt, errors.New("refreshed target-registration Secret differs from exact material")
	}
	receipt.State, receipt.MutationState = "REFRESHED", "ATTEMPTED"
	receipt.RegistrationUIDDigest = digest.SHA256([]byte(updatedUID))
	receipt.ResourceVersionDigest = digest.SHA256([]byte(resourceVersion))
	receipt.StaticRegistrationPreserved = true
	return receipt, nil
}

func prepareExactTargetRegistrationRefresh(existingRaw []byte, desired targetRegistrationLaunchObject) ([]byte, string, error) {
	existing, err := decodeCapabilityJSONObject(existingRaw)
	if err != nil {
		return nil, "", errors.New("existing target-registration Secret is invalid")
	}
	wanted, err := decodeCapabilityJSONObject(desired.raw)
	if err != nil {
		return nil, "", errors.New("desired target-registration Secret is invalid")
	}
	existingMetadata, _ := existing["metadata"].(map[string]any)
	wantedMetadata, _ := wanted["metadata"].(map[string]any)
	uid, _ := existingMetadata["uid"].(string)
	resourceVersion, _ := existingMetadata["resourceVersion"].(string)
	if existing["apiVersion"] != "v1" || existing["kind"] != "Secret" || existing["type"] != wanted["type"] ||
		existingMetadata["name"] != desired.name || existingMetadata["namespace"] != desired.namespace ||
		!runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return nil, "", errors.New("existing target-registration Secret identity is invalid")
	}
	for _, field := range []string{"labels", "annotations"} {
		if !equalTargetRegistrationMetadata(field, existingMetadata[field], wantedMetadata[field], field == "annotations") {
			return nil, "", errors.New("existing target-registration Secret metadata differs")
		}
	}
	existingStrings, err := decodeTargetRegistrationSecretData(existing["data"])
	if err != nil {
		return nil, "", err
	}
	wantedStrings, _ := wanted["stringData"].(map[string]any)
	if len(existingStrings) != len(wantedStrings) {
		return nil, "", errors.New("existing target-registration Secret data membership differs")
	}
	for _, key := range []string{"name", "server", "namespaces", "clusterResources", "project"} {
		if existingStrings[key] != wantedStrings[key] {
			return nil, "", errors.New("existing target-registration Secret target binding differs")
		}
	}
	var existingConfig, wantedConfig targetRegistrationSecretConfig
	existingConfigRaw, existingOK := existingStrings["config"].(string)
	wantedConfigRaw, wantedOK := wantedStrings["config"].(string)
	if !existingOK || !wantedOK || json.Unmarshal([]byte(existingConfigRaw), &existingConfig) != nil || json.Unmarshal([]byte(wantedConfigRaw), &wantedConfig) != nil ||
		existingConfig.TLSClientConfig != wantedConfig.TLSClientConfig || len(existingConfig.BearerToken) < 80 || len(wantedConfig.BearerToken) < 80 ||
		len(existingConfig.BearerToken) == len(wantedConfig.BearerToken) && subtle.ConstantTimeCompare([]byte(existingConfig.BearerToken), []byte(wantedConfig.BearerToken)) == 1 {
		return nil, "", errors.New("existing target-registration Secret credential boundary is invalid")
	}
	existingAnnotations, _ := existingMetadata["annotations"].(map[string]any)
	existingExpiration, _ := existingAnnotations["openkubes.io/token-expiration"].(string)
	if _, err := time.Parse(time.RFC3339, existingExpiration); err != nil {
		return nil, "", errors.New("existing target-registration Secret expiration is invalid")
	}
	wantedMetadata["uid"], wantedMetadata["resourceVersion"] = uid, resourceVersion
	replacement, err := canonicalTargetRegistrationValue(wanted)
	if err != nil {
		return nil, "", errors.New("canonicalize target-registration Secret refresh")
	}
	return replacement, uid, nil
}

func equalTargetRegistrationMetadata(field string, existing, wanted any, allowTokenExpirationDifference bool) bool {
	if existing == nil && wanted == nil {
		return true
	}
	existingMap, existingOK := existing.(map[string]any)
	wantedMap, wantedOK := wanted.(map[string]any)
	if !existingOK || !wantedOK || len(existingMap) != len(wantedMap) {
		return false
	}
	for key, value := range wantedMap {
		if field == "annotations" && key == "openkubes.io/token-expiration" && allowTokenExpirationDifference {
			if _, ok := existingMap[key].(string); !ok {
				return false
			}
			continue
		}
		if existingMap[key] != value {
			return false
		}
	}
	return true
}

func decodeTargetRegistrationSecretData(value any) (map[string]any, error) {
	data, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("existing target-registration Secret data is invalid")
	}
	decoded := make(map[string]any, len(data))
	for key, value := range data {
		encoded, ok := value.(string)
		if !ok {
			return nil, errors.New("existing target-registration Secret data is invalid")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, errors.New("existing target-registration Secret data is invalid")
		}
		decoded[key] = string(raw)
	}
	return decoded, nil
}

func verifyExactTargetRegistrationRefresh(raw []byte, desired targetRegistrationLaunchObject, expectedUID string) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if uid != expectedUID || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return "", "", errors.New("refreshed target-registration Secret server identity differs")
	}
	wanted, err := decodeCapabilityJSONObject(desired.raw)
	if err != nil {
		return "", "", err
	}
	wantedMetadata, _ := wanted["metadata"].(map[string]any)
	if observed["apiVersion"] != "v1" || observed["kind"] != "Secret" || observed["type"] != wanted["type"] ||
		metadata["name"] != desired.name || metadata["namespace"] != desired.namespace ||
		!equalTargetRegistrationMetadata("labels", metadata["labels"], wantedMetadata["labels"], false) ||
		!equalTargetRegistrationMetadata("annotations", metadata["annotations"], wantedMetadata["annotations"], false) {
		return "", "", errors.New("refreshed target-registration Secret metadata differs")
	}
	observedStrings, err := decodeTargetRegistrationSecretData(observed["data"])
	if err != nil {
		return "", "", err
	}
	wantedStrings, _ := wanted["stringData"].(map[string]any)
	if len(observedStrings) != len(wantedStrings) {
		return "", "", errors.New("refreshed target-registration Secret data membership differs")
	}
	for key, wantedValue := range wantedStrings {
		if observedStrings[key] != wantedValue {
			return "", "", errors.New("refreshed target-registration Secret data differs")
		}
	}
	return uid, resourceVersion, nil
}

func verifyExactExistingTargetRegistrationProject(raw []byte, desired targetRegistrationLaunchObject) (string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", err
	}
	wanted, err := decodeCapabilityJSONObject(desired.raw)
	if err != nil {
		return "", err
	}
	observedMetadata, _ := observed["metadata"].(map[string]any)
	wantedMetadata, _ := wanted["metadata"].(map[string]any)
	uid, _ := observedMetadata["uid"].(string)
	resourceVersion, _ := observedMetadata["resourceVersion"].(string)
	if observed["apiVersion"] != wanted["apiVersion"] || observed["kind"] != wanted["kind"] ||
		observedMetadata["name"] != desired.name || observedMetadata["namespace"] != desired.namespace ||
		!runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) ||
		!equalTargetRegistrationMetadata("labels", observedMetadata["labels"], wantedMetadata["labels"], false) ||
		!equalTargetRegistrationMetadata("annotations", observedMetadata["annotations"], wantedMetadata["annotations"], false) {
		return "", errors.New("existing target-registration project identity differs")
	}
	observedSpec, observedOK := observed["spec"]
	wantedSpec, wantedOK := wanted["spec"]
	observedRaw, observedErr := canonicalTargetRegistrationValue(observedSpec)
	wantedRaw, wantedErr := canonicalTargetRegistrationValue(wantedSpec)
	if !observedOK || !wantedOK || observedErr != nil || wantedErr != nil || !bytes.Equal(observedRaw, wantedRaw) {
		return "", errors.New("existing target-registration project spec differs")
	}
	return uid, nil
}

func (refresher *kubernetesTargetRegistrationRefresher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *refresher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded target-registration refresh request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+refresher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := refresher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded target-registration refresh %s request failed", method)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if err != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded target-registration refresh response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded target-registration refresh response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func targetRegistrationRefreshError(method string, status int, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("bounded target-registration refresh %s returned status %d", method, status)
}
