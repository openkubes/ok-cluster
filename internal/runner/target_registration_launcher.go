package runner

import (
	"bytes"
	"context"
	"crypto/subtle"
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

const TargetRegistrationLaunchReceiptFormat = "ok147-target-registration-launch-receipt/v1"

type TargetRegistrationLauncherConfig struct {
	Authority KubernetesAuthorityConfig
	Clock     func() time.Time
}

type TargetRegistrationLaunchResult struct {
	Order                            int    `json:"order"`
	Role                             string `json:"role"`
	Namespace                        string `json:"namespace"`
	Name                             string `json:"name"`
	BoundDigest                      string `json:"boundDigest"`
	UIDDigest                        string `json:"uidDigest"`
	ResourceVersionDigest            string `json:"resourceVersionDigest"`
	State                            string `json:"state"`
	MaterializedObjectDigestRetained bool   `json:"materializedObjectDigestRetained"`
}

type TargetRegistrationLaunchReceipt struct {
	Format                       string                           `json:"format"`
	StageID                      string                           `json:"stageId"`
	PlanDigest                   string                           `json:"planDigest"`
	TargetIdentityDigest         string                           `json:"targetIdentityDigest"`
	MaterializationBindingDigest string                           `json:"materializationBindingDigest"`
	Authority                    string                           `json:"authority"`
	State                        string                           `json:"state"`
	MutationState                string                           `json:"mutationState"`
	CredentialBytesInReceipt     bool                             `json:"credentialBytesInReceipt"`
	Results                      []TargetRegistrationLaunchResult `json:"results"`
}

type targetRegistrationLaunchObject struct {
	order           int
	role            string
	namespace       string
	name            string
	collectionPath  string
	objectPath      string
	boundDigest     string
	privateDigest   string
	credentialToken []byte
	raw             []byte
}

// KubernetesTargetRegistrationLauncher is a single-use, two-object,
// create-only writer against the verified GitOps authority. Both exact
// absence checks complete before the AppProject and credential-bearing Secret
// are submitted. Partial state is preserved and no retry path exists.
type KubernetesTargetRegistrationLauncher struct {
	mu             sync.Mutex
	used           bool
	endpoint       *url.URL
	token          string
	client         *http.Client
	clock          func() time.Time
	expiresAt      time.Time
	materializedAt time.Time
	authority      string
	receipt        TargetRegistrationMaterialReceipt
	objects        []targetRegistrationLaunchObject
}

type targetRegistrationLauncherClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
	Clock             func() time.Time
}

// OpenKubernetesTargetRegistrationLauncher opens the bounded ok-shared
// credential and verifies all private material without contacting an API.
func OpenKubernetesTargetRegistrationLauncher(config TargetRegistrationLauncherConfig, material VerifiedTargetRegistrationMaterial) (*KubernetesTargetRegistrationLauncher, error) {
	if err := verifyTargetRegistrationMaterial(material); err != nil {
		return nil, err
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != material.authority ||
		!stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("target-registration launcher authority differs from verified GitOps authority")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded target-registration launcher credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest {
		return nil, errors.New("target-registration launcher CA differs from bound identity")
	}
	return newKubernetesTargetRegistrationLauncher(targetRegistrationLauncherClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity,
		Client: client, Clock: config.Clock,
	}, material)
}

func newKubernetesTargetRegistrationLauncher(config targetRegistrationLauncherClientConfig, material VerifiedTargetRegistrationMaterial) (*KubernetesTargetRegistrationLauncher, error) {
	receipt, objects, err := prepareTargetRegistrationLaunchMaterial(material)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != material.authority {
		return nil, errors.New("target-registration launcher authority differs from verified GitOps authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.New("target-registration launcher endpoint is invalid")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("target-registration launcher credential, client, or clock is invalid")
	}
	if len(config.BearerToken) == len(objects[1].credentialToken) && subtle.ConstantTimeCompare([]byte(config.BearerToken), objects[1].credentialToken) == 1 {
		return nil, errors.New("GitOps writer and workload target credentials must be distinct")
	}
	expiresAt, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
	if err != nil {
		return nil, errors.New("target-registration material expiration is invalid")
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("target-registration launcher endpoint is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return &KubernetesTargetRegistrationLauncher{
		endpoint: parsedEndpoint, token: config.BearerToken, client: &client, clock: config.Clock,
		expiresAt: expiresAt, materializedAt: material.materializedAt,
		authority: config.AuthorityIdentity, receipt: receipt, objects: objects,
	}, nil
}

func (launcher *KubernetesTargetRegistrationLauncher) Install(ctx context.Context) (TargetRegistrationLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil || launcher.clock == nil {
		return receipt, errors.New("target-registration launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stoppedTargetRegistrationLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("target-registration launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()
	now := launcher.clock().UTC()
	if now.Before(launcher.materializedAt) || launcher.expiresAt.Sub(now) < minimumTargetRegistrationCredentialRemaining {
		return stoppedTargetRegistrationLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("target-registration credential has insufficient remaining lifetime"))
	}
	for _, object := range launcher.objects {
		_, status, err := launcher.request(ctx, http.MethodGet, object.objectPath, nil)
		if err != nil {
			return stoppedTargetRegistrationLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			return stoppedTargetRegistrationLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("target-registration object already exists; zero-write preflight stopped"))
		default:
			return stoppedTargetRegistrationLaunch(receipt, "STOPPED_ZERO_WRITE", targetRegistrationLaunchStatusError(http.MethodGet, status))
		}
	}
	receipt.State = "CREATING"
	for _, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := launcher.request(ctx, http.MethodPost, object.collectionPath, object.raw)
		if err != nil {
			return stoppedTargetRegistrationLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stoppedTargetRegistrationLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", targetRegistrationLaunchStatusError(http.MethodPost, status))
		}
		uid, resourceVersion, err := verifyTargetRegistrationCreatedObject(raw, object)
		if err != nil {
			return stoppedTargetRegistrationLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created target-registration object differs from verified material"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, TargetRegistrationLaunchResult{
			Order: object.order, Role: object.role, Namespace: object.namespace, Name: object.name,
			BoundDigest: object.boundDigest, UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
			State: "CREATED", MaterializedObjectDigestRetained: false,
		})
	}
	receipt.State = "INSTALLED"
	return receipt, nil
}

func (launcher *KubernetesTargetRegistrationLauncher) newReceipt() TargetRegistrationLaunchReceipt {
	receipt := TargetRegistrationLaunchReceipt{
		Format: TargetRegistrationLaunchReceiptFormat, StageID: "target-registration",
		State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", CredentialBytesInReceipt: false,
		Results: []TargetRegistrationLaunchResult{},
	}
	if launcher != nil {
		receipt.PlanDigest = launcher.receipt.PlanDigest
		receipt.TargetIdentityDigest = launcher.receipt.TargetIdentityDigest
		receipt.MaterializationBindingDigest = launcher.receipt.MaterializationBindingDigest
		receipt.Authority = launcher.authority
	}
	return receipt
}

func stoppedTargetRegistrationLaunch(receipt TargetRegistrationLaunchReceipt, state string, err error) (TargetRegistrationLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func prepareTargetRegistrationLaunchMaterial(material VerifiedTargetRegistrationMaterial) (TargetRegistrationMaterialReceipt, []targetRegistrationLaunchObject, error) {
	if err := verifyTargetRegistrationMaterial(material); err != nil {
		return TargetRegistrationMaterialReceipt{}, nil, err
	}
	objects := []targetRegistrationLaunchObject{
		{order: 1, role: "project", collectionPath: material.projectCollection, objectPath: material.projectPath, boundDigest: material.receipt.ProjectDigest, privateDigest: digest.SHA256(material.project), raw: append([]byte(nil), material.project...)},
		{order: 2, role: "registration", collectionPath: material.registrationCollection, objectPath: material.registrationPath, boundDigest: material.receipt.RegistrationTemplateDigest, privateDigest: material.registrationDigest, raw: append([]byte(nil), material.registration...)},
	}
	for index := range objects {
		var value map[string]any
		if err := json.Unmarshal(objects[index].raw, &value); err != nil {
			return TargetRegistrationMaterialReceipt{}, nil, errors.New("target-registration launch object is invalid JSON")
		}
		metadata, _ := value["metadata"].(map[string]any)
		objects[index].namespace, _ = metadata["namespace"].(string)
		objects[index].name, _ = metadata["name"].(string)
		if objects[index].namespace == "" || objects[index].name == "" || !stageReceiptPrefixDigestPattern.MatchString(objects[index].privateDigest) {
			return TargetRegistrationMaterialReceipt{}, nil, errors.New("target-registration launch object identity is invalid")
		}
		if objects[index].role == "registration" {
			stringData, _ := value["stringData"].(map[string]any)
			configRaw, _ := stringData["config"].(string)
			var config targetRegistrationSecretConfig
			if json.Unmarshal([]byte(configRaw), &config) != nil || len(config.BearerToken) < 80 {
				return TargetRegistrationMaterialReceipt{}, nil, errors.New("target-registration private credential config is invalid")
			}
			objects[index].credentialToken = []byte(config.BearerToken)
		}
	}
	return material.receipt, objects, nil
}

func verifyTargetRegistrationCreatedObject(raw []byte, expected targetRegistrationLaunchObject) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	desired, err := decodeCapabilityJSONObject(expected.raw)
	if err != nil || !capabilitySubset(desired, observed) {
		return "", "", errors.New("observed target-registration object does not contain exact desired fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if metadata["name"] != expected.name || metadata["namespace"] != expected.namespace || !runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return "", "", errors.New("observed target-registration server identity is invalid")
	}
	return uid, resourceVersion, nil
}

func (launcher *KubernetesTargetRegistrationLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded target-registration request")
	}
	request.Header.Set("Accept", "application/json")
	if method == http.MethodGet {
		request.Header.Set("Accept", partialObjectMetadataAccept)
	}
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded target-registration %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded target-registration response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded target-registration response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func targetRegistrationLaunchStatusError(method string, status int) error {
	return fmt.Errorf("bounded target-registration %s returned status %d", method, status)
}
