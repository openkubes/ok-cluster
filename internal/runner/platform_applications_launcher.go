package runner

import (
	"bytes"
	"context"
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

const PlatformApplicationsLaunchReceiptFormat = "ok147-platform-applications-launch-receipt/v1"

type PlatformApplicationsLauncherConfig struct {
	Authority KubernetesAuthorityConfig
}

type PlatformApplicationsLaunchReceipt struct {
	Format               string                        `json:"format"`
	StageID              string                        `json:"stageId"`
	PlanDigest           string                        `json:"planDigest"`
	ArtifactDigest       string                        `json:"artifactDigest"`
	TargetIdentityDigest string                        `json:"targetIdentityDigest"`
	ProfileDigest        string                        `json:"profileDigest"`
	Authority            string                        `json:"authority"`
	State                string                        `json:"state"`
	MutationState        string                        `json:"mutationState"`
	Results              []SubmissionStageLaunchResult `json:"results"`
}

type platformApplicationLaunchObject struct {
	order          int
	apiVersion     string
	kind           string
	namespace      string
	name           string
	collectionPath string
	objectPath     string
	digest         string
	raw            []byte
}

// KubernetesPlatformApplicationsLauncher is a single-use, three-Application,
// create-only writer. All exact absence checks complete before its first POST;
// a partial or unknown result is preserved and cannot be retried.
type KubernetesPlatformApplicationsLauncher struct {
	mu        sync.Mutex
	used      bool
	endpoint  *url.URL
	token     string
	client    *http.Client
	authority string
	receipt   PlatformApplicationsStageBundleReceipt
	objects   []platformApplicationLaunchObject
}

type platformApplicationsLauncherClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
}

// OpenKubernetesPlatformApplicationsLauncher opens the bounded GitOps writer
// credential without contacting an API.
func OpenKubernetesPlatformApplicationsLauncher(config PlatformApplicationsLauncherConfig, bundle VerifiedPlatformApplicationsStageBundle) (*KubernetesPlatformApplicationsLauncher, error) {
	if err := verifyPlatformApplicationsStageBundle(bundle); err != nil {
		return nil, err
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != bundle.receipt.Authority || !stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("platform-applications launcher authority differs from verified GitOps authority")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded platform-applications launcher credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest {
		return nil, errors.New("platform-applications launcher CA differs from bound identity")
	}
	return newKubernetesPlatformApplicationsLauncher(platformApplicationsLauncherClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token,
		AuthorityIdentity: config.Authority.AuthorityIdentity, Client: client,
	}, bundle)
}

func newKubernetesPlatformApplicationsLauncher(config platformApplicationsLauncherClientConfig, bundle VerifiedPlatformApplicationsStageBundle) (*KubernetesPlatformApplicationsLauncher, error) {
	if err := verifyPlatformApplicationsStageBundle(bundle); err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != bundle.receipt.Authority {
		return nil, errors.New("platform-applications launcher authority differs from verified GitOps authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.New("platform-applications launcher endpoint is invalid")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("platform-applications launcher credential or client is invalid")
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("platform-applications launcher endpoint is invalid")
	}
	objects := make([]platformApplicationLaunchObject, len(bundle.projection.Applications))
	for index, application := range bundle.projection.Applications {
		objects[index] = platformApplicationLaunchObject{
			order: index + 1, apiVersion: application.Identity.APIVersion, kind: application.Identity.Kind,
			namespace: application.Identity.Namespace, name: application.Identity.Name,
			collectionPath: application.CollectionPath, objectPath: application.ObjectPath,
			digest: application.Digest, raw: append([]byte(nil), application.Raw...),
		}
	}
	if err := verifyPlatformApplicationLaunchObjects(objects); err != nil {
		return nil, err
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return &KubernetesPlatformApplicationsLauncher{
		endpoint: parsedEndpoint, token: config.BearerToken, client: &client,
		authority: config.AuthorityIdentity, receipt: bundle.receipt, objects: objects,
	}, nil
}

func (launcher *KubernetesPlatformApplicationsLauncher) Install(ctx context.Context) (PlatformApplicationsLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil {
		return receipt, errors.New("platform-applications launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopPlatformApplicationsLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("platform-applications launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()
	for _, object := range launcher.objects {
		_, status, err := launcher.request(ctx, http.MethodGet, object.objectPath, nil)
		if err != nil {
			return stopPlatformApplicationsLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			return stopPlatformApplicationsLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("platform Application already exists; zero-write preflight stopped"))
		default:
			return stopPlatformApplicationsLaunch(receipt, "STOPPED_ZERO_WRITE", platformApplicationsLaunchStatusError(http.MethodGet, status))
		}
	}
	receipt.State = "CREATING"
	for _, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := launcher.request(ctx, http.MethodPost, object.collectionPath, object.raw)
		if err != nil {
			return stopPlatformApplicationsLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stopPlatformApplicationsLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", platformApplicationsLaunchStatusError(http.MethodPost, status))
		}
		uid, resourceVersion, err := verifyPlatformApplicationCreatedObject(raw, object)
		if err != nil {
			return stopPlatformApplicationsLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created platform Application differs from verified projection"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, SubmissionStageLaunchResult{
			Order: object.order, Phase: "platform-application", APIVersion: object.apiVersion, Kind: object.kind,
			Namespace: object.namespace, Name: object.name, ObjectDigest: object.digest, ObjectState: "CREATED",
			UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
		})
	}
	receipt.State = "INSTALLED"
	return receipt, nil
}

func (launcher *KubernetesPlatformApplicationsLauncher) newReceipt() PlatformApplicationsLaunchReceipt {
	receipt := PlatformApplicationsLaunchReceipt{
		Format: PlatformApplicationsLaunchReceiptFormat, StageID: "platform-applications",
		State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageLaunchResult{},
	}
	if launcher != nil {
		receipt.PlanDigest = launcher.receipt.PlanDigest
		receipt.ArtifactDigest = launcher.receipt.ArtifactDigest
		receipt.TargetIdentityDigest = launcher.receipt.TargetIdentityDigest
		receipt.ProfileDigest = launcher.receipt.ProfileDigest
		receipt.Authority = launcher.authority
	}
	return receipt
}

func stopPlatformApplicationsLaunch(receipt PlatformApplicationsLaunchReceipt, state string, err error) (PlatformApplicationsLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func verifyPlatformApplicationCreatedObject(raw []byte, expected platformApplicationLaunchObject) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	desired, err := decodeCapabilityJSONObject(expected.raw)
	if err != nil || !capabilitySubset(desired, observed) {
		return "", "", errors.New("observed platform Application does not contain exact desired fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if metadata["name"] != expected.name || metadata["namespace"] != expected.namespace || !runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return "", "", errors.New("observed platform Application server identity is invalid")
	}
	return uid, resourceVersion, nil
}

func (launcher *KubernetesPlatformApplicationsLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded platform-applications request")
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
		return nil, 0, fmt.Errorf("bounded platform-applications %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded platform-applications response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded platform-applications response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func platformApplicationsLaunchStatusError(method string, status int) error {
	return fmt.Errorf("bounded platform-applications %s returned status %d", method, status)
}

func verifyPlatformApplicationLaunchObjects(objects []platformApplicationLaunchObject) error {
	if len(objects) != 3 {
		return errors.New("platform-applications launcher requires exactly three objects")
	}
	for index, object := range objects {
		var value map[string]any
		if object.order != index+1 || object.apiVersion != "argoproj.io/v1alpha1" || object.kind != "Application" || object.namespace == "" || object.name == "" || !stageReceiptPrefixDigestPattern.MatchString(object.digest) || digest.SHA256(object.raw) != object.digest || json.Unmarshal(object.raw, &value) != nil {
			return errors.New("platform-applications launcher object binding is invalid")
		}
	}
	return nil
}
