package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const PostRuntimeExecutionActivationLaunchReceiptFormat = "ok147-post-runtime-execution-activation-launch-receipt/v1"

type PostRuntimeExecutionActivationLauncherConfig struct {
	Authority             KubernetesAuthorityConfig
	ExpectedPackageDigest string
}

// PostRuntimeExecutionActivationLaunchReceipt contains only redaction-safe
// identities. The private activation package and bearer credential are never
// retained in the receipt.
type PostRuntimeExecutionActivationLaunchReceipt struct {
	Format        string                           `json:"format"`
	RunID         string                           `json:"runId"`
	PackageDigest string                           `json:"packageDigest"`
	PlanDigest    string                           `json:"planDigest"`
	Authority     string                           `json:"authority"`
	State         string                           `json:"state"`
	MutationState string                           `json:"mutationState"`
	Results       []SubmissionStageInstalledObject `json:"results"`
}

// KubernetesPostRuntimeExecutionActivationLauncher is a single-use bounded
// installer for one verified private activation package.
type KubernetesPostRuntimeExecutionActivationLauncher struct {
	mu       sync.Mutex
	used     bool
	endpoint *url.URL
	token    string
	client   *http.Client
	plan     PostRuntimeExecutionActivationInstallationPlan
	objects  []submissionStageInstallObject
}

// OpenKubernetesPostRuntimeExecutionActivationLauncher opens the exact
// management credential but performs no API request.
func OpenKubernetesPostRuntimeExecutionActivationLauncher(config PostRuntimeExecutionActivationLauncherConfig, packaged VerifiedPostRuntimeExecutionActivationPackage) (*KubernetesPostRuntimeExecutionActivationLauncher, error) {
	receipt, err := packaged.Receipt()
	if err != nil || config.ExpectedPackageDigest != receipt.PackageDigest {
		return nil, errors.New("post-runtime activation package differs from expected identity")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != packaged.managementAuthority || !stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("post-runtime activation authority differs from verified management authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil {
		return nil, errors.New("post-runtime activation endpoint is invalid")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded post-runtime activation credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest {
		return nil, errors.New("post-runtime activation CA differs from bound identity")
	}
	return newKubernetesPostRuntimeExecutionActivationLauncher(submissionStageInstallerClientConfig{
		Endpoint: endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity, Client: client,
	}, packaged)
}

func newKubernetesPostRuntimeExecutionActivationLauncher(config submissionStageInstallerClientConfig, packaged VerifiedPostRuntimeExecutionActivationPackage) (*KubernetesPostRuntimeExecutionActivationLauncher, error) {
	plan, objects, err := preparePostRuntimeExecutionActivationInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("post-runtime activation authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("post-runtime activation Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("post-runtime activation Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken ||
		strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("post-runtime activation credential or client is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesPostRuntimeExecutionActivationLauncher{
		endpoint: endpoint, token: config.BearerToken, client: &client, plan: plan, objects: objects,
	}, nil
}

// Launch completes all three exact-name GETs before the first POST, then
// creates Secret, NetworkPolicy and Job exactly once in that order. It has no
// update, patch, apply, delete, list, watch, retry, rollback or cleanup path.
func (launcher *KubernetesPostRuntimeExecutionActivationLauncher) Launch(ctx context.Context) (PostRuntimeExecutionActivationLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil {
		return receipt, errors.New("post-runtime activation launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopPostRuntimeExecutionActivation(receipt, "STOPPED_ZERO_WRITE", errors.New("post-runtime activation launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	for _, object := range launcher.objects {
		_, status, err := launcher.request(ctx, http.MethodGet, object.plan.ObjectPath, nil)
		if err != nil {
			return stopPostRuntimeExecutionActivation(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			return stopPostRuntimeExecutionActivation(receipt, "STOPPED_ZERO_WRITE", errors.New("post-runtime activation object already exists; zero-write preflight stopped"))
		default:
			return stopPostRuntimeExecutionActivation(receipt, "STOPPED_ZERO_WRITE", postRuntimeActivationStatusError(http.MethodGet, status))
		}
	}

	receipt.State = "ACTIVATING"
	for _, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
		if err != nil {
			return stopPostRuntimeExecutionActivation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stopPostRuntimeExecutionActivation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", postRuntimeActivationStatusError(http.MethodPost, status))
		}
		uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
		if err != nil {
			return stopPostRuntimeExecutionActivation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created post-runtime activation object differs from verified package"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, SubmissionStageInstalledObject{
			Order: object.plan.Order, APIVersion: object.plan.APIVersion, Kind: object.plan.Kind,
			Namespace: object.plan.Namespace, Name: object.plan.Name, ObjectDigest: object.plan.ObjectDigest,
			UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)), State: "CREATED",
		})
	}
	receipt.State = "ACTIVATED"
	return receipt, nil
}

func (launcher *KubernetesPostRuntimeExecutionActivationLauncher) newReceipt() PostRuntimeExecutionActivationLaunchReceipt {
	receipt := PostRuntimeExecutionActivationLaunchReceipt{
		Format: PostRuntimeExecutionActivationLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED",
		Results: []SubmissionStageInstalledObject{},
	}
	if launcher != nil {
		receipt.RunID, receipt.PackageDigest, receipt.PlanDigest, receipt.Authority =
			launcher.plan.RunID, launcher.plan.PackageDigest, launcher.plan.PlanDigest, launcher.plan.Authority
	}
	return receipt
}

func stopPostRuntimeExecutionActivation(receipt PostRuntimeExecutionActivationLaunchReceipt, state string, err error) (PostRuntimeExecutionActivationLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (launcher *KubernetesPostRuntimeExecutionActivationLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded post-runtime activation request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded post-runtime activation %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded post-runtime activation response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded post-runtime activation response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func postRuntimeActivationStatusError(method string, status int) error {
	return fmt.Errorf("bounded post-runtime activation %s returned HTTP %d", method, status)
}
