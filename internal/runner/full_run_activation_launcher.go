package runner

import (
	"bytes"
	"context"
	"encoding/json"
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

const FullRunExecutionActivationLaunchReceiptFormat = "ok147-full-run-execution-activation-launch-receipt/v1"

type FullRunExecutionActivationLauncherConfig struct {
	Authority             KubernetesAuthorityConfig
	ExpectedPackageDigest string
}

// FullRunExecutionActivationLaunchReceipt contains only redaction-safe
// identities. Package bytes and installer credentials are never retained.
type FullRunExecutionActivationLaunchReceipt struct {
	Format        string                           `json:"format"`
	RunID         string                           `json:"runId"`
	PackageDigest string                           `json:"packageDigest"`
	PlanDigest    string                           `json:"planDigest"`
	Authority     string                           `json:"authority"`
	State         string                           `json:"state"`
	MutationState string                           `json:"mutationState"`
	Results       []SubmissionStageInstalledObject `json:"results"`
}

// KubernetesFullRunExecutionActivationLauncher installs one verified private
// full-run activation package. It is bounded, single-use and create-only.
type KubernetesFullRunExecutionActivationLauncher struct {
	mu       sync.Mutex
	used     bool
	endpoint *url.URL
	token    string
	client   *http.Client
	plan     FullRunExecutionActivationInstallationPlan
	objects  []submissionStageInstallObject
}

// OpenKubernetesFullRunExecutionActivationLauncher verifies the exact package
// identity before opening the management credential and performs no API call.
func OpenKubernetesFullRunExecutionActivationLauncher(config FullRunExecutionActivationLauncherConfig, packaged VerifiedFullRunExecutionActivationPackage) (*KubernetesFullRunExecutionActivationLauncher, error) {
	receipt, err := packaged.Receipt()
	if err != nil || config.ExpectedPackageDigest != receipt.PackageDigest {
		return nil, errors.New("full-run activation package differs from expected identity")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != packaged.managementAuthority ||
		!stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("full-run activation authority differs from verified management authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil {
		return nil, errors.New("full-run activation endpoint is invalid")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded full-run activation credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest {
		return nil, errors.New("full-run activation CA differs from bound identity")
	}
	return newKubernetesFullRunExecutionActivationLauncher(submissionStageInstallerClientConfig{
		Endpoint: endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity, Client: client,
	}, packaged)
}

func newKubernetesFullRunExecutionActivationLauncher(config submissionStageInstallerClientConfig, packaged VerifiedFullRunExecutionActivationPackage) (*KubernetesFullRunExecutionActivationLauncher, error) {
	plan, objects, err := prepareFullRunExecutionActivationInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("full-run activation authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("full-run activation Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("full-run activation Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken ||
		strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("full-run activation credential or client is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesFullRunExecutionActivationLauncher{
		endpoint: endpoint, token: config.BearerToken, client: &client, plan: plan, objects: objects,
	}, nil
}

// Launch verifies the exact Namespace and runtime ServiceAccount, completes
// all four exact-name absence GETs before its first POST, then
// creates executor Secret, Evidence Authority Secret, NetworkPolicy and Job in
// that order. It exposes no retry, update, patch, apply, delete or cleanup.
func (launcher *KubernetesFullRunExecutionActivationLauncher) Launch(ctx context.Context) (FullRunExecutionActivationLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil {
		return receipt, errors.New("full-run activation launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", errors.New("full-run activation launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	for _, prerequisite := range launcher.plan.Prerequisites {
		raw, status, err := launcher.request(ctx, http.MethodGet, prerequisite.ObjectPath, nil)
		if err != nil {
			return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", err)
		}
		if status != http.StatusOK {
			return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", fullRunActivationStatusError(http.MethodGet, status))
		}
		if !fullRunActivationPrerequisiteMatches(raw, prerequisite) {
			return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", errors.New("full-run activation prerequisite differs; zero-write preflight stopped"))
		}
	}

	for _, object := range launcher.objects {
		_, status, err := launcher.request(ctx, http.MethodGet, object.plan.ObjectPath, nil)
		if err != nil {
			return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", errors.New("full-run activation object already exists; zero-write preflight stopped"))
		default:
			return stopFullRunExecutionActivation(receipt, "STOPPED_ZERO_WRITE", fullRunActivationStatusError(http.MethodGet, status))
		}
	}

	receipt.State = "ACTIVATING"
	for _, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
		if err != nil {
			return stopFullRunExecutionActivation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stopFullRunExecutionActivation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", fullRunActivationStatusError(http.MethodPost, status))
		}
		uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
		if err != nil {
			return stopFullRunExecutionActivation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created full-run activation object differs from verified package"))
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

func fullRunActivationPrerequisiteMatches(raw []byte, prerequisite FullRunExecutionActivationPrerequisite) bool {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object["apiVersion"] != prerequisite.APIVersion || object["kind"] != prerequisite.Kind {
		return false
	}
	metadata, ok := object["metadata"].(map[string]any)
	if !ok || metadata["name"] != prerequisite.Name {
		return false
	}
	if prerequisite.Namespace != "" && metadata["namespace"] != prerequisite.Namespace {
		return false
	}
	if prerequisite.ExpectState == "PRESENT_EXACT_RUNTIME" {
		labels, _ := metadata["labels"].(map[string]any)
		return object["automountServiceAccountToken"] == false &&
			labels["app.kubernetes.io/name"] == "ok-cluster-contract-executor" &&
			labels["openkubes.io/runtime-boundary"] == "submission-stage"
	}
	return prerequisite.ExpectState == "PRESENT"
}

func (launcher *KubernetesFullRunExecutionActivationLauncher) newReceipt() FullRunExecutionActivationLaunchReceipt {
	receipt := FullRunExecutionActivationLaunchReceipt{
		Format: FullRunExecutionActivationLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED",
		Results: []SubmissionStageInstalledObject{},
	}
	if launcher != nil {
		receipt.RunID, receipt.PackageDigest, receipt.PlanDigest, receipt.Authority =
			launcher.plan.RunID, launcher.plan.PackageDigest, launcher.plan.PlanDigest, launcher.plan.Authority
	}
	return receipt
}

func stopFullRunExecutionActivation(receipt FullRunExecutionActivationLaunchReceipt, state string, err error) (FullRunExecutionActivationLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (launcher *KubernetesFullRunExecutionActivationLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded full-run activation request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded full-run activation %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded full-run activation response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded full-run activation response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func fullRunActivationStatusError(method string, status int) error {
	return fmt.Errorf("bounded full-run activation %s returned HTTP %d", method, status)
}
