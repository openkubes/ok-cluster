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

const SubmissionStageRuntimeInstallationReceiptFormat = "ok147-submission-stage-runtime-installation-receipt/v1"

type SubmissionStageRuntimeInstallationReceipt struct {
	Format                string `json:"format"`
	StagePackageDigest    string `json:"stagePackageDigest"`
	ManifestDigest        string `json:"manifestDigest"`
	ObjectDigest          string `json:"objectDigest"`
	Authority             string `json:"authority"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	State                 string `json:"state"`
	MutationState         string `json:"mutationState"`
	ObjectState           string `json:"objectState,omitempty"`
	UIDDigest             string `json:"uidDigest,omitempty"`
	ResourceVersionDigest string `json:"resourceVersionDigest,omitempty"`
}

type KubernetesSubmissionStageRuntimeInstaller struct {
	mu       sync.Mutex
	used     bool
	endpoint *url.URL
	token    string
	client   *http.Client
	runtime  VerifiedSubmissionStageRuntimePrerequisite
}

type submissionStageRuntimeInstallerClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
}

// OpenKubernetesSubmissionStageRuntimeInstaller opens a bounded management
// client for one verified tokenless ServiceAccount prerequisite. It performs
// no API request.
func OpenKubernetesSubmissionStageRuntimeInstaller(config KubernetesAuthorityConfig, runtime VerifiedSubmissionStageRuntimePrerequisite) (*KubernetesSubmissionStageRuntimeInstaller, error) {
	if err := verifySubmissionStageRuntimePrerequisite(runtime); err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != runtime.receipt.Authority {
		return nil, errors.New("stage runtime installer authority differs from verified management authority")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) {
		return nil, errors.New("stage runtime installer CA identity is required")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, errors.New("open bounded stage runtime installer credential")
	}
	if digest.SHA256(ca) != config.CABundleDigest {
		return nil, errors.New("stage runtime installer CA differs from bound identity")
	}
	return newKubernetesSubmissionStageRuntimeInstaller(submissionStageRuntimeInstallerClientConfig{
		Endpoint: config.Endpoint, BearerToken: token, AuthorityIdentity: config.AuthorityIdentity, Client: client,
	}, runtime)
}

func newKubernetesSubmissionStageRuntimeInstaller(config submissionStageRuntimeInstallerClientConfig, runtime VerifiedSubmissionStageRuntimePrerequisite) (*KubernetesSubmissionStageRuntimeInstaller, error) {
	if err := verifySubmissionStageRuntimePrerequisite(runtime); err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != runtime.receipt.Authority {
		return nil, errors.New("stage runtime installer authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("stage runtime installer Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("stage runtime installer Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("stage runtime installer Kubernetes credential or client is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	runtime.raw = append([]byte(nil), runtime.raw...)
	return &KubernetesSubmissionStageRuntimeInstaller{endpoint: endpoint, token: config.BearerToken, client: &client, runtime: runtime}, nil
}

// Ensure performs exactly one GET and, only when absent, one POST. Existing
// state is accepted only after exact semantic verification. There is no
// update, patch, apply, delete, list, watch, discovery or retry operation.
func (installer *KubernetesSubmissionStageRuntimeInstaller) Ensure(ctx context.Context) (SubmissionStageRuntimeInstallationReceipt, error) {
	receipt := installer.newReceipt()
	if installer == nil || installer.client == nil {
		return receipt, errors.New("stage runtime installer is required")
	}
	installer.mu.Lock()
	if installer.used {
		installer.mu.Unlock()
		receipt.State = "STOPPED_ZERO_WRITE"
		return receipt, errors.New("stage runtime installer is single-use")
	}
	installer.used = true
	installer.mu.Unlock()

	objectPath := "/api/v1/namespaces/" + installer.runtime.receipt.Namespace + "/serviceaccounts/" + installer.runtime.receipt.Name
	collectionPath := "/api/v1/namespaces/" + installer.runtime.receipt.Namespace + "/serviceaccounts"
	raw, status, err := installer.request(ctx, http.MethodGet, objectPath, nil)
	if err != nil {
		receipt.State = "STOPPED_ZERO_WRITE"
		return receipt, err
	}
	switch status {
	case http.StatusOK:
		uid, resourceVersion, err := verifySubmissionStageRuntimeObject(raw, installer.runtime.raw)
		if err != nil {
			receipt.State = "STOPPED_ZERO_WRITE"
			return receipt, errors.New("existing stage runtime differs from verified prerequisite")
		}
		receipt.State, receipt.ObjectState = "READY", "EXISTING_VERIFIED"
		receipt.UIDDigest, receipt.ResourceVersionDigest = digest.SHA256([]byte(uid)), digest.SHA256([]byte(resourceVersion))
		return receipt, nil
	case http.StatusNotFound:
	default:
		receipt.State = "STOPPED_ZERO_WRITE"
		return receipt, stageRuntimeInstallationStatusError(http.MethodGet, status)
	}

	receipt.MutationState = "ATTEMPTED_UNKNOWN"
	raw, status, err = installer.request(ctx, http.MethodPost, collectionPath, installer.runtime.raw)
	if err != nil {
		receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
		return receipt, err
	}
	if status != http.StatusCreated {
		receipt.State, receipt.MutationState = "STOPPED_PARTIAL_OR_UNKNOWN", "ATTEMPTED"
		return receipt, stageRuntimeInstallationStatusError(http.MethodPost, status)
	}
	uid, resourceVersion, err := verifySubmissionStageRuntimeObject(raw, installer.runtime.raw)
	if err != nil {
		receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
		return receipt, errors.New("created stage runtime differs from verified prerequisite")
	}
	receipt.State, receipt.MutationState, receipt.ObjectState = "READY", "ATTEMPTED", "CREATED"
	receipt.UIDDigest, receipt.ResourceVersionDigest = digest.SHA256([]byte(uid)), digest.SHA256([]byte(resourceVersion))
	return receipt, nil
}

func (installer *KubernetesSubmissionStageRuntimeInstaller) newReceipt() SubmissionStageRuntimeInstallationReceipt {
	receipt := SubmissionStageRuntimeInstallationReceipt{Format: SubmissionStageRuntimeInstallationReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED"}
	if installer != nil {
		receipt.StagePackageDigest = installer.runtime.receipt.StagePackageDigest
		receipt.ManifestDigest = installer.runtime.receipt.ManifestDigest
		receipt.ObjectDigest = installer.runtime.receipt.ObjectDigest
		receipt.Authority = installer.runtime.receipt.Authority
		receipt.Namespace = installer.runtime.receipt.Namespace
		receipt.Name = installer.runtime.receipt.Name
	}
	return receipt
}

func (installer *KubernetesSubmissionStageRuntimeInstaller) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *installer.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded stage runtime request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+installer.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := installer.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded stage runtime %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded stage runtime response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded stage runtime response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func verifySubmissionStageRuntimePrerequisite(runtime VerifiedSubmissionStageRuntimePrerequisite) error {
	if !runtime.verified || runtime.receipt.Format != SubmissionStageRuntimePrerequisiteFormat || runtime.receipt.State != "VERIFIED" || runtime.receipt.Authority == "" || runtime.receipt.Namespace != submissionStageInputNamespace || runtime.receipt.Name != "ok147-contract-executor-runtime" || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.StagePackageDigest) || !stageReceiptPrefixDigestPattern.MatchString(runtime.receipt.ManifestDigest) || digest.SHA256(runtime.raw) != runtime.receipt.ObjectDigest {
		return errors.New("submission stage runtime prerequisite changed after verification")
	}
	var object map[string]any
	if err := json.Unmarshal(runtime.raw, &object); err != nil {
		return errors.New("submission stage runtime prerequisite is invalid JSON")
	}
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	if object["apiVersion"] != "v1" || object["kind"] != "ServiceAccount" || object["automountServiceAccountToken"] != false || metadata["name"] != runtime.receipt.Name || metadata["namespace"] != runtime.receipt.Namespace || labels["app.kubernetes.io/name"] != "ok-cluster-contract-executor" || labels["openkubes.io/runtime-boundary"] != "submission-stage" || len(object) != 4 || len(metadata) != 3 || len(labels) != 2 {
		return errors.New("submission stage runtime prerequisite semantics changed after verification")
	}
	return nil
}

func verifySubmissionStageRuntimeObject(raw, desiredRaw []byte) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	desired, err := decodeCapabilityJSONObject(desiredRaw)
	if err != nil || !capabilitySubset(desired, observed) {
		return "", "", errors.New("observed ServiceAccount does not contain exact prerequisite fields")
	}
	allowedTopLevel := map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "automountServiceAccountToken": true}
	for key := range observed {
		if !allowedTopLevel[key] {
			return "", "", errors.New("observed ServiceAccount contains additional runtime semantics")
		}
	}
	metadata, _ := observed["metadata"].(map[string]any)
	allowedMetadata := map[string]bool{
		"name": true, "namespace": true, "labels": true, "uid": true, "resourceVersion": true,
		"creationTimestamp": true, "managedFields": true,
	}
	for key := range metadata {
		if !allowedMetadata[key] {
			return "", "", errors.New("observed ServiceAccount metadata contains additional runtime semantics")
		}
	}
	labels, _ := metadata["labels"].(map[string]any)
	if len(labels) != 2 || labels["app.kubernetes.io/name"] != "ok-cluster-contract-executor" || labels["openkubes.io/runtime-boundary"] != "submission-stage" {
		return "", "", errors.New("observed ServiceAccount labels differ from exact prerequisite")
	}
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if !runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return "", "", errors.New("stage runtime lacks bounded runtime identity")
	}
	return uid, resourceVersion, nil
}

func stageRuntimeInstallationStatusError(method string, status int) error {
	return fmt.Errorf("bounded stage runtime %s returned HTTP %d", method, status)
}
