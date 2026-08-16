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
	"gopkg.in/yaml.v3"
)

const (
	SubmissionStageInstallationReceiptFormat = "ok147-submission-stage-installation-receipt/v1"
	maximumStageInstallationResponseBytes    = 4 * 1024 * 1024
)

// SubmissionStageInstalledObject records only redaction-safe runtime identity
// for the exact successfully created prefix. Raw UID and resourceVersion
// values remain private to the execution environment.
type SubmissionStageInstalledObject struct {
	Order                 int    `json:"order"`
	APIVersion            string `json:"apiVersion"`
	Kind                  string `json:"kind"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	ObjectDigest          string `json:"objectDigest"`
	UIDDigest             string `json:"uidDigest"`
	ResourceVersionDigest string `json:"resourceVersionDigest"`
	State                 string `json:"state"`
}

// SubmissionStageInstallationReceipt is useful on success and failure. Its
// Results are only the exact prefix whose create responses were verified.
type SubmissionStageInstallationReceipt struct {
	Format        string                           `json:"format"`
	StageID       string                           `json:"stageId"`
	PackageDigest string                           `json:"packageDigest"`
	Authority     string                           `json:"authority"`
	State         string                           `json:"state"`
	MutationState string                           `json:"mutationState"`
	Results       []SubmissionStageInstalledObject `json:"results"`
}

type submissionStageInstallObject struct {
	plan SubmissionStageCreatePlan
	raw  []byte
}

// KubernetesSubmissionStagePackageInstaller is single-use and can perform
// only the exact GET/POST sequence retained from one verified package.
type KubernetesSubmissionStagePackageInstaller struct {
	mu        sync.Mutex
	used      bool
	endpoint  *url.URL
	token     string
	client    *http.Client
	authority string
	plan      SubmissionStageInstallationPlan
	objects   []submissionStageInstallObject
}

type submissionStageInstallerClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
}

// OpenKubernetesSubmissionStagePackageInstaller opens one TLS-only installer
// from an exact verified package and a separately supplied installer
// credential. It performs no API request and does not read either credential
// Secret named by the future Job.
func OpenKubernetesSubmissionStagePackageInstaller(config KubernetesAuthorityConfig, packaged VerifiedSubmissionStagePackage) (*KubernetesSubmissionStagePackageInstaller, error) {
	if _, _, err := prepareSubmissionStageInstallation(packaged); err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != packaged.installationAuthority {
		return nil, errors.New("stage package installer authority differs from verified management authority")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.CABundleDigest) {
		return nil, errors.New("stage package installer CA identity is required")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, errors.New("open bounded stage package installer credential")
	}
	if digest.SHA256(ca) != config.CABundleDigest {
		return nil, errors.New("stage package installer CA differs from bound identity")
	}
	return newKubernetesSubmissionStagePackageInstaller(submissionStageInstallerClientConfig{
		Endpoint: config.Endpoint, BearerToken: token, AuthorityIdentity: config.AuthorityIdentity, Client: client,
	}, packaged)
}

func newKubernetesSubmissionStagePackageInstaller(config submissionStageInstallerClientConfig, packaged VerifiedSubmissionStagePackage) (*KubernetesSubmissionStagePackageInstaller, error) {
	plan, objects, err := prepareSubmissionStageInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != packaged.installationAuthority {
		return nil, errors.New("stage package installer authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("stage package installer Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("stage package installer Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("stage package installer Kubernetes credential or client is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesSubmissionStagePackageInstaller{
		endpoint: endpoint, token: config.BearerToken, client: &client,
		authority: config.AuthorityIdentity, plan: plan, objects: objects,
	}, nil
}

// Install performs a complete zero-write preflight before the first POST,
// then creates ConfigMap, NetworkPolicy and Job in that fixed order. It never
// adopts, updates, patches, applies, deletes, lists, watches or retries.
func (installer *KubernetesSubmissionStagePackageInstaller) Install(ctx context.Context) (SubmissionStageInstallationReceipt, error) {
	receipt := installer.newReceipt()
	if installer == nil || installer.client == nil {
		return receipt, errors.New("stage package installer is required")
	}
	installer.mu.Lock()
	if installer.used {
		installer.mu.Unlock()
		return stoppedStageInstallation(receipt, "STOPPED_ZERO_WRITE", errors.New("stage package installer is single-use"))
	}
	installer.used = true
	installer.mu.Unlock()

	for _, object := range installer.objects {
		_, status, err := installer.request(ctx, http.MethodGet, object.plan.ObjectPath, nil)
		if err != nil {
			return stoppedStageInstallation(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
			// Exact absence is the only state that can reach the create phase.
		case http.StatusOK:
			return stoppedStageInstallation(receipt, "STOPPED_ZERO_WRITE", errors.New("stage package object already exists; zero-write preflight stopped"))
		default:
			return stoppedStageInstallation(receipt, "STOPPED_ZERO_WRITE", stageInstallationStatusError(http.MethodGet, status))
		}
	}

	receipt.State = "CREATING"
	for _, object := range installer.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := installer.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
		if err != nil {
			return stoppedStageInstallation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stoppedStageInstallation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", stageInstallationStatusError(http.MethodPost, status))
		}
		uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
		if err != nil {
			return stoppedStageInstallation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created stage package object differs from verified package"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, SubmissionStageInstalledObject{
			Order: object.plan.Order, APIVersion: object.plan.APIVersion, Kind: object.plan.Kind,
			Namespace: object.plan.Namespace, Name: object.plan.Name, ObjectDigest: object.plan.ObjectDigest,
			UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)), State: "CREATED",
		})
	}
	receipt.State = "INSTALLED"
	return receipt, nil
}

func (installer *KubernetesSubmissionStagePackageInstaller) newReceipt() SubmissionStageInstallationReceipt {
	receipt := SubmissionStageInstallationReceipt{
		Format: SubmissionStageInstallationReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED",
		Results: []SubmissionStageInstalledObject{},
	}
	if installer != nil {
		receipt.StageID, receipt.PackageDigest, receipt.Authority = installer.plan.StageID, installer.plan.PackageDigest, installer.authority
	}
	return receipt
}

func stoppedStageInstallation(receipt SubmissionStageInstallationReceipt, state string, err error) (SubmissionStageInstallationReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (installer *KubernetesSubmissionStagePackageInstaller) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *installer.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded stage package request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+installer.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := installer.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded stage package %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded stage package response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded stage package response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func prepareSubmissionStageInstallation(packaged VerifiedSubmissionStagePackage) (SubmissionStageInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanSubmissionStageInstallation(packaged)
	if err != nil {
		return SubmissionStageInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return SubmissionStageInstallationPlan{}, nil, errors.New("decode verified stage package installation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return SubmissionStageInstallationPlan{}, nil, errors.New("stage package installation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SubmissionStageInstallationPlan{}, nil, errors.New("stage package installation contains trailing object")
	}
	return plan, objects, nil
}

func verifySubmissionStageCreatedObject(raw []byte, expected submissionStageInstallObject) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	desired, err := decodeCapabilityJSONObject(expected.raw)
	if err != nil || !capabilitySubset(desired, observed) {
		return "", "", errors.New("observed object does not contain exact package fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if !runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return "", "", errors.New("created object lacks bounded runtime identity")
	}
	return uid, resourceVersion, nil
}

func stageInstallationStatusError(method string, status int) error {
	return fmt.Errorf("bounded stage package %s returned HTTP %d", method, status)
}
